use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use wisp_core::auth;
use wisp_core::frame::FrameHeader;
use wisp_core::types::{D0_FRAME_SIZE, D0_FRAME_SIZE_AUTH, D0_PAYLOAD_SIZE, FLAGS_AUTH_HMAC, HEADER_SIZE, HMAC_TAG_SIZE, MAX_C0_PAYLOAD};

/// C0 (TCP) reliable ordered transport.
pub struct C0Transport {
    stream: TcpStream,
    session_key: Option<[u8; 32]>,
    /// Highest frame_id received — enforces strictly increasing on authenticated sessions.
    last_recv_frame_id: u64,
    /// Maximum allowed payload size for received frames.
    max_payload: u32,
}

impl C0Transport {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self { stream, session_key: None, last_recv_frame_id: 0, max_payload: MAX_C0_PAYLOAD })
    }

    pub async fn accept(listener: &TcpListener) -> io::Result<Self> {
        let (stream, _addr) = listener.accept().await?;
        Ok(Self { stream, session_key: None, last_recv_frame_id: 0, max_payload: MAX_C0_PAYLOAD })
    }

    /// Set the maximum payload size for received C0 frames (after HELLO negotiation).
    pub fn set_max_payload(&mut self, max: u32) {
        self.max_payload = max.min(MAX_C0_PAYLOAD);
    }

    /// Set the session key for HMAC authentication on all subsequent frames.
    pub fn set_session_key(&mut self, key: [u8; 32]) {
        self.session_key = Some(key);
    }

    /// Returns the peer address of the underlying TCP connection.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub async fn send_frame(&mut self, header: &FrameHeader, payload: &[u8]) -> io::Result<()> {
        let mut hdr_bytes = header.encode();
        if let Some(ref key) = self.session_key {
            // Set the AUTH flag in the encoded header bytes.
            let flags = u16::from_le_bytes([hdr_bytes[4], hdr_bytes[5]]) | FLAGS_AUTH_HMAC;
            hdr_bytes[4..6].copy_from_slice(&flags.to_le_bytes());
            let tag = auth::compute_tag(key, &hdr_bytes, payload);
            self.stream.write_all(&hdr_bytes).await?;
            self.stream.write_all(payload).await?;
            self.stream.write_all(&tag).await?;
        } else {
            self.stream.write_all(&hdr_bytes).await?;
            self.stream.write_all(payload).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> io::Result<(FrameHeader, Vec<u8>)> {
        let mut hdr_buf = [0u8; HEADER_SIZE];
        self.stream.read_exact(&mut hdr_buf).await?;
        let header = FrameHeader::decode(&hdr_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if header.payload_len > self.max_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("C0 payload_len {} exceeds maximum {}", header.payload_len, self.max_payload),
            ));
        }
        let payload_len = header.payload_len as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.stream.read_exact(&mut payload).await?;
        }
        // Enforce HMAC policy: if session_key is set, ALL frames must be authenticated.
        if header.flags & FLAGS_AUTH_HMAC != 0 {
            let mut tag = [0u8; HMAC_TAG_SIZE];
            self.stream.read_exact(&mut tag).await?;
            let key = self.session_key.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "received authenticated frame but no session key set")
            })?;
            if !auth::verify_tag(key, &hdr_buf, &payload, &tag) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed on C0 frame"));
            }
        } else if self.session_key.is_some() {
            // Strict: session key exists but frame lacks AUTH flag — reject.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received unauthenticated C0 frame on authenticated session",
            ));
        }
        // Enforce strictly increasing frame_id on authenticated sessions.
        // Skip for handshake frames (frame_id=0 during HELLO/SELECT exchange before key exists).
        if self.session_key.is_some() && header.frame_id > 0 {
            if header.frame_id <= self.last_recv_frame_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "C0 frame_id {} not strictly increasing (last: {})",
                        header.frame_id, self.last_recv_frame_id
                    ),
                ));
            }
            self.last_recv_frame_id = header.frame_id;
        }
        Ok((header, payload))
    }
}

/// D0 (UDP) unreliable datagram transport.
pub struct D0Transport {
    socket: UdpSocket,
    session_key: Option<[u8; 32]>,
}

impl D0Transport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            session_key: None,
        }
    }

    /// Set the session key for HMAC authentication on all subsequent frames.
    /// Must be called before passing D0Transport to sender/receiver.
    pub fn set_session_key(&mut self, key: [u8; 32]) {
        self.session_key = Some(key);
    }

    pub async fn send_frame(
        &self,
        header: &FrameHeader,
        payload: &[u8],
        addr: SocketAddr,
    ) -> io::Result<()> {
        let mut hdr_bytes = header.encode();
        let key_opt = self.session_key;

        let frame_size = if key_opt.is_some() { D0_FRAME_SIZE_AUTH } else { D0_FRAME_SIZE };
        let data_size = D0_FRAME_SIZE - HEADER_SIZE;

        if payload.len() > data_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "D0 payload {} bytes exceeds maximum {} bytes",
                    payload.len(),
                    data_size,
                ),
            ));
        }

        let mut buf = Vec::with_capacity(frame_size);

        if let Some(key) = key_opt {
            // Set AUTH flag in header bytes.
            let flags = u16::from_le_bytes([hdr_bytes[4], hdr_bytes[5]]) | FLAGS_AUTH_HMAC;
            hdr_bytes[4..6].copy_from_slice(&flags.to_le_bytes());

            buf.extend_from_slice(&hdr_bytes);
            buf.extend_from_slice(payload);
            // Pad payload to fixed data_size before computing tag.
            buf.resize(D0_FRAME_SIZE, 0);

            let tag = auth::compute_tag(&key, &buf[..HEADER_SIZE], &buf[HEADER_SIZE..D0_FRAME_SIZE]);
            buf.extend_from_slice(&tag);
        } else {
            buf.extend_from_slice(&hdr_bytes);
            buf.extend_from_slice(payload);
            buf.resize(D0_FRAME_SIZE, 0);
        }

        self.socket.send_to(&buf, addr).await?;
        Ok(())
    }

    /// Receive a D0 frame, returning the source address even on auth failure.
    /// On success: Ok((header, payload, addr)).
    /// On auth failure: Err(error) + addr still available via the tuple.
    pub async fn try_recv_frame(&self) -> (io::Result<(FrameHeader, Vec<u8>)>, Option<SocketAddr>) {
        let mut buf = [0u8; D0_FRAME_SIZE_AUTH];
        let (len, addr) = match self.socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => return (Err(e), None),
        };
        if len < HEADER_SIZE {
            return (Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram too short for header",
            )), Some(addr));
        }
        let hdr_buf: [u8; HEADER_SIZE] = buf[..HEADER_SIZE].try_into().unwrap();
        let header = match FrameHeader::decode(&hdr_buf) {
            Ok(h) => h,
            Err(e) => return (Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())), Some(addr)),
        };

        // Validate payload_len against protocol maximum and actual datagram size.
        let plen = header.payload_len as usize;
        if plen > D0_PAYLOAD_SIZE {
            return (Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("D0 payload_len {} exceeds D0_PAYLOAD_SIZE {}", plen, D0_PAYLOAD_SIZE),
            )), Some(addr));
        }

        if header.flags & FLAGS_AUTH_HMAC != 0 {
            if len < HEADER_SIZE + HMAC_TAG_SIZE {
                return (Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authenticated datagram too short for tag",
                )), Some(addr));
            }
            let key = match self.session_key {
                Some(k) => k,
                None => return (Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "received authenticated D0 frame but no session key set",
                )), Some(addr)),
            };
            let tag_start = len - HMAC_TAG_SIZE;
            let mut tag = [0u8; HMAC_TAG_SIZE];
            tag.copy_from_slice(&buf[tag_start..len]);
            let payload_region = &buf[HEADER_SIZE..tag_start];
            if !auth::verify_tag(&key, &hdr_buf, payload_region, &tag) {
                return (Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HMAC verification failed on D0 frame",
                )), Some(addr));
            }
            // Use payload_len to extract actual payload (rest is zero-padding).
            let payload = buf[HEADER_SIZE..HEADER_SIZE + plen].to_vec();
            (Ok((header, payload)), Some(addr))
        } else if self.session_key.is_some() {
            (Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received unauthenticated D0 frame on authenticated session",
            )), Some(addr))
        } else {
            let payload = buf[HEADER_SIZE..HEADER_SIZE + plen].to_vec();
            (Ok((header, payload)), Some(addr))
        }
    }

    pub async fn recv_frame(&self) -> io::Result<(FrameHeader, Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; D0_FRAME_SIZE_AUTH]; // big enough for both modes
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        if len < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram too short for header",
            ));
        }
        let hdr_buf: [u8; HEADER_SIZE] = buf[..HEADER_SIZE].try_into().unwrap();
        let header = FrameHeader::decode(&hdr_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Validate payload_len against protocol maximum.
        let plen = header.payload_len as usize;
        if plen > D0_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("D0 payload_len {} exceeds D0_PAYLOAD_SIZE {}", plen, D0_PAYLOAD_SIZE),
            ));
        }

        if header.flags & FLAGS_AUTH_HMAC != 0 {
            // Authenticated frame: last 16 bytes are HMAC tag.
            if len < HEADER_SIZE + HMAC_TAG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authenticated datagram too short for tag",
                ));
            }
            let key = self.session_key.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "received authenticated D0 frame but no session key set")
            })?;
            let tag_start = len - HMAC_TAG_SIZE;
            let mut tag = [0u8; HMAC_TAG_SIZE];
            tag.copy_from_slice(&buf[tag_start..len]);
            let payload_region = &buf[HEADER_SIZE..tag_start];
            if !auth::verify_tag(&key, &hdr_buf, payload_region, &tag) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HMAC verification failed on D0 frame"));
            }
            let payload = buf[HEADER_SIZE..HEADER_SIZE + plen].to_vec();
            Ok((header, payload, addr))
        } else if self.session_key.is_some() {
            // Strict: session key exists but frame lacks AUTH flag — reject.
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received unauthenticated D0 frame on authenticated session",
            ))
        } else {
            let payload = buf[HEADER_SIZE..HEADER_SIZE + plen].to_vec();
            Ok((header, payload, addr))
        }
    }
}

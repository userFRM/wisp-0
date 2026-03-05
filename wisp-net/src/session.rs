use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use wisp_core::auth;
use wisp_core::frame::{Frame, FrameHeader, HelloAuth};
use wisp_core::types::{Digest32, D0_PAYLOAD_SIZE, MAX_SESSION_DURATION_SECS, MAX_SESSION_FRAMES};
use zeroize::Zeroize;

use crate::transport::{C0Transport, D0Transport};

/// Maximum retransmission attempts before declaring a timeout fatal.
pub const MAX_RETRIES: u32 = 3;

/// EWMA-based RTT estimator (RFC 6298 simplified).
struct RttEstimator {
    avg: f64,
    var: f64,
    has_sample: bool,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            avg: 2.0,
            var: 0.5,
            has_sample: false,
        }
    }

    fn record_sample(&mut self, rtt_secs: f64) {
        if !self.has_sample {
            self.avg = rtt_secs;
            self.var = rtt_secs / 2.0;
            self.has_sample = true;
        } else {
            self.var = 0.75 * self.var + 0.25 * (rtt_secs - self.avg).abs();
            self.avg = 0.875 * self.avg + 0.125 * rtt_secs;
        }
    }

    fn control_timeout(&self) -> Duration {
        let t = self.avg + 4.0 * self.var;
        Duration::from_secs_f64(t.clamp(1.0, 30.0))
    }

    fn data_timeout(&self) -> Duration {
        self.control_timeout().mul_f64(3.0).max(Duration::from_secs(10))
    }
}

/// AIMD congestion controller for D0 send pacing.
///
/// Slow start: cwnd doubles per RTT until ssthresh.
/// Congestion avoidance: cwnd += 1/cwnd per ACK (additive increase).
/// Loss (NEEDMORE or timeout): ssthresh = cwnd/2, cwnd = ssthresh (multiplicative decrease).
/// Pacing: inter-packet gap = rtt / cwnd, clamped to [10µs, 10ms].
pub struct CongestionController {
    cwnd: f64,
    ssthresh: f64,
    in_flight: u64,
    last_send: Option<tokio::time::Instant>,
}

impl CongestionController {
    const INITIAL_CWND: f64 = 10.0;
    const MIN_CWND: f64 = 2.0;
    const MAX_CWND: f64 = 10_000.0;

    fn new() -> Self {
        Self {
            cwnd: Self::INITIAL_CWND,
            ssthresh: Self::MAX_CWND,
            in_flight: 0,
            last_send: None,
        }
    }

    /// Pace sending: sleep for rtt/cwnd interval since last send.
    async fn pace(&mut self, rtt: &RttEstimator) {
        if let Some(last) = self.last_send {
            let gap_secs = rtt.avg / self.cwnd;
            let gap = Duration::from_secs_f64(gap_secs.clamp(10e-6, 10e-3));
            let elapsed = tokio::time::Instant::now().duration_since(last);
            if elapsed < gap {
                tokio::time::sleep(gap - elapsed).await;
            }
        }
        self.last_send = Some(tokio::time::Instant::now());
    }

    /// Record a sent packet.
    fn on_send(&mut self) {
        self.in_flight += 1;
    }

    /// Implicit ACK: decoder made progress. Increase window.
    pub fn on_progress(&mut self, packets: u64) {
        self.in_flight = self.in_flight.saturating_sub(packets);
        for _ in 0..packets {
            if self.cwnd < self.ssthresh {
                // Slow start: double cwnd per RTT (one +1 per ACK).
                self.cwnd += 1.0;
            } else {
                // Congestion avoidance: cwnd += 1/cwnd per ACK.
                self.cwnd += 1.0 / self.cwnd;
            }
        }
        self.cwnd = self.cwnd.min(Self::MAX_CWND);
    }

    /// Loss detected (NEEDMORE or timeout). Halve window.
    pub fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(Self::MIN_CWND);
        self.cwnd = self.ssthresh;
        self.in_flight = 0;
    }
}

/// Generate a 32-byte random buffer.
fn generate_random() -> std::io::Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(buf)
}

/// Negotiated session parameters.
pub struct SessionParams {
    pub session_id: u64,
    pub object_id: u64,
    pub update_id: u64,
    pub capsule_id: u32,
    pub capsule_ver: u16,
    pub max_m_log2: u8,
    pub max_symbols: u32,
}

/// Manages a wisp session: HELLO/SELECT handshake, frame ID counter, ACK tracking.
pub struct Session {
    pub params: SessionParams,
    next_frame_id: u64,
    unacked: HashMap<u64, (FrameHeader, Vec<u8>)>,
    session_key: Option<[u8; 32]>,
    /// Monotonic sequence counter for D0 data frames.
    data_seq: u64,
    /// Total frames sent (C0 + D0) for session limit enforcement.
    total_frames_sent: u64,
    /// Session start time.
    started_at: Instant,
    /// RTT estimator for adaptive timeouts.
    rtt: RttEstimator,
    /// Send timestamps for RTT measurement (frame_id -> sent_at).
    send_times: HashMap<u64, Instant>,
    /// D0 congestion controller (AIMD).
    pub cc: CongestionController,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.session_key {
            key.zeroize();
        }
    }
}

impl Session {
    fn new(params: SessionParams) -> Self {
        Self {
            params,
            next_frame_id: 1,
            unacked: HashMap::new(),
            session_key: None,
            data_seq: 0,
            total_frames_sent: 0,
            started_at: Instant::now(),
            rtt: RttEstimator::new(),
            send_times: HashMap::new(),
            cc: CongestionController::new(),
        }
    }

    /// Returns the negotiated session key, if HMAC authentication was established.
    pub fn session_key(&self) -> Option<&[u8; 32]> {
        self.session_key.as_ref()
    }

    fn alloc_frame_id(&mut self) -> u64 {
        let id = self.next_frame_id;
        self.next_frame_id += 1;
        id
    }

    /// Returns the frame_id assigned to the most recently sent control frame.
    pub fn last_sent_frame_id(&self) -> u64 {
        self.next_frame_id - 1
    }

    /// Check session limits (frame count and duration).
    fn check_session_limits(&self) -> std::io::Result<()> {
        if self.total_frames_sent >= MAX_SESSION_FRAMES {
            return Err(std::io::Error::other(format!(
                "session frame limit exceeded: {} >= {}",
                self.total_frames_sent, MAX_SESSION_FRAMES
            )));
        }
        if self.started_at.elapsed().as_secs() >= MAX_SESSION_DURATION_SECS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "session duration limit exceeded",
            ));
        }
        Ok(())
    }

    /// Build a FrameHeader for a control frame (chan=0) on the current update.
    pub fn make_control_header(
        &mut self,
        frame: &Frame,
        payload_len: u32,
        base_digest: Digest32,
    ) -> FrameHeader {
        let frame_id = self.alloc_frame_id();
        self.total_frames_sent += 1;
        FrameHeader {
            frame_type: frame.frame_type_code(),
            flags: 0,
            payload_len,
            session_id: self.params.session_id,
            object_id: self.params.object_id,
            update_id: self.params.update_id,
            frame_id,
            capsule_id: self.params.capsule_id,
            chan: 0,
            base_digest,
        }
    }

    /// Build a FrameHeader for a data frame (chan=1) with monotonic sequence counter.
    pub fn make_data_header(
        &mut self,
        frame: &Frame,
        payload_len: u32,
        base_digest: Digest32,
    ) -> FrameHeader {
        self.data_seq += 1;
        self.total_frames_sent += 1;
        FrameHeader {
            frame_type: frame.frame_type_code(),
            flags: 0,
            payload_len,
            session_id: self.params.session_id,
            object_id: self.params.object_id,
            update_id: self.params.update_id,
            frame_id: self.data_seq,
            capsule_id: self.params.capsule_id,
            chan: 1,
            base_digest,
        }
    }

    /// Build a session-scoped header (HELLO/SELECT).
    fn make_session_header(&mut self, frame: &Frame, payload_len: u32) -> FrameHeader {
        let frame_id = if frame.channel() == 0 {
            self.alloc_frame_id()
        } else {
            0
        };
        FrameHeader {
            frame_type: frame.frame_type_code(),
            flags: 0,
            payload_len,
            session_id: self.params.session_id,
            object_id: 0,
            update_id: 0,
            frame_id,
            capsule_id: 0,
            chan: 0,
            base_digest: Digest32::default(),
        }
    }

    /// Returns the current adaptive control-plane timeout.
    pub fn control_timeout(&self) -> Duration {
        self.rtt.control_timeout()
    }

    /// Returns the current adaptive data-plane inactivity timeout.
    pub fn data_timeout(&self) -> Duration {
        self.rtt.data_timeout()
    }

    /// Send a control frame on C0, tracking it for ACK and RTT measurement.
    pub async fn send_control(
        &mut self,
        c0: &mut C0Transport,
        frame: &Frame,
        base_digest: Digest32,
    ) -> std::io::Result<u64> {
        self.check_session_limits()?;
        let payload = frame.encode_payload();
        let header = self.make_control_header(frame, payload.len() as u32, base_digest);
        let fid = header.frame_id;
        self.unacked
            .insert(fid, (header.clone(), payload.clone()));
        self.send_times.insert(fid, Instant::now());
        c0.send_frame(&header, &payload).await?;
        Ok(fid)
    }

    /// Send a data frame on D0 with congestion-controlled pacing.
    pub async fn send_data(
        &mut self,
        d0: &D0Transport,
        frame: &Frame,
        base_digest: Digest32,
        peer: SocketAddr,
    ) -> std::io::Result<()> {
        self.check_session_limits()?;
        self.cc.pace(&self.rtt).await;
        self.cc.on_send();
        let payload = frame.encode_payload();
        let header = self.make_data_header(frame, payload.len() as u32, base_digest);
        d0.send_frame(&header, &payload, peer).await?;
        Ok(())
    }

    /// Record an ACK for a frame_id, updating RTT estimator.
    pub fn record_ack(&mut self, ack_frame_id: u64) {
        self.unacked.remove(&ack_frame_id);
        if let Some(sent_at) = self.send_times.remove(&ack_frame_id) {
            let rtt = sent_at.elapsed().as_secs_f64();
            self.rtt.record_sample(rtt);
        }
    }

    /// Retransmit all unacked C0 frames. Returns the number of frames resent.
    pub async fn resend_unacked(&self, c0: &mut C0Transport) -> std::io::Result<usize> {
        let mut count = 0;
        for (header, payload) in self.unacked.values() {
            c0.send_frame(header, payload).await?;
            count += 1;
        }
        Ok(count)
    }

    /// Perform initiator-side HELLO/SELECT handshake (sender role).
    ///
    /// Uses X25519 ephemeral DH + PSK for key derivation with forward secrecy.
    /// The session key is set on `c0` and available via `session_key()` for D0.
    pub async fn handshake_initiator(
        c0: &mut C0Transport,
        session_id: u64,
        psk: Option<&[u8]>,
        object_id: u64,
        update_id: u64,
    ) -> std::io::Result<Session> {
        let mut sess = Session::new(SessionParams {
            session_id,
            object_id,
            update_id,
            capsule_id: 1,
            capsule_ver: 0,
            max_m_log2: 20,
            max_symbols: 65536,
        });

        // Generate ephemeral X25519 keypair + nonce if PSK provided.
        let our_auth = if let Some(psk) = psk {
            let nonce = generate_random()?;
            let eph_secret = generate_random()?;
            let eph_pub = auth::x25519_public_key(&eph_secret);
            let key_id = auth::compute_key_id(psk);
            // Keep eph_secret alive for DH computation after peer HELLO.
            Some((nonce, eph_secret, eph_pub, key_id))
        } else {
            None
        };

        // Send HELLO (unauthenticated — key doesn't exist yet).
        let hello_auth = our_auth.as_ref().map(|(nonce, _, eph_pub, key_id)| {
            HelloAuth::X25519Psk {
                nonce: *nonce,
                ephemeral_pub: *eph_pub,
                key_id: *key_id,
            }
        });
        let hello = Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: D0_PAYLOAD_SIZE as u32,
            max_m_log2: 20,
            max_symbols: 65536,
            profiles: vec![(1, 0)],
            auth: hello_auth,
        };
        let payload = hello.encode_payload();
        let header = sess.make_session_header(&hello, payload.len() as u32);
        c0.send_frame(&header, &payload).await?;

        // Receive peer HELLO.
        let (_hdr, payload) = c0.recv_frame().await?;
        let peer_hello = Frame::decode_payload(_hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let peer_auth = match &peer_hello {
            Frame::Hello {
                max_control_payload,
                max_m_log2,
                max_symbols,
                auth,
                ..
            } => {
                sess.params.max_m_log2 = sess.params.max_m_log2.min(*max_m_log2);
                sess.params.max_symbols = sess.params.max_symbols.min(*max_symbols);
                c0.set_max_payload((*max_control_payload).min(65536));
                auth.clone()
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected HELLO from peer",
                ));
            }
        };

        // Derive session key via X25519 DH + HKDF.
        if let Some((our_nonce, mut eph_secret, _eph_pub, _key_id)) = our_auth {
            let psk = psk.unwrap(); // Safe: our_auth is Some only when psk is Some.
            match peer_auth {
                Some(HelloAuth::X25519Psk {
                    nonce: peer_nonce,
                    ephemeral_pub: peer_eph_pub,
                    key_id: peer_key_id,
                }) => {
                    // Verify peer's key_id matches our PSK (optional but helpful).
                    let expected_kid = auth::compute_key_id(psk);
                    if peer_key_id != expected_kid {
                        eph_secret.zeroize();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "peer key_id does not match our PSK",
                        ));
                    }
                    let mut dh_shared = auth::x25519_dh(&eph_secret, &peer_eph_pub);
                    eph_secret.zeroize();
                    let key = auth::derive_session_key_x25519(
                        &dh_shared,
                        psk,
                        &our_nonce,
                        &peer_nonce,
                        session_id,
                    );
                    dh_shared.zeroize();
                    c0.set_session_key(key);
                    sess.session_key = Some(key);
                }
                Some(HelloAuth::PskHmac { .. }) => {
                    eph_secret.zeroize();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "peer offered deprecated auth_mode 0x01 (PSK-HMAC); X25519 required",
                    ));
                }
                None => {
                    eph_secret.zeroize();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "PSK provided but peer did not offer authentication — refusing unauthenticated session",
                    ));
                }
            }
        }
        // else: no PSK, no auth — proceed unauthenticated.

        // Send SELECT (authenticated if key was derived).
        let select = Frame::Select {
            capsule_id: 1,
            capsule_ver: 0,
        };
        let payload = select.encode_payload();
        let header = sess.make_session_header(&select, payload.len() as u32);
        c0.send_frame(&header, &payload).await?;

        Ok(sess)
    }

    /// Perform responder-side HELLO/SELECT handshake (receiver role).
    ///
    /// Uses X25519 ephemeral DH + PSK for key derivation with forward secrecy.
    /// The session key is set on `c0` and available via `session_key()`.
    pub async fn handshake_responder(
        c0: &mut C0Transport,
        psk: Option<&[u8]>,
        object_id: u64,
        update_id: u64,
    ) -> std::io::Result<Session> {
        // Receive peer HELLO (unauthenticated).
        let (hdr, payload) = c0.recv_frame().await?;
        let peer_hello = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let session_id = hdr.session_id;

        let (peer_max_m, peer_max_sym, peer_auth) = match &peer_hello {
            Frame::Hello {
                max_control_payload,
                max_m_log2,
                max_symbols,
                auth,
                ..
            } => {
                c0.set_max_payload((*max_control_payload).min(65536));
                (*max_m_log2, *max_symbols, auth.clone())
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected HELLO from peer",
                ));
            }
        };

        let mut sess = Session::new(SessionParams {
            session_id,
            object_id,
            update_id,
            capsule_id: 1,
            capsule_ver: 0,
            max_m_log2: 20u8.min(peer_max_m),
            max_symbols: 65536u32.min(peer_max_sym),
        });

        // Generate our auth parameters if PSK provided AND peer offered X25519 auth.
        let our_auth = match (&psk, &peer_auth) {
            (Some(psk_val), Some(HelloAuth::X25519Psk { key_id: peer_kid, .. })) => {
                // Verify peer's key_id matches our PSK.
                let expected_kid = auth::compute_key_id(psk_val);
                if *peer_kid != expected_kid {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "peer key_id does not match our PSK",
                    ));
                }
                let nonce = generate_random()?;
                let eph_secret = generate_random()?;
                let eph_pub = auth::x25519_public_key(&eph_secret);
                let key_id = auth::compute_key_id(psk_val);
                Some((nonce, eph_secret, eph_pub, key_id))
            }
            (Some(_), Some(HelloAuth::PskHmac { .. })) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "peer offered deprecated auth_mode 0x01 (PSK-HMAC); X25519 required",
                ));
            }
            (Some(_), None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "PSK provided but peer did not offer authentication — refusing unauthenticated session",
                ));
            }
            (None, _) => None,
        };

        // Send our HELLO (unauthenticated — key doesn't exist yet).
        let hello_auth = our_auth.as_ref().map(|(nonce, _, eph_pub, key_id)| {
            HelloAuth::X25519Psk {
                nonce: *nonce,
                ephemeral_pub: *eph_pub,
                key_id: *key_id,
            }
        });
        let hello = Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: D0_PAYLOAD_SIZE as u32,
            max_m_log2: sess.params.max_m_log2,
            max_symbols: sess.params.max_symbols,
            profiles: vec![(1, 0)],
            auth: hello_auth,
        };
        let payload = hello.encode_payload();
        let header = sess.make_session_header(&hello, payload.len() as u32);
        c0.send_frame(&header, &payload).await?;

        // Derive session key if both sides offered X25519 auth.
        if let (Some((our_nonce, mut eph_secret, _, _)), Some(HelloAuth::X25519Psk { nonce: peer_nonce, ephemeral_pub: peer_eph_pub, .. })) =
            (our_auth, peer_auth)
        {
            let psk = psk.unwrap();
            // Initiator nonce = nonce_i (peer), responder nonce = nonce_r (us).
            let mut dh_shared = auth::x25519_dh(&eph_secret, &peer_eph_pub);
            eph_secret.zeroize();
            let key = auth::derive_session_key_x25519(
                &dh_shared,
                psk,
                &peer_nonce,
                &our_nonce,
                session_id,
            );
            dh_shared.zeroize();
            c0.set_session_key(key);
            sess.session_key = Some(key);
        }

        // Receive SELECT (authenticated if key was derived).
        let (hdr, payload) = c0.recv_frame().await?;
        let select = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        match select {
            Frame::Select {
                capsule_id,
                capsule_ver,
            } => {
                sess.params.capsule_id = capsule_id;
                sess.params.capsule_ver = capsule_ver;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected SELECT from peer",
                ));
            }
        }

        Ok(sess)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_estimator_initial_timeout() {
        let rtt = RttEstimator::new();
        // Initial: avg=2.0, var=0.5 → timeout = 2.0 + 4*0.5 = 4.0s
        let ct = rtt.control_timeout();
        assert!(ct.as_secs_f64() >= 3.9 && ct.as_secs_f64() <= 4.1);
    }

    #[test]
    fn rtt_estimator_converges_low() {
        let mut rtt = RttEstimator::new();
        // Feed low RTT samples — timeout should converge toward floor (1.0s).
        for _ in 0..20 {
            rtt.record_sample(0.001);
        }
        let ct = rtt.control_timeout();
        assert_eq!(ct, Duration::from_secs(1), "should clamp to 1s floor");
    }

    #[test]
    fn rtt_estimator_high_samples_capped() {
        let mut rtt = RttEstimator::new();
        for _ in 0..10 {
            rtt.record_sample(100.0);
        }
        let ct = rtt.control_timeout();
        assert_eq!(ct, Duration::from_secs(30), "should clamp to 30s ceiling");
    }

    #[test]
    fn rtt_data_timeout_minimum() {
        let mut rtt = RttEstimator::new();
        for _ in 0..20 {
            rtt.record_sample(0.001);
        }
        let dt = rtt.data_timeout();
        assert!(dt >= Duration::from_secs(10), "data timeout minimum is 10s");
    }

    #[test]
    fn rtt_first_sample_sets_estimate() {
        let mut rtt = RttEstimator::new();
        rtt.record_sample(0.5);
        // First sample: avg=0.5, var=0.25 → timeout = 0.5 + 4*0.25 = 1.5s
        let ct = rtt.control_timeout();
        assert!(ct.as_secs_f64() >= 1.4 && ct.as_secs_f64() <= 1.6);
    }

    #[test]
    fn cc_initial_cwnd() {
        let cc = CongestionController::new();
        assert_eq!(cc.cwnd, CongestionController::INITIAL_CWND);
    }

    #[test]
    fn cc_slow_start_increases() {
        let mut cc = CongestionController::new();
        let initial = cc.cwnd;
        cc.on_progress(5);
        assert!(cc.cwnd > initial, "slow start should increase cwnd");
    }

    #[test]
    fn cc_loss_halves() {
        let mut cc = CongestionController::new();
        cc.cwnd = 100.0;
        cc.on_loss();
        assert!((cc.cwnd - 50.0).abs() < 0.1);
        assert!((cc.ssthresh - 50.0).abs() < 0.1);
    }

    #[test]
    fn cc_cwnd_bounds() {
        let mut cc = CongestionController::new();
        // Push cwnd to max.
        cc.on_progress(100_000);
        assert!(cc.cwnd <= CongestionController::MAX_CWND);

        // Loss should respect minimum.
        cc.cwnd = CongestionController::MIN_CWND;
        cc.on_loss();
        assert!(cc.cwnd >= CongestionController::MIN_CWND);
    }

    #[test]
    fn cc_congestion_avoidance() {
        let mut cc = CongestionController::new();
        cc.ssthresh = 10.0;
        cc.cwnd = 10.0; // at ssthresh → congestion avoidance mode
        let before = cc.cwnd;
        cc.on_progress(1);
        let delta = cc.cwnd - before;
        // In CA mode, delta should be ~1/cwnd = 0.1, not 1.0.
        assert!(delta < 0.5, "CA mode should grow slowly, got delta={delta}");
    }

    #[tokio::test]
    async fn cc_pace_first_call_immediate() {
        let mut cc = CongestionController::new();
        let rtt = RttEstimator::new();
        let start = tokio::time::Instant::now();
        cc.pace(&rtt).await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(50));
    }
}

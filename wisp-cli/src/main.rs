use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use memmap2::Mmap;
use tokio::net::{TcpListener, UdpSocket};

use wisp_core::auth;
use wisp_core::manifest::ConflictPolicy;
use wisp_net::peer::{run_sync_initiator, run_sync_responder};
use wisp_net::receiver::{run_receiver, run_receiver_dir};
use wisp_net::sender::{run_sender, run_sender_dir};
use wisp_net::session::Session;
use wisp_net::transport::{C0Transport, D0Transport};

#[derive(Parser)]
#[command(name = "wisp", about = "WISP file transfer tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file to a remote receiver
    Send {
        /// Path to the file to send
        file: PathBuf,
        /// Receiver address (host:port)
        #[arg(long)]
        to: String,
        /// Base file for incremental sync (only changed chunks are transferred)
        #[arg(long)]
        base: Option<PathBuf>,
        /// Pre-shared key (hex-encoded)
        #[arg(long, conflicts_with = "psk_file")]
        psk: Option<String>,
        /// Path to PSK keyring file (one [label:]hex per line, # comments)
        #[arg(long, conflicts_with = "psk")]
        psk_file: Option<PathBuf>,
    },
    /// Receive a file from a remote sender
    Recv {
        /// TCP port to listen on
        #[arg(long)]
        listen: u16,
        /// Output file path
        #[arg(long)]
        out: PathBuf,
        /// Base file for incremental sync (must match sender's base)
        #[arg(long)]
        base: Option<PathBuf>,
        /// Pre-shared key (hex-encoded)
        #[arg(long, conflicts_with = "psk_file")]
        psk: Option<String>,
        /// Path to PSK keyring file (one [label:]hex per line, # comments)
        #[arg(long, conflicts_with = "psk")]
        psk_file: Option<PathBuf>,
        /// Directory to persist partial state for resume-on-reconnect
        #[arg(long)]
        resume_dir: Option<PathBuf>,
    },
    /// Send a directory tree to a remote receiver
    SendDir {
        /// Path to the directory to send
        dir: PathBuf,
        /// Receiver address (host:port)
        #[arg(long)]
        to: String,
        /// Pre-shared key (hex-encoded)
        #[arg(long, conflicts_with = "psk_file")]
        psk: Option<String>,
        /// Path to PSK keyring file
        #[arg(long, conflicts_with = "psk")]
        psk_file: Option<PathBuf>,
    },
    /// Receive a directory tree from a remote sender
    RecvDir {
        /// TCP port to listen on
        #[arg(long)]
        listen: u16,
        /// Output directory path
        #[arg(long)]
        out: PathBuf,
        /// Pre-shared key (hex-encoded)
        #[arg(long, conflicts_with = "psk_file")]
        psk: Option<String>,
        /// Path to PSK keyring file
        #[arg(long, conflicts_with = "psk")]
        psk_file: Option<PathBuf>,
    },
    /// Bidirectional directory sync with a remote peer
    Sync {
        /// Local directory to sync
        dir: PathBuf,
        /// Peer address (host:port) — connect as initiator
        #[arg(long, conflicts_with = "listen")]
        peer: Option<String>,
        /// Listen on port — act as responder
        #[arg(long, conflicts_with = "peer")]
        listen: Option<u16>,
        /// Conflict policy: initiator-wins, responder-wins, skip
        #[arg(long, default_value = "initiator-wins")]
        conflict: String,
        /// Pre-shared key (hex-encoded)
        #[arg(long, conflicts_with = "psk_file")]
        psk: Option<String>,
        /// Path to PSK keyring file
        #[arg(long, conflicts_with = "psk")]
        psk_file: Option<PathBuf>,
    },
}

/// Decode a hex string into bytes. Returns an error if the string is invalid hex.
fn decode_hex(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(Into::into))
        .collect()
}

/// Format a key_id as colon-separated hex bytes.
fn format_key_id(key_id: &[u8; 8]) -> String {
    key_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Load a PSK from --psk or --psk-file arguments.
///
/// Keyring file format: one key per line, `[label:]hex`, `#` comments.
/// Uses the first key in the keyring.
fn load_psk(
    psk: Option<&str>,
    psk_file: Option<&PathBuf>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if let Some(hex) = psk {
        return Ok(Some(decode_hex(hex)?));
    }
    if let Some(path) = psk_file {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Format: [label:]hex
            let hex_part = if let Some((_label, hex)) = line.split_once(':') {
                hex.trim()
            } else {
                line
            };
            return Ok(Some(decode_hex(hex_part)?));
        }
        return Err(format!("no keys found in keyring file: {}", path.display()).into());
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Send {
            file,
            to,
            base,
            psk,
            psk_file,
        } => {
            let psk_bytes = load_psk(psk.as_deref(), psk_file.as_ref())?;
            if let Some(ref key) = psk_bytes {
                let kid = auth::compute_key_id(key);
                eprintln!("PSK fingerprint: {}", format_key_id(&kid));
            }
            let file_handle = std::fs::File::open(&file)?;
            let mmap = unsafe { Mmap::map(&file_handle)? };
            let data: &[u8] = &mmap;
            let base_mmap;
            let base_data = match &base {
                Some(path) => {
                    let bh = std::fs::File::open(path)?;
                    base_mmap = unsafe { Mmap::map(&bh)? };
                    eprintln!("Base file: {} ({} bytes)", path.display(), base_mmap.len());
                    Some(base_mmap.as_ref() as &[u8])
                }
                None => None,
            };
            eprintln!("Sending {} ({} bytes)...", file.display(), data.len());

            let addr: SocketAddr = to.parse()?;
            let udp_peer_addr: SocketAddr = SocketAddr::new(addr.ip(), addr.port() + 1);

            let mut c0 = C0Transport::connect(addr).await?;
            let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
            let mut d0 = D0Transport::new(udp_socket);

            let session_id: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64;

            let object_id: u64 = if base.is_some() { 1 } else { 0 };
            let mut session =
                Session::handshake_initiator(&mut c0, session_id, psk_bytes.as_deref(), object_id, 1).await?;

            if let Some(key) = session.session_key() {
                d0.set_session_key(*key);
                eprintln!("X25519-PSK-HKDF authentication active (forward secrecy enabled).");
            }

            run_sender(&mut session, &mut c0, &d0, udp_peer_addr, data, base_data).await?;

            eprintln!("Done.");
        }
        Command::Recv {
            listen,
            out,
            base,
            psk,
            psk_file,
            resume_dir,
        } => {
            let psk_bytes = load_psk(psk.as_deref(), psk_file.as_ref())?;
            if let Some(ref key) = psk_bytes {
                let kid = auth::compute_key_id(key);
                eprintln!("PSK fingerprint: {}", format_key_id(&kid));
            }
            let base_mmap;
            let base_data = match &base {
                Some(path) => {
                    let bh = std::fs::File::open(path)?;
                    base_mmap = unsafe { Mmap::map(&bh)? };
                    eprintln!("Base file: {} ({} bytes)", path.display(), base_mmap.len());
                    Some(base_mmap.as_ref() as &[u8])
                }
                None => None,
            };
            let tcp_addr: SocketAddr = format!("0.0.0.0:{}", listen).parse()?;
            let udp_addr: SocketAddr = format!("0.0.0.0:{}", listen + 1).parse()?;

            let tcp_listener = TcpListener::bind(tcp_addr).await?;
            let udp_socket = UdpSocket::bind(udp_addr).await?;

            eprintln!(
                "Listening on TCP {} / UDP {}...",
                tcp_addr, udp_addr
            );

            let mut c0 = C0Transport::accept(&tcp_listener).await?;
            let mut d0 = D0Transport::new(udp_socket);

            let object_id: u64 = if base.is_some() { 1 } else { 0 };
            let mut session =
                Session::handshake_responder(&mut c0, psk_bytes.as_deref(), object_id, 1).await?;

            if let Some(key) = session.session_key() {
                d0.set_session_key(*key);
                eprintln!("X25519-PSK-HKDF authentication active (forward secrecy enabled).");
            }

            let resume = match &resume_dir {
                Some(dir) => {
                    let rs = wisp_net::resume::ResumeState::new(dir.clone())?;
                    eprintln!("Resume state: {}", dir.display());
                    Some(rs)
                }
                None => None,
            };
            let data = run_receiver(&mut session, &mut c0, &d0, base_data, resume.as_ref()).await?;

            tokio::fs::write(&out, &data).await?;
            eprintln!("Received {} bytes -> {}", data.len(), out.display());
        }
        Command::SendDir {
            dir,
            to,
            psk,
            psk_file,
        } => {
            let psk_bytes = load_psk(psk.as_deref(), psk_file.as_ref())?;
            if let Some(ref key) = psk_bytes {
                let kid = auth::compute_key_id(key);
                eprintln!("PSK fingerprint: {}", format_key_id(&kid));
            }

            let addr: SocketAddr = to.parse()?;
            let udp_peer_addr: SocketAddr = SocketAddr::new(addr.ip(), addr.port() + 1);

            let mut c0 = C0Transport::connect(addr).await?;
            let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
            let mut d0 = D0Transport::new(udp_socket);

            let session_id: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64;

            let mut session =
                Session::handshake_initiator(&mut c0, session_id, psk_bytes.as_deref(), 0, 1).await?;

            if let Some(key) = session.session_key() {
                d0.set_session_key(*key);
                eprintln!("X25519-PSK-HKDF authentication active (forward secrecy enabled).");
            }

            run_sender_dir(&mut session, &mut c0, &d0, udp_peer_addr, &dir).await?;

            eprintln!("Done.");
        }
        Command::RecvDir {
            listen,
            out,
            psk,
            psk_file,
        } => {
            let psk_bytes = load_psk(psk.as_deref(), psk_file.as_ref())?;
            if let Some(ref key) = psk_bytes {
                let kid = auth::compute_key_id(key);
                eprintln!("PSK fingerprint: {}", format_key_id(&kid));
            }

            let tcp_addr: SocketAddr = format!("0.0.0.0:{}", listen).parse()?;
            let udp_addr: SocketAddr = format!("0.0.0.0:{}", listen + 1).parse()?;

            let tcp_listener = TcpListener::bind(tcp_addr).await?;
            let udp_socket = UdpSocket::bind(udp_addr).await?;

            eprintln!(
                "Listening on TCP {} / UDP {}...",
                tcp_addr, udp_addr
            );

            let mut c0 = C0Transport::accept(&tcp_listener).await?;
            let mut d0 = D0Transport::new(udp_socket);

            let mut session =
                Session::handshake_responder(&mut c0, psk_bytes.as_deref(), 0, 1).await?;

            if let Some(key) = session.session_key() {
                d0.set_session_key(*key);
                eprintln!("X25519-PSK-HKDF authentication active (forward secrecy enabled).");
            }

            run_receiver_dir(&mut session, &mut c0, &d0, &out).await?;

            eprintln!("Done.");
        }
        Command::Sync {
            dir,
            peer,
            listen,
            conflict,
            psk,
            psk_file,
        } => {
            let psk_bytes = load_psk(psk.as_deref(), psk_file.as_ref())?;
            if let Some(ref key) = psk_bytes {
                let kid = auth::compute_key_id(key);
                eprintln!("PSK fingerprint: {}", format_key_id(&kid));
            }

            let policy = match conflict.as_str() {
                "initiator-wins" => ConflictPolicy::InitiatorWins,
                "responder-wins" => ConflictPolicy::ResponderWins,
                "skip" => ConflictPolicy::Skip,
                other => {
                    return Err(format!("unknown conflict policy: {} (use initiator-wins, responder-wins, or skip)", other).into());
                }
            };

            if let Some(peer_addr_str) = peer {
                // Initiator mode: connect to responder.
                let addr: SocketAddr = peer_addr_str.parse()?;
                let peer_ip = addr.ip();

                let mut c0 = C0Transport::connect(addr).await?;
                let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
                let d0_local_port = udp_socket.local_addr()?.port();
                let mut d0 = D0Transport::new(udp_socket);

                let session_id: u64 = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos() as u64;

                let mut session =
                    Session::handshake_initiator(&mut c0, session_id, psk_bytes.as_deref(), 0, 1).await?;

                if let Some(key) = session.session_key() {
                    d0.set_session_key(*key);
                    eprintln!("X25519-PSK-HKDF authentication active (forward secrecy enabled).");
                }

                let report = run_sync_initiator(
                    &mut session, &mut c0, &d0, &dir, d0_local_port, peer_ip, policy,
                ).await?;

                eprintln!(
                    "Sent {} files, received {} files, skipped {} conflicts.",
                    report.files_sent, report.files_received, report.files_skipped.len(),
                );
            } else if let Some(port) = listen {
                // Responder mode: listen for connections.
                let tcp_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
                let udp_addr: SocketAddr = format!("0.0.0.0:{}", port + 1).parse()?;

                let tcp_listener = TcpListener::bind(tcp_addr).await?;
                let udp_socket = UdpSocket::bind(udp_addr).await?;
                let d0_local_port = udp_socket.local_addr()?.port();

                eprintln!("Listening on TCP {} / UDP {}...", tcp_addr, udp_addr);

                let mut c0 = C0Transport::accept(&tcp_listener).await?;
                let peer_ip = c0.peer_addr()?.ip();
                let mut d0 = D0Transport::new(udp_socket);

                let mut session =
                    Session::handshake_responder(&mut c0, psk_bytes.as_deref(), 0, 1).await?;

                if let Some(key) = session.session_key() {
                    d0.set_session_key(*key);
                    eprintln!("X25519-PSK-HKDF authentication active (forward secrecy enabled).");
                }

                let report = run_sync_responder(
                    &mut session, &mut c0, &d0, &dir, d0_local_port, peer_ip, policy,
                ).await?;

                eprintln!(
                    "Sent {} files, received {} files, skipped {} conflicts.",
                    report.files_sent, report.files_received, report.files_skipped.len(),
                );
            } else {
                return Err("sync requires either --peer <host:port> or --listen <port>".into());
            }

            eprintln!("Done.");
        }
    }

    Ok(())
}

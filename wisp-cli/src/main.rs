use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tokio::net::{TcpListener, UdpSocket};

use wisp_core::auth;
use wisp_net::receiver::run_receiver;
use wisp_net::sender::run_sender;
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
            let data = tokio::fs::read(&file).await?;
            let base_data = match &base {
                Some(path) => {
                    let bd = tokio::fs::read(path).await?;
                    eprintln!("Base file: {} ({} bytes)", path.display(), bd.len());
                    Some(bd)
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

            run_sender(&mut session, &mut c0, &d0, udp_peer_addr, &data, base_data.as_deref()).await?;

            eprintln!("Done.");
        }
        Command::Recv {
            listen,
            out,
            base,
            psk,
            psk_file,
        } => {
            let psk_bytes = load_psk(psk.as_deref(), psk_file.as_ref())?;
            if let Some(ref key) = psk_bytes {
                let kid = auth::compute_key_id(key);
                eprintln!("PSK fingerprint: {}", format_key_id(&kid));
            }
            let base_data = match &base {
                Some(path) => {
                    let bd = tokio::fs::read(path).await?;
                    eprintln!("Base file: {} ({} bytes)", path.display(), bd.len());
                    Some(bd)
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

            let data = run_receiver(&mut session, &mut c0, &d0, base_data.as_deref()).await?;

            tokio::fs::write(&out, &data).await?;
            eprintln!("Received {} bytes -> {}", data.len(), out.display());
        }
    }

    Ok(())
}

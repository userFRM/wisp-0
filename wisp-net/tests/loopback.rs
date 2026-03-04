use tokio::net::{TcpListener, UdpSocket};
use wisp_core::auth;
use wisp_net::session::Session;
use wisp_net::sender::run_sender;
use wisp_net::receiver::run_receiver;
use wisp_net::transport::{C0Transport, D0Transport};

#[tokio::test]
async fn loopback_send_recv() {
    // Bind TCP listener and two UDP sockets on localhost.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_recv_addr = udp_recv.local_addr().unwrap();

    let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Test data: 50KB of pseudo-random data (enough for multiple CDC chunks).
    let test_data: Vec<u8> = (0u32..50_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let test_data_clone = test_data.clone();

    let session_id: u64 = 0xDEAD_BEEF_0000_0001;

    // Spawn receiver task.
    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let d0 = D0Transport::new(udp_recv);
        let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
        run_receiver(&mut session, &mut c0, &d0, None).await.unwrap()
    });

    // Spawn sender task.
    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let d0 = D0Transport::new(udp_send);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
        run_sender(&mut session, &mut c0, &d0, udp_recv_addr, &test_data_clone, None)
            .await
            .unwrap();
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    let received = recv_result.unwrap();

    assert_eq!(received.len(), test_data.len(), "received length mismatch");
    assert_eq!(received, test_data, "received data mismatch");
}

#[tokio::test]
async fn loopback_small_file() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_recv_addr = udp_recv.local_addr().unwrap();

    let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let test_data = b"Hello, WISP protocol!".to_vec();
    let test_data_clone = test_data.clone();
    let session_id: u64 = 42;

    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let d0 = D0Transport::new(udp_recv);
        let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
        run_receiver(&mut session, &mut c0, &d0, None).await.unwrap()
    });

    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let d0 = D0Transport::new(udp_send);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
        run_sender(&mut session, &mut c0, &d0, udp_recv_addr, &test_data_clone, None)
            .await
            .unwrap();
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    let received = recv_result.unwrap();

    assert_eq!(received, test_data);
}

#[tokio::test]
async fn loopback_authenticated() {
    let psk = b"test-pre-shared-key-for-wisp0";

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_recv_addr = udp_recv.local_addr().unwrap();
    let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let test_data: Vec<u8> = (0u32..50_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let test_data_clone = test_data.clone();
    let session_id: u64 = 0xA077_0000_0001;

    let psk_clone = psk.to_vec();
    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let mut d0 = D0Transport::new(udp_recv);
        let session = Session::handshake_responder(&mut c0, Some(&psk_clone), 0, 1).await.unwrap();
        assert!(session.session_key().is_some(), "responder should have session key");
        d0.set_session_key(*session.session_key().unwrap());
        let mut session = session;
        run_receiver(&mut session, &mut c0, &d0, None).await.unwrap()
    });

    let psk_clone = psk.to_vec();
    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let mut d0 = D0Transport::new(udp_send);
        let session = Session::handshake_initiator(&mut c0, session_id, Some(&psk_clone), 0, 1).await.unwrap();
        assert!(session.session_key().is_some(), "initiator should have session key");
        d0.set_session_key(*session.session_key().unwrap());
        let mut session = session;
        run_sender(&mut session, &mut c0, &d0, udp_recv_addr, &test_data_clone, None)
            .await
            .unwrap();
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    let received = recv_result.unwrap();

    assert_eq!(received.len(), test_data.len());
    assert_eq!(received, test_data);
}

#[tokio::test]
async fn loopback_auth_one_side_only_refused() {
    // Sender has PSK, receiver doesn't — strict policy refuses the downgrade.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let _udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let _udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let session_id: u64 = 999;

    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        // Receiver has no PSK — will complete its side of the handshake without auth.
        // The initiator will reject, causing the TCP stream to drop, which
        // makes the responder's recv_frame (for SELECT) fail with a connection error.
        let result = Session::handshake_responder(&mut c0, None, 0, 1).await;
        // Responder sees a connection-level error because initiator drops before SELECT.
        assert!(result.is_err(), "responder should fail when initiator refuses downgrade");
    });

    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let psk = b"only-sender-has-this";
        let result = Session::handshake_initiator(&mut c0, session_id, Some(psk), 0, 1).await;
        assert!(result.is_err(), "initiator should refuse unauthenticated session when PSK is set");
        let err = result.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    recv_result.unwrap();
}

#[tokio::test]
async fn loopback_wrong_psk() {
    // Both sides have a PSK but different values — handshake derives different keys,
    // so the authenticated SELECT frame will fail HMAC verification on the responder.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let _udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let _udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let session_id: u64 = 0xBAD_0000_0001;

    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let result = Session::handshake_responder(&mut c0, Some(b"responder-key-alpha"), 0, 1).await;
        // With X25519 auth, different PSKs produce different key_ids — rejected early.
        assert!(result.is_err(), "wrong PSK should cause handshake failure");
        let err = result.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("key_id"),
            "error should mention key_id mismatch: {}",
            err
        );
    });

    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        // Initiator sends HELLO+SELECT with its own key. The SELECT will be
        // authenticated with a key derived from "initiator-key-beta", which
        // differs from the responder's key. Initiator itself succeeds (it
        // doesn't receive anything after SELECT in handshake_initiator).
        let result = Session::handshake_initiator(&mut c0, session_id, Some(b"initiator-key-beta"), 0, 1).await;
        // Initiator completes its side — it sent SELECT but doesn't know
        // the responder will reject it. That's fine; the responder catches it.
        // (result may be Ok or Err depending on timing of TCP teardown)
        let _ = result;
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    recv_result.unwrap();
}

#[tokio::test]
async fn loopback_x25519_key_derivation_differs_per_session() {
    // Two sessions with the same PSK should derive different session keys
    // (because ephemeral X25519 keypairs differ each time = forward secrecy).
    let psk = b"same-psk-both-sessions";

    let mut keys = Vec::new();
    for _ in 0..2 {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();

        let psk_clone = psk.to_vec();
        let recv_handle = tokio::spawn(async move {
            let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
            let session = Session::handshake_responder(&mut c0, Some(&psk_clone), 0, 1).await.unwrap();
            *session.session_key().unwrap()
        });

        let psk_clone = psk.to_vec();
        let send_handle = tokio::spawn(async move {
            let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
            let sid = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            let session = Session::handshake_initiator(&mut c0, sid, Some(&psk_clone), 0, 1).await.unwrap();
            *session.session_key().unwrap()
        });

        let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
        let recv_key = recv_result.unwrap();
        let send_key = send_result.unwrap();
        // Both sides should derive the same key within a session.
        assert_eq!(recv_key, send_key, "initiator and responder keys should match");
        keys.push(recv_key);
    }
    // Different sessions should have different keys (forward secrecy).
    assert_ne!(keys[0], keys[1], "different sessions should have different keys");
}

#[tokio::test]
async fn loopback_key_id_fingerprint_matches() {
    // Verify key_id computation determinism and uniqueness.
    let psk = b"fingerprint-test-key";
    let kid = auth::compute_key_id(psk);
    assert_eq!(kid.len(), 8);
    assert_eq!(kid, auth::compute_key_id(psk));
    assert_ne!(kid, auth::compute_key_id(b"different-key"));
}

#[tokio::test]
async fn loopback_responder_psk_sender_no_psk_refused() {
    // Responder has PSK, sender doesn't — responder should refuse.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let result = Session::handshake_responder(&mut c0, Some(b"responder-only-key"), 0, 1).await;
        assert!(result.is_err(), "responder should refuse unauthenticated peer when PSK set");
        let err = result.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    });

    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let result = Session::handshake_initiator(&mut c0, 12345, None, 0, 1).await;
        let _ = result;
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    recv_result.unwrap();
}

#[tokio::test]
async fn loopback_d0_monotonic_seq_with_replay_protection() {
    // Verify authenticated transfer works end-to-end with replay window active.
    // The receiver's ReplayWindow accepts monotonic D0 frame_ids from the sender.
    let psk = b"monotonic-seq-test";

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_recv_addr = udp_recv.local_addr().unwrap();
    let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let test_data: Vec<u8> = (0u32..50_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let test_data_clone = test_data.clone();
    let session_id: u64 = 0x5E00_0000_0001;

    let psk_clone = psk.to_vec();
    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let mut d0 = D0Transport::new(udp_recv);
        let session = Session::handshake_responder(&mut c0, Some(&psk_clone), 0, 1).await.unwrap();
        d0.set_session_key(*session.session_key().unwrap());
        let mut session = session;
        run_receiver(&mut session, &mut c0, &d0, None).await.unwrap()
    });

    let psk_clone = psk.to_vec();
    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let mut d0 = D0Transport::new(udp_send);
        let session = Session::handshake_initiator(&mut c0, session_id, Some(&psk_clone), 0, 1).await.unwrap();
        d0.set_session_key(*session.session_key().unwrap());
        let mut session = session;
        run_sender(&mut session, &mut c0, &d0, udp_recv_addr, &test_data_clone, None)
            .await
            .unwrap();
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    let received = recv_result.unwrap();
    assert_eq!(received, test_data);
}

#[tokio::test]
async fn loopback_incremental() {
    // v1: 200KB pseudo-random base.
    let base: Vec<u8> = (0u32..200_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    // v2: modify 40KB in middle, append 10KB.
    let mut v2 = base.clone();
    for i in 80_000..120_000 {
        v2[i] ^= 0x5A;
    }
    v2.extend(vec![0xBB; 10_000]);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_recv_addr = udp_recv.local_addr().unwrap();
    let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let session_id: u64 = 0x1C8E_0000_0001;
    let base_clone = base.clone();
    let v2_clone = v2.clone();

    let recv_handle = tokio::spawn({
        let base_clone = base_clone.clone();
        async move {
            let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
            let d0 = D0Transport::new(udp_recv);
            let mut session = Session::handshake_responder(&mut c0, None, 1, 1).await.unwrap();
            run_receiver(&mut session, &mut c0, &d0, Some(&base_clone)).await.unwrap()
        }
    });

    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let d0 = D0Transport::new(udp_send);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 1, 1).await.unwrap();
        run_sender(&mut session, &mut c0, &d0, udp_recv_addr, &v2_clone, Some(&base_clone))
            .await
            .unwrap();
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    let received = recv_result.unwrap();

    assert_eq!(received.len(), v2.len(), "incremental: received length mismatch");
    assert_eq!(received, v2, "incremental: received data mismatch");
}

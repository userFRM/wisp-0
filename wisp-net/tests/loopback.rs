use tokio::net::{TcpListener, UdpSocket};
use wisp_core::auth;
use wisp_core::manifest::ConflictPolicy;
use wisp_net::peer::{run_sync_initiator, run_sync_responder};
use wisp_net::session::Session;
use wisp_net::sender::{run_sender, run_sender_dir};
use wisp_net::receiver::{run_receiver, run_receiver_dir};
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
        run_receiver(&mut session, &mut c0, &d0, None, None).await.unwrap()
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
        run_receiver(&mut session, &mut c0, &d0, None, None).await.unwrap()
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
        run_receiver(&mut session, &mut c0, &d0, None, None).await.unwrap()
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
        run_receiver(&mut session, &mut c0, &d0, None, None).await.unwrap()
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
            run_receiver(&mut session, &mut c0, &d0, Some(&base_clone), None).await.unwrap()
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

#[tokio::test]
async fn loopback_dir_sync() {
    // Create a temporary source directory with multiple files.
    let tmp = std::env::temp_dir().join("wisp_dir_test_src");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("sub")).unwrap();
    std::fs::write(tmp.join("a.txt"), b"hello world").unwrap();
    std::fs::write(tmp.join("b.bin"), vec![0xAA; 5000]).unwrap();
    std::fs::write(tmp.join("sub/c.txt"), b"nested file content").unwrap();

    let out = std::env::temp_dir().join("wisp_dir_test_dst");
    let _ = std::fs::remove_dir_all(&out);

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_recv_addr = udp_recv.local_addr().unwrap();
    let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let session_id: u64 = 0xD180_0000_0001;

    let out_clone = out.clone();
    let recv_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let d0 = D0Transport::new(udp_recv);
        let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
        run_receiver_dir(&mut session, &mut c0, &d0, &out_clone).await.unwrap();
    });

    let tmp_clone = tmp.clone();
    let send_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let d0 = D0Transport::new(udp_send);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
        run_sender_dir(&mut session, &mut c0, &d0, udp_recv_addr, &tmp_clone).await.unwrap();
    });

    let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
    send_result.unwrap();
    recv_result.unwrap();

    // Verify all files were transferred.
    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"hello world");
    assert_eq!(std::fs::read(out.join("b.bin")).unwrap(), vec![0xAA; 5000]);
    assert_eq!(
        std::fs::read(out.join("sub/c.txt")).unwrap(),
        b"nested file content"
    );

    // Clean up.
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&out);
}

#[tokio::test]
async fn loopback_dir_sync_resync_only_changed() {
    // First sync: create and send 3 files.
    let tmp = std::env::temp_dir().join("wisp_dir_resync_src");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("unchanged.txt"), b"same content").unwrap();
    std::fs::write(tmp.join("modified.txt"), b"original version").unwrap();
    std::fs::write(tmp.join("deleted.txt"), b"will be removed").unwrap();

    let out = std::env::temp_dir().join("wisp_dir_resync_dst");
    let _ = std::fs::remove_dir_all(&out);

    // First sync.
    {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_recv_addr = udp_recv.local_addr().unwrap();
        let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session_id: u64 = 0xD280_0000_0001;

        let out_clone = out.clone();
        let recv_handle = tokio::spawn(async move {
            let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
            let d0 = D0Transport::new(udp_recv);
            let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
            run_receiver_dir(&mut session, &mut c0, &d0, &out_clone).await.unwrap();
        });

        let tmp_clone = tmp.clone();
        let send_handle = tokio::spawn(async move {
            let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
            let d0 = D0Transport::new(udp_send);
            let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
            run_sender_dir(&mut session, &mut c0, &d0, udp_recv_addr, &tmp_clone).await.unwrap();
        });

        let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
        send_result.unwrap();
        recv_result.unwrap();
    }

    // Now modify sender-side: change one file, delete one, add one.
    std::fs::write(tmp.join("modified.txt"), b"updated version!").unwrap();
    std::fs::remove_file(tmp.join("deleted.txt")).unwrap();
    std::fs::write(tmp.join("added.txt"), b"new file").unwrap();

    // Second sync.
    {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let udp_recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_recv_addr = udp_recv.local_addr().unwrap();
        let udp_send = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session_id: u64 = 0xD280_0000_0002;

        let out_clone = out.clone();
        let recv_handle = tokio::spawn(async move {
            let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
            let d0 = D0Transport::new(udp_recv);
            let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
            run_receiver_dir(&mut session, &mut c0, &d0, &out_clone).await.unwrap();
        });

        let tmp_clone = tmp.clone();
        let send_handle = tokio::spawn(async move {
            let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
            let d0 = D0Transport::new(udp_send);
            let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
            run_sender_dir(&mut session, &mut c0, &d0, udp_recv_addr, &tmp_clone).await.unwrap();
        });

        let (recv_result, send_result) = tokio::join!(recv_handle, send_handle);
        send_result.unwrap();
        recv_result.unwrap();
    }

    // Verify results.
    assert_eq!(std::fs::read(out.join("unchanged.txt")).unwrap(), b"same content");
    assert_eq!(std::fs::read(out.join("modified.txt")).unwrap(), b"updated version!");
    assert_eq!(std::fs::read(out.join("added.txt")).unwrap(), b"new file");
    assert!(!out.join("deleted.txt").exists(), "deleted.txt should be removed");

    // Clean up.
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&out);
}

#[tokio::test]
async fn loopback_bidirectional_sync() {
    // Initiator has files A, B. Responder has files B, C.
    // After sync: both should have A, B, C.
    let dir_init = std::env::temp_dir().join("wisp_bidir_init");
    let dir_resp = std::env::temp_dir().join("wisp_bidir_resp");
    let _ = std::fs::remove_dir_all(&dir_init);
    let _ = std::fs::remove_dir_all(&dir_resp);
    std::fs::create_dir_all(&dir_init).unwrap();
    std::fs::create_dir_all(&dir_resp).unwrap();

    // Initiator-only file.
    std::fs::write(dir_init.join("a.txt"), b"initiator only").unwrap();
    // Shared file (identical content).
    std::fs::write(dir_init.join("shared.txt"), b"same on both").unwrap();
    std::fs::write(dir_resp.join("shared.txt"), b"same on both").unwrap();
    // Responder-only file.
    std::fs::write(dir_resp.join("c.txt"), b"responder only").unwrap();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_resp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_resp_port = udp_resp.local_addr().unwrap().port();
    let udp_init = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_init_port = udp_init.local_addr().unwrap().port();

    let session_id: u64 = 0xB1D1_0000_0001;

    let dir_resp_clone = dir_resp.clone();
    let resp_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let peer_ip = c0.peer_addr().unwrap().ip();
        let d0 = D0Transport::new(udp_resp);
        let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
        run_sync_responder(
            &mut session, &mut c0, &d0, &dir_resp_clone, udp_resp_port, peer_ip,
            ConflictPolicy::InitiatorWins,
        ).await.unwrap()
    });

    let dir_init_clone = dir_init.clone();
    let init_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let peer_ip = tcp_addr.ip();
        let d0 = D0Transport::new(udp_init);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
        run_sync_initiator(
            &mut session, &mut c0, &d0, &dir_init_clone, udp_init_port, peer_ip,
            ConflictPolicy::InitiatorWins,
        ).await.unwrap()
    });

    let (resp_result, init_result) = tokio::join!(resp_handle, init_handle);
    let init_report = init_result.unwrap();
    let resp_report = resp_result.unwrap();

    // Initiator sent a.txt to responder. Responder sent c.txt to initiator.
    assert_eq!(init_report.files_sent, 1);
    assert_eq!(init_report.files_received, 1);
    assert_eq!(resp_report.files_sent, 1);
    assert_eq!(resp_report.files_received, 1);

    // Both sides now have all files.
    assert_eq!(std::fs::read(dir_init.join("a.txt")).unwrap(), b"initiator only");
    assert_eq!(std::fs::read(dir_init.join("shared.txt")).unwrap(), b"same on both");
    assert_eq!(std::fs::read(dir_init.join("c.txt")).unwrap(), b"responder only");
    assert_eq!(std::fs::read(dir_resp.join("a.txt")).unwrap(), b"initiator only");
    assert_eq!(std::fs::read(dir_resp.join("shared.txt")).unwrap(), b"same on both");
    assert_eq!(std::fs::read(dir_resp.join("c.txt")).unwrap(), b"responder only");

    let _ = std::fs::remove_dir_all(&dir_init);
    let _ = std::fs::remove_dir_all(&dir_resp);
}

#[tokio::test]
async fn loopback_bidirectional_noop() {
    // Both sides identical — no files transferred.
    let dir_init = std::env::temp_dir().join("wisp_bidir_noop_init");
    let dir_resp = std::env::temp_dir().join("wisp_bidir_noop_resp");
    let _ = std::fs::remove_dir_all(&dir_init);
    let _ = std::fs::remove_dir_all(&dir_resp);
    std::fs::create_dir_all(&dir_init).unwrap();
    std::fs::create_dir_all(&dir_resp).unwrap();

    std::fs::write(dir_init.join("same.txt"), b"identical").unwrap();
    std::fs::write(dir_resp.join("same.txt"), b"identical").unwrap();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_resp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_resp_port = udp_resp.local_addr().unwrap().port();
    let udp_init = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_init_port = udp_init.local_addr().unwrap().port();

    let session_id: u64 = 0xB1D2_0000_0001;

    let dir_resp_clone = dir_resp.clone();
    let resp_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let peer_ip = c0.peer_addr().unwrap().ip();
        let d0 = D0Transport::new(udp_resp);
        let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
        run_sync_responder(
            &mut session, &mut c0, &d0, &dir_resp_clone, udp_resp_port, peer_ip,
            ConflictPolicy::InitiatorWins,
        ).await.unwrap()
    });

    let dir_init_clone = dir_init.clone();
    let init_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let peer_ip = tcp_addr.ip();
        let d0 = D0Transport::new(udp_init);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
        run_sync_initiator(
            &mut session, &mut c0, &d0, &dir_init_clone, udp_init_port, peer_ip,
            ConflictPolicy::InitiatorWins,
        ).await.unwrap()
    });

    let (resp_result, init_result) = tokio::join!(resp_handle, init_handle);
    let init_report = init_result.unwrap();
    let resp_report = resp_result.unwrap();

    assert_eq!(init_report.files_sent, 0);
    assert_eq!(init_report.files_received, 0);
    assert_eq!(resp_report.files_sent, 0);
    assert_eq!(resp_report.files_received, 0);

    let _ = std::fs::remove_dir_all(&dir_init);
    let _ = std::fs::remove_dir_all(&dir_resp);
}

#[tokio::test]
async fn loopback_bidirectional_conflict_skip() {
    // Same file, different content — with Skip policy, neither side gets it.
    let dir_init = std::env::temp_dir().join("wisp_bidir_skip_init");
    let dir_resp = std::env::temp_dir().join("wisp_bidir_skip_resp");
    let _ = std::fs::remove_dir_all(&dir_init);
    let _ = std::fs::remove_dir_all(&dir_resp);
    std::fs::create_dir_all(&dir_init).unwrap();
    std::fs::create_dir_all(&dir_resp).unwrap();

    std::fs::write(dir_init.join("conflict.txt"), b"initiator version").unwrap();
    std::fs::write(dir_resp.join("conflict.txt"), b"responder version").unwrap();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();

    let udp_resp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_resp_port = udp_resp.local_addr().unwrap().port();
    let udp_init = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_init_port = udp_init.local_addr().unwrap().port();

    let session_id: u64 = 0xB1D3_0000_0001;

    let dir_resp_clone = dir_resp.clone();
    let resp_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::accept(&tcp_listener).await.unwrap();
        let peer_ip = c0.peer_addr().unwrap().ip();
        let d0 = D0Transport::new(udp_resp);
        let mut session = Session::handshake_responder(&mut c0, None, 0, 1).await.unwrap();
        run_sync_responder(
            &mut session, &mut c0, &d0, &dir_resp_clone, udp_resp_port, peer_ip,
            ConflictPolicy::Skip,
        ).await.unwrap()
    });

    let dir_init_clone = dir_init.clone();
    let init_handle = tokio::spawn(async move {
        let mut c0 = C0Transport::connect(tcp_addr).await.unwrap();
        let peer_ip = tcp_addr.ip();
        let d0 = D0Transport::new(udp_init);
        let mut session = Session::handshake_initiator(&mut c0, session_id, None, 0, 1).await.unwrap();
        run_sync_initiator(
            &mut session, &mut c0, &d0, &dir_init_clone, udp_init_port, peer_ip,
            ConflictPolicy::Skip,
        ).await.unwrap()
    });

    let (resp_result, init_result) = tokio::join!(resp_handle, init_handle);
    let init_report = init_result.unwrap();
    let resp_report = resp_result.unwrap();

    // No files transferred — conflict skipped.
    assert_eq!(init_report.files_sent, 0);
    assert_eq!(init_report.files_received, 0);
    assert_eq!(init_report.files_skipped.len(), 1);
    assert_eq!(resp_report.files_sent, 0);
    assert_eq!(resp_report.files_received, 0);
    assert_eq!(resp_report.files_skipped.len(), 1);

    // Both sides keep their original content.
    assert_eq!(std::fs::read(dir_init.join("conflict.txt")).unwrap(), b"initiator version");
    assert_eq!(std::fs::read(dir_resp.join("conflict.txt")).unwrap(), b"responder version");

    let _ = std::fs::remove_dir_all(&dir_init);
    let _ = std::fs::remove_dir_all(&dir_resp);
}

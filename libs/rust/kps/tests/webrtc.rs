//! Rust↔Rust WebRTC integration: dial_webrtc → listener over the §6.2 framed
//! data channels — echo, concurrent streams, datagrams, close codes. Mirrors
//! the QUIC suite; together with it this exercises the single-port demux from
//! the WebRTC side.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{datagram_round_trip, echo_round_trip, start_echo_server, start_echo_server_on, T};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use kps::{Conn, ErrorCode, Identity, ListenOptions};

#[tokio::test]
async fn webrtc_echo() {
    let (_l, addr) = start_echo_server().await;
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    let echoed = echo_round_trip(conn.as_ref(), b"hello kps over webrtc").await;
    assert_eq!(echoed, b"hello kps over webrtc");
    conn.close().await.unwrap();
}

#[tokio::test]
async fn webrtc_echo_wildcard_listener_on_loopback() {
    // A gateway binds every interface and a browser on the same machine dials
    // it on loopback. The server must still gather exactly one candidate per
    // family when the loopback interface carries extra addresses (macOS lo0
    // has fe80::1 beside ::1, and 127.x aliases are common), or its ICE agent
    // never converges.
    let (_l, addr) = start_echo_server_on("0.0.0.0:0").await;
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    let echoed = echo_round_trip(conn.as_ref(), b"hello from the same machine").await;
    assert_eq!(echoed, b"hello from the same machine");
    conn.close().await.unwrap();
}

#[tokio::test]
async fn webrtc_multi_stream() {
    let (_l, addr) = start_echo_server().await;
    let conn: Arc<dyn Conn> =
        Arc::from(timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap());
    let mut tasks = Vec::new();
    for i in 0..4 {
        let conn = conn.clone();
        tasks.push(tokio::spawn(async move {
            let payload = format!("webrtc-stream-{i}").into_bytes();
            let echoed = echo_round_trip(conn.as_ref(), &payload).await;
            assert_eq!(echoed, payload);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn webrtc_large_payload() {
    let (_l, addr) = start_echo_server().await;
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    // Exercises frame splitting (>16 KiB) and SCTP backpressure.
    let payload: Vec<u8> = (0..(1 << 20)).map(|i| (i % 249) as u8).collect(); // 1 MiB
    let echoed = echo_round_trip(conn.as_ref(), &payload).await;
    assert_eq!(echoed.len(), payload.len());
    assert_eq!(echoed, payload, "large echo must be byte-exact");
}

#[tokio::test]
async fn webrtc_datagram_echo() {
    let (_l, addr) = start_echo_server().await;
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    assert!(datagram_round_trip(conn.as_ref(), b"kps webrtc datagram").await);
}

#[tokio::test]
async fn webrtc_datagram_too_large() {
    let (_l, addr) = start_echo_server().await;
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    let huge = vec![0u8; 4096];
    match conn.send_datagram(&huge).await {
        Err(kps::Error::DatagramTooLarge(e)) => {
            assert!(e.max_datagram_payload_size > 0);
            assert!(e.max_datagram_payload_size < huge.len());
        }
        other => panic!("expected DatagramTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_stream_reset_code() {
    // reset_write(code) → peer's read side observes a stream error with the
    // code, via the §6.2 RESET frame.
    let listener = kps::listen(
        "127.0.0.1:0",
        ListenOptions { identity: Some(Identity::generate().unwrap()), ..Default::default() },
    )
    .await
    .unwrap();
    let addr = listener.address("127.0.0.1");

    let server_side = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        let mut stream = conn.accept_stream().await.unwrap();
        let mut buf = Vec::new();
        let read_res = timeout(T, stream.read_to_end(&mut buf)).await.unwrap();
        (read_res.err(), stream.err())
    });

    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    let mut stream = timeout(T, conn.open_stream()).await.unwrap().unwrap();
    stream.write_all(b"partial").await.unwrap();
    stream.reset_write(ErrorCode::Reset).await.unwrap();

    let (io_err, stream_err) = server_side.await.unwrap();
    assert!(io_err.is_some(), "peer read must fail, not EOF");
    let se = stream_err.expect("stream err() must carry the reset");
    assert_eq!(se.code, ErrorCode::Reset);
    assert!(se.remote);
}

#[tokio::test]
async fn webrtc_conn_close_code() {
    // close_with_error(code) travels as CONNECTION_CLOSE on the reserved
    // control channel (SPEC §8) and surfaces as the peer's close reason.
    let listener = kps::listen(
        "127.0.0.1:0",
        ListenOptions { identity: Some(Identity::generate().unwrap()), ..Default::default() },
    )
    .await
    .unwrap();
    let addr = listener.address("127.0.0.1");

    let server_side = tokio::spawn(async move {
        let conn = listener.accept().await.unwrap();
        timeout(T, conn.closed()).await.unwrap();
        conn.err()
    });

    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    let _ = timeout(T, conn.open_stream()).await.unwrap().unwrap();
    conn.close_with_error(ErrorCode::ProtocolError).await.unwrap();

    let err = server_side.await.unwrap();
    match err {
        Some(kps::Error::Stream(se)) => {
            assert_eq!(se.code, ErrorCode::ProtocolError);
            assert!(se.remote);
        }
        other => panic!("expected StreamError(ProtocolError), got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_bad_certhash_rejected() {
    // A corrupted certhash derives the wrong ICE pwd AND the wrong pinned
    // fingerprint, so the handshake can never complete — the dial must not
    // produce a connection.
    let (_l, addr) = start_echo_server().await;
    let mut chars: Vec<char> = addr.chars().collect();
    let n = chars.len();
    chars[n - 1] = if chars[n - 1] == 'A' { 'B' } else { 'A' };
    let bad_addr: String = chars.into_iter().collect();

    match timeout(Duration::from_secs(5), kps::dial_webrtc(&bad_addr)).await {
        Err(_elapsed) => {}  // timed out: never connected
        Ok(Err(_)) => {}     // failed outright
        Ok(Ok(_)) => panic!("dial must not succeed with a bad certhash"),
    }
}

#[tokio::test]
async fn single_port_both_transports() {
    // SPEC §10.3: a WebRTC client and a QUIC client on the same listener UDP
    // port, concurrently, one advertised address.
    let (_l, addr) = start_echo_server().await;

    let a1 = addr.clone();
    let quic_task = tokio::spawn(async move {
        let conn = timeout(T, kps::dial(&a1)).await.unwrap().unwrap();
        let echoed = echo_round_trip(conn.as_ref(), b"via-quic").await;
        assert_eq!(echoed, b"via-quic");
    });
    let a2 = addr.clone();
    let webrtc_task = tokio::spawn(async move {
        let conn = timeout(T, kps::dial_webrtc(&a2)).await.unwrap().unwrap();
        let echoed = echo_round_trip(conn.as_ref(), b"via-webrtc").await;
        assert_eq!(echoed, b"via-webrtc");
    });

    quic_task.await.unwrap();
    webrtc_task.await.unwrap();
}

/// Several streams echo bulk data at once, each written in 64 KiB chunks.
/// A chunk is four full DATA frames (16 383-byte payloads, SPEC §6.2) plus a
/// 4-byte one, so small SCTP messages travel interleaved with large
/// fragmented ones on several streams at once. Every echo must be byte-exact
/// and must finish: a lost small frame shows up as a short echo, and a lost
/// FIN or credit frame stalls a stream, which the per-step timeouts turn into
/// a failure naming the stream and how far it got.
///
/// Guards the SCTP read path under concurrency. It stalled 2 runs in 3 on an
/// early port to the sans-I/O `rtc` stack; set `KPS_BULK_BYTES` to stress it
/// harder than the CI default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_concurrent_bulk_streams_byte_exact() {
    const STREAMS: usize = 4;
    const CHUNK: usize = 64 << 10;
    let per_stream: usize = std::env::var("KPS_BULK_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 << 20);
    let (_l, addr) = start_echo_server().await;
    let conn: Arc<dyn Conn> =
        Arc::from(timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap());

    let mut tasks = Vec::new();
    for i in 0..STREAMS {
        let conn = conn.clone();
        tasks.push(tokio::spawn(async move {
            // Distinct per stream, so a frame delivered to the wrong stream
            // can't pass for the right one.
            let payload: Vec<u8> = (0..per_stream)
                .map(|j| ((j * 7 + i * 13) % 251) as u8)
                .collect();
            let stream = timeout(T, conn.open_stream()).await.unwrap().unwrap();
            let (mut rd, mut wr) = tokio::io::split(stream);

            let to_send = payload.clone();
            let writer = tokio::spawn(async move {
                for chunk in to_send.chunks(CHUNK) {
                    timeout(T, wr.write_all(chunk))
                        .await
                        .expect("write stalled")
                        .unwrap();
                }
                timeout(T, wr.shutdown())
                    .await
                    .expect("FIN stalled")
                    .unwrap();
            });

            let mut echoed = Vec::with_capacity(per_stream);
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = timeout(T, rd.read(&mut buf))
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "stream {i}: read stalled after {} of {per_stream} bytes",
                            echoed.len()
                        )
                    })
                    .unwrap();
                if n == 0 {
                    break;
                }
                echoed.extend_from_slice(&buf[..n]);
            }
            writer.await.unwrap();
            assert_eq!(echoed.len(), per_stream, "stream {i}: echo length");
            assert!(echoed == payload, "stream {i}: echo content differs");
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

/// The peer writes first on a stream we opened. The first frame can arrive
/// right after the channel opens, before our side has finished setting the
/// stream up, and must still be delivered (and the FIN behind it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_peer_writes_first_on_locally_opened_streams() {
    let listener = kps::listen(
        "127.0.0.1:0",
        ListenOptions { identity: Some(Identity::generate().unwrap()), ..Default::default() },
    )
    .await
    .unwrap();
    let addr = listener.address("127.0.0.1");
    let listener = Arc::new(listener);
    let l = listener.clone();
    tokio::spawn(async move {
        let conn = l.accept().await.unwrap();
        // Greet on every stream the moment it's accepted, without reading.
        while let Ok(mut s) = conn.accept_stream().await {
            tokio::spawn(async move {
                let _ = s.write_all(b"hello").await;
                let _ = s.close_write().await;
            });
        }
    });
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    for i in 0..300 {
        let mut s = timeout(T, conn.open_stream()).await.unwrap().unwrap();
        // The client sends nothing first: the open alone makes the server
        // accept. (A KPS stream surfaces to the acceptor once the channel
        // opens.)
        let mut got = Vec::new();
        timeout(T, s.read_to_end(&mut got))
            .await
            .unwrap_or_else(|_| panic!("stream {i}: read stalled after {got:?}"))
            .unwrap();
        assert_eq!(got, b"hello", "stream {i}");
        s.close_write().await.unwrap();
    }
}

/// A sender that keeps the datagram channel saturated must not stall the
/// connection's other traffic: a stream echo alongside it still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_datagram_flood_does_not_starve_streams() {
    let (_l, addr) = start_echo_server().await;
    let conn: Arc<dyn Conn> = Arc::from(timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap());
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flood = {
        let (conn, stop) = (conn.clone(), stop.clone());
        tokio::spawn(async move {
            let p = vec![7u8; 1000];
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if conn.send_datagram(&p).await.is_err() {
                    break;
                }
                // A dropped datagram completes without waiting; yield so this
                // loop can't monopolise a worker thread.
                tokio::task::yield_now().await;
            }
        })
    };
    let payload: Vec<u8> = (0..(1 << 20)).map(|j| (j % 251) as u8).collect();
    let echoed = timeout(T, echo_round_trip(conn.as_ref(), &payload)).await.expect("stream echo stalled under a datagram flood");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flood.await.unwrap();
    assert!(echoed == payload);
}

/// Closing a stale handle must not touch a newer stream. The rtc core
/// reuses SCTP stream ids as channels close, so a late close of an old
/// stream (retirement closes the channel from a spawned task, up to 250 ms
/// later) could in principle land on a new stream that reused the id. The
/// driver addresses channels by a connection-local handle that is never
/// reused, so the stale close must be a no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_stale_close_leaves_newer_streams_alone() {
    let (_l, addr) = start_echo_server().await;
    let conn = timeout(T, kps::dial_webrtc(&addr)).await.unwrap().unwrap();
    for round in 0..5 {
        // A: a complete echo, then wait for its channel to be fully closed
        // (both resets done, so its SCTP stream id is free for reuse).
        let mut a = timeout(T, conn.open_stream()).await.unwrap().unwrap();
        a.write_all(b"old").await.unwrap();
        a.close_write().await.unwrap();
        let mut got = Vec::new();
        timeout(T, a.read_to_end(&mut got)).await.unwrap().unwrap();
        // Retirement closes A's channel after up to 250 ms, then both resets
        // must complete before its stream id is free.
        tokio::time::sleep(Duration::from_millis(400)).await;
        // B, on A's freed stream id (rtc hands out the lowest free one);
        // write, but don't finish yet.
        let mut b = timeout(T, conn.open_stream()).await.unwrap().unwrap();
        b.write_all(b"new").await.unwrap();
        // The stale close: must not reset or close B.
        let _ = a.close().await;
        drop(a);
        tokio::time::sleep(Duration::from_millis(20)).await;
        b.close_write().await.unwrap();
        let mut got = Vec::new();
        timeout(T, b.read_to_end(&mut got))
            .await
            .unwrap_or_else(|_| panic!("round {round}: B stalled"))
            .unwrap_or_else(|e| panic!("round {round}: B failed: {e}"));
        assert_eq!(got, b"new", "round {round}");
        // Let B's channel close too, so the next round's A and B both land on
        // the same freed id again.
        drop(b);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

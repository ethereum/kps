//! The WebRTC dialer (SPEC §5.2). Native clients default to QUIC
//! ([`crate::dial`]); this is the explicit override the spec allows for
//! tests/debugging and for interop with browser-facing listeners (SPEC §5.4).
//! It mirrors the browser client: the offerer synthesizes the server's answer
//! from the address, derives the ICE password from the certhash, and pins the
//! server's DTLS certificate via the answer fingerprint.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use rtc::peer_connection::sdp::RTCSessionDescription;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::address::{decode_certhash, parse_address, Address};
use crate::api::Conn;
use crate::conn::WebrtcConn;
use crate::error::{Error, Result};
use crate::ice::{derive_ice_pwd, rand_ufrag};
use crate::rtc_driver::{self, DriverIo, RTCDataChannelInit, RTCPeerConnectionState};
use crate::rtc_transport::{failure, host_candidate, peer_connection, setting_engine};

/// Opens a kps connection over the WebRTC transport. The server's DTLS
/// certificate is pinned via the synthesized answer's fingerprint (= the
/// address certhash); no signaling server is involved. Apply timeouts
/// caller-side with `tokio::time::timeout`.
pub async fn dial_webrtc(addr: &str) -> Result<Box<dyn Conn>> {
    let a = parse_address(addr)?;
    let digest = decode_certhash(&a.certhash)?;
    let ufrag = rand_ufrag();
    let pwd = derive_ice_pwd(&digest, &ufrag);
    let remote: SocketAddr = format!(
        "{}:{}",
        if a.ip.contains(':') { format!("[{}]", a.ip) } else { a.ip.clone() },
        a.port
    )
    .parse()
    .map_err(|e| Error::Address(format!("bad ip in address: {e}")))?;

    let socket = Arc::new(
        UdpSocket::bind(if remote.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })
            .await
            .map_err(|e| Error::Dial(format!("bind: {e}")))?,
    );
    // Rule 6 (rtc_driver.rs): a bulk download overflows the default receive
    // buffer as easily as the listener's.
    crate::listener::enlarge_udp_buffers(&socket);
    let port = socket.local_addr()?.port();
    let ip = route_ip(remote).unwrap_or(if remote.is_ipv6() {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    });
    let local = SocketAddr::new(ip, port);

    let pc = peer_connection(setting_engine(&ufrag, &pwd, false), None).map_err(Error::Dial)?;

    // Socket reader → driver inbox.
    let (tx, inbox) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
    let reader = {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if tx.send((buf[..n].to_vec(), from)).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
    };
    let pc = rtc_driver::spawn(pc, DriverIo { socket, inbox, local });

    // The negotiated control channel (ID 0) before the offer, so the offer
    // carries the application m-line; WebrtcConn::new adds the datagram
    // channel (ID 1).
    let control = pc
        .create_data_channel(
            "_kps_control",
            Some(RTCDataChannelInit { negotiated: Some(0), ..Default::default() }),
        )
        .await
        .map_err(|e| Error::Dial(format!("control channel: {e}")))?;
    let conn = WebrtcConn::new(Arc::new(pc.clone()), Some(control), remote).await?;
    let close_state = conn.close_state.clone();
    pc.on_peer_connection_state_change(Box::new(move |s| {
        if matches!(s, RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed) {
            close_state.mark(failure(s));
            reader.abort();
        }
        Box::pin(async {})
    }));

    let answer = synthesize_webrtc_answer(&a, &ufrag, &pwd, &digest_to_fingerprint(&digest));
    pc.with(move |pc| -> std::result::Result<(), String> {
        pc.add_local_candidate(host_candidate(local)?).map_err(|e| format!("local candidate: {e}"))?;
        let offer = pc.create_offer(None).map_err(|e| format!("create offer: {e}"))?;
        pc.set_local_description(Instant::now(), offer).map_err(|e| format!("set local: {e}"))?;
        let answer = RTCSessionDescription::answer(answer).map_err(|e| format!("answer: {e}"))?;
        pc.set_remote_description(Instant::now(), answer).map_err(|e| format!("set remote: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| Error::Dial(e.to_string()))?
    .map_err(Error::Dial)?;

    // Established = transport up AND mutual HELLO (SPEC §8).
    if let Err(e) = conn.wait_established().await {
        let _ = pc.close().await;
        return Err(Error::Dial(format!("connection failed: {e}")));
    }
    Ok(Box::new(conn))
}

/// The local IP the OS would use to reach `remote`. Connecting a UDP socket
/// picks the route; no packet is sent.
fn route_ip(remote: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr =
        if remote.is_ipv6() { "[::]:0".parse().ok()? } else { "0.0.0.0:0".parse().ok()? };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(remote).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

fn digest_to_fingerprint(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Fabricates the answer SDP the server would have sent (it never actually
/// transmits one — SPEC §5.2): ICE-lite, the derived ICE creds, the pinned
/// fingerprint, and a host candidate at the dialed endpoint.
fn synthesize_webrtc_answer(a: &Address, ufrag: &str, pwd: &str, fingerprint: &str) -> String {
    let (fam, any_addr) = if a.ip.contains(':') { ("IP6", "::") } else { ("IP4", "0.0.0.0") };
    [
        "v=0".to_string(),
        format!("o=- 0 0 IN {fam} {any_addr}"),
        "s=-".to_string(),
        "t=0 0".to_string(),
        "a=ice-lite".to_string(),
        format!("m=application {} UDP/DTLS/SCTP webrtc-datachannel", a.port),
        format!("c=IN {fam} {}", a.ip),
        "a=mid:0".to_string(),
        format!("a=ice-ufrag:{ufrag}"),
        format!("a=ice-pwd:{pwd}"),
        format!("a=fingerprint:sha-256 {fingerprint}"),
        "a=setup:passive".to_string(),
        "a=sctp-port:5000".to_string(),
        "a=max-message-size:1048576".to_string(),
        format!("a=candidate:1 1 UDP 1 {} {} typ host", a.ip, a.port),
    ]
    .join("\r\n")
        + "\r\n"
}

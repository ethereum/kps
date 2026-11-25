//! WebRTC plumbing on the `rtc` core shared by the dialer
//! (`webrtc_client.rs`) and the listener: building peer connections, the one
//! host candidate each side registers, and the server's per-client
//! ICE-lite peer connection. The KPS protocol on top (HELLO, streams, flow
//! control) is `conn.rs` / `stream.rs`.
//!
//! Host candidates: `rtc` doesn't gather, so each side registers exactly one
//! host candidate. It's a local key, not something the peer sees: KPS has no
//! signaling, and the ICE-lite server learns the client's address from its
//! STUN checks (peer-reflexive). So:
//! - the dialer uses the local IP the OS routes toward the server (the
//!   connected-UDP-socket trick; no packet is sent), plus its socket's port;
//! - the server uses its listen port on the loopback address of the client's
//!   family. With exactly one candidate per connection, the webrtc 0.14
//!   multi-candidate race behind kps#8 can't happen.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rtc::peer_connection::certificate::RTCCertificate;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::api::Conn;
use crate::cert::Identity;
use crate::conn::WebrtcConn;
use crate::error::{Error, ErrorCode, Result, StreamError};
use crate::ice::derive_ice_pwd;
use crate::rtc_driver::{self, DriverIo, RTCPeerConnectionState};

type Packet = (Vec<u8>, SocketAddr);

/// ICE timers: disconnected after 5 s without traffic, failed (the
/// connection closes with a network error) after a further 25 s, consent
/// checks every 2 s. These are webrtc 0.14's defaults, so dead-peer
/// detection behaves as it did before the move to `rtc`.
const ICE_DISCONNECTED: Duration = Duration::from_secs(5);
const ICE_FAILED: Duration = Duration::from_secs(25);
const ICE_KEEPALIVE: Duration = Duration::from_secs(2);

/// A setting engine with KPS's fixed ICE credentials and timers. `lite`
/// selects the server's ICE-lite role.
pub(crate) fn setting_engine(ufrag: &str, pwd: &str, lite: bool) -> SettingEngine {
    let mut se = SettingEngineBuilder::new()
        .with_ice_credentials(ufrag.to_owned(), pwd.to_owned())
        .with_ice_timeouts(Some(ICE_DISCONNECTED), Some(ICE_FAILED), Some(ICE_KEEPALIVE))
        .with_include_loopback_candidate(true);
    if lite {
        // The server never verifies the client's certificate: KPS
        // authenticates the server only (SPEC §3), and the offer it builds
        // for the client carries a placeholder fingerprint.
        se = se.with_lite(true).with_disable_certificate_fingerprint_verification(true);
    }
    se.build()
}

/// Builds an `rtc` peer connection with `se` and, for the server, its
/// certificate.
pub(crate) fn peer_connection(
    se: SettingEngine,
    certificate: Option<RTCCertificate>,
) -> std::result::Result<rtc::peer_connection::RTCPeerConnection, String> {
    let mut config = RTCConfigurationBuilder::new();
    if let Some(c) = certificate {
        config = config.with_certificates(vec![c]);
    }
    RTCPeerConnectionBuilder::new()
        .with_configuration(config.build())
        .with_setting_engine(se)
        .build(Instant::now())
        .map_err(|e| format!("peer connection: {e}"))
}

/// The one host candidate a connection registers (see the module doc).
pub(crate) fn host_candidate(addr: SocketAddr) -> std::result::Result<RTCIceCandidateInit, String> {
    let c = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .map_err(|e| format!("host candidate: {e}"))?;
    RTCIceCandidate::from(&c).to_json().map_err(|e| format!("host candidate: {e}"))
}

/// The close reason for a terminal peer-connection state: an ICE failure
/// (the peer died or the path broke) is a network error, as QUIC reports at
/// its idle timeout; a close is clean.
pub(crate) fn failure(s: RTCPeerConnectionState) -> Option<StreamError> {
    (s == RTCPeerConnectionState::Failed)
        .then_some(StreamError { code: ErrorCode::NetworkError, remote: false })
}

/// Server side: the ICE-lite peer connection for one client ufrag. Returns
/// the handle (the listener closes it on shutdown); the conn surfaces on
/// `accept_tx` after mutual HELLO. `on_gone` runs once when it closes.
pub(crate) async fn spawn_pc(
    socket: Arc<UdpSocket>,
    identity: Arc<Identity>,
    ufrag: String,
    client_addr: SocketAddr,
    inbox: mpsc::Receiver<Packet>,
    accept_tx: mpsc::Sender<Box<dyn Conn>>,
    on_gone: Box<dyn FnOnce() + Send + Sync>,
) -> Result<rtc_driver::RTCPeerConnection> {
    let port = socket.local_addr()?.port();
    let pwd = derive_ice_pwd(&identity.digest, &ufrag);
    let local = SocketAddr::new(
        if client_addr.is_ipv6() { IpAddr::V6(Ipv6Addr::LOCALHOST) } else { IpAddr::V4(Ipv4Addr::LOCALHOST) },
        port,
    );

    let pc = peer_connection(setting_engine(&ufrag, &pwd, true), Some(identity.rtc_certificate()?))
        .map_err(Error::Transport)?;
    let pc = rtc_driver::spawn(pc, DriverIo { socket, inbox, local });

    let conn = WebrtcConn::new(Arc::new(pc.clone()), None, client_addr).await?;
    let close_state = conn.close_state.clone();
    let slot = Arc::new(Mutex::new(Some(conn)));
    let on_gone = Mutex::new(Some(on_gone));
    pc.on_peer_connection_state_change(Box::new(move |s| {
        match s {
            RTCPeerConnectionState::Connected => {
                if let Some(conn) = slot.lock().unwrap().take() {
                    let accept_tx = accept_tx.clone();
                    // Surface only after mutual HELLO (SPEC §8: accept MUST NOT
                    // complete before it), bounded by the conn's HELLO timeout.
                    // A failed handshake tears the conn down without surfacing it.
                    tokio::spawn(async move {
                        if conn.wait_established().await.is_ok() {
                            let _ = accept_tx.send(Box::new(conn) as Box<dyn Conn>).await;
                        }
                    });
                }
            }
            RTCPeerConnectionState::Closed | RTCPeerConnectionState::Failed => {
                close_state.mark(failure(s));
                slot.lock().unwrap().take();
                if let Some(f) = on_gone.lock().unwrap().take() {
                    f();
                }
            }
            _ => {}
        }
        Box::pin(async {})
    }));

    let offer = crate::listener::build_client_offer(&ufrag, &pwd, port, client_addr);
    pc.with(move |pc| -> std::result::Result<(), String> {
        pc.add_local_candidate(host_candidate(local)?).map_err(|e| format!("local candidate: {e}"))?;
        let offer = RTCSessionDescription::offer(offer).map_err(|e| format!("offer: {e}"))?;
        pc.set_remote_description(Instant::now(), offer).map_err(|e| format!("set remote: {e}"))?;
        let answer = pc.create_answer(None).map_err(|e| format!("answer: {e}"))?;
        // Never transmitted: KPS has no signaling; the client synthesizes it.
        pc.set_local_description(Instant::now(), answer).map_err(|e| format!("set local: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| Error::Transport(e.to_string()))?
    .map_err(Error::Transport)?;
    Ok(pc)
}

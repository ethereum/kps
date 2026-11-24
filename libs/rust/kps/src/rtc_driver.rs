//! The per-connection driver for webrtc-rs's sans-I/O `rtc` core.
//!
//! One tokio task per connection owns the `rtc::RTCPeerConnection`. It reads
//! datagrams from an inbox (the listener's pump, or the dialer's socket
//! reader), runs `rtc`'s timers, writes `poll_write` output to the UDP socket,
//! and dispatches events and messages to handlers.
//!
//! The rest of the crate talks to the driver through the [`RTCPeerConnection`]
//! and [`RTCDataChannel`] handles. They mirror the small part of the webrtc
//! 0.14 API that `conn.rs` and `stream.rs` use (async `send`,
//! `buffered_amount`, `on_open` / `on_message` / `on_close` handlers, ...), so
//! the KPS protocol code (HELLO, flow control, framing, retirement) didn't
//! have to change with the stack.
//!
//! Handlers run on the driver task, one at a time, in event order. Handle
//! methods never wait for the driver except [`RTCPeerConnection::with`] and
//! `create_data_channel`, which must not be called from inside a handler.
//!
//! # Rules
//!
//! Each of these was a bug found the hard way; the code points back here.
//!
//! 1. **Dispatch events after every `handle_read`, not once per batch.** `rtc`
//!    used to drop data that reached a negotiated channel before
//!    `SCTPHandshakeComplete` had been polled (webrtc-rs/rtc#292), and reading
//!    a batch of datagrams before polling lost the peer's HELLO on every
//!    connection. That is fixed in `rtc` now; per-datagram dispatch stays
//!    because it costs little and keeps events in arrival order.
//! 2. **Run `handle_timeout(now)` right after an ICE state change.** `rtc`
//!    starts DTLS on its next timer tick, not on the state change: connect
//!    took ~200 ms instead of 2-6 ms.
//! 3. **A channel's buffered amount is the driver's queue plus `rtc`'s
//!    `outstanding_bytes`, and the outstanding count is published before the
//!    queued bytes are released.** Otherwise it reads 0 for an instant, KPS's
//!    stream retirement closes the channel, and the SCTP reset overtakes our
//!    FIN (about 1 browser stream-cycle run in 10).
//! 4. **[`RTCDataChannel::send`] only queues.** State that depends on a frame
//!    being on the wire must be set before handing it over, because the peer
//!    can react before `send` returns (see `local_terminal_sent` in
//!    `stream.rs`).
//! 5. **Run `handle_timeout` whenever its deadline has passed,** not only when
//!    the select's sleep wins. Under steady traffic the biased select never
//!    picked the sleep, so SCTP's retransmission timer never fired and a lost
//!    chunk was never resent.
//! 6. **Keep loss off loopback.** A full inbox drops packets, and the kernel's
//!    default UDP buffers overflow under a burst; SCTP reads both as
//!    congestion. The inbox sizes and socket buffers are set where the
//!    sockets are made (`listener.rs`, `rtc_transport.rs`).

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rtc::data_channel::RTCDataChannelId;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

pub(crate) use rtc::peer_connection::state::RTCPeerConnectionState;

type Packet = (Vec<u8>, SocketAddr);
type BoxFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// The webrtc 0.14 `DataChannelMessage` shape.
#[derive(Debug, Clone)]
pub(crate) struct DataChannelMessage {
    #[allow(dead_code)]
    pub(crate) is_string: bool,
    pub(crate) data: Bytes,
}

/// The webrtc 0.14 `RTCDataChannelInit` shape (the fields KPS uses).
#[derive(Debug, Clone, Default)]
pub(crate) struct RTCDataChannelInit {
    pub(crate) ordered: Option<bool>,
    pub(crate) max_retransmits: Option<u16>,
    pub(crate) negotiated: Option<u16>,
    pub(crate) max_packet_life_time: Option<u16>,
}

/// The webrtc 0.14 `RTCDataChannelState` shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RTCDataChannelState {
    Connecting,
    Open,
    Closing,
    Closed,
}

type OnOpenFn = Box<dyn FnOnce() -> BoxFut + Send + Sync>;
type OnMessageFn = Box<dyn FnMut(DataChannelMessage) -> BoxFut + Send + Sync>;
type OnEventFn = Box<dyn FnMut() -> BoxFut + Send + Sync>;
type OnDataChannelFn = Box<dyn FnMut(Arc<RTCDataChannel>) -> BoxFut + Send + Sync>;
type OnStateFn = Box<dyn FnMut(RTCPeerConnectionState) -> BoxFut + Send + Sync>;
type WithFn = Box<dyn FnOnce(&mut rtc::peer_connection::RTCPeerConnection) + Send>;

#[derive(Debug)]
pub(crate) struct DriverError(String);

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DriverError {}

enum Cmd {
    Create {
        label: String,
        init: RTCDataChannelInit,
        reply: oneshot::Sender<Result<Arc<RTCDataChannel>, DriverError>>,
    },
    Send(RTCDataChannelId, BytesMut),
    CloseChannel(RTCDataChannelId),
    SetLowThreshold(RTCDataChannelId, usize),
    With(WithFn),
    Close,
}

/// Per-channel state shared between the handle and the driver.
struct DcInner {
    state: Mutex<RTCDataChannelState>,
    /// Bytes handed to `send` that the driver hasn't passed to `rtc` yet.
    queued: AtomicUsize,
    /// `rtc`'s `outstanding_bytes` (sent but not yet released by SCTP),
    /// published by the driver after every pass.
    outstanding: AtomicUsize,
    low_threshold: AtomicUsize,
    on_open: Mutex<Option<OnOpenFn>>,
    on_message: Mutex<Option<OnMessageFn>>,
    on_close: Mutex<Option<OnEventFn>>,
    on_low: Mutex<Option<OnEventFn>>,
}

impl DcInner {
    fn new(state: RTCDataChannelState) -> Self {
        Self {
            state: Mutex::new(state),
            queued: AtomicUsize::new(0),
            outstanding: AtomicUsize::new(0),
            low_threshold: AtomicUsize::new(0),
            on_open: Mutex::new(None),
            on_message: Mutex::new(None),
            on_close: Mutex::new(None),
            on_low: Mutex::new(None),
        }
    }

    fn buffered(&self) -> usize {
        self.queued.load(Ordering::SeqCst) + self.outstanding.load(Ordering::SeqCst)
    }

    fn set_state(&self, s: RTCDataChannelState) {
        *self.state.lock().unwrap() = s;
    }
}

/// A data channel handle (webrtc 0.14 `RTCDataChannel` shape).
pub(crate) struct RTCDataChannel {
    id: RTCDataChannelId,
    inner: Arc<DcInner>,
    cmd: mpsc::UnboundedSender<Cmd>,
}

impl RTCDataChannel {
    pub(crate) fn ready_state(&self) -> RTCDataChannelState {
        *self.inner.state.lock().unwrap()
    }

    /// Queues `data` as one message (rule 4: it isn't on the wire yet when
    /// this returns). Fails only when the channel isn't open; later transport
    /// errors are logged by the driver, the same best-effort contract SCTP
    /// gives after the send call returns.
    pub(crate) async fn send(&self, data: &Bytes) -> Result<usize, DriverError> {
        if self.ready_state() != RTCDataChannelState::Open {
            return Err(DriverError(format!("data channel {} not open", self.id)));
        }
        let n = data.len();
        self.inner.queued.fetch_add(n, Ordering::SeqCst);
        if self.cmd.send(Cmd::Send(self.id, BytesMut::from(&data[..]))).is_err() {
            self.inner.queued.fetch_sub(n, Ordering::SeqCst);
            return Err(DriverError("peer connection closed".into()));
        }
        Ok(n)
    }

    pub(crate) async fn buffered_amount(&self) -> usize {
        self.inner.buffered()
    }

    pub(crate) async fn set_buffered_amount_low_threshold(&self, threshold: usize) {
        self.inner.low_threshold.store(threshold, Ordering::SeqCst);
        let _ = self.cmd.send(Cmd::SetLowThreshold(self.id, threshold));
    }

    pub(crate) async fn on_buffered_amount_low(&self, f: OnEventFn) {
        *self.inner.on_low.lock().unwrap() = Some(f);
    }

    pub(crate) fn on_open(&self, f: OnOpenFn) {
        *self.inner.on_open.lock().unwrap() = Some(f);
    }

    pub(crate) fn on_message(&self, f: OnMessageFn) {
        *self.inner.on_message.lock().unwrap() = Some(f);
    }

    pub(crate) fn on_close(&self, mut f: OnEventFn) {
        // Closed before the handler was registered (the driver closes a
        // channel on its own task): run it now, as the close already happened.
        if self.ready_state() == RTCDataChannelState::Closed {
            tokio::spawn(f());
            return;
        }
        *self.inner.on_close.lock().unwrap() = Some(f);
    }

    pub(crate) async fn close(&self) -> Result<(), DriverError> {
        let _ = self.cmd.send(Cmd::CloseChannel(self.id));
        Ok(())
    }
}

struct PcShared {
    state: Mutex<RTCPeerConnectionState>,
    on_data_channel: Mutex<Option<OnDataChannelFn>>,
    on_state: Mutex<Option<OnStateFn>>,
}

/// A peer connection handle (webrtc 0.14 `RTCPeerConnection` shape).
#[derive(Clone)]
pub(crate) struct RTCPeerConnection {
    shared: Arc<PcShared>,
    cmd: mpsc::UnboundedSender<Cmd>,
}

impl RTCPeerConnection {
    pub(crate) fn connection_state(&self) -> RTCPeerConnectionState {
        *self.shared.state.lock().unwrap()
    }

    pub(crate) async fn create_data_channel(
        &self,
        label: &str,
        init: Option<RTCDataChannelInit>,
    ) -> Result<Arc<RTCDataChannel>, DriverError> {
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Create { label: label.to_owned(), init: init.unwrap_or_default(), reply })
            .map_err(|_| DriverError("peer connection closed".into()))?;
        rx.await.map_err(|_| DriverError("peer connection closed".into()))?
    }

    pub(crate) fn on_data_channel(&self, f: OnDataChannelFn) {
        *self.shared.on_data_channel.lock().unwrap() = Some(f);
    }

    pub(crate) fn on_peer_connection_state_change(&self, f: OnStateFn) {
        *self.shared.on_state.lock().unwrap() = Some(f);
    }

    /// Starts closing. Doesn't wait, so handlers may call it.
    pub(crate) async fn close(&self) -> Result<(), DriverError> {
        let _ = self.cmd.send(Cmd::Close);
        Ok(())
    }

    /// Runs `f` on the driver task with the `rtc` peer connection (setup:
    /// descriptions, candidates). Not callable from handlers.
    pub(crate) async fn with<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut rtc::peer_connection::RTCPeerConnection) -> R + Send + 'static,
    ) -> Result<R, DriverError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::With(Box::new(move |pc| {
                let _ = tx.send(f(pc));
            })))
            .map_err(|_| DriverError("peer connection closed".into()))?;
        rx.await.map_err(|_| DriverError("peer connection closed".into()))
    }
}

/// Where the driver's datagrams go.
pub(crate) struct DriverIo {
    pub(crate) socket: Arc<UdpSocket>,
    /// Inbound datagrams for this connection.
    pub(crate) inbox: mpsc::Receiver<Packet>,
    /// The local address `rtc` sees in every `TransportContext`: the address
    /// of the one host candidate this connection registers.
    pub(crate) local: SocketAddr,
}

/// Spawns the driver for `pc` and returns its handle.
pub(crate) fn spawn(pc: rtc::peer_connection::RTCPeerConnection, io: DriverIo) -> RTCPeerConnection {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(PcShared {
        state: Mutex::new(RTCPeerConnectionState::New),
        on_data_channel: Mutex::new(None),
        on_state: Mutex::new(None),
    });
    let handle = RTCPeerConnection { shared: shared.clone(), cmd: cmd_tx.clone() };
    let driver = Driver {
        pc,
        io,
        cmd_rx,
        cmd_tx: cmd_tx.downgrade(),
        shared,
        channels: HashMap::new(),
        early: HashMap::new(),
        terminal: false,
        sock_local: None,
    };
    tokio::spawn(driver.run());
    handle
}

fn kps_debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("KPS_DEBUG").is_some())
}

/// Re-maps a v4 destination for a dual-stack (v6) socket.
fn map_for_socket(local: &SocketAddr, target: SocketAddr) -> SocketAddr {
    match (local, target) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => target,
    }
}

struct Channel {
    inner: Arc<DcInner>,
    /// For the low-threshold crossing (fires `on_low` when the buffered
    /// amount falls to or below the threshold from above).
    above: bool,
}

struct Driver {
    pc: rtc::peer_connection::RTCPeerConnection,
    io: DriverIo,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    /// For handles to channels the peer opens (weak, so the driver doesn't
    /// keep its own command channel alive).
    cmd_tx: mpsc::WeakUnboundedSender<Cmd>,
    shared: Arc<PcShared>,
    channels: HashMap<RTCDataChannelId, Channel>,
    /// Messages for a channel the driver hasn't seen open yet.
    early: HashMap<RTCDataChannelId, Vec<DataChannelMessage>>,
    terminal: bool,
    sock_local: Option<SocketAddr>,
}

/// Datagrams drained per wakeup before the driver runs a pass, so one busy
/// connection can't starve its own timers and writes.
const READ_BATCH: usize = 64;

impl Driver {
    async fn run(mut self) {
        let sock_local = self.io.socket.local_addr().ok();
        self.sock_local = sock_local;
        loop {
            self.pass(sock_local).await;
            if self.terminal {
                break;
            }
            let now = Instant::now();
            let next = self.pc.poll_timeout().unwrap_or(now + Duration::from_secs(1));
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next.max(now)));
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(c) => {
                        self.command(c).await;
                        while let Ok(c) = self.cmd_rx.try_recv() {
                            self.command(c).await;
                        }
                    }
                    None => {
                        // Every handle is gone: nobody can use this connection.
                        let _ = self.pc.close();
                        self.pass(sock_local).await;
                        self.finish().await;
                        break;
                    }
                },
                pkt = self.io.inbox.recv() => match pkt {
                    Some(p) => {
                        // Rule 1: dispatch after every datagram.
                        self.read(p);
                        for _ in 1..READ_BATCH {
                            match self.io.inbox.try_recv() {
                                Ok(p) => {
                                    self.pass(sock_local).await;
                                    self.read(p);
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    None => {
                        // The listener or dial socket went away.
                        let _ = self.pc.close();
                        self.pass(sock_local).await;
                        self.finish().await;
                        break;
                    }
                },
                _ = sleep => {}
            }
            // Rule 5: run rtc's timers whenever they are due, whichever
            // branch the biased select took.
            if Instant::now() >= next {
                if let Err(e) = self.pc.handle_timeout(Instant::now()) {
                    if kps_debug() {
                        eprintln!("[kps-rtc] handle_timeout: {e}");
                    }
                }
            }
        }
    }

    fn read(&mut self, (pkt, from): Packet) {
        let r = self.pc.handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: self.io.local,
                peer_addr: SocketAddr::new(from.ip().to_canonical(), from.port()),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&pkt[..]),
        });
        if let Err(e) = r {
            if kps_debug() {
                eprintln!("[kps-rtc] handle_read: {e}");
            }
        }
    }

    async fn flush(&mut self, sock_local: Option<SocketAddr>) {
        while let Some(msg) = self.pc.poll_write() {
            let to = match sock_local {
                Some(l) => map_for_socket(&l, msg.transport.peer_addr),
                None => msg.transport.peer_addr,
            };
            if let Err(e) = self.io.socket.send_to(&msg.message, to).await {
                if kps_debug() {
                    eprintln!("[kps-rtc] send_to {to}: {e}");
                }
            }
        }
    }

    /// Flush writes, dispatch events and messages, publish buffered amounts;
    /// repeat while handlers produced more work.
    async fn pass(&mut self, sock_local: Option<SocketAddr>) {
        for _ in 0..16 {
            self.flush(sock_local).await;
            let mut kick = false;
            let mut worked = false;
            while let Some(ev) = self.pc.poll_event() {
                worked = true;
                if matches!(ev, RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(_)) {
                    kick = true;
                }
                self.event(ev).await;
            }
            while let Some(TaggedRTCMessage { message, .. }) = self.pc.poll_read() {
                worked = true;
                if let RTCMessage::DataChannelMessage(id, m) = message {
                    self.deliver(id, DataChannelMessage { is_string: m.is_string, data: m.data.freeze() })
                        .await;
                }
            }
            // Handlers queue sends as commands; run them before publishing the
            // buffered amounts so the next writer decision sees them.
            while let Ok(c) = self.cmd_rx.try_recv() {
                worked = true;
                self.command(c).await;
            }
            // Rule 2: start DTLS now rather than on the next timer tick.
            if kick {
                let _ = self.pc.handle_timeout(Instant::now());
            }
            self.publish_buffered().await;
            if !worked && !kick {
                break;
            }
        }
        self.flush(sock_local).await;
    }

    async fn publish_buffered(&mut self) {
        let mut low = Vec::new();
        for (id, ch) in self.channels.iter_mut() {
            let out = self.pc.data_channel(*id).map(|d| d.outstanding_bytes()).unwrap_or(0);
            ch.inner.outstanding.store(out, Ordering::SeqCst);
            let threshold = ch.inner.low_threshold.load(Ordering::SeqCst);
            let buffered = ch.inner.buffered();
            if buffered > threshold {
                ch.above = true;
            } else if ch.above {
                ch.above = false;
                low.push(ch.inner.clone());
            }
        }
        for inner in low {
            let fut = inner.on_low.lock().unwrap().as_mut().map(|f| f());
            if let Some(fut) = fut {
                fut.await;
            }
        }
    }

    async fn event(&mut self, ev: RTCPeerConnectionEvent) {
        match ev {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => {
                if kps_debug() {
                    eprintln!("[kps-rtc] connection state {s}");
                }
                *self.shared.state.lock().unwrap() = s;
                let fut = self.shared.on_state.lock().unwrap().as_mut().map(|f| f(s));
                if let Some(fut) = fut {
                    fut.await;
                }
                if matches!(s, RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed) {
                    self.finish().await;
                }
            }
            RTCPeerConnectionEvent::OnDataChannel(dce) => {
                if kps_debug() {
                    eprintln!("[kps-rtc] {} dc event {dce:?}", self.io.local);
                }
                self.channel_event(dce).await;
            }
            _ => {}
        }
    }

    async fn channel_event(&mut self, dce: RTCDataChannelEvent) {
        match dce {
            RTCDataChannelEvent::OnOpen(id) => self.channel_open(id).await,
            RTCDataChannelEvent::OnClosing(id) => {
                if let Some(ch) = self.channels.get(&id) {
                    ch.inner.set_state(RTCDataChannelState::Closing);
                }
            }
            RTCDataChannelEvent::OnClose(id) => self.channel_closed(id).await,
            _ => {}
        }
    }

    async fn channel_open(&mut self, id: RTCDataChannelId) {
        if let Some(ch) = self.channels.get(&id) {
            ch.inner.set_state(RTCDataChannelState::Open);
            let f = ch.inner.on_open.lock().unwrap().take();
            if let Some(f) = f {
                f().await;
            }
        } else {
            // The peer opened it (DCEP): surface it.
            let inner = Arc::new(DcInner::new(RTCDataChannelState::Open));
            self.channels.insert(id, Channel { inner: inner.clone(), above: false });
            let Some(cmd) = self.cmd_tx.upgrade() else { return };
            let dc = Arc::new(RTCDataChannel { id, inner, cmd });
            let fut = self.shared.on_data_channel.lock().unwrap().as_mut().map(|f| f(dc));
            if let Some(fut) = fut {
                fut.await;
            }
        }
        if let Some(msgs) = self.early.remove(&id) {
            for m in msgs {
                self.deliver(id, m).await;
            }
        }
    }

    async fn channel_closed(&mut self, id: RTCDataChannelId) {
        self.early.remove(&id);
        if let Some(ch) = self.channels.remove(&id) {
            ch.inner.set_state(RTCDataChannelState::Closed);
            ch.inner.queued.store(0, Ordering::SeqCst);
            ch.inner.outstanding.store(0, Ordering::SeqCst);
            let f = ch.inner.on_close.lock().unwrap().as_mut().map(|f| f());
            if let Some(f) = f {
                f.await;
            }
            // Drop the handlers: they hold the stream/conn state (no cycles
            // outlive the channel).
            ch.inner.on_message.lock().unwrap().take();
            ch.inner.on_close.lock().unwrap().take();
            ch.inner.on_low.lock().unwrap().take();
            ch.inner.on_open.lock().unwrap().take();
        }
    }

    async fn deliver(&mut self, id: RTCDataChannelId, m: DataChannelMessage) {
        let Some(ch) = self.channels.get(&id) else {
            // Before its open event: hold it (bounded).
            let q = self.early.entry(id).or_default();
            if q.len() < 64 {
                q.push(m);
            }
            return;
        };
        let fut = ch.inner.on_message.lock().unwrap().as_mut().map(|f| f(m));
        if let Some(fut) = fut {
            fut.await;
        }
    }

    async fn command(&mut self, c: Cmd) {
        match c {
            Cmd::Create { label, init, reply } => {
                let rinit = rtc::data_channel::RTCDataChannelInit {
                    ordered: init.ordered.unwrap_or(true),
                    max_retransmits: init.max_retransmits,
                    negotiated: init.negotiated,
                    max_packet_life_time: init.max_packet_life_time,
                    ..Default::default()
                };
                let r = match self.pc.create_data_channel(&label, Some(rinit)) {
                    Ok(dc) => {
                        let id = dc.id();
                        if kps_debug() {
                            eprintln!("[kps-rtc] {} created channel {id} ({label})", self.io.local);
                        }
                        let inner = Arc::new(DcInner::new(RTCDataChannelState::Connecting));
                        self.channels.insert(id, Channel { inner: inner.clone(), above: false });
                        match self.cmd_tx.upgrade() {
                            Some(cmd) => Ok(Arc::new(RTCDataChannel { id, inner, cmd })),
                            None => Err(DriverError("peer connection closed".into())),
                        }
                    }
                    Err(e) => Err(DriverError(format!("create data channel: {e}"))),
                };
                let _ = reply.send(r);
            }
            Cmd::Send(id, data) => {
                let n = data.len();
                let outstanding = match self.pc.data_channel(id) {
                    Some(mut dc) => {
                        if let Err(e) = dc.send(Instant::now(), data) {
                            if kps_debug() {
                                eprintln!("[kps-rtc] send on {id}: {e}");
                            }
                        }
                        Some(dc.outstanding_bytes())
                    }
                    None => {
                        if kps_debug() {
                            eprintln!("[kps-rtc] send on unknown channel {id}");
                        }
                        None
                    }
                };
                // Rule 3: publish the new outstanding count before releasing
                // the queued bytes, so the buffered amount never reads 0
                // while these bytes are unacknowledged.
                if let Some(ch) = self.channels.get(&id) {
                    if let Some(out) = outstanding {
                        ch.inner.outstanding.store(out, Ordering::SeqCst);
                    }
                    ch.inner.queued.fetch_sub(n, Ordering::SeqCst);
                }
            }
            Cmd::CloseChannel(id) => {
                if let Some(mut dc) = self.pc.data_channel(id) {
                    let _ = dc.close();
                }
            }
            Cmd::SetLowThreshold(id, t) => {
                if let Some(mut dc) = self.pc.data_channel(id) {
                    dc.set_buffered_amount_low_threshold(t.min(u32::MAX as usize) as u32);
                }
            }
            Cmd::With(f) => f(&mut self.pc),
            Cmd::Close => {
                let _ = self.pc.close();
                // Send the close alerts, then report Closed.
                self.flush(self.sock_local).await;
                self.finish().await;
            }
        }
    }

    /// Terminal: mark Closed, close every channel (firing handlers), exit.
    async fn finish(&mut self) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        let prev = {
            let mut st = self.shared.state.lock().unwrap();
            let prev = *st;
            if !matches!(prev, RTCPeerConnectionState::Failed) {
                *st = RTCPeerConnectionState::Closed;
            }
            prev
        };
        if !matches!(prev, RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed) {
            let fut = self
                .shared
                .on_state
                .lock()
                .unwrap()
                .as_mut()
                .map(|f| f(RTCPeerConnectionState::Closed));
            if let Some(fut) = fut {
                fut.await;
            }
        }
        let ids: Vec<_> = self.channels.keys().copied().collect();
        for id in ids {
            self.channel_closed(id).await;
        }
        self.shared.on_data_channel.lock().unwrap().take();
        self.shared.on_state.lock().unwrap().take();
    }
}

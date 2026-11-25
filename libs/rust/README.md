# kps (Rust)

The Rust implementation of [KPS](../../README.md) — see
[`SPEC.md`](../../SPEC.md) for the protocol. Dial `ip:port:certhash`, get an
authenticated, encrypted, multiplexed connection with unnamed byte streams and
datagrams; serve both transports (QUIC + WebRTC) on one UDP port.

## Layout

- `kps/` — the library crate: `dial` (QUIC, the native default),
  `dial_webrtc` (explicit override / browser-facing listeners), `listen`
  (both transports, one port), `Identity` (persistent self-signed cert).
- `kps-server/`, `kps-dial/` — echo server / echo client binaries with the
  same flags and output contract as `libs/go`'s `cmd/server` and `cmd/dial`;
  used by the cross-implementation test harnesses.

## Quick taste

```rust
// Server: echo every stream.
let ln = kps::listen(":4242", kps::ListenOptions::default()).await?;
println!("{}", ln.address("")); // 192.168.x.y:4242:uEi...
while let Ok(conn) = ln.accept().await {
    tokio::spawn(async move {
        while let Ok(stream) = conn.accept_stream().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await; // FIN → peer sees EOF
            });
        }
    });
}
```

```rust
// Client (QUIC by default; kps::dial_webrtc for the WebRTC transport).
let conn = kps::dial("192.168.x.y:4242:uEi...").await?;
let mut stream = conn.open_stream().await?;
stream.write_all(b"hello").await?;
stream.close_write().await?;
let mut echoed = Vec::new();
stream.read_to_end(&mut echoed).await?; // "hello"
```

Timeouts/cancellation are caller-side: wrap any call in
`tokio::time::timeout` (the JS packages express the same thing through
`AbortSignal.timeout`).

## Using kps in your project

The crate is **not published to crates.io** (it depends on a patched fork of
webrtc-rs's `rtc` crates; see below). Depend on it via git:

```toml
[dependencies]
kps = { git = "https://github.com/ethereum/kps" }

# REQUIRED: kps needs the patched rtc crates below. Cargo applies [patch] ONLY
# from the root workspace manifest (a patch in a dependency does NOT propagate
# to you), so copy this block verbatim into YOUR workspace-root Cargo.toml.
# Without it kps still builds, against unpatched rtc, and hits the bugs the
# patches fix (stalled and silently dropped streams, rejected pion v5 clients).
[patch.crates-io]
rtc             = { git = "https://github.com/ethereum/kps.git", rev = "9eedaa4045d17c74ccf5d89044c60926581c0173" }
rtc-sctp        = { git = "https://github.com/ethereum/kps.git", rev = "9eedaa4045d17c74ccf5d89044c60926581c0173" }
rtc-dtls        = { git = "https://github.com/ethereum/kps.git", rev = "9eedaa4045d17c74ccf5d89044c60926581c0173" }
rtc-datachannel = { git = "https://github.com/ethereum/kps.git", rev = "9eedaa4045d17c74ccf5d89044c60926581c0173" }
```

All four lines must use the **same rev** this repo's
[`libs/rust/Cargo.toml`](Cargo.toml) pins; bump them together when you update
`kps`. This goes away once `rtc` releases the fixes (see below).

## Tests

```
cargo test --workspace
```

Unit tests cover the core (address, certhash, ICE-pwd derivation with a
Go-pinned vector, §6.2 framing); integration tests run Rust↔Rust over both
transports, including both on one port concurrently. The cross-implementation
matrix (Rust ↔ Go ↔ JS ↔ browser) lives in `libs/js/test/integration/` and
`tests/interop/`.

## The patched rtc crates (required)

The WebRTC transport runs on webrtc-rs's sans-I/O
[`rtc`](https://github.com/webrtc-rs/rtc) core. `kps` takes four of its crates
(`rtc`, `rtc-sctp`, `rtc-dtls`, `rtc-datachannel`) from branch `vendor/rtc` of
this repo via `[patch.crates-io]` in [`Cargo.toml`](Cargo.toml), pinned by rev
so builds don't float with the branch. The branch is a copy of `rtc` master
plus these commits (grep `KPS PATCH`):

| Crate | Fix | Upstream |
|-------|-----|----------|
| `rtc-dtls` | the ServerHello no longer carries `supported_groups`, a ClientHello-only extension that made pion v5 clients abort the handshake | not filed yet |
| `rtc` | a closed data channel's stream id stays reserved until SCTP finishes resetting it; otherwise the peer's late reset closed the new channel that reused the id | [rtc#311](https://github.com/webrtc-rs/rtc/issues/311) |
| `rtc-sctp` | no duplicate outgoing reset when both ends close a stream at once; the duplicate could reset a stream that reused the id | not filed yet |
| `rtc` | one unreadable stream no longer aborts the SCTP read batch, which silently dropped other channels' acknowledged messages and stalled their streams | [rtc#340](https://github.com/webrtc-rs/rtc/issues/340) |
| `rtc-sctp` | a peer's reset is no longer held open forever by data on a stream we already closed | not filed yet |
| `rtc-sctp`, `rtc-datachannel` | bounds checks for two unmarshal panics a connected peer could trigger (cherry-picked) | [rtc#333](https://github.com/webrtc-rs/rtc/pull/333) |
| `rtc-sctp` | a retransmitted reset request (our response was lost) is answered again, not performed again; performing it reset whatever stream had reused the ids | not filed yet |
| `rtc`, `rtc-sctp` | a stream id isn't reused while our reset of it is unfinished at the peer; otherwise the new channel's open landed on the peer's old stream and was lost | not filed yet |
| `rtc` | a channel open on an id still mapped to an old channel replaces it; it arrives in the same read that unregisters the old stream, and was fed to the old channel | not filed yet |
| `rtc-sctp` | a reset performed when late data arrives is answered with our own reset, as one performed on arrival is; otherwise the peer's next open on the id failed | not filed yet |
| `rtc-sctp` | retries of a partly performed reset request skip the ids already reset; they reset any stream that had reused one | not filed yet |
| `rtc-sctp` | a reset request is retransmitted until its final answer, including after In Progress and for the reset sent in answer to the peer's; a lost answer blocked the ids for good | not filed yet |

Drop the patches (and this section) once `rtc` releases equivalent fixes.

//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

#![cfg_attr(feature = "benchmark", feature(test))]

pub mod packet;

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{Packet, tcp};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tun::Tun;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB

#[derive(Clone, Copy, Debug)]
pub struct PayloadPaddingConfig {
    pub enabled: bool,
    pub max_len: u8,
}

impl Default for PayloadPaddingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_len: 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ServerHandshakeConfig {
    pub allow_syn_extensions: bool,
    pub accept_nonzero_syn_seq: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClientHandshakeConfig {
    pub realistic_syn: bool,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Bytes>>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<Tun>>,
    ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
    payload_padding: PayloadPaddingConfig,
    allow_syn_extensions: AtomicBool,
    accept_nonzero_syn_seq: AtomicBool,
    realistic_syn: AtomicBool,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    ready: mpsc::Receiver<Socket>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<Tun>,
    incoming: flume::Receiver<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    state: State,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    fn encode_payload(payload: &[u8], config: PayloadPaddingConfig) -> Bytes {
        if !config.enabled {
            return Bytes::copy_from_slice(payload);
        }

        let mut rng = SmallRng::from_os_rng();
        let padding_len = rng.random_range(1..=config.max_len);
        let padding_len_first = rng.random_range(1..=127u8);
        let padding_len_second = padding_len.wrapping_sub(padding_len_first);
        let padding_len = padding_len as usize;
        let total_len = 2 + padding_len + payload.len();
        let mut framed_payload = BytesMut::with_capacity(total_len);
        framed_payload.extend_from_slice(&[padding_len_first, padding_len_second]);

        let mut padding = vec![0u8; padding_len];
        rng.fill_bytes(&mut padding);
        framed_payload.extend_from_slice(&padding);
        framed_payload.extend_from_slice(payload);

        framed_payload.freeze()
    }

    fn decode_payload(payload: &[u8], config: PayloadPaddingConfig) -> Option<&[u8]> {
        if !config.enabled || payload.is_empty() {
            return Some(payload);
        }

        if payload.len() < 2 {
            return None;
        }

        let padding_len = payload[0].wrapping_add(payload[1]) as usize;
        let header_len = 2 + padding_len;
        if padding_len == 0 || payload.len() < header_len {
            return None;
        }

        Some(&payload[header_len..])
    }

    fn new(
        shared: Arc<Shared>,
        tun: Arc<Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);
        let initial_seq = if ack.is_none() && shared.realistic_syn.load(Ordering::Relaxed) {
            SmallRng::from_os_rng().random::<u32>()
        } else {
            0
        };

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                seq: AtomicU32::new(initial_seq),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                last_ack: AtomicU32::new(ack.unwrap_or(0)),
                state,
            },
            incoming_tx,
        )
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);
        let packet_style =
            if flags == tcp::TcpFlags::SYN && self.shared.realistic_syn.load(Ordering::Relaxed) {
                TcpPacketStyle::Realistic
            } else if payload.is_some() && self.shared.realistic_syn.load(Ordering::Relaxed) {
                TcpPacketStyle::Realistic
            } else {
                TcpPacketStyle::Minimal
            };

        build_tcp_packet_with_style(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
            packet_style,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        match self.state {
            State::Established => {
                let payload = Self::encode_payload(payload, self.shared.payload_padding);
                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload.as_ref()));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                self.tun.send(&buf).await.ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        match self.state {
            State::Established => {
                self.incoming.recv_async().await.ok().and_then(|raw_buf| {
                    let (_v4_packet, tcp_packet) = parse_ip_packet(&raw_buf).unwrap();

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    let payload = tcp_packet.payload();

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    let last_ask = self.last_ack.load(Ordering::Relaxed);
                    self.ack.store(new_ack, Ordering::Relaxed);

                    if new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN {
                        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                        if let Err(e) = self.tun.try_send(&buf) {
                            // This should not really happen as we have not sent anything for
                            // quite some time...
                            info!("Connection {} unable to send idling ACK back: {}", self, e)
                        }
                    }

                    let payload = match Self::decode_payload(payload, self.shared.payload_padding) {
                        Some(payload) => payload,
                        None => {
                            warn!("Connection {} received malformed padded payload", self);
                            return None;
                        }
                    };
                    buf[..payload.len()].copy_from_slice(payload);

                    Some(payload.len())
                })
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
                    if let Ok(buf) = res {
                        let buf = buf.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.seq.load(Ordering::Relaxed) + 1
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
                            self.state = State::Established;

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            if let Err(e) = ready.send(self).await {
                                error!("Unable to send accepted socket to ready queue: {}", e);
                            }
                            return;
                        }
                    } else {
                        info!("Waiting for client ACK timed out");
                        self.state = State::Idle;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) -> Option<()> {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return None;
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK
                                && tcp_packet.get_acknowledgement()
                                    == self.seq.load(Ordering::Relaxed) + 1
                            {
                                // found our SYN + ACK
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack
                                    .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                self.tun.send(&buf).await.unwrap();

                                self.state = State::Established;

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache
        self.shared.tuples_purge.send(tuple).unwrap();

        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
        );
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(tun: Vec<Tun>, local_ip: Ipv4Addr, local_ip6: Option<Ipv6Addr>) -> Stack {
        Self::new_with_config(tun, local_ip, local_ip6, PayloadPaddingConfig::default())
    }

    /// Create a new stack with optional payload padding support.
    pub fn new_with_config(
        tun: Vec<Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        payload_padding: PayloadPaddingConfig,
    ) -> Stack {
        let payload_padding = PayloadPaddingConfig {
            enabled: payload_padding.enabled,
            max_len: payload_padding.max_len.max(1),
        };
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
            payload_padding,
            allow_syn_extensions: AtomicBool::new(false),
            accept_nonzero_syn_seq: AtomicBool::new(false),
            realistic_syn: AtomicBool::new(false),
        });

        for t in tun {
            tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            local_ip6,
            ready: ready_rx,
        }
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    pub fn set_server_handshake_config(&self, config: ServerHandshakeConfig) {
        self.shared
            .allow_syn_extensions
            .store(config.allow_syn_extensions, Ordering::Relaxed);
        self.shared
            .accept_nonzero_syn_seq
            .store(config.accept_nonzero_syn_seq, Ordering::Relaxed);
    }

    pub fn set_client_handshake_config(&self, config: ClientHandshakeConfig) {
        self.shared
            .realistic_syn
            .store(config.realistic_syn, Ordering::Relaxed);
    }

    /// Accepts an incoming connection.
    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    /// Connects to the remote end. `None` returned means
    /// the connection attempt failed.
    pub async fn connect(&mut self, addr: SocketAddr) -> Option<Socket> {
        let mut rng = SmallRng::from_os_rng();
        for local_port in rng.random_range(32768..=60999)..=60999 {
            let local_addr = SocketAddr::new(
                if addr.is_ipv4() {
                    IpAddr::V4(self.local_ip)
                } else {
                    IpAddr::V6(self.local_ip6.expect("IPv6 local address undefined"))
                },
                local_port,
            );
            let tuple = AddrTuple::new(local_addr, addr);
            let mut sock;

            {
                let mut tuples = self.shared.tuples.write().unwrap();
                if tuples.contains_key(&tuple) {
                    trace!(
                        "Fake TCP connection to {}, local port number {} already in use, trying another one",
                        addr, local_port
                    );
                    continue;
                }

                let incoming;
                (sock, incoming) = Socket::new(
                    self.shared.clone(),
                    self.shared.tun.choose(&mut rng).unwrap().clone(),
                    local_addr,
                    addr,
                    None,
                    State::Idle,
                );

                assert!(tuples.insert(tuple, incoming).is_none());
            }

            return sock.connect().await.map(|_| sock);
        }

        error!(
            "Fake TCP connection to {} failed, emphemeral port number exhausted",
            addr
        );
        None
    }

    async fn reader_task(
        tun: Arc<Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::zeroed(MAX_PACKET_LEN);

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = size.unwrap();
                    buf.truncate(size);
                    let buf = buf.freeze();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(buf).await.is_err() {
                                    trace!("Cache hit, but receiver already closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    c.send_async(buf).await.unwrap();
                                    continue;
                                }
                            }

                            if is_server_syn(
                                tcp_packet.get_flags(),
                                shared.allow_syn_extensions.load(Ordering::Relaxed),
                            )
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                // SYN seen on listening socket
                                if shared.accept_nonzero_syn_seq.load(Ordering::Relaxed)
                                    || tcp_packet.get_sequence() == 0
                                {
                                    let (sock, incoming) = Socket::new(
                                        shared.clone(),
                                        tun.clone(),
                                        local_addr,
                                        remote_addr,
                                        Some(tcp_packet.get_sequence().wrapping_add(1)),
                                        State::Idle,
                                    );
                                    assert!(shared
                                        .tuples
                                        .write()
                                        .unwrap()
                                        .insert(tuple, incoming)
                                        .is_none());
                                    tokio::spawn(sock.accept());
                                } else {
                                    trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                                    let buf = build_tcp_packet(
                                        local_addr,
                                        remote_addr,
                                        0,
                                        tcp_packet.get_sequence() + tcp_packet.payload().len() as u32 + 1, // +1 because of SYN flag set
                                        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                        None,
                                    );
                                    shared.tun[0].try_send(&buf).unwrap();
                                }
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    tcp_packet.get_acknowledgement(),
                                    tcp_packet.get_sequence() + tcp_packet.payload().len() as u32,
                                    tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                    None,
                                );
                                shared.tun[0].try_send(&buf).unwrap();
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    let tuple = tuple.unwrap();
                    tuples.remove(&tuple);
                    trace!("Removed cached tuple: {:?}", tuple);
                }
            }
        }
    }
}

fn is_server_syn(flags: u8, allow_syn_extensions: bool) -> bool {
    if !allow_syn_extensions {
        return flags == tcp::TcpFlags::SYN;
    }

    (flags & tcp::TcpFlags::SYN) != 0
        && (flags & (tcp::TcpFlags::ACK | tcp::TcpFlags::FIN | tcp::TcpFlags::RST)) == 0
}

#[cfg(test)]
mod tests {
    use super::{
        ClientHandshakeConfig, PayloadPaddingConfig, ServerHandshakeConfig, Socket, is_server_syn,
    };
    use crate::packet::{TcpPacketStyle, build_tcp_packet_with_style, parse_ip_packet};
    use pnet::packet::Packet;
    use pnet::packet::tcp;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn decode_payload_returns_original_when_padding_disabled() {
        let payload = [1u8, 2, 3, 4];
        let config = PayloadPaddingConfig {
            enabled: false,
            max_len: 5,
        };

        assert_eq!(Socket::decode_payload(&payload, config).unwrap(), &payload);
    }

    #[test]
    fn decode_payload_strips_padding_frame() {
        let payload = b"hello";
        let mut framed = Vec::new();
        framed.extend_from_slice(&[1, 2]);
        framed.extend_from_slice(&[9, 8, 7]);
        framed.extend_from_slice(payload);

        let config = PayloadPaddingConfig {
            enabled: true,
            max_len: 5,
        };

        assert_eq!(Socket::decode_payload(&framed, config).unwrap(), payload);
    }

    #[test]
    fn decode_payload_rejects_invalid_padding_frame() {
        let framed = [1u8, 2, 9];
        let config = PayloadPaddingConfig {
            enabled: true,
            max_len: 5,
        };

        assert!(Socket::decode_payload(&framed, config).is_none());
    }

    #[test]
    fn encode_payload_without_padding_is_passthrough() {
        let payload = b"hello";
        let config = PayloadPaddingConfig {
            enabled: false,
            max_len: 5,
        };

        let encoded = Socket::encode_payload(payload, config);
        assert_eq!(encoded.as_ref(), payload);
    }

    #[test]
    fn encode_payload_with_padding_uses_two_byte_sum_header() {
        let payload = b"hello";
        let config = PayloadPaddingConfig {
            enabled: true,
            max_len: 5,
        };

        let encoded = Socket::encode_payload(payload, config);
        let padding_len = encoded[0].wrapping_add(encoded[1]) as usize;

        assert!((1..=5).contains(&padding_len));
        assert_eq!(encoded.len(), 2 + padding_len + payload.len());
        assert_eq!(&encoded[2 + padding_len..], payload);
    }

    #[test]
    fn server_handshake_config_defaults_disabled() {
        let config = ServerHandshakeConfig::default();
        assert!(!config.allow_syn_extensions);
        assert!(!config.accept_nonzero_syn_seq);
    }

    #[test]
    fn client_handshake_config_defaults_disabled() {
        let config = ClientHandshakeConfig::default();
        assert!(!config.realistic_syn);
    }

    #[test]
    fn strict_server_syn_matching_only_accepts_plain_syn() {
        assert!(is_server_syn(tcp::TcpFlags::SYN, false));
        assert!(!is_server_syn(
            tcp::TcpFlags::SYN | tcp::TcpFlags::ECE | tcp::TcpFlags::CWR,
            false,
        ));
    }

    #[test]
    fn relaxed_server_syn_matching_accepts_ecn_syn() {
        assert!(is_server_syn(
            tcp::TcpFlags::SYN | tcp::TcpFlags::ECE | tcp::TcpFlags::CWR,
            true,
        ));
        assert!(!is_server_syn(
            tcp::TcpFlags::SYN | tcp::TcpFlags::ACK,
            true,
        ));
        assert!(!is_server_syn(
            tcp::TcpFlags::SYN | tcp::TcpFlags::FIN,
            true,
        ));
        assert!(!is_server_syn(
            tcp::TcpFlags::SYN | tcp::TcpFlags::RST,
            true,
        ));
    }

    #[test]
    fn realistic_syn_builder_adds_common_extensions() {
        let local = SocketAddrV4::new(Ipv4Addr::new(192, 168, 200, 2), 40000);
        let remote = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 9280);
        let packet = build_tcp_packet_with_style(
            local.into(),
            remote.into(),
            42,
            0,
            tcp::TcpFlags::SYN,
            None,
            TcpPacketStyle::Realistic,
        );
        let (_, tcp_packet) = parse_ip_packet(&packet).unwrap();
        let options = tcp_packet.get_options();

        assert_eq!(
            tcp_packet.get_flags(),
            tcp::TcpFlags::SYN | tcp::TcpFlags::ECE | tcp::TcpFlags::CWR
        );
        assert_eq!(tcp_packet.packet().len(), 40);
        assert_eq!(options.len(), 5);
    }

    #[test]
    fn realistic_payload_packets_use_psh_ack() {
        let local = SocketAddrV4::new(Ipv4Addr::new(192, 168, 200, 2), 40000);
        let remote = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 9280);
        let packet = build_tcp_packet_with_style(
            local.into(),
            remote.into(),
            42,
            99,
            tcp::TcpFlags::ACK,
            Some(b"hello"),
            TcpPacketStyle::Realistic,
        );
        let (_, tcp_packet) = parse_ip_packet(&packet).unwrap();

        assert_eq!(
            tcp_packet.get_flags(),
            tcp::TcpFlags::ACK | tcp::TcpFlags::PSH
        );
    }
}

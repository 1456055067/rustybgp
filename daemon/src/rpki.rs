// Copyright (C) 2024 The RustyBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

use fnv::{FnvHashMap, FnvHashSet};
use futures::{SinkExt, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::codec::{Encoder, Framed};
use tokio_util::sync::CancellationToken;

use rustybgp_packet::rpki::error_code;
use rustybgp_packet::{self as packet, rpki};
use rustybgp_table as table;

use crate::error::Error;
use crate::event::TableHandle;

#[derive(Default)]
pub(crate) struct RpkiState {
    pub(crate) uptime: AtomicU64,
    pub(crate) downtime: AtomicU64,
    pub(crate) up: AtomicBool,
    session_id: AtomicU16,
    pub(crate) serial: AtomicU32,
    pub(crate) received_ipv4: AtomicI64,
    pub(crate) received_ipv6: AtomicI64,
    pub(crate) serial_notify: AtomicI64,
    pub(crate) cache_reset: AtomicI64,
    pub(crate) cache_response: AtomicI64,
    pub(crate) end_of_data: AtomicI64,
    pub(crate) error: AtomicI64,
    pub(crate) serial_query: AtomicI64,
    pub(crate) reset_query: AtomicI64,
}

impl RpkiState {
    fn update(&self, msg: &rpki::Message) {
        match msg {
            rpki::Message::SerialNotify { .. } => {
                self.serial_notify.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::SerialQuery { .. } => {
                let _ = self.serial_query.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::ResetQuery => {
                let _ = self.reset_query.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::CacheResponse { .. } => {
                let _ = self.cache_response.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::IpPrefix(prefix) => match prefix.net {
                packet::IpNet::V4(_) => {
                    let _ = self.received_ipv4.fetch_add(1, Ordering::Relaxed);
                }
                packet::IpNet::V6(_) => {
                    let _ = self.received_ipv6.fetch_add(1, Ordering::Relaxed);
                }
            },
            rpki::Message::EndOfData { .. } => {
                let _ = self.end_of_data.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::CacheReset => {
                let _ = self.cache_reset.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::ErrorReport { .. } => {
                let _ = self.error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Timing parameters of a cache (RFC 8210 section 6).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Timers {
    /// Interval between Serial Queries while the session is up.
    refresh: Duration,
    /// Delay before retrying a failed query or connection.
    retry: Duration,
    /// How long data may be used without a successful update.
    expire: Duration,
}

impl Timers {
    /// (minimum, default, maximum) in seconds, from RFC 8210 section 6.
    const REFRESH: (u32, u32, u32) = (1, 3600, 86400);
    const RETRY: (u32, u32, u32) = (1, 600, 7200);
    const EXPIRE: (u32, u32, u32) = (600, 7200, 172800);
    /// Retry delay until a version 1 cache supplies one. Shorter than the
    /// RFC default so that a cache that is restarting is picked up quickly.
    const INITIAL_RETRY: Duration = Duration::from_secs(10);

    fn interval(value: u32, (min, default, max): (u32, u32, u32)) -> Duration {
        let v = if (min..=max).contains(&value) {
            value
        } else {
            default
        };
        Duration::from_secs(v as u64)
    }

    /// Timers announced in an End of Data PDU. Version 0 End of Data
    /// carries none, so the defaults apply. Values outside the ranges of
    /// RFC 8210 section 6 are replaced by the defaults.
    fn from_end_of_data(version: u8, refresh: u32, retry: u32, expire: u32) -> Self {
        if version == 0 {
            return Timers {
                retry: Self::INITIAL_RETRY,
                ..Timers::default()
            };
        }
        let mut t = Timers {
            refresh: Self::interval(refresh, Self::REFRESH),
            retry: Self::interval(retry, Self::RETRY),
            expire: Self::interval(expire, Self::EXPIRE),
        };
        // The Expire Interval must exceed both other intervals.
        if t.expire <= t.refresh.max(t.retry) {
            t.expire = Duration::from_secs(Self::EXPIRE.1 as u64).max(t.refresh.max(t.retry) * 2);
        }
        t
    }
}

impl Default for Timers {
    fn default() -> Self {
        Timers {
            refresh: Duration::from_secs(Self::REFRESH.1 as u64),
            retry: Self::INITIAL_RETRY,
            expire: Duration::from_secs(Self::EXPIRE.1 as u64),
        }
    }
}

/// A ROA as carried in an IP Prefix PDU, with the host bits of the prefix
/// cleared.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct RoaKey {
    addr: IpAddr,
    len: u8,
    max_length: u8,
    asn: u32,
}

impl RoaKey {
    fn new(prefix: &rpki::Prefix) -> Self {
        let (addr, len) = match &prefix.net {
            packet::IpNet::V4(n) => {
                let mask = u32::MAX.checked_shl(32 - n.mask as u32).unwrap_or(0);
                (
                    IpAddr::from((u32::from(n.addr) & mask).to_be_bytes()),
                    n.mask,
                )
            }
            packet::IpNet::V6(n) => {
                let mask = u128::MAX.checked_shl(128 - n.mask as u32).unwrap_or(0);
                (
                    IpAddr::from((u128::from(n.addr) & mask).to_be_bytes()),
                    n.mask,
                )
            }
        };
        RoaKey {
            addr,
            len,
            max_length: prefix.max_length,
            asn: prefix.as_number,
        }
    }

    fn entry(&self, source: &Arc<IpAddr>) -> (packet::IpNet, Arc<table::Roa>) {
        (
            packet::IpNet::new(self.addr, self.len),
            Arc::new(table::Roa::new(self.max_length, self.asn, source.clone())),
        )
    }
}

/// What the router keeps about one cache across connections.
pub(crate) struct Cache {
    /// Source tag of the ROAs from this cache in the shared ROA table.
    source: Arc<IpAddr>,
    /// The ROAs from this cache currently in the ROA table.
    roas: FnvHashSet<RoaKey>,
    /// Session ID and serial number of `roas`, when they can be brought up
    /// to date with a Serial Query. `None` makes the next query a Reset
    /// Query.
    session: Option<(u16, u32)>,
    /// Protocol version to speak (RFC 8210 section 7).
    version: u8,
    timers: Timers,
    /// When `roas` must be discarded unless refreshed before.
    expire_at: Option<Instant>,
}

impl Cache {
    pub(crate) fn new(source: Arc<IpAddr>) -> Self {
        Cache {
            source,
            roas: FnvHashSet::default(),
            session: None,
            version: rpki::Message::MAX_VERSION,
            timers: Timers::default(),
            expire_at: None,
        }
    }

    /// Discards all data learned from this cache.
    async fn drop_data(&mut self, tables: &TableHandle) {
        self.session = None;
        self.expire_at = None;
        if self.roas.is_empty() {
            return;
        }
        self.roas.clear();
        let tables = tables.clone();
        let source = self.source.clone();
        let _ = tokio::task::spawn_blocking(move || tables.rpki_drop_all(source)).await;
    }

    /// Replaces or updates this cache's ROAs at End of Data and pushes the
    /// difference to the ROA table, which re-validates affected routes.
    async fn apply(
        &mut self,
        query: Query,
        pending: FnvHashMap<RoaKey, bool>,
        tables: &TableHandle,
    ) {
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        if query == Query::Reset {
            // The response is the cache's complete data set.
            for k in self.roas.iter() {
                if pending.get(k) != Some(&true) {
                    withdraw.push(*k);
                }
            }
        }
        for (k, present) in pending {
            if present && !self.roas.contains(&k) {
                announce.push(k);
            } else if !present && query == Query::Serial && self.roas.contains(&k) {
                withdraw.push(k);
            }
        }
        if announce.is_empty() && withdraw.is_empty() {
            return;
        }
        for k in &withdraw {
            self.roas.remove(k);
        }
        self.roas.extend(announce.iter().copied());
        let announce: Vec<_> = announce.iter().map(|k| k.entry(&self.source)).collect();
        let withdraw: Vec<_> = withdraw.iter().map(|k| k.entry(&self.source)).collect();
        let tables = tables.clone();
        let _ = tokio::task::spawn_blocking(move || tables.rpki_apply(announce, withdraw)).await;
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Query {
    Reset,
    Serial,
}

/// A Cache Response being received.
struct Response {
    query: Query,
    session_id: u16,
    /// Final presence of each ROA announced or withdrawn so far.
    pending: FnvHashMap<RoaKey, bool>,
}

/// The connection to the cache must be closed.
struct Close;

/// One connection to a cache.
struct Session<'a, IO> {
    lines: Framed<IO, rpki::RtrCodec>,
    cache: &'a mut Cache,
    state: &'a RpkiState,
    tables: &'a TableHandle,
    /// Query awaiting its response.
    query: Option<Query>,
    response: Option<Response>,
    /// When to send the next query (Refresh or Retry Interval).
    next_query: Option<Instant>,
    /// Whether the cache's protocol version has been seen.
    negotiated: bool,
}

impl<IO> Session<'_, IO>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    async fn send(&mut self, msg: &rpki::Message) -> Result<(), Close> {
        if !matches!(msg, rpki::Message::ErrorReport { .. }) {
            self.state.update(msg);
        }
        self.lines.send(msg).await.map_err(|_| Close)
    }

    /// Sends a Serial Query when the data can be updated incrementally,
    /// a Reset Query otherwise.
    async fn send_query(&mut self) -> Result<(), Close> {
        self.response = None;
        self.next_query = None;
        match self.cache.session {
            Some((session_id, serial_number)) => {
                self.query = Some(Query::Serial);
                self.send(&rpki::Message::SerialQuery {
                    session_id,
                    serial_number,
                })
                .await
            }
            None => {
                self.query = Some(Query::Reset);
                self.send(&rpki::Message::ResetQuery).await
            }
        }
    }

    /// Sends an Error Report for `msg` and closes the connection. The data
    /// is kept, but resynchronized with a Reset Query on reconnect.
    async fn fail(&mut self, code: u16, msg: &rpki::Message, text: String) -> Result<(), Close> {
        log::warn!(
            "rpki: sending {} to {}: {}",
            error_code::name(code),
            self.cache.source,
            text
        );
        let mut pdu = bytes::BytesMut::new();
        let version = self
            .lines
            .codec()
            .last_version()
            .unwrap_or(self.cache.version);
        let _ = rpki::RtrCodec::with_version(version).encode(msg, &mut pdu);
        let _ = self
            .send(&rpki::Message::ErrorReport {
                error_code: code,
                pdu: pdu.to_vec(),
                text,
            })
            .await;
        self.cache.session = None;
        Err(Close)
    }

    /// The cache's session ID changed: it lost or replaced its state, so
    /// flush everything learned from it and start over (RFC 8210 section
    /// 5.1).
    async fn flush_and_reset(&mut self, session_id: u16) -> Result<(), Close> {
        log::info!(
            "rpki: session ID of {} changed to {}, flushing its data",
            self.cache.source,
            session_id
        );
        self.cache.drop_data(self.tables).await;
        self.send_query().await
    }

    /// Switches to a lower protocol version (RFC 8210 section 7).
    fn downgrade(&mut self, version: u8) {
        log::info!(
            "rpki: {} speaks version {}, downgrading from {}",
            self.cache.source,
            version,
            self.cache.version
        );
        self.cache.version = version;
        self.lines.codec_mut().set_version(version);
    }

    async fn on_expire(&mut self) -> Result<(), Close> {
        log::warn!(
            "rpki: data from {} expired without an update",
            self.cache.source
        );
        self.cache.drop_data(self.tables).await;
        if self.query.is_none() {
            self.send_query().await?;
        }
        Ok(())
    }

    async fn on_message(&mut self, msg: rpki::Message) -> Result<(), Close> {
        self.state.update(&msg);
        let version = self
            .lines
            .codec()
            .last_version()
            .unwrap_or(self.cache.version);
        if let rpki::Message::ErrorReport {
            error_code,
            text,
            pdu: _,
        } = &msg
        {
            return self.on_error_report(version, *error_code, text).await;
        }
        if !self.negotiated {
            self.negotiated = true;
            if version < self.cache.version {
                self.downgrade(version);
            }
        }
        if version != self.cache.version {
            return self
                .fail(
                    error_code::UNEXPECTED_PROTOCOL_VERSION,
                    &msg,
                    format!(
                        "version {} PDU in a version {} session",
                        version, self.cache.version
                    ),
                )
                .await;
        }
        match msg {
            rpki::Message::SerialNotify {
                session_id,
                serial_number,
            } => match self.cache.session {
                Some((sid, _)) if sid != session_id => self.flush_and_reset(session_id).await,
                Some((_, serial)) if serial != serial_number && self.query.is_none() => {
                    self.send_query().await
                }
                _ => Ok(()),
            },
            rpki::Message::CacheResponse { session_id } => {
                let Some(query) = self.query else {
                    log::warn!(
                        "rpki: unsolicited Cache Response from {}",
                        self.cache.source
                    );
                    return Ok(());
                };
                if query == Query::Serial && self.cache.session.map(|s| s.0) != Some(session_id) {
                    return self.flush_and_reset(session_id).await;
                }
                self.response = Some(Response {
                    query,
                    session_id,
                    pending: FnvHashMap::default(),
                });
                Ok(())
            }
            rpki::Message::IpPrefix(ref prefix) => {
                let key = RoaKey::new(prefix);
                let announce = prefix.flags & 1 != 0;
                let Some(response) = self.response.as_mut() else {
                    log::warn!(
                        "rpki: IP Prefix outside a Cache Response from {}",
                        self.cache.source
                    );
                    return Ok(());
                };
                let present =
                    response.pending.get(&key).copied().unwrap_or(
                        response.query == Query::Serial && self.cache.roas.contains(&key),
                    );
                // RFC 8210 section 5.6: announcing a record the router
                // already has or withdrawing one it does not have is an
                // error.
                if announce && present {
                    return self
                        .fail(
                            error_code::DUPLICATE_ANNOUNCEMENT_RECEIVED,
                            &msg,
                            "duplicate announcement".to_string(),
                        )
                        .await;
                }
                if !announce && !present {
                    return self
                        .fail(
                            error_code::WITHDRAWAL_OF_UNKNOWN_RECORD,
                            &msg,
                            "withdrawal of unknown record".to_string(),
                        )
                        .await;
                }
                response.pending.insert(key, announce);
                Ok(())
            }
            rpki::Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                let Some(response) = self.response.take() else {
                    log::warn!(
                        "rpki: End of Data outside a Cache Response from {}",
                        self.cache.source
                    );
                    return Ok(());
                };
                if response.session_id != session_id {
                    return self.flush_and_reset(session_id).await;
                }
                self.cache
                    .apply(response.query, response.pending, self.tables)
                    .await;
                self.cache.session = Some((session_id, serial_number));
                self.cache.timers = Timers::from_end_of_data(
                    version,
                    refresh_interval,
                    retry_interval,
                    expire_interval,
                );
                let now = Instant::now();
                self.cache.expire_at = Some(now + self.cache.timers.expire);
                self.query = None;
                self.next_query = Some(now + self.cache.timers.refresh);
                self.state.session_id.store(session_id, Ordering::Relaxed);
                self.state.serial.store(serial_number, Ordering::Relaxed);
                Ok(())
            }
            rpki::Message::CacheReset => {
                // The cache cannot answer the Serial Query incrementally
                // (RFC 8210 section 5.9): fetch everything. The current data
                // is kept until the new set is complete.
                if self.query == Some(Query::Reset) {
                    log::warn!(
                        "rpki: Cache Reset in reply to Reset Query from {}",
                        self.cache.source
                    );
                    self.query = None;
                    self.response = None;
                    self.next_query = Some(Instant::now() + self.cache.timers.retry);
                    return Ok(());
                }
                self.cache.session = None;
                self.send_query().await
            }
            rpki::Message::SerialQuery { .. } | rpki::Message::ResetQuery => {
                self.fail(
                    error_code::UNSUPPORTED_PDU_TYPE,
                    &msg,
                    "router-to-cache PDU received".to_string(),
                )
                .await
            }
            rpki::Message::ErrorReport { .. } => unreachable!(),
        }
    }

    async fn on_error_report(&mut self, version: u8, code: u16, text: &str) -> Result<(), Close> {
        log::warn!(
            "rpki: {} reported {} ({}): {}",
            self.cache.source,
            error_code::name(code),
            code,
            text
        );
        match code {
            // Not fatal: ask again after the Retry Interval.
            error_code::NO_DATA_AVAILABLE => {
                self.query = None;
                self.response = None;
                self.next_query = Some(Instant::now() + self.cache.timers.retry);
                Ok(())
            }
            error_code::UNSUPPORTED_PROTOCOL_VERSION if self.cache.version > 0 => {
                self.downgrade(version.min(self.cache.version - 1));
                self.send_query().await
            }
            _ => {
                self.cache.session = None;
                Err(Close)
            }
        }
    }
}

pub(crate) struct RpkiClient {
    pub(crate) cancel: CancellationToken,
    pub(crate) state: Arc<RpkiState>,
    pub(crate) disabled: bool,
    pub(crate) soft_reset: Arc<Notify>,
}

impl RpkiClient {
    pub(crate) fn new() -> Self {
        RpkiClient {
            cancel: CancellationToken::new(),
            state: Arc::new(RpkiState::default()),
            disabled: false,
            soft_reset: Arc::new(Notify::new()),
        }
    }

    async fn serve(
        stream: TcpStream,
        cache: &mut Cache,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let lines = Framed::new(stream, rpki::RtrCodec::new());
        Self::serve_inner(lines, cache, cancel, soft_reset, state, tables).await
    }

    async fn serve_inner<IO>(
        mut lines: Framed<IO, rpki::RtrCodec>,
        cache: &mut Cache,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) -> Result<(), Error>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        lines.codec_mut().set_version(cache.version);
        let mut s = Session {
            lines,
            cache,
            state: &state,
            tables: &tables,
            query: None,
            response: None,
            next_query: None,
            negotiated: false,
        };
        state.uptime.store(unix_now(), Ordering::Relaxed);
        state.up.store(true, Ordering::Relaxed);
        // On reconnect, data still held is brought up to date with a Serial
        // Query; the cache answers Cache Reset if it cannot.
        let mut r = s.send_query().await;
        while r.is_ok() {
            let next_query = s.next_query;
            let expire_at = s.cache.expire_at;
            r = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = soft_reset.notified(), if s.cache.session.is_some() && s.query.is_none() => {
                    s.send_query().await
                }
                _ = sleep_until(next_query), if next_query.is_some() => {
                    s.send_query().await
                }
                _ = sleep_until(expire_at), if expire_at.is_some() => s.on_expire().await,
                msg = s.lines.next() => match msg {
                    Some(Ok(msg)) => s.on_message(msg).await,
                    Some(Err(e)) => {
                        log::warn!("rpki: bad PDU from {}: {}", s.cache.source, e);
                        if let Some(report) = e.report() {
                            let _ = s.send(&report).await;
                        }
                        s.cache.session = None;
                        Err(Close)
                    }
                    None => break,
                },
            };
        }
        state.up.store(false, Ordering::Relaxed);
        state.downtime.store(unix_now(), Ordering::Relaxed);
        Ok(())
    }

    /// Connects to the cache at `sockaddr` and keeps its data synchronized
    /// until `cancel` fires. Data survives disconnects until its Expire
    /// Interval passes (RFC 8210 section 6); reconnects are spaced by the
    /// Retry Interval.
    pub(crate) fn try_connect(
        sockaddr: SocketAddr,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) {
        tokio::spawn(async move {
            let mut cache = Cache::new(Arc::new(sockaddr.ip()));
            Self::run(sockaddr, &mut cache, &cancel, &soft_reset, &state, &tables).await;
            // The client was removed: forget what it learned.
            cache.drop_data(&tables).await;
        });
    }

    async fn run(
        sockaddr: SocketAddr,
        cache: &mut Cache,
        cancel: &CancellationToken,
        soft_reset: &Arc<Notify>,
        state: &Arc<RpkiState>,
        tables: &TableHandle,
    ) {
        loop {
            let stream = tokio::select! {
                r = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(sockaddr)) => {
                    r.ok().and_then(|r| r.ok())
                }
                _ = cancel.cancelled() => return,
            };
            if let Some(stream) = stream {
                let _ = Self::serve(
                    stream,
                    cache,
                    cancel.clone(),
                    soft_reset.clone(),
                    state.clone(),
                    tables.clone(),
                )
                .await;
                if cancel.is_cancelled() {
                    return;
                }
            }
            let retry_at = Instant::now() + cache.timers.retry;
            loop {
                let expire_at = cache.expire_at;
                tokio::select! {
                    _ = tokio::time::sleep_until(retry_at) => break,
                    _ = sleep_until(expire_at), if expire_at.is_some() => {
                        log::warn!("rpki: data from {} expired while disconnected", cache.source);
                        cache.drop_data(tables).await;
                    }
                    _ = cancel.cancelled() => return,
                }
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sleeps until `at`; never completes for `None` (callers guard on it).
async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use rustybgp_packet::Family;
    use std::net::Ipv4Addr;
    use tokio::io::DuplexStream;
    use tokio_util::codec::Framed;

    use crate::table_manager::TableManager;

    type Server = Framed<DuplexStream, rpki::RtrCodec>;

    struct Harness {
        server: Server,
        state: Arc<RpkiState>,
        tables: TableHandle,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
        handle: tokio::task::JoinHandle<Cache>,
    }

    fn source() -> Arc<IpAddr> {
        Arc::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
    }

    /// Runs the client against an in-memory cache speaking `version`.
    fn start(cache: Cache, tables: TableHandle, version: u8) -> Harness {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());
        let handle = {
            let (state, cancel, soft_reset, tables) = (
                state.clone(),
                cancel.clone(),
                soft_reset.clone(),
                tables.clone(),
            );
            tokio::spawn(async move {
                let mut cache = cache;
                let framed = Framed::new(client_io, rpki::RtrCodec::new());
                RpkiClient::serve_inner(framed, &mut cache, cancel, soft_reset, state, tables)
                    .await
                    .unwrap();
                cache
            })
        };
        Harness {
            server: Framed::new(server_io, rpki::RtrCodec::with_version(version)),
            state,
            tables,
            cancel,
            soft_reset,
            handle,
        }
    }

    fn start_new() -> Harness {
        start(Cache::new(source()), Arc::new(TableManager::new(1)), 1)
    }

    impl Harness {
        async fn recv(&mut self) -> rpki::Message {
            self.server.next().await.unwrap().unwrap()
        }

        async fn send(&mut self, msg: rpki::Message) {
            self.server.send(&msg).await.unwrap();
        }

        async fn send_all(&mut self, msgs: Vec<rpki::Message>) {
            for m in msgs {
                self.send(m).await;
            }
        }

        /// Answers the client's Reset Query with `prefixes` and waits until
        /// the data is installed.
        async fn initial_sync(
            &mut self,
            session_id: u16,
            serial: u32,
            prefixes: &[(&str, u8, u32)],
        ) {
            assert!(matches!(self.recv().await, rpki::Message::ResetQuery));
            let mut msgs = vec![rpki::Message::CacheResponse { session_id }];
            msgs.extend(prefixes.iter().map(|p| announce(p.0, p.1, p.2)));
            msgs.push(end_of_data(session_id, serial));
            self.send_all(msgs).await;
            self.wait_serial(serial).await;
        }

        async fn wait_serial(&self, serial: u32) {
            wait_for(|| self.state.serial.load(Ordering::Relaxed) == serial).await;
        }

        fn roas(&self) -> Vec<String> {
            roas(&self.tables)
        }

        async fn stop(self) -> Cache {
            self.cancel.cancel();
            self.handle.await.unwrap()
        }
    }

    fn roas(tables: &TableHandle) -> Vec<String> {
        let mut v: Vec<String> = [Family::IPV4, Family::IPV6]
            .into_iter()
            .flat_map(|f| tables.collect_roa(f))
            .map(|(net, roa)| format!("{} {} AS{}", net, roa.max_length, roa.as_number))
            .collect();
        v.sort();
        v
    }

    async fn wait_for(f: impl Fn() -> bool) {
        for _ in 0..1000 {
            if f() {
                return;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("condition not reached");
    }

    fn prefix(p: &str, max_length: u8, asn: u32, flags: u8) -> rpki::Message {
        let (addr, len) = p.split_once('/').unwrap();
        rpki::Message::IpPrefix(rpki::Prefix {
            net: packet::IpNet::new(addr.parse().unwrap(), len.parse().unwrap()),
            flags,
            max_length,
            as_number: asn,
        })
    }

    fn announce(p: &str, max_length: u8, asn: u32) -> rpki::Message {
        prefix(p, max_length, asn, 1)
    }

    fn withdraw(p: &str, max_length: u8, asn: u32) -> rpki::Message {
        prefix(p, max_length, asn, 0)
    }

    fn end_of_data(session_id: u16, serial_number: u32) -> rpki::Message {
        end_of_data_timers(session_id, serial_number, 3600, 600, 7200)
    }

    fn end_of_data_timers(
        session_id: u16,
        serial_number: u32,
        refresh_interval: u32,
        retry_interval: u32,
        expire_interval: u32,
    ) -> rpki::Message {
        rpki::Message::EndOfData {
            session_id,
            serial_number,
            refresh_interval,
            retry_interval,
            expire_interval,
        }
    }

    fn expect_serial_query(msg: rpki::Message, session: u16, serial: u32) {
        match msg {
            rpki::Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                assert_eq!((session_id, serial_number), (session, serial));
            }
            _ => panic!("expected SerialQuery"),
        }
    }

    fn expect_error(msg: rpki::Message, code: u16) -> Vec<u8> {
        match msg {
            rpki::Message::ErrorReport {
                error_code, pdu, ..
            } => {
                assert_eq!(error_code, code);
                pdu
            }
            _ => panic!("expected ErrorReport"),
        }
    }

    #[tokio::test]
    async fn sends_reset_query_on_connect() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert_eq!(h.server.codec().last_version(), Some(1));
        h.stop().await;
    }

    #[tokio::test]
    async fn reset_sync_installs_data_at_end_of_data() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 42 },
            announce("10.0.0.0/16", 24, 65001),
            announce("2001:db8::/32", 48, 65002),
        ])
        .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Nothing is used before End of Data.
        assert!(h.roas().is_empty());
        h.send(end_of_data(42, 7)).await;
        h.wait_serial(7).await;
        assert_eq!(
            h.roas(),
            ["10.0.0.0/16 24 AS65001", "2001:db8::/32 48 AS65002"]
        );
        assert_eq!(h.state.session_id.load(Ordering::Relaxed), 42);
        let cache = h.stop().await;
        assert_eq!(cache.session, Some((42, 7)));
        assert_eq!(cache.timers.refresh, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn serial_notify_fetches_incremental_update() {
        let mut h = start_new();
        h.initial_sync(
            1,
            10,
            &[("10.0.0.0/16", 24, 65001), ("10.1.0.0/16", 16, 65001)],
        )
        .await;
        h.send(rpki::Message::SerialNotify {
            session_id: 1,
            serial_number: 11,
        })
        .await;
        expect_serial_query(h.recv().await, 1, 10);
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 1 },
            withdraw("10.1.0.0/16", 16, 65001),
            announce("10.2.0.0/16", 24, 65003),
            end_of_data(1, 11),
        ])
        .await;
        h.wait_serial(11).await;
        assert_eq!(
            h.roas(),
            ["10.0.0.0/16 24 AS65001", "10.2.0.0/16 24 AS65003"]
        );
        // A Serial Notify for the serial already held is ignored.
        h.send(rpki::Message::SerialNotify {
            session_id: 1,
            serial_number: 11,
        })
        .await;
        h.soft_reset.notify_one();
        expect_serial_query(h.recv().await, 1, 11);
        h.stop().await;
    }

    #[tokio::test]
    async fn cache_reset_triggers_reset_query_and_replaces_data() {
        let mut h = start_new();
        h.initial_sync(
            1,
            10,
            &[("10.0.0.0/16", 24, 65001), ("10.1.0.0/16", 16, 65001)],
        )
        .await;
        h.soft_reset.notify_one();
        expect_serial_query(h.recv().await, 1, 10);
        h.send(rpki::Message::CacheReset).await;
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        // The old data stays in use while the new set is transferred.
        assert_eq!(h.roas().len(), 2);
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 1 },
            announce("10.0.0.0/16", 24, 65001),
            announce("10.3.0.0/16", 16, 65001),
            end_of_data(1, 20),
        ])
        .await;
        h.wait_serial(20).await;
        // 10.1.0.0/16 was not in the new set and is withdrawn.
        assert_eq!(
            h.roas(),
            ["10.0.0.0/16 24 AS65001", "10.3.0.0/16 16 AS65001"]
        );
        assert_eq!(h.state.cache_reset.load(Ordering::Relaxed), 1);
        h.stop().await;
    }

    #[tokio::test]
    async fn serial_notify_with_new_session_id_flushes_and_resets() {
        let mut h = start_new();
        h.initial_sync(1, 10, &[("10.0.0.0/16", 24, 65001)]).await;
        h.send(rpki::Message::SerialNotify {
            session_id: 2,
            serial_number: 1,
        })
        .await;
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert!(h.roas().is_empty());
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 2 },
            announce("10.9.0.0/16", 24, 65009),
            end_of_data(2, 1),
        ])
        .await;
        h.wait_serial(1).await;
        assert_eq!(h.roas(), ["10.9.0.0/16 24 AS65009"]);
        assert_eq!(h.state.session_id.load(Ordering::Relaxed), 2);
        h.stop().await;
    }

    #[tokio::test]
    async fn cache_response_or_end_of_data_with_new_session_id_flushes() {
        let mut h = start_new();
        h.initial_sync(1, 10, &[("10.0.0.0/16", 24, 65001)]).await;
        h.soft_reset.notify_one();
        expect_serial_query(h.recv().await, 1, 10);
        h.send(rpki::Message::CacheResponse { session_id: 5 }).await;
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert!(h.roas().is_empty());

        // End of Data whose session ID differs from the Cache Response.
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 5 },
            announce("10.0.0.0/16", 24, 65001),
            end_of_data(6, 1),
        ])
        .await;
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert!(h.roas().is_empty());
        h.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_interval_sends_serial_query() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 3 },
            end_of_data_timers(3, 5, 30, 10, 900),
        ])
        .await;
        let t0 = Instant::now();
        expect_serial_query(h.recv().await, 3, 5);
        assert!(t0.elapsed() >= Duration::from_secs(30));
        assert!(t0.elapsed() < Duration::from_secs(31));
        let cache = h.stop().await;
        assert_eq!(
            cache.timers,
            Timers {
                refresh: Duration::from_secs(30),
                retry: Duration::from_secs(10),
                expire: Duration::from_secs(900),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_data_available_retries_after_retry_interval() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send(rpki::Message::ErrorReport {
            error_code: error_code::NO_DATA_AVAILABLE,
            pdu: vec![],
            text: "starting".to_string(),
        })
        .await;
        let t0 = Instant::now();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert!(t0.elapsed() >= Timers::INITIAL_RETRY);
        assert!(h.state.up.load(Ordering::Relaxed));
        h.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn data_expires_without_update() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 3 },
            announce("10.0.0.0/16", 24, 65001),
            end_of_data_timers(3, 5, 100, 50, 600),
        ])
        .await;
        // The cache never answers the refresh query.
        expect_serial_query(h.recv().await, 3, 5);
        assert_eq!(h.roas().len(), 1);
        tokio::time::sleep(Duration::from_secs(499)).await;
        assert_eq!(h.roas().len(), 1);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(h.roas().is_empty());
        h.stop().await;
    }

    #[tokio::test]
    async fn data_kept_across_reconnect_and_resynced_with_serial_query() {
        let tables: TableHandle = Arc::new(TableManager::new(1));
        let mut h = start(Cache::new(source()), tables.clone(), 1);
        h.initial_sync(4, 40, &[("10.0.0.0/16", 24, 65001)]).await;
        // Connection loss: the client exits but keeps the data.
        drop(h.server);
        let cache = h.handle.await.unwrap();
        assert!(!h.state.up.load(Ordering::Relaxed));
        assert_eq!(roas(&tables), ["10.0.0.0/16 24 AS65001"]);
        assert!(cache.expire_at.is_some());

        let mut h = start(cache, tables.clone(), 1);
        expect_serial_query(h.recv().await, 4, 40);
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 4 },
            withdraw("10.0.0.0/16", 24, 65001),
            end_of_data(4, 41),
        ])
        .await;
        h.wait_serial(41).await;
        assert!(h.roas().is_empty());
        h.stop().await;
    }

    #[tokio::test]
    async fn unsupported_version_error_downgrades_to_v0() {
        let mut h = start(Cache::new(source()), Arc::new(TableManager::new(1)), 0);
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert_eq!(h.server.codec().last_version(), Some(1));
        h.send(rpki::Message::ErrorReport {
            error_code: error_code::UNSUPPORTED_PROTOCOL_VERSION,
            pdu: vec![],
            text: String::new(),
        })
        .await;
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        assert_eq!(h.server.codec().last_version(), Some(0));
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 9 },
            announce("10.0.0.0/16", 24, 65001),
            end_of_data(9, 1),
        ])
        .await;
        h.wait_serial(1).await;
        assert_eq!(h.roas().len(), 1);
        let cache = h.stop().await;
        assert_eq!(cache.version, 0);
        // Version 0 End of Data has no timers: defaults apply.
        assert_eq!(cache.timers, Timers::default());
    }

    #[tokio::test]
    async fn v0_response_downgrades_session() {
        let mut h = start(Cache::new(source()), Arc::new(TableManager::new(1)), 0);
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 9 },
            end_of_data(9, 1),
        ])
        .await;
        h.wait_serial(1).await;
        h.soft_reset.notify_one();
        expect_serial_query(h.recv().await, 9, 1);
        assert_eq!(h.server.codec().last_version(), Some(0));
        h.stop().await;
    }

    #[tokio::test]
    async fn version_change_mid_session_is_an_error() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send(rpki::Message::CacheResponse { session_id: 9 }).await;
        h.server.codec_mut().set_version(0);
        h.send(end_of_data(9, 1)).await;
        expect_error(h.recv().await, error_code::UNEXPECTED_PROTOCOL_VERSION);
        let cache = h.handle.await.unwrap();
        assert_eq!(cache.session, None);
    }

    #[tokio::test]
    async fn corrupt_prefix_is_reported() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        h.send(rpki::Message::CacheResponse { session_id: 9 }).await;
        // Max length shorter than the prefix length.
        let bad = announce("10.0.0.0/24", 16, 65001);
        h.send(bad).await;
        let pdu = expect_error(h.recv().await, error_code::CORRUPT_DATA);
        assert_eq!(pdu.len(), 20);
        assert_eq!(pdu[1], rpki::Message::IPV4_PREFIX);
        // The client closes the connection.
        assert!(h.server.next().await.is_none());
        let cache = h.handle.await.unwrap();
        assert!(cache.roas.is_empty());
    }

    #[tokio::test]
    async fn duplicate_announcement_is_reported() {
        let mut h = start_new();
        h.initial_sync(1, 1, &[("10.0.0.0/16", 24, 65001)]).await;
        h.soft_reset.notify_one();
        expect_serial_query(h.recv().await, 1, 1);
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 1 },
            announce("10.0.0.0/16", 24, 65001),
        ])
        .await;
        let pdu = expect_error(h.recv().await, error_code::DUPLICATE_ANNOUNCEMENT_RECEIVED);
        assert_eq!(pdu[1], rpki::Message::IPV4_PREFIX);
        let cache = h.handle.await.unwrap();
        // Data kept, but the next connection starts with a Reset Query.
        assert_eq!(cache.session, None);
        assert_eq!(cache.roas.len(), 1);
    }

    #[tokio::test]
    async fn withdrawal_of_unknown_record_is_reported() {
        let mut h = start_new();
        h.initial_sync(1, 1, &[("10.0.0.0/16", 24, 65001)]).await;
        h.soft_reset.notify_one();
        expect_serial_query(h.recv().await, 1, 1);
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 1 },
            withdraw("10.0.0.0/16", 24, 65999),
        ])
        .await;
        expect_error(h.recv().await, error_code::WITHDRAWAL_OF_UNKNOWN_RECORD);
        h.handle.await.unwrap();
    }

    #[tokio::test]
    async fn fatal_error_report_closes_session() {
        let mut h = start_new();
        h.initial_sync(1, 1, &[("10.0.0.0/16", 24, 65001)]).await;
        h.send(rpki::Message::ErrorReport {
            error_code: error_code::INTERNAL_ERROR,
            pdu: vec![],
            text: "oops".to_string(),
        })
        .await;
        let cache = h.handle.await.unwrap();
        assert_eq!(cache.session, None);
        assert!(!h.state.up.load(Ordering::Relaxed));
        assert_eq!(h.state.error.load(Ordering::Relaxed), 1);
        // Data is kept until it expires or is replaced.
        assert_eq!(roas(&h.tables).len(), 1);
    }

    #[tokio::test]
    async fn soft_reset_before_sync_fires_after_end_of_data() {
        let mut h = start_new();
        assert!(matches!(h.recv().await, rpki::Message::ResetQuery));
        // Notify before the initial sync is complete; the guard suppresses
        // the arm until End of Data is processed.
        h.soft_reset.notify_one();
        h.send_all(vec![
            rpki::Message::CacheResponse { session_id: 3 },
            end_of_data(3, 50),
        ])
        .await;
        expect_serial_query(h.recv().await, 3, 50);
        h.stop().await;
    }

    #[tokio::test]
    async fn cancel_keeps_cache_and_marks_down() {
        let mut h = start_new();
        h.initial_sync(1, 1, &[("10.0.0.0/16", 24, 65001)]).await;
        let state = h.state.clone();
        let cache = h.stop().await;
        assert!(!state.up.load(Ordering::Relaxed));
        assert_eq!(cache.roas.len(), 1);
    }

    #[test]
    fn timers_from_end_of_data() {
        let t = Timers::from_end_of_data(1, 0, 0, 0);
        assert_eq!(t.refresh, Duration::from_secs(3600));
        assert_eq!(t.retry, Duration::from_secs(600));
        assert_eq!(t.expire, Duration::from_secs(7200));
        // Expire must exceed the other intervals.
        let t = Timers::from_end_of_data(1, 86400, 600, 7200);
        assert!(t.expire > t.refresh);
        assert_eq!(Timers::from_end_of_data(0, 1, 1, 1), Timers::default());
    }

    #[test]
    fn roa_key_clears_host_bits() {
        let a = RoaKey::new(&rpki::Prefix {
            net: packet::IpNet::new("10.0.1.7".parse().unwrap(), 16),
            flags: 1,
            max_length: 24,
            as_number: 1,
        });
        assert_eq!(a.addr, "10.0.0.0".parse::<IpAddr>().unwrap());
        let b = RoaKey::new(&rpki::Prefix {
            net: packet::IpNet::new("::1".parse().unwrap(), 0),
            flags: 1,
            max_length: 0,
            as_number: 1,
        });
        assert_eq!(b.addr, "::".parse::<IpAddr>().unwrap());
    }
}

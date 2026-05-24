use core::cell::Cell;
use core::cmp::min;
use core::fmt;
#[cfg(feature = "async")]
use core::task::Waker;

use heapless::Vec;
use managed::ManagedSlice;

use crate::config::{DNS_MAX_NAME_SIZE, DNS_MAX_SERVER_COUNT};
use crate::socket::{Context, PollAt};
use crate::time::{Duration, Instant};
use crate::wire::dns::{
    Flags, Name, Opcode, Packet, Question, Rcode, Record, RecordData, Repr, SrvRecord, Type,
};
use crate::wire::{self, IpAddress, IpProtocol, IpRepr, UdpRepr};

#[cfg(feature = "async")]
use super::WakerRegistration;

const DNS_PORT: u16 = 53;
const MDNS_DNS_PORT: u16 = 5353;
const RETRANSMIT_DELAY: Duration = Duration::from_millis(1_000);
const MAX_RETRANSMIT_DELAY: Duration = Duration::from_millis(10_000);
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(10_000); // Should generally be 2-10 secs
// NOTE: This will need to be configurable if/when smoltcp every supports EDNS
// or TCP fallback for large responses (TC response flag). This is just the only realistic
// value for DNS over unicast UDP.
const MAX_STORED_DNS_RESPONSE_SIZE: usize = 512;

#[cfg(feature = "proto-ipv6")]
#[allow(unused)]
const MDNS_IPV6_ADDR: IpAddress = IpAddress::Ipv6(crate::wire::Ipv6Address::new(
    0xff02, 0, 0, 0, 0, 0, 0, 0xfb,
));

#[cfg(feature = "proto-ipv4")]
#[allow(unused)]
const MDNS_IPV4_ADDR: IpAddress = IpAddress::Ipv4(crate::wire::Ipv4Address::new(224, 0, 0, 251));

/// Error returned by [`Socket::start_query`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StartQueryError {
    NoFreeSlot,
    InvalidName,
    NameTooLong,
}

impl core::fmt::Display for StartQueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartQueryError::NoFreeSlot => write!(f, "No free slot"),
            StartQueryError::InvalidName => write!(f, "Invalid name"),
            StartQueryError::NameTooLong => write!(f, "Name too long"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StartQueryError {}

/// Error returned by [`Socket::get_query_result`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GetQueryResultError {
    /// Query is not done yet.
    Pending,
    /// Query failed.
    Failed,
}

impl core::fmt::Display for GetQueryResultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GetQueryResultError::Pending => write!(f, "Query is not done yet"),
            GetQueryResultError::Failed => write!(f, "Query failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetQueryResultError {}

/// State for an in-progress DNS query.
///
/// The only reason this struct is public is to allow the socket state
/// to be allocated externally.
#[derive(Debug)]
pub struct DnsQuery {
    state: State,

    #[cfg(feature = "async")]
    waker: WakerRegistration,
}

impl DnsQuery {
    fn set_state(&mut self, state: State) {
        self.state = state;
        #[cfg(feature = "async")]
        self.waker.wake();
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum State {
    Pending(PendingQuery),
    Completed(CompletedQuery),
    Failure(GetQueryResultError),
}

#[derive(Debug)]
struct PendingQuery {
    name: Vec<u8, DNS_MAX_NAME_SIZE>,
    type_: Type,

    port: u16, // UDP port (src for request, dst for response)
    txid: u16, // transaction ID

    timeout_at: Option<Instant>,
    retransmit_at: Instant,
    delay: Duration,

    server_idx: usize,
    mdns: MulticastDns,
}

#[derive(Debug)]
pub enum MulticastDns {
    Disabled,
    #[cfg(feature = "socket-mdns")]
    Enabled,
}

#[derive(Debug)]
struct CompletedQuery {
    type_: Type,
    query_name_len: usize,
    query_name: [u8; DNS_MAX_NAME_SIZE],
    response_len: usize,
    response: [u8; MAX_STORED_DNS_RESPONSE_SIZE],
    consumed: Cell<bool>,
}

/// A DNS answer returned by [`Socket::get_query_result`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum QueryResult<'a> {
    Address(IpAddress),
    Ptr(Name<'a>),
    Srv(SrvRecord<Name<'a>>),
}

impl fmt::Display for QueryResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryResult::Address(addr) => write!(f, "address={addr}"),
            QueryResult::Ptr(name) => write!(f, "ptr={name}"),
            QueryResult::Srv(srv) => write!(
                f,
                "priority={} weight={} port={} target={}",
                srv.priority, srv.weight, srv.port, srv.target
            ),
        }
    }
}

/// An iterator over the answers retained for a completed DNS query.
///
/// The iterator borrows the retained response packet from the completed query state.
/// Dropping it marks the query slot as consumed so a later free-slot search can reclaim it.
pub struct QueryResultIter<'a> {
    query: &'a CompletedQuery,
    payload: &'a [u8],
    remaining_answers: usize,
    current_name: Name<'a>,
}

impl<'a> QueryResultIter<'a> {
    fn new(query: &'a CompletedQuery) -> Option<Self> {
        let response = &query.response[..query.response_len];
        let packet = Packet::new_checked(response).ok()?;
        let (payload, current_name) = match packet.question_count() {
            0 => (
                &response[12..],
                Name::from_const(&query.query_name[..query.query_name_len]).ok()?,
            ),
            1 => {
                let (payload, question) = Question::parse(response, &response[12..]).ok()?;
                (payload, question.name)
            }
            _ => return None,
        };

        Some(Self {
            query,
            payload,
            remaining_answers: usize::from(packet.answer_record_count()),
            current_name,
        })
    }
}

impl Drop for QueryResultIter<'_> {
    fn drop(&mut self) {
        self.query.consumed.set(true);
    }
}

impl<'a> Iterator for QueryResultIter<'a> {
    type Item = QueryResult<'a>;

    /// Lazily parses the retained response packet and yields the next matching answer.
    fn next(&mut self) -> Option<Self::Item> {
        if self.query.consumed.get() {
            return None;
        }

        let response = &self.query.response[..self.query.response_len];
        while self.remaining_answers > 0 {
            let (next_payload, record) = match Record::parse(response, self.payload) {
                Ok(parsed) => parsed,
                Err(_) => {
                    self.query.consumed.set(true);
                    return None;
                }
            };
            self.payload = next_payload;
            self.remaining_answers -= 1;

            let matches_name = match record.name.labels_eq(self.current_name) {
                Ok(matches) => matches,
                Err(_) => {
                    self.query.consumed.set(true);
                    return None;
                }
            };
            if !matches_name {
                continue;
            }

            match record.data {
                #[cfg(feature = "proto-ipv4")]
                RecordData::A(addr) if self.query.type_ == Type::A => {
                    return Some(QueryResult::Address(addr.into()));
                }
                #[cfg(feature = "proto-ipv6")]
                RecordData::Aaaa(addr) if self.query.type_ == Type::Aaaa => {
                    return Some(QueryResult::Address(addr.into()));
                }
                RecordData::Ptr(name) if self.query.type_ == Type::Ptr => {
                    return Some(QueryResult::Ptr(name));
                }
                RecordData::Srv(srv) if self.query.type_ == Type::Srv => {
                    return Some(QueryResult::Srv(srv));
                }
                RecordData::Cname(name) => self.current_name = name,
                _ => {}
            }
        }

        self.query.consumed.set(true);
        None
    }
}

/// A handle to an in-progress DNS query.
#[derive(Clone, Copy)]
pub struct QueryHandle(usize);

/// A Domain Name System socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    servers: Vec<IpAddress, DNS_MAX_SERVER_COUNT>,
    queries: ManagedSlice<'a, Option<DnsQuery>>,

    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
}

impl<'a> Socket<'a> {
    /// Create a DNS socket.
    ///
    /// Truncates the server list if `servers.len() > MAX_SERVER_COUNT`
    pub fn new<Q>(servers: &[IpAddress], queries: Q) -> Socket<'a>
    where
        Q: Into<ManagedSlice<'a, Option<DnsQuery>>>,
    {
        let truncated_servers = &servers[..min(servers.len(), DNS_MAX_SERVER_COUNT)];

        Socket {
            servers: Vec::from_slice(truncated_servers).unwrap(),
            queries: queries.into(),
            hop_limit: None,
        }
    }

    /// Update the list of DNS servers, will replace all existing servers
    ///
    /// Truncates the server list if `servers.len() > MAX_SERVER_COUNT`
    pub fn update_servers(&mut self, servers: &[IpAddress]) {
        if servers.len() > DNS_MAX_SERVER_COUNT {
            net_trace!("Max DNS Servers exceeded. Increase MAX_SERVER_COUNT");
            self.servers = Vec::from_slice(&servers[..DNS_MAX_SERVER_COUNT]).unwrap();
        } else {
            self.servers = Vec::from_slice(servers).unwrap();
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Finds a free query slot, reclaiming consumed completed slots before scanning.
    fn find_free_query(&mut self) -> Option<QueryHandle> {
        for i in 0..self.queries.len() {
            let is_free = match self.queries[i].as_ref() {
                None => true,
                Some(query) => match &query.state {
                    State::Completed(completed) => completed.consumed.get(),
                    _ => false,
                },
            };

            if is_free {
                self.queries[i] = None;
                return Some(QueryHandle(i));
            }
        }

        match &mut self.queries {
            ManagedSlice::Borrowed(_) => None,
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Some(QueryHandle(index))
            }
        }
    }

    /// Start a query.
    ///
    /// `name` is specified as a DNS name.
    ///
    /// If you have a human-friendly dotted name such as `"rust-lang.org"`, use
    /// [`Name::from_str`](crate::wire::dns::Name::from_str) to construct it first. DNS search
    /// path expansion is not supported.
    pub fn start_query(
        &mut self,
        cx: &mut Context,
        name: Name<'_>,
        query_type: Type,
    ) -> Result<QueryHandle, StartQueryError> {
        let mut raw_name: Vec<u8, DNS_MAX_NAME_SIZE> = Vec::new();
        if copy_name(&mut raw_name, name).is_err() {
            net_trace!("invalid name");
            return Err(StartQueryError::InvalidName);
        }

        #[cfg(not(feature = "socket-mdns"))]
        let mdns = MulticastDns::Disabled;
        #[cfg(feature = "socket-mdns")]
        let mdns = {
            let mut last_label = None;
            for label in name.labels() {
                let label = label.map_err(|_| StartQueryError::InvalidName)?;
                last_label = Some(label);
            }

            if matches!(last_label, Some(label) if label == b"local") {
                net_trace!("Starting a mDNS query");
                MulticastDns::Enabled
            } else {
                MulticastDns::Disabled
            }
        };

        self.start_query_raw(cx, &raw_name, query_type, mdns)
    }

    /// Start a query with a raw (wire-format) DNS name.
    /// `b"\x09rust-lang\x03org\x00"`
    ///
    /// You probably want to use [`start_query`] instead.
    pub fn start_query_raw(
        &mut self,
        cx: &mut Context,
        raw_name: &[u8],
        query_type: Type,
        mdns: MulticastDns,
    ) -> Result<QueryHandle, StartQueryError> {
        let handle = self.find_free_query().ok_or(StartQueryError::NoFreeSlot)?;

        self.queries[handle.0] = Some(DnsQuery {
            state: State::Pending(PendingQuery {
                name: Vec::from_slice(raw_name).map_err(|_| StartQueryError::NameTooLong)?,
                type_: query_type,
                txid: cx.rand().rand_u16(),
                port: cx.rand().rand_source_port(),
                delay: RETRANSMIT_DELAY,
                timeout_at: None,
                retransmit_at: Instant::ZERO,
                server_idx: 0,
                mdns,
            }),
            #[cfg(feature = "async")]
            waker: WakerRegistration::new(),
        });
        Ok(handle)
    }

    /// Get the result of a query.
    ///
    /// If the query is completed, this returns an iterator over the retained response packet.
    /// The query slot is marked as consumed when the iterator is exhausted or dropped, and is
    /// reclaimed when the socket next searches for a free query slot.
    ///
    /// # Panics
    /// Panics if the QueryHandle corresponds to a free slot.
    pub fn get_query_result(
        &mut self,
        handle: QueryHandle,
    ) -> Result<QueryResultIter<'_>, GetQueryResultError> {
        let slot = &mut self.queries[handle.0];

        match slot {
            None => panic!("Getting query result from a free slot."),
            Some(DnsQuery {
                state: State::Pending(_),
                ..
            }) => Err(GetQueryResultError::Pending),
            Some(DnsQuery {
                state: State::Completed(completed),
                ..
            }) => {
                if completed.consumed.get() {
                    panic!("Getting query result from a free slot.")
                }

                QueryResultIter::new(completed).ok_or(GetQueryResultError::Failed)
            }
            Some(DnsQuery {
                state: State::Failure(error),
                ..
            }) => {
                let error = *error;
                *slot = None;
                Err(error)
            }
        }
    }

    /// Cancels a query, freeing the slot.
    ///
    /// # Panics
    ///
    /// Panics if the QueryHandle corresponds to an already free slot.
    pub fn cancel_query(&mut self, handle: QueryHandle) {
        let slot = &mut self.queries[handle.0];
        if slot.is_none() {
            panic!("Canceling query in a free slot.")
        }
        *slot = None; // Free up the slot for recycling.
    }

    /// Assign a waker to a query slot
    ///
    /// The waker will be woken when the query completes, either successfully or failed.
    ///
    /// # Panics
    ///
    /// Panics if the QueryHandle corresponds to an already free slot.
    #[cfg(feature = "async")]
    pub fn register_query_waker(&mut self, handle: QueryHandle, waker: &Waker) {
        self.queries[handle.0]
            .as_mut()
            .unwrap()
            .waker
            .register(waker);
    }

    /// Returns whether an incoming UDP packet could belong to this DNS socket.
    pub(crate) fn accepts(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> bool {
        (udp_repr.src_port == DNS_PORT
            && self
                .servers
                .iter()
                .any(|server| *server == ip_repr.src_addr()))
            || (udp_repr.src_port == MDNS_DNS_PORT)
    }

    /// Processes an incoming DNS response and retains the matching packet for later iteration.
    pub(crate) fn process(
        &mut self,
        _cx: &mut Context,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        payload: &[u8],
    ) {
        debug_assert!(self.accepts(ip_repr, udp_repr));

        let message = payload;
        let size = message.len();

        net_trace!(
            "receiving {} octets from {:?}:{}",
            size,
            ip_repr.src_addr(),
            udp_repr.dst_port
        );

        let p = match Packet::new_checked(message) {
            Ok(x) => x,
            Err(_) => {
                net_trace!("dns packet malformed");
                return;
            }
        };
        if p.opcode() != Opcode::Query {
            net_trace!("unwanted opcode {:?}", p.opcode());
            return;
        }

        if !p.flags().contains(Flags::RESPONSE) {
            net_trace!("packet doesn't have response bit set");
            return;
        }

        // Find pending query
        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                let is_mdns_query = !matches!(pq.mdns, MulticastDns::Disabled);
                let is_legacy_response = udp_repr.dst_port == pq.port;
                let is_multicast_mdns_response =
                    is_mdns_query && udp_repr.dst_port == MDNS_DNS_PORT;

                if !is_legacy_response && !is_multicast_mdns_response {
                    continue;
                }

                let transaction_id_matches = p.transaction_id() == pq.txid
                    || (is_mdns_query
                        && udp_repr.src_port == MDNS_DNS_PORT
                        && p.transaction_id() == 0);

                if is_legacy_response && !transaction_id_matches {
                    continue;
                }

                if p.rcode() == Rcode::NXDomain {
                    net_trace!("rcode NXDomain");
                    q.set_state(State::Failure(GetQueryResultError::Failed));
                    continue;
                }

                let query_name = match Name::from_const(pq.name.as_slice()) {
                    Ok(name) => name,
                    Err(_) => {
                        net_trace!("stored query name malformed");
                        q.set_state(State::Failure(GetQueryResultError::Failed));
                        return;
                    }
                };

                let (mut payload, mut current_name) = match p.question_count() {
                    0 if is_multicast_mdns_response => (p.payload(), query_name),
                    1 => {
                        let (payload, question) = match Question::parse(message, p.payload()) {
                            Ok(x) => x,
                            Err(_) => {
                                net_trace!("question malformed");
                                return;
                            }
                        };

                        if question.type_ != pq.type_ {
                            net_trace!("question type mismatch");
                            continue;
                        }

                        match question.name.labels_eq(query_name) {
                            Ok(true) => (payload, question.name),
                            Ok(false) => {
                                net_trace!("question name mismatch");
                                continue;
                            }
                            Err(_) => {
                                net_trace!("dns question name malformed");
                                return;
                            }
                        }
                    }
                    count => {
                        net_trace!("bad question count {:?}", count);
                        continue;
                    }
                };

                let mut has_result = false;

                for _ in 0..p.answer_record_count() {
                    let (payload2, r) = match Record::parse(message, payload) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("dns answer record malformed");
                            return;
                        }
                    };
                    payload = payload2;

                    match r.name.labels_eq(current_name) {
                        Ok(true) => {}
                        Ok(false) => {
                            net_trace!("answer name mismatch: {:?}", r);
                            continue;
                        }
                        Err(_) => {
                            net_trace!("dns answer record name malformed");
                            return;
                        }
                    }

                    match r.data {
                        #[cfg(feature = "proto-ipv4")]
                        RecordData::A(addr) if pq.type_ == Type::A => {
                            net_trace!("A: {:?}", addr);
                            has_result = true;
                        }
                        #[cfg(feature = "proto-ipv6")]
                        RecordData::Aaaa(addr) if pq.type_ == Type::Aaaa => {
                            net_trace!("AAAA: {:?}", addr);
                            has_result = true;
                        }
                        RecordData::Ptr(name) if pq.type_ == Type::Ptr => {
                            net_trace!("PTR: {:?}", name);
                            has_result = true;
                        }
                        RecordData::Srv(srv) if pq.type_ == Type::Srv => {
                            net_trace!("SRV: {:?}", srv);
                            has_result = true;
                        }
                        RecordData::Cname(name) => {
                            net_trace!("CNAME: {:?}", name);

                            // When faced with a CNAME, recursive resolvers are supposed to
                            // resolve the CNAME and append the results for it.
                            //
                            // We update the expected name, so that we pick up the A/AAAA records
                            // for the CNAME when we parse them later.
                            // I believe it's mandatory the CNAME results MUST come *after* in the
                            // packet, so it's enough to do one linear pass over it.
                            current_name = name;
                        }
                        RecordData::Other(type_, data) => {
                            net_trace!("unknown: {:?} {:?}", type_, data)
                        }
                        _ => {}
                    }
                }

                let new_state = if !has_result {
                    if is_multicast_mdns_response {
                        continue;
                    }
                    State::Failure(GetQueryResultError::Failed)
                } else {
                    let mut response = [0u8; MAX_STORED_DNS_RESPONSE_SIZE];
                    let mut query_name_storage = [0u8; DNS_MAX_NAME_SIZE];
                    if size > response.len() {
                        net_trace!("dns response too large to retain");
                        State::Failure(GetQueryResultError::Failed)
                    } else {
                        response[..size].copy_from_slice(message);
                        query_name_storage[..pq.name.len()].copy_from_slice(pq.name.as_slice());
                        State::Completed(CompletedQuery {
                            type_: pq.type_,
                            query_name_len: pq.name.len(),
                            query_name: query_name_storage,
                            response_len: size,
                            response,
                            consumed: Cell::new(false),
                        })
                    }
                };
                let _ = pq;
                q.set_state(new_state);

                // If we get here, packet matched the current query, stop processing.
                return;
            }
        }

        // If we get here, packet matched with no query.
        net_trace!("no query matched");
    }

    /// Emits the next pending DNS query packet.
    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, UdpRepr, &[u8])) -> Result<(), E>,
    {
        let hop_limit = self.hop_limit.unwrap_or(64);

        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                // As per RFC 6762 any DNS query ending in .local. MUST be sent as mdns
                // so we internally overwrite the servers for any of those queries
                // in this function.
                let servers = match pq.mdns {
                    #[cfg(feature = "socket-mdns")]
                    MulticastDns::Enabled => &[
                        #[cfg(feature = "proto-ipv6")]
                        MDNS_IPV6_ADDR,
                        #[cfg(feature = "proto-ipv4")]
                        MDNS_IPV4_ADDR,
                    ],
                    MulticastDns::Disabled => self.servers.as_slice(),
                };

                let timeout = if let Some(timeout) = pq.timeout_at {
                    timeout
                } else {
                    let v = cx.now() + RETRANSMIT_TIMEOUT;
                    pq.timeout_at = Some(v);
                    v
                };

                // Check timeout
                if timeout < cx.now() {
                    // DNS timeout
                    pq.timeout_at = Some(cx.now() + RETRANSMIT_TIMEOUT);
                    pq.retransmit_at = Instant::ZERO;
                    pq.delay = RETRANSMIT_DELAY;

                    // Try next server. We check below whether we've tried all servers.
                    pq.server_idx += 1;
                }
                // Check if we've run out of servers to try.
                if pq.server_idx >= servers.len() {
                    net_trace!("already tried all servers.");
                    q.set_state(State::Failure(GetQueryResultError::Failed));
                    continue;
                }

                // Check so the IP address is valid
                if servers[pq.server_idx].is_unspecified() {
                    net_trace!("invalid unspecified DNS server addr.");
                    q.set_state(State::Failure(GetQueryResultError::Failed));
                    continue;
                }

                if pq.retransmit_at > cx.now() {
                    // query is waiting for retransmit
                    continue;
                }

                let repr = Repr {
                    transaction_id: pq.txid,
                    flags: Flags::RECURSION_DESIRED,
                    opcode: Opcode::Query,
                    question: Question {
                        name: Name::from_const(pq.name.as_slice())
                            .expect("stored query name should stay canonical"),
                        type_: pq.type_,
                    },
                };

                let mut payload = [0u8; 512];
                let payload = &mut payload[..repr.buffer_len()];
                repr.emit(&mut Packet::new_unchecked(payload));

                let dst_port = match pq.mdns {
                    #[cfg(feature = "socket-mdns")]
                    MulticastDns::Enabled => MDNS_DNS_PORT,
                    MulticastDns::Disabled => DNS_PORT,
                };

                let udp_repr = UdpRepr {
                    src_port: pq.port,
                    dst_port,
                };

                let dst_addr = servers[pq.server_idx];
                let src_addr = match cx.get_source_address(&dst_addr) {
                    Some(src_addr) => src_addr,
                    None => {
                        net_trace!("no source address for destination {}", dst_addr);
                        q.set_state(State::Failure(GetQueryResultError::Failed));
                        continue;
                    }
                };

                let ip_repr = IpRepr::new(
                    src_addr,
                    dst_addr,
                    IpProtocol::Udp,
                    udp_repr.header_len() + payload.len(),
                    hop_limit,
                );

                net_trace!(
                    "sending {} octets to {} from port {}",
                    payload.len(),
                    ip_repr.dst_addr(),
                    udp_repr.src_port
                );

                emit(cx, (ip_repr, udp_repr, payload))?;

                pq.retransmit_at = cx.now() + pq.delay;
                pq.delay = MAX_RETRANSMIT_DELAY.min(pq.delay * 2);

                return Ok(());
            }
        }

        // Nothing to dispatch
        Ok(())
    }

    /// Returns the next time this DNS socket should be polled.
    pub(crate) fn poll_at(&self, _cx: &Context) -> PollAt {
        self.queries
            .iter()
            .flatten()
            .filter_map(|q| match &q.state {
                State::Pending(pq) => Some(PollAt::Time(pq.retransmit_at)),
                State::Completed(_) => None,
                State::Failure(_) => None,
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }
}

/// Copies `name` into canonical, uncompressed wire format inside `dest`.
fn copy_name<const N: usize>(dest: &mut Vec<u8, N>, name: Name<'_>) -> Result<(), wire::Error> {
    dest.truncate(0);

    for label in name.labels() {
        let label = label?;
        dest.push(label.len() as u8).map_err(|_| wire::Error)?;
        dest.extend_from_slice(label).map_err(|_| wire::Error)?;
    }

    dest.push(0).map_err(|_| wire::Error)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use std::vec::Vec as StdVec;

    use super::*;
    use crate::phy::Medium;
    use crate::tests::setup;

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
            const SERVER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 53);

            const ADDRESS_QUERY_NAME: &str = "example.com";
            const ADDRESS_QUERY_TYPE: Type = Type::A;

            fn address_answer() -> StdVec<u8> {
                vec![
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1,
                    2, 3, 4,
                ]
            }

            fn second_address_answer() -> StdVec<u8> {
                vec![
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 5,
                    6, 7, 8,
                ]
            }

            fn expected_address_result() -> QueryResult<'static> {
                QueryResult::Address(IpvXAddress::new(1, 2, 3, 4).into())
            }

            fn expected_second_address_result() -> QueryResult<'static> {
                QueryResult::Address(IpvXAddress::new(5, 6, 7, 8).into())
            }
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            const SERVER_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 53);

            const ADDRESS_QUERY_NAME: &str = "example.com";
            const ADDRESS_QUERY_TYPE: Type = Type::Aaaa;

            fn address_answer() -> StdVec<u8> {
                vec![
                    0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]
            }

            fn second_address_answer() -> StdVec<u8> {
                vec![
                    0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ]
            }

            fn expected_address_result() -> QueryResult<'static> {
                QueryResult::Address(IpvXAddress::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).into())
            }

            fn expected_second_address_result() -> QueryResult<'static> {
                QueryResult::Address(IpvXAddress::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2).into())
            }
        }
    }

    fn test_medium() -> Medium {
        cfg_if::cfg_if! {
            if #[cfg(feature = "medium-ip")] {
                Medium::Ip
            } else if #[cfg(feature = "medium-ethernet")] {
                Medium::Ethernet
            } else if #[cfg(feature = "medium-ieee802154")] {
                Medium::Ieee802154
            } else {
                unreachable!()
            }
        }
    }

    fn dispatch_query(socket: &mut Socket<'_>, cx: &mut Context) -> (u16, StdVec<u8>) {
        let mut emitted = None;

        assert_eq!(
            socket.dispatch(cx, |_, (_, udp_repr, payload)| {
                emitted = Some((udp_repr.src_port, payload.to_vec()));
                Ok::<_, ()>(())
            }),
            Ok(())
        );

        emitted.expect("DNS query should have been emitted")
    }

    fn build_response(query_payload: &[u8], answer: &[u8]) -> StdVec<u8> {
        build_response_with_answer_count(query_payload, answer, 1)
    }

    fn raw_name(name: &str) -> StdVec<u8> {
        let mut bytes = [0u8; DNS_MAX_NAME_SIZE];
        Name::from_str(&mut bytes, name).unwrap().raw().to_vec()
    }

    fn build_response_with_answer_count(
        query_payload: &[u8],
        answer: &[u8],
        answer_count: u16,
    ) -> StdVec<u8> {
        let query = Packet::new_checked(query_payload).unwrap();
        let question = query.payload();

        let mut response = vec![0; 12 + question.len() + answer.len()];
        let mut packet = Packet::new_unchecked(response.as_mut_slice());
        packet.set_transaction_id(query.transaction_id());
        packet.set_flags(Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE);
        packet.set_opcode(query.opcode());
        packet.set_question_count(1);
        packet.set_answer_record_count(answer_count);
        packet.set_authority_record_count(0);
        packet.set_additional_record_count(0);

        let payload = packet.payload_mut();
        payload[..question.len()].copy_from_slice(question);
        payload[question.len()..].copy_from_slice(answer);

        response
    }

    fn build_mdns_response(answer: &[u8], answer_count: u16) -> StdVec<u8> {
        let mut response = vec![0; 12 + answer.len()];
        let mut packet = Packet::new_unchecked(response.as_mut_slice());
        packet.set_transaction_id(0);
        packet.set_flags(Flags::RESPONSE | Flags::AUTHORITATIVE);
        packet.set_opcode(Opcode::Query);
        packet.set_question_count(0);
        packet.set_answer_record_count(answer_count);
        packet.set_authority_record_count(0);
        packet.set_additional_record_count(0);
        packet.payload_mut()[..answer.len()].copy_from_slice(answer);
        response
    }

    fn build_rr(name: &str, type_: u16, class: u16, ttl: u32, rdata: &[u8]) -> StdVec<u8> {
        let mut rr = raw_name(name);
        rr.extend_from_slice(&type_.to_be_bytes());
        rr.extend_from_slice(&class.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(rdata);
        rr
    }

    fn process_mdns_response(socket: &mut Socket<'_>, cx: &mut Context, payload: &[u8]) {
        let udp_repr = UdpRepr {
            src_port: MDNS_DNS_PORT,
            dst_port: MDNS_DNS_PORT,
        };
        let ip_repr = IpRepr::new(
            SERVER_ADDR.into(),
            LOCAL_ADDR.into(),
            IpProtocol::Udp,
            udp_repr.header_len() + payload.len(),
            255,
        );

        socket.process(cx, &ip_repr, &udp_repr, payload);
    }

    fn process_response(socket: &mut Socket<'_>, cx: &mut Context, dst_port: u16, payload: &[u8]) {
        let udp_repr = UdpRepr {
            src_port: DNS_PORT,
            dst_port,
        };
        let ip_repr = IpRepr::new(
            SERVER_ADDR.into(),
            LOCAL_ADDR.into(),
            IpProtocol::Udp,
            udp_repr.header_len() + payload.len(),
            64,
        );

        socket.process(cx, &ip_repr, &udp_repr, payload);
    }

    fn process_mdns_unicast_response(
        socket: &mut Socket<'_>,
        cx: &mut Context,
        dst_port: u16,
        payload: &[u8],
    ) {
        let udp_repr = UdpRepr {
            src_port: MDNS_DNS_PORT,
            dst_port,
        };
        let ip_repr = IpRepr::new(
            SERVER_ADDR.into(),
            LOCAL_ADDR.into(),
            IpProtocol::Udp,
            udp_repr.header_len() + payload.len(),
            255,
        );

        socket.process(cx, &ip_repr, &udp_repr, payload);
    }

    #[test]
    fn test_get_query_result_address() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);
        let mut query_name = [0u8; DNS_MAX_NAME_SIZE];

        let handle = socket
            .start_query(
                cx,
                Name::from_str(&mut query_name, ADDRESS_QUERY_NAME).unwrap(),
                ADDRESS_QUERY_TYPE,
            )
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let response = build_response(&query_payload, &address_answer());
        process_response(&mut socket, cx, query_port, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        assert_eq!(results.next(), Some(expected_address_result()));
        assert_eq!(results.next(), None);
    }

    #[test]
    fn test_get_query_result_multiple_addresses() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);
        let mut query_name = [0u8; DNS_MAX_NAME_SIZE];

        let handle = socket
            .start_query(
                cx,
                Name::from_str(&mut query_name, ADDRESS_QUERY_NAME).unwrap(),
                ADDRESS_QUERY_TYPE,
            )
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let mut answers = address_answer();
        answers.extend_from_slice(&second_address_answer());
        let response = build_response_with_answer_count(&query_payload, &answers, 2);
        process_response(&mut socket, cx, query_port, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        assert_eq!(results.next(), Some(expected_address_result()));
        assert_eq!(results.next(), Some(expected_second_address_result()));
        assert_eq!(results.next(), None);
    }

    #[test]
    fn test_get_query_result_ptr() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);
        let mut query_name = [0u8; DNS_MAX_NAME_SIZE];

        let handle = socket
            .start_query(
                cx,
                Name::from_str(&mut query_name, "4.3.2.1.in-addr.arpa").unwrap(),
                Type::Ptr,
            )
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let response = build_response(
            &query_payload,
            &[
                0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x0d, 0x07, 0x65,
                0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            ],
        );
        process_response(&mut socket, cx, query_port, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        match results.next() {
            Some(QueryResult::Ptr(name)) => assert_eq!(format!("{name}"), "example.com"),
            other => panic!("unexpected PTR result: {other:?}"),
        }
        assert_eq!(results.next(), None);
    }

    #[test]
    fn test_get_query_result_srv() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);
        let mut query_name = [0u8; DNS_MAX_NAME_SIZE];

        let handle = socket
            .start_query(
                cx,
                Name::from_str(&mut query_name, "_sip._tcp.example.com").unwrap(),
                Type::Srv,
            )
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let response = build_response(
            &query_payload,
            &[
                0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x12, 0x00, 0x00,
                0x00, 0x05, 0x13, 0xc4, 0x09, 0x73, 0x69, 0x70, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
                0xc0, 0x16,
            ],
        );
        process_response(&mut socket, cx, query_port, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        match results.next() {
            Some(QueryResult::Srv(srv)) => {
                assert_eq!(srv.priority, 0);
                assert_eq!(srv.weight, 5);
                assert_eq!(srv.port, 5060);
                assert_eq!(format!("{}", srv.target), "sipserver.example.com");
            }
            other => panic!("unexpected SRV result: {other:?}"),
        }
        assert_eq!(results.next(), None);
    }

    #[test]
    #[cfg(feature = "socket-mdns")]
    fn test_get_query_result_mdns_address_without_question() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);

        let handle = socket
            .start_query_raw(
                cx,
                raw_name("example.local").as_slice(),
                ADDRESS_QUERY_TYPE,
                MulticastDns::Enabled,
            )
            .unwrap();

        let response = build_mdns_response(
            &build_rr("example.local", 0x0001, 0x8001, 120, &[1, 2, 3, 4]),
            1,
        );
        process_mdns_response(&mut socket, cx, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        assert_eq!(results.next(), Some(expected_address_result()));
        assert_eq!(results.next(), None);
    }

    #[test]
    #[cfg(feature = "socket-mdns")]
    fn test_get_query_result_mdns_ptr_without_question() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);

        let handle = socket
            .start_query_raw(
                cx,
                raw_name("_service._tcp.local").as_slice(),
                Type::Ptr,
                MulticastDns::Enabled,
            )
            .unwrap();

        let target = raw_name("instance._service._tcp.local");
        let response = build_mdns_response(
            &build_rr("_service._tcp.local", 0x000c, 0x0001, 4500, &target),
            1,
        );
        process_mdns_response(&mut socket, cx, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        match results.next() {
            Some(QueryResult::Ptr(name)) => {
                assert_eq!(format!("{name}"), "instance._service._tcp.local")
            }
            other => panic!("unexpected PTR result: {other:?}"),
        }
        assert_eq!(results.next(), None);
    }

    #[test]
    #[cfg(feature = "socket-mdns")]
    fn test_get_query_result_mdns_ptr_unicast_zero_transaction_id() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);
        let mut query_name = [0u8; DNS_MAX_NAME_SIZE];

        let handle = socket
            .start_query(
                cx,
                Name::from_str(&mut query_name, "_service._tcp.local").unwrap(),
                Type::Ptr,
            )
            .unwrap();
        let (query_port, query_payload) = dispatch_query(&mut socket, cx);

        let target = raw_name("instance._service._tcp.local");
        let mut response = build_response(
            &query_payload,
            &build_rr("_service._tcp.local", 0x000c, 0x0001, 4500, &target),
        );
        Packet::new_unchecked(response.as_mut_slice()).set_transaction_id(0);
        process_mdns_unicast_response(&mut socket, cx, query_port, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        match results.next() {
            Some(QueryResult::Ptr(name)) => {
                assert_eq!(format!("{name}"), "instance._service._tcp.local")
            }
            other => panic!("unexpected PTR result: {other:?}"),
        }
        assert_eq!(results.next(), None);
    }

    #[test]
    #[cfg(feature = "socket-mdns")]
    fn test_get_query_result_mdns_srv_without_question() {
        let (mut iface, _, _) = setup(test_medium());
        let cx = iface.context();
        let mut socket = Socket::new(&[SERVER_ADDR.into()], vec![None]);

        let handle = socket
            .start_query_raw(
                cx,
                raw_name("_svc._tcp.local").as_slice(),
                Type::Srv,
                MulticastDns::Enabled,
            )
            .unwrap();

        let mut rdata = StdVec::new();
        rdata.extend_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x13, 0xc4]);
        rdata.extend_from_slice(&raw_name("sipserver.local"));
        let response =
            build_mdns_response(&build_rr("_svc._tcp.local", 0x0021, 0x8001, 120, &rdata), 1);
        process_mdns_response(&mut socket, cx, &response);

        let mut results = socket.get_query_result(handle).unwrap();
        match results.next() {
            Some(QueryResult::Srv(srv)) => {
                assert_eq!(srv.priority, 0);
                assert_eq!(srv.weight, 5);
                assert_eq!(srv.port, 5060);
                assert_eq!(format!("{}", srv.target), "sipserver.local");
            }
            other => panic!("unexpected SRV result: {other:?}"),
        }
        assert_eq!(results.next(), None);
    }
}

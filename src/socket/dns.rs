#![allow(dead_code, unused)]
use heapless::Vec;
use managed::ManagedSlice;

use crate::socket::{Context, PollAt, Socket};
use crate::time::{Duration, Instant};
use crate::wire::dns::{Flags, Opcode, Packet, Question, Record, RecordData, Repr, Type};
use crate::wire::{IpAddress, IpEndpoint, IpProtocol, IpRepr, Ipv4Address, UdpRepr};
use crate::{rand, Error, Result};

const DNS_PORT: u16 = 53;
const MAX_NAME_LEN: usize = 255;
const MAX_ADDRESS_COUNT: usize = 4;
const RETRANSMIT_DELAY: Duration = Duration::from_millis(1000);
const MAX_RETRANSMIT_DELAY: Duration = Duration::from_millis(10000);

/// State for an in-progress DNS query.
///
/// The only reason this struct is public is to allow the socket state
/// to be allocated externally.
#[derive(Debug)]
pub struct DnsQuery {
    state: State,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum State {
    Pending(PendingQuery),
    Completed(CompletedQuery),
}

#[derive(Debug)]
struct PendingQuery {
    name: Vec<u8, MAX_NAME_LEN>,
    type_: Type,

    port: u16, // UDP port (src for request, dst for response)
    txid: u16, // transaction ID

    retransmit_at: Instant,
    delay: Duration,
}

#[derive(Debug)]
struct CompletedQuery {
    addresses: Vec<IpAddress, MAX_ADDRESS_COUNT>,
}

/// A handle to an in-progress DNS query.
#[derive(Clone, Copy)]
pub struct QueryHandle(usize);

/// A Domain Name System socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct DnsSocket<'a> {
    servers: ManagedSlice<'a, IpAddress>,
    queries: ManagedSlice<'a, Option<DnsQuery>>,

    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
}

impl<'a> DnsSocket<'a> {
    /// Create a DNS socket with the given buffers.
    pub fn new<Q, S>(servers: S, queries: Q) -> DnsSocket<'a>
    where
        S: Into<ManagedSlice<'a, IpAddress>>,
        Q: Into<ManagedSlice<'a, Option<DnsQuery>>>,
    {
        DnsSocket {
            servers: servers.into(),
            queries: queries.into(),
            hop_limit: None,
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

    fn find_free_query(&mut self) -> Result<QueryHandle> {
        for (i, q) in self.queries.iter().enumerate() {
            if q.is_none() {
                return Ok(QueryHandle(i));
            }
        }

        match self.queries {
            ManagedSlice::Borrowed(_) => Err(Error::Exhausted),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Ok(QueryHandle(index))
            }
        }
    }

    pub fn start_query(&mut self, cx: &mut Context, name: &[u8]) -> Result<QueryHandle> {
        let handle = self.find_free_query()?;

        self.queries[handle.0] = Some(DnsQuery {
            state: State::Pending(PendingQuery {
                name: Vec::from_slice(name).map_err(|_| Error::Truncated)?,
                type_: Type::A,
                txid: cx.rand().rand_u16(),
                port: cx.rand().rand_source_port(),
                delay: RETRANSMIT_DELAY,
                retransmit_at: Instant::ZERO,
            }),
        });
        Ok(handle)
    }

    pub fn get_query_result(
        &mut self,
        handle: QueryHandle,
    ) -> Result<Vec<IpAddress, MAX_ADDRESS_COUNT>> {
        let slot = self.queries.get_mut(handle.0).ok_or(Error::Illegal)?;
        let q = slot.as_mut().ok_or(Error::Illegal)?;
        match &mut q.state {
            // Query is not done yet.
            State::Pending(_) => Err(Error::Exhausted),
            // Query is done
            State::Completed(q) => {
                let res = q.addresses.clone();
                *slot = None; // Free up the slot for recycling.
                Ok(res)
            }
        }
    }

    pub fn cancel_query(&mut self, handle: QueryHandle) -> Result<()> {
        let slot = self.queries.get_mut(handle.0).ok_or(Error::Illegal)?;
        let q = slot.as_mut().ok_or(Error::Illegal)?;
        *slot = None; // Free up the slot for recycling.
        Ok(())
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> bool {
        udp_repr.src_port == DNS_PORT
            && self
                .servers
                .iter()
                .any(|server| *server == ip_repr.src_addr())
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        udp_repr: &UdpRepr,
        payload: &[u8],
    ) -> Result<()> {
        debug_assert!(self.accepts(ip_repr, udp_repr));

        let size = payload.len();

        net_trace!(
            "receiving {} octets from {:?}:{}",
            size,
            ip_repr.src_addr(),
            udp_repr.dst_port
        );

        let p = Packet::new_checked(payload)?;
        if p.opcode() != Opcode::Query {
            net_trace!("unwanted opcode {:?}", p.opcode());
            return Err(Error::Malformed);
        }

        if !p.flags().contains(Flags::RESPONSE) {
            net_trace!("packet doesn't have response bit set");
            return Err(Error::Malformed);
        }

        if p.question_count() != 1 {
            net_trace!("bad question count {:?}", p.question_count());
            return Err(Error::Malformed);
        }

        // Find pending query
        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                if udp_repr.dst_port != pq.port || p.transaction_id() != pq.txid {
                    continue;
                }

                let payload = p.payload();
                let (mut payload, question) = Question::parse(payload)?;

                if question.type_ != pq.type_ {
                    net_trace!("question type mismatch");
                    return Err(Error::Malformed);
                }
                if !eq_names(p.parse_name(question.name), p.parse_name(&pq.name))? {
                    net_trace!("question name mismatch");
                    return Err(Error::Malformed);
                }

                let mut addresses = Vec::new();

                for _ in 0..p.answer_record_count() {
                    let (payload2, r) = Record::parse(payload)?;
                    payload = payload2;

                    if !eq_names(p.parse_name(r.name), p.parse_name(&pq.name))? {
                        net_trace!("answer name mismatch: {:?}", r);
                        continue;
                    }

                    match r.data {
                        RecordData::A(addr) => {
                            net_trace!("A: {:?}", addr);
                            if addresses.push(addr.into()).is_err() {
                                net_trace!("too many addresses in response, ignoring {:?}", addr);
                            }
                        }
                        RecordData::Aaaa(addr) => {
                            net_trace!("AAAA: {:?}", addr);
                            if addresses.push(addr.into()).is_err() {
                                net_trace!("too many addresses in response, ignoring {:?}", addr);
                            }
                        }
                        RecordData::Cname(name) => {
                            net_trace!("CNAME: {:?}", name);
                            copy_name(&mut pq.name, p.parse_name(name))?;

                            // Relaunch query with the new name.
                            // If the server has bundled A records for the CNAME in the same packet,
                            // we'll process them in next iterations, and cancel the query relaunch.
                            pq.retransmit_at = Instant::ZERO;
                            pq.delay = RETRANSMIT_DELAY;

                            pq.txid = cx.rand().rand_u16();
                            pq.port = cx.rand().rand_source_port();
                        }
                        RecordData::Other(type_, data) => {
                            net_trace!("unknown: {:?} {:?}", type_, data)
                        }
                    }
                }

                if !addresses.is_empty() {
                    q.state = State::Completed(CompletedQuery { addresses })
                }
                // If we get here, packet matched the current query, stop processing.
                return Ok(());
            }
        }

        // If we get here, packet matched with no query.
        net_trace!("no query matched");
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, cx: &mut Context, emit: F) -> Result<()>
    where
        F: FnOnce(&mut Context, (IpRepr, UdpRepr, &[u8])) -> Result<()>,
    {
        let hop_limit = self.hop_limit.unwrap_or(64);

        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                if pq.retransmit_at > cx.now() {
                    // query is waiting for retransmit
                    continue;
                }

                let repr = Repr {
                    transaction_id: pq.txid,
                    flags: Flags::RECURSION_DESIRED,
                    opcode: Opcode::Query,
                    question: Question {
                        name: &pq.name,
                        type_: Type::A,
                    },
                };

                let mut payload = [0u8; 512];
                let payload = &mut payload[..repr.buffer_len()];
                repr.emit(&mut Packet::new_unchecked(payload));

                let udp_repr = UdpRepr {
                    src_port: pq.port,
                    dst_port: 53,
                };

                let dst_addr = self.servers[0];
                let src_addr = cx.get_source_address(dst_addr).unwrap(); // TODO remove unwrap
                let ip_repr = IpRepr::new(
                    src_addr,
                    dst_addr,
                    IpProtocol::Udp,
                    udp_repr.header_len() + payload.len(),
                    hop_limit,
                );

                net_trace!(
                    "sending {} octets to {:?}:{}",
                    payload.len(),
                    ip_repr.dst_addr(),
                    udp_repr.src_port
                );

                if let Err(e) = emit(cx, (ip_repr, udp_repr, payload)) {
                    net_trace!("DNS emit error {:?}", e);
                    return Ok(());
                }

                pq.retransmit_at = cx.now() + pq.delay;
                pq.delay = MAX_RETRANSMIT_DELAY.min(pq.delay * 2);

                return Ok(());
            }
        }

        // Nothing to dispatch
        Err(Error::Exhausted)
    }

    pub(crate) fn poll_at(&self, _cx: &Context) -> PollAt {
        self.queries
            .iter()
            .flatten()
            .filter_map(|q| match &q.state {
                State::Pending(pq) => Some(PollAt::Time(pq.retransmit_at)),
                State::Completed(_) => None,
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }
}

impl<'a> From<DnsSocket<'a>> for Socket<'a> {
    fn from(val: DnsSocket<'a>) -> Self {
        Socket::Dns(val)
    }
}

fn eq_names<'a>(
    mut a: impl Iterator<Item = Result<&'a [u8]>>,
    mut b: impl Iterator<Item = Result<&'a [u8]>>,
) -> Result<bool> {
    loop {
        match (a.next(), b.next()) {
            // Handle errors
            (Some(Err(e)), _) => return Err(e),
            (_, Some(Err(e))) => return Err(e),

            // Both finished -> equal
            (None, None) => return Ok(true),

            // One finished before the other -> not equal
            (None, _) => return Ok(false),
            (_, None) => return Ok(false),

            // Got two labels, check if they're equal
            (Some(Ok(la)), Some(Ok(lb))) => {
                if la != lb {
                    return Ok(false);
                }
            }
        }
    }
}

fn copy_name<'a, const N: usize>(
    dest: &mut Vec<u8, N>,
    name: impl Iterator<Item = Result<&'a [u8]>>,
) -> Result<()> {
    dest.truncate(0);

    for label in name {
        let label = label?;
        dest.push(label.len() as u8).map_err(|_| Error::Truncated);
        dest.extend_from_slice(label).map_err(|_| Error::Truncated);
    }

    // Write terminator 0x00
    dest.push(0).map_err(|_| Error::Truncated);

    Ok(())
}

// Heads up! Before working on this file you should read, at least, RFC 793 and
// the parts of RFC 1122 that discuss TCP. Consult RFC 7414 when implementing
// a new feature.

#[cfg(feature = "async")]
use core::task::Waker;
use core::{cmp, fmt, mem};

#[cfg(feature = "async")]
use crate::socket::WakerRegistration;
use crate::socket::{Context, PollAt};
use crate::storage::{Assembler, RingBuffer};
use crate::time::{Duration, Instant};
use crate::wire::{
    IpAddress, IpEndpoint, IpProtocol, IpRepr, TcpControl, TcpRepr, TcpSeqNumber, TCP_HEADER_LEN,
};
use crate::{Error, Result};

/// A TCP socket ring buffer.
pub type SocketBuffer<'a> = RingBuffer<'a, u8>;

/// The state of a TCP socket, according to [RFC 793].
///
/// [RFC 793]: https://tools.ietf.org/html/rfc793
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            State::Closed => write!(f, "CLOSED"),
            State::Listen => write!(f, "LISTEN"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::Closing => write!(f, "CLOSING"),
            State::LastAck => write!(f, "LAST-ACK"),
            State::TimeWait => write!(f, "TIME-WAIT"),
        }
    }
}

// Conservative initial RTT estimate.
const RTTE_INITIAL_RTT: u32 = 300;
const RTTE_INITIAL_DEV: u32 = 100;

// Minimum "safety margin" for the RTO that kicks in when the
// variance gets very low.
const RTTE_MIN_MARGIN: u32 = 5;

const RTTE_MIN_RTO: u32 = 10;
const RTTE_MAX_RTO: u32 = 10000;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RttEstimator {
    // Using u32 instead of Duration to save space (Duration is i64)
    rtt: u32,
    deviation: u32,
    timestamp: Option<(Instant, TcpSeqNumber)>,
    max_seq_sent: Option<TcpSeqNumber>,
    rto_count: u8,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            rtt: RTTE_INITIAL_RTT,
            deviation: RTTE_INITIAL_DEV,
            timestamp: None,
            max_seq_sent: None,
            rto_count: 0,
        }
    }
}

impl RttEstimator {
    fn retransmission_timeout(&self) -> Duration {
        let margin = RTTE_MIN_MARGIN.max(self.deviation * 4);
        let ms = (self.rtt + margin).max(RTTE_MIN_RTO).min(RTTE_MAX_RTO);
        Duration::from_millis(ms as u64)
    }

    fn sample(&mut self, new_rtt: u32) {
        // "Congestion Avoidance and Control", Van Jacobson, Michael J. Karels, 1988
        self.rtt = (self.rtt * 7 + new_rtt + 7) / 8;
        let diff = (self.rtt as i32 - new_rtt as i32).abs() as u32;
        self.deviation = (self.deviation * 3 + diff + 3) / 4;

        self.rto_count = 0;

        let rto = self.retransmission_timeout().total_millis();
        net_trace!(
            "rtte: sample={:?} rtt={:?} dev={:?} rto={:?}",
            new_rtt,
            self.rtt,
            self.deviation,
            rto
        );
    }

    fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if self
            .max_seq_sent
            .map(|max_seq_sent| seq > max_seq_sent)
            .unwrap_or(true)
        {
            self.max_seq_sent = Some(seq);
            if self.timestamp.is_none() {
                self.timestamp = Some((timestamp, seq));
                net_trace!("rtte: sampling at seq={:?}", seq);
            }
        }
    }

    fn on_ack(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if let Some((sent_timestamp, sent_seq)) = self.timestamp {
            if seq >= sent_seq {
                self.sample((timestamp - sent_timestamp).total_millis() as u32);
                self.timestamp = None;
            }
        }
    }

    fn on_retransmit(&mut self) {
        if self.timestamp.is_some() {
            net_trace!("rtte: abort sampling due to retransmit");
        }
        self.timestamp = None;
        self.rto_count = self.rto_count.saturating_add(1);
        if self.rto_count >= 3 {
            // This happens in 2 scenarios:
            // - The RTT is higher than the initial estimate
            // - The network conditions change, suddenly making the RTT much higher
            // In these cases, the estimator can get stuck, because it can't sample because
            // all packets sent would incur a retransmit. To avoid this, force an estimate
            // increase if we see 3 consecutive retransmissions without any successful sample.
            self.rto_count = 0;
            self.rtt = RTTE_MAX_RTO.min(self.rtt * 2);
            let rto = self.retransmission_timeout().total_millis();
            net_trace!(
                "rtte: too many retransmissions, increasing: rtt={:?} dev={:?} rto={:?}",
                self.rtt,
                self.deviation,
                rto
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Timer {
    Idle {
        keep_alive_at: Option<Instant>,
    },
    Retransmit {
        expires_at: Instant,
        delay: Duration,
    },
    FastRetransmit,
    Close {
        expires_at: Instant,
    },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);

impl Timer {
    fn new() -> Timer {
        Timer::Idle {
            keep_alive_at: None,
        }
    }

    fn should_keep_alive(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } if timestamp >= keep_alive_at => true,
            _ => false,
        }
    }

    fn should_retransmit(&self, timestamp: Instant) -> Option<Duration> {
        match *self {
            Timer::Retransmit { expires_at, delay } if timestamp >= expires_at => {
                Some(timestamp - expires_at + delay)
            }
            Timer::FastRetransmit => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn should_close(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Close { expires_at } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn poll_at(&self) -> PollAt {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } => PollAt::Time(keep_alive_at),
            Timer::Idle {
                keep_alive_at: None,
            } => PollAt::Ingress,
            Timer::Retransmit { expires_at, .. } => PollAt::Time(expires_at),
            Timer::FastRetransmit => PollAt::Now,
            Timer::Close { expires_at } => PollAt::Time(expires_at),
        }
    }

    fn set_for_idle(&mut self, timestamp: Instant, interval: Option<Duration>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| timestamp + interval),
        }
    }

    fn set_keep_alive(&mut self) {
        if let Timer::Idle {
            ref mut keep_alive_at,
        } = *self
        {
            if keep_alive_at.is_none() {
                *keep_alive_at = Some(Instant::from_millis(0))
            }
        }
    }

    fn rewind_keep_alive(&mut self, timestamp: Instant, interval: Option<Duration>) {
        if let Timer::Idle {
            ref mut keep_alive_at,
        } = *self
        {
            *keep_alive_at = interval.map(|interval| timestamp + interval)
        }
    }

    fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
        match *self {
            Timer::Idle { .. } | Timer::FastRetransmit { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                    delay,
                }
            }
            Timer::Retransmit { expires_at, delay } if timestamp >= expires_at => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                    delay: delay * 2,
                }
            }
            Timer::Retransmit { .. } => (),
            Timer::Close { .. } => (),
        }
    }

    fn set_for_fast_retransmit(&mut self) {
        *self = Timer::FastRetransmit
    }

    fn set_for_close(&mut self, timestamp: Instant) {
        *self = Timer::Close {
            expires_at: timestamp + CLOSE_DELAY,
        }
    }

    fn is_retransmit(&self) -> bool {
        match *self {
            Timer::Retransmit { .. } | Timer::FastRetransmit => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

/// A Transmission Control Protocol socket.
///
/// A TCP socket may passively listen for connections or actively connect to another endpoint.
/// Note that, for listening sockets, there is no "backlog"; to be able to simultaneously
/// accept several connections, as many sockets must be allocated, or any new connection
/// attempts will be reset.
#[derive(Debug)]
pub struct TcpSocket<'a> {
    state: State,
    timer: Timer,
    rtte: RttEstimator,
    assembler: Assembler,
    rx_buffer: SocketBuffer<'a>,
    rx_fin_received: bool,
    tx_buffer: SocketBuffer<'a>,
    /// Interval after which, if no inbound packets are received, the connection is aborted.
    timeout: Option<Duration>,
    /// Interval at which keep-alive packets will be sent.
    keep_alive: Option<Duration>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    /// Address passed to listen(). Listen address is set when listen() is called and
    /// used every time the socket is reset back to the LISTEN state.
    listen_address: IpAddress,
    /// Current local endpoint. This is used for both filtering the incoming packets and
    /// setting the source address. When listening or initiating connection on/from
    /// an unspecified address, this field is updated with the chosen source address before
    /// any packets are sent.
    local_endpoint: IpEndpoint,
    /// Current remote endpoint. This is used for both filtering the incoming packets and
    /// setting the destination address. If the remote endpoint is unspecified, it means that
    /// aborting the connection will not send an RST, and, in TIME-WAIT state, will not
    /// send an ACK.
    remote_endpoint: IpEndpoint,
    /// The sequence number corresponding to the beginning of the transmit buffer.
    /// I.e. an ACK(local_seq_no+n) packet removes n bytes from the transmit buffer.
    local_seq_no: TcpSeqNumber,
    /// The sequence number corresponding to the beginning of the receive buffer.
    /// I.e. userspace reading n bytes adds n to remote_seq_no.
    remote_seq_no: TcpSeqNumber,
    /// The last sequence number sent.
    /// I.e. in an idle socket, local_seq_no+tx_buffer.len().
    remote_last_seq: TcpSeqNumber,
    /// The last acknowledgement number sent.
    /// I.e. in an idle socket, remote_seq_no+rx_buffer.len().
    remote_last_ack: Option<TcpSeqNumber>,
    /// The last window length sent.
    remote_last_win: u16,
    /// The sending window scaling factor advertised to remotes which support RFC 1323.
    /// It is zero if the window <= 64KiB and/or the remote does not support it.
    remote_win_shift: u8,
    /// The remote window size, relative to local_seq_no
    /// I.e. we're allowed to send octets until local_seq_no+remote_win_len
    remote_win_len: usize,
    /// The receive window scaling factor for remotes which support RFC 1323, None if unsupported.
    remote_win_scale: Option<u8>,
    /// Whether or not the remote supports selective ACK as described in RFC 2018.
    remote_has_sack: bool,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss: usize,
    /// The timestamp of the last packet received.
    remote_last_ts: Option<Instant>,
    /// The sequence number of the last packet recived, used for sACK
    local_rx_last_seq: Option<TcpSeqNumber>,
    /// The ACK number of the last packet recived.
    local_rx_last_ack: Option<TcpSeqNumber>,
    /// The number of packets recived directly after
    /// each other which have the same ACK number.
    local_rx_dup_acks: u8,

    /// Duration for Delayed ACK. If None no ACKs will be delayed.
    ack_delay: Option<Duration>,
    /// Delayed ack timer. If set, packets containing exclusively
    /// ACK or window updates (ie, no data) won't be sent until expiry.
    ack_delay_timer: AckDelayTimer,

    /// Used for rate-limiting: No more challenge ACKs will be sent until this instant.
    challenge_ack_timer: Instant,

    /// Nagle's Algorithm enabled.
    nagle: bool,

    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

const DEFAULT_MSS: usize = 536;

impl<'a> TcpSocket<'a> {
    #[allow(unused_comparisons)] // small usize platforms always pass rx_capacity check
    /// Create a socket using the given buffers.
    pub fn new<T>(rx_buffer: T, tx_buffer: T) -> TcpSocket<'a>
    where
        T: Into<SocketBuffer<'a>>,
    {
        let (rx_buffer, tx_buffer) = (rx_buffer.into(), tx_buffer.into());
        let rx_capacity = rx_buffer.capacity();

        // From RFC 1323:
        // [...] the above constraints imply that 2 * the max window size must be less
        // than 2**31 [...] Thus, the shift count must be limited to 14 (which allows
        // windows of 2**30 = 1 Gbyte).
        if rx_capacity > (1 << 30) {
            panic!("receiving buffer too large, cannot exceed 1 GiB")
        }
        let rx_cap_log2 = mem::size_of::<usize>() * 8 - rx_capacity.leading_zeros() as usize;

        TcpSocket {
            state: State::Closed,
            timer: Timer::new(),
            rtte: RttEstimator::default(),
            assembler: Assembler::new(rx_buffer.capacity()),
            tx_buffer,
            rx_buffer,
            rx_fin_received: false,
            timeout: None,
            keep_alive: None,
            hop_limit: None,
            listen_address: IpAddress::default(),
            local_endpoint: IpEndpoint::default(),
            remote_endpoint: IpEndpoint::default(),
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_win: 0,
            remote_win_len: 0,
            remote_win_shift: rx_cap_log2.saturating_sub(16) as u8,
            remote_win_scale: None,
            remote_has_sack: false,
            remote_mss: DEFAULT_MSS,
            remote_last_ts: None,
            local_rx_last_ack: None,
            local_rx_last_seq: None,
            local_rx_dup_acks: 0,
            ack_delay: Some(ACK_DELAY_DEFAULT),
            ack_delay_timer: AckDelayTimer::Idle,
            challenge_ack_timer: Instant::from_secs(0),
            nagle: true,

            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the timeout duration.
    ///
    /// See also the [set_timeout](#method.set_timeout) method.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Return the ACK delay duration.
    ///
    /// See also the [set_ack_delay](#method.set_ack_delay) method.
    pub fn ack_delay(&self) -> Option<Duration> {
        self.ack_delay
    }

    /// Return whether Nagle's Algorithm is enabled.
    ///
    /// See also the [set_nagle_enabled](#method.set_nagle_enabled) method.
    pub fn nagle_enabled(&self) -> Option<Duration> {
        self.ack_delay
    }

    /// Return the current window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    ///
    #[inline]
    fn scaled_window(&self) -> u16 {
        cmp::min(
            self.rx_buffer.window() >> self.remote_win_shift as usize,
            (1 << 16) - 1,
        ) as u16
    }

    /// Set the timeout duration.
    ///
    /// A socket with a timeout duration set will abort the connection if either of the following
    /// occurs:
    ///
    ///   * After a [connect](#method.connect) call, the remote endpoint does not respond within
    ///     the specified duration;
    ///   * After establishing a connection, there is data in the transmit buffer and the remote
    ///     endpoint exceeds the specified duration between any two packets it sends;
    ///   * After enabling [keep-alive](#method.set_keep_alive), the remote endpoint exceeds
    ///     the specified duration between any two packets it sends.
    pub fn set_timeout(&mut self, duration: Option<Duration>) {
        self.timeout = duration
    }

    /// Set the ACK delay duration.
    ///
    /// By default, the ACK delay is set to 10ms.
    pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
        self.ack_delay = duration
    }

    /// Enable or disable Nagle's Algorithm.
    ///
    /// Also known as "tinygram prevention". By default, it is enabled.
    /// Disabling it is equivalent to Linux's TCP_NODELAY flag.
    ///
    /// When enabled, Nagle's Algorithm prevents sending segments smaller than MSS if
    /// there is data in flight (sent but not acknowledged). In other words, it ensures
    /// at most only one segment smaller than MSS is in flight at a time.
    ///
    /// It ensures better network utilization by preventing sending many very small packets,
    /// at the cost of increased latency in some situations, particularly when the remote peer
    /// has ACK delay enabled.
    pub fn set_nagle_enabled(&mut self, enabled: bool) {
        self.nagle = enabled
    }

    /// Return the keep-alive interval.
    ///
    /// See also the [set_keep_alive](#method.set_keep_alive) method.
    pub fn keep_alive(&self) -> Option<Duration> {
        self.keep_alive
    }

    /// Set the keep-alive interval.
    ///
    /// An idle socket with a keep-alive interval set will transmit a "keep-alive ACK" packet
    /// every time it receives no communication during that interval. As a result, three things
    /// may happen:
    ///
    ///   * The remote endpoint is fine and answers with an ACK packet.
    ///   * The remote endpoint has rebooted and answers with an RST packet.
    ///   * The remote endpoint has crashed and does not answer.
    ///
    /// The keep-alive functionality together with the timeout functionality allows to react
    /// to these error conditions.
    pub fn set_keep_alive(&mut self, interval: Option<Duration>) {
        self.keep_alive = interval;
        if self.keep_alive.is_some() {
            // If the connection is idle and we've just set the option, it would not take effect
            // until the next packet, unless we wind up the timer explicitly.
            self.timer.set_keep_alive();
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

    /// Return the local endpoint.
    #[inline]
    pub fn local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    /// Return the remote endpoint.
    #[inline]
    pub fn remote_endpoint(&self) -> IpEndpoint {
        self.remote_endpoint
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    fn reset(&mut self) {
        let rx_cap_log2 =
            mem::size_of::<usize>() * 8 - self.rx_buffer.capacity().leading_zeros() as usize;

        self.state = State::Closed;
        self.timer = Timer::new();
        self.rtte = RttEstimator::default();
        self.assembler = Assembler::new(self.rx_buffer.capacity());
        self.tx_buffer.clear();
        self.rx_buffer.clear();
        self.rx_fin_received = false;
        self.listen_address = IpAddress::default();
        self.local_endpoint = IpEndpoint::default();
        self.remote_endpoint = IpEndpoint::default();
        self.local_seq_no = TcpSeqNumber::default();
        self.remote_seq_no = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_win = 0;
        self.remote_win_len = 0;
        self.remote_win_scale = None;
        self.remote_win_shift = rx_cap_log2.saturating_sub(16) as u8;
        self.remote_mss = DEFAULT_MSS;
        self.remote_last_ts = None;
        self.ack_delay_timer = AckDelayTimer::Idle;
        self.challenge_ack_timer = Instant::from_secs(0);

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    /// Start listening on the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was already open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn listen<T>(&mut self, local_endpoint: T) -> Result<()>
    where
        T: Into<IpEndpoint>,
    {
        let local_endpoint = local_endpoint.into();
        if local_endpoint.port == 0 {
            return Err(Error::Unaddressable);
        }

        if self.is_open() {
            return Err(Error::Illegal);
        }

        self.reset();
        self.listen_address = local_endpoint.addr;
        self.local_endpoint = local_endpoint;
        self.remote_endpoint = IpEndpoint::default();
        self.set_state(State::Listen);
        Ok(())
    }

    /// Connect to a given endpoint.
    ///
    /// The local port must be provided explicitly. Assuming `fn get_ephemeral_port() -> u16`
    /// allocates a port between 49152 and 65535, a connection may be established as follows:
    ///
    /// ```rust,ignore
    /// socket.connect((IpAddress::v4(10, 0, 0, 1), 80), get_ephemeral_port())
    /// ```
    ///
    /// The local address may optionally be provided.
    ///
    /// This function returns an error if the socket was open; see [is_open](#method.is_open).
    /// It also returns an error if the local or remote port is zero, or if the remote address
    /// is unspecified.
    pub fn connect<T, U>(
        &mut self,
        cx: &mut Context,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<()>
    where
        T: Into<IpEndpoint>,
        U: Into<IpEndpoint>,
    {
        let remote_endpoint: IpEndpoint = remote_endpoint.into();
        let mut local_endpoint: IpEndpoint = local_endpoint.into();

        if self.is_open() {
            return Err(Error::Illegal);
        }
        if !remote_endpoint.is_specified() {
            return Err(Error::Unaddressable);
        }
        if local_endpoint.port == 0 {
            return Err(Error::Unaddressable);
        }

        // If local address is not provided, choose it automatically.
        if local_endpoint.addr.is_unspecified() {
            local_endpoint.addr = cx
                .get_source_address(remote_endpoint.addr)
                .ok_or(Error::Unaddressable)?;
        }

        self.reset();
        self.local_endpoint = local_endpoint;
        self.remote_endpoint = remote_endpoint;
        self.set_state(State::SynSent);

        let seq = Self::random_seq_no(cx);
        self.local_seq_no = seq;
        self.remote_last_seq = seq;
        Ok(())
    }

    #[cfg(test)]
    fn random_seq_no(_cx: &mut Context) -> TcpSeqNumber {
        TcpSeqNumber(10000)
    }

    #[cfg(not(test))]
    fn random_seq_no(cx: &mut Context) -> TcpSeqNumber {
        TcpSeqNumber(cx.rand().rand_u32() as i32)
    }

    /// Close the transmit half of the full-duplex connection.
    ///
    /// Note that there is no corresponding function for the receive half of the full-duplex
    /// connection; only the remote end can close it. If you no longer wish to receive any
    /// data and would like to reuse the socket right away, use [abort](#method.abort).
    pub fn close(&mut self) {
        match self.state {
            // In the LISTEN state there is no established connection.
            State::Listen => self.set_state(State::Closed),
            // In the SYN-SENT state the remote endpoint is not yet synchronized and, upon
            // receiving an RST, will abort the connection.
            State::SynSent => self.set_state(State::Closed),
            // In the SYN-RECEIVED, ESTABLISHED and CLOSE-WAIT states the transmit half
            // of the connection is open, and needs to be explicitly closed with a FIN.
            State::SynReceived | State::Established => self.set_state(State::FinWait1),
            State::CloseWait => self.set_state(State::LastAck),
            // In the FIN-WAIT-1, FIN-WAIT-2, CLOSING, LAST-ACK, TIME-WAIT and CLOSED states,
            // the transmit half of the connection is already closed, and no further
            // action is needed.
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck
            | State::Closed => (),
        }
    }

    /// Aborts the connection, if any.
    ///
    /// This function instantly closes the socket. One reset packet will be sent to the remote
    /// endpoint.
    ///
    /// In terms of the TCP state machine, the socket may be in any state and is moved to
    /// the `CLOSED` state.
    pub fn abort(&mut self) {
        self.set_state(State::Closed);
    }

    /// Return whether the socket is passively listening for incoming connections.
    ///
    /// In terms of the TCP state machine, the socket must be in the `LISTEN` state.
    #[inline]
    pub fn is_listening(&self) -> bool {
        match self.state {
            State::Listen => true,
            _ => false,
        }
    }

    /// Return whether the socket is open.
    ///
    /// This function returns true if the socket will process incoming or dispatch outgoing
    /// packets. Note that this does not mean that it is possible to send or receive data through
    /// the socket; for that, use [can_send](#method.can_send) or [can_recv](#method.can_recv).
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`
    /// or `TIME-WAIT` states.
    #[inline]
    pub fn is_open(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            _ => true,
        }
    }

    /// Return whether a connection is active.
    ///
    /// This function returns true if the socket is actively exchanging packets with
    /// a remote endpoint. Note that this does not mean that it is possible to send or receive
    /// data through the socket; for that, use [can_send](#method.can_send) or
    /// [can_recv](#method.can_recv).
    ///
    /// If a connection is established, [abort](#method.close) will send a reset to
    /// the remote endpoint.
    ///
    /// In terms of the TCP state machine, the socket must not be in the `CLOSED`, `TIME-WAIT`,
    /// or `LISTEN` state.
    #[inline]
    pub fn is_active(&self) -> bool {
        match self.state {
            State::Closed => false,
            State::TimeWait => false,
            State::Listen => false,
            _ => true,
        }
    }

    /// Return whether the transmit half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to send data and have it arrive
    /// to the remote endpoint. However, it does not make any guarantees about the state
    /// of the transmit buffer, and even if it returns true, [send](#method.send) may
    /// not be able to enqueue any octets.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED` or
    /// `CLOSE-WAIT` state.
    #[inline]
    pub fn may_send(&self) -> bool {
        match self.state {
            State::Established => true,
            // In CLOSE-WAIT, the remote endpoint has closed our receive half of the connection
            // but we still can transmit indefinitely.
            State::CloseWait => true,
            _ => false,
        }
    }

    /// Return whether the receive half of the full-duplex connection is open.
    ///
    /// This function returns true if it's possible to receive data from the remote endpoint.
    /// It will return true while there is data in the receive buffer, and if there isn't,
    /// as long as the remote endpoint has not closed the connection.
    ///
    /// In terms of the TCP state machine, the socket must be in the `ESTABLISHED`,
    /// `FIN-WAIT-1`, or `FIN-WAIT-2` state, or have data in the receive buffer instead.
    #[inline]
    pub fn may_recv(&self) -> bool {
        match self.state {
            State::Established => true,
            // In FIN-WAIT-1/2, we have closed our transmit half of the connection but
            // we still can receive indefinitely.
            State::FinWait1 | State::FinWait2 => true,
            // If we have something in the receive buffer, we can receive that.
            _ if !self.rx_buffer.is_empty() => true,
            _ => false,
        }
    }

    /// Check whether the transmit half of the full-duplex connection is open
    /// (see [may_send](#method.may_send)), and the transmit buffer is not full.
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.may_send() {
            return false;
        }

        !self.tx_buffer.is_full()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn recv_capacity(&self) -> usize {
        self.rx_buffer.capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn send_capacity(&self) -> usize {
        self.tx_buffer.capacity()
    }

    /// Check whether the receive half of the full-duplex connection buffer is open
    /// (see [may_recv](#method.may_recv)), and the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        if !self.may_recv() {
            return false;
        }

        !self.rx_buffer.is_empty()
    }

    fn send_impl<'b, F, R>(&'b mut self, f: F) -> Result<R>
    where
        F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R),
    {
        if !self.may_send() {
            return Err(Error::Illegal);
        }

        // The connection might have been idle for a long time, and so remote_last_ts
        // would be far in the past. Unless we clear it here, we'll abort the connection
        // down over in dispatch() by erroneously detecting it as timed out.
        if self.tx_buffer.is_empty() {
            self.remote_last_ts = None
        }

        let _old_length = self.tx_buffer.len();
        let (size, result) = f(&mut self.tx_buffer);
        if size > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!(
                "tcp:{}:{}: tx buffer: enqueueing {} octets (now {})",
                self.local_endpoint,
                self.remote_endpoint,
                size,
                _old_length + size
            );
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the transmit buffer,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// This function returns `Err(Error::Illegal)` if the transmit half of
    /// the connection is not open; see [may_send](#method.may_send).
    pub fn send<'b, F, R>(&'b mut self, f: F) -> Result<R>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.send_impl(|tx_buffer| tx_buffer.enqueue_many_with(f))
    }

    /// Enqueue a sequence of octets to be sent, and fill it from a slice.
    ///
    /// This function returns the amount of octets actually enqueued, which is limited
    /// by the amount of free space in the transmit buffer; down to zero.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        self.send_impl(|tx_buffer| {
            let size = tx_buffer.enqueue_slice(data);
            (size, size)
        })
    }

    fn recv_error_check(&mut self) -> Result<()> {
        // We may have received some data inside the initial SYN, but until the connection
        // is fully open we must not dequeue any data, as it may be overwritten by e.g.
        // another (stale) SYN. (We do not support TCP Fast Open.)
        if !self.may_recv() {
            if self.rx_fin_received {
                return Err(Error::Finished);
            }
            return Err(Error::Illegal);
        }

        Ok(())
    }

    fn recv_impl<'b, F, R>(&'b mut self, f: F) -> Result<R>
    where
        F: FnOnce(&'b mut SocketBuffer<'a>) -> (usize, R),
    {
        self.recv_error_check()?;

        let _old_length = self.rx_buffer.len();
        let (size, result) = f(&mut self.rx_buffer);
        self.remote_seq_no += size;
        if size > 0 {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!(
                "tcp:{}:{}: rx buffer: dequeueing {} octets (now {})",
                self.local_endpoint,
                self.remote_endpoint,
                size,
                _old_length - size
            );
        }
        Ok(result)
    }

    /// Call `f` with the largest contiguous slice of octets in the receive buffer,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// This function errors if the receive half of the connection is not open.
    ///
    /// If the receive half has been gracefully closed (with a FIN packet), `Err(Error::Finished)`
    /// is returned. In this case, the previously received data is guaranteed to be complete.
    ///
    /// In all other cases, `Err(Error::Illegal)` is returned and previously received data (if any)
    /// may be incomplete (truncated).
    pub fn recv<'b, F, R>(&'b mut self, f: F) -> Result<R>
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        self.recv_impl(|rx_buffer| rx_buffer.dequeue_many_with(f))
    }

    /// Dequeue a sequence of received octets, and fill a slice from it.
    ///
    /// This function returns the amount of octets actually dequeued, which is limited
    /// by the amount of occupied space in the receive buffer; down to zero.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        self.recv_impl(|rx_buffer| {
            let size = rx_buffer.dequeue_slice(data);
            (size, size)
        })
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and return a pointer to it.
    ///
    /// This function otherwise behaves identically to [recv](#method.recv).
    pub fn peek(&mut self, size: usize) -> Result<&[u8]> {
        self.recv_error_check()?;

        let buffer = self.rx_buffer.get_allocated(0, size);
        if !buffer.is_empty() {
            #[cfg(any(test, feature = "verbose"))]
            net_trace!(
                "tcp:{}:{}: rx buffer: peeking at {} octets",
                self.local_endpoint,
                self.remote_endpoint,
                buffer.len()
            );
        }
        Ok(buffer)
    }

    /// Peek at a sequence of received octets without removing them from
    /// the receive buffer, and fill a slice from it.
    ///
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let buffer = self.peek(data.len())?;
        let data = &mut data[..buffer.len()];
        data.copy_from_slice(buffer);
        Ok(buffer.len())
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Return the amount of octets queued in the receive buffer. This value can be larger than
    /// the slice read by the next `recv` or `peek` call because it includes all queued octets,
    /// and not only the octets that may be returned as a contiguous slice.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.len()
    }

    fn set_state(&mut self, state: State) {
        if self.state != state {
            if self.remote_endpoint.addr.is_unspecified() {
                net_trace!(
                    "tcp:{}: state={}=>{}",
                    self.local_endpoint,
                    self.state,
                    state
                );
            } else {
                net_trace!(
                    "tcp:{}:{}: state={}=>{}",
                    self.local_endpoint,
                    self.remote_endpoint,
                    self.state,
                    state
                );
            }
        }

        self.state = state;

        #[cfg(feature = "async")]
        {
            // Wake all tasks waiting. Even if we haven't received/sent data, this
            // is needed because return values of functions may change depending on the state.
            // For example, a pending read has to fail with an error if the socket is closed.
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    pub(crate) fn reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let reply_repr = TcpRepr {
            src_port: repr.dst_port,
            dst_port: repr.src_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        };
        let ip_reply_repr = IpRepr::new(
            ip_repr.dst_addr(),
            ip_repr.src_addr(),
            IpProtocol::Tcp,
            reply_repr.buffer_len(),
            64,
        );
        (ip_reply_repr, reply_repr)
    }

    pub(crate) fn rst_reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        debug_assert!(repr.control != TcpControl::Rst);

        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // See https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for explanation
        // of why we sometimes send an RST and sometimes an RST|ACK
        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        (ip_reply_repr, reply_repr)
    }

    fn ack_reply(&mut self, ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let (mut ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.remote_last_seq;
        reply_repr.ack_number = Some(self.remote_seq_no + self.rx_buffer.len());
        self.remote_last_ack = reply_repr.ack_number;

        // From RFC 1323:
        // The window field [...] of every outgoing segment, with the exception of SYN
        // segments, is right-shifted by [advertised scale value] bits[...]
        reply_repr.window_len = self.scaled_window();
        self.remote_last_win = reply_repr.window_len;

        // If the remote supports selective acknowledgement, add the option to the outgoing
        // segment.
        if self.remote_has_sack {
            net_debug!("sending sACK option with current assembler ranges");

            // RFC 2018: The first SACK block (i.e., the one immediately following the kind and
            // length fields in the option) MUST specify the contiguous block of data containing
            // the segment which triggered this ACK, unless that segment advanced the
            // Acknowledgment Number field in the header.
            reply_repr.sack_ranges[0] = None;

            if let Some(last_seg_seq) = self.local_rx_last_seq.map(|s| s.0 as u32) {
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data(reply_repr.ack_number.map(|s| s.0 as usize).unwrap_or(0))
                    .map(|(left, right)| (left as u32, right as u32))
                    .find(|(left, right)| *left <= last_seg_seq && *right >= last_seg_seq);
            }

            if reply_repr.sack_ranges[0].is_none() {
                // The matching segment was removed from the assembler, meaning the acknowledgement
                // number has advanced, or there was no previous sACK.
                //
                // While the RFC says we SHOULD keep a list of reported sACK ranges, and iterate
                // through those, that is currently infeasable. Instead, we offer the range with
                // the lowest sequence number (if one exists) to hint at what segments would
                // most quickly advance the acknowledgement number.
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data(reply_repr.ack_number.map(|s| s.0 as usize).unwrap_or(0))
                    .map(|(left, right)| (left as u32, right as u32))
                    .next();
            }
        }

        // Since the sACK option may have changed the length of the payload, update that.
        ip_reply_repr.set_payload_len(reply_repr.buffer_len());
        (ip_reply_repr, reply_repr)
    }

    fn challenge_ack_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if cx.now() < self.challenge_ack_timer {
            return None;
        }

        // Rate-limit to 1 per second max.
        self.challenge_ack_timer = cx.now() + Duration::from_secs(1);

        return Some(self.ack_reply(ip_repr, repr));
    }

    pub(crate) fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state == State::Closed {
            return false;
        }

        // If we're still listening for SYNs and the packet has an ACK, it cannot
        // be destined to this socket, but another one may well listen on the same
        // local endpoint.
        if self.state == State::Listen && repr.ack_number.is_some() {
            return false;
        }

        // Reject packets with a wrong destination.
        if self.local_endpoint.port != repr.dst_port {
            return false;
        }
        if !self.local_endpoint.addr.is_unspecified()
            && self.local_endpoint.addr != ip_repr.dst_addr()
        {
            return false;
        }

        // Reject packets from a source to which we aren't connected.
        if self.remote_endpoint.port != 0 && self.remote_endpoint.port != repr.src_port {
            return false;
        }
        if !self.remote_endpoint.addr.is_unspecified()
            && self.remote_endpoint.addr != ip_repr.src_addr()
        {
            return false;
        }

        true
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Result<Option<(IpRepr, TcpRepr<'static>)>> {
        debug_assert!(self.accepts(cx, ip_repr, repr));

        // Consider how much the sequence number space differs from the transmit buffer space.
        let (sent_syn, sent_fin) = match self.state {
            // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
            State::SynSent | State::SynReceived => (true, false),
            // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
            State::FinWait1 | State::LastAck | State::Closing => (false, true),
            // In all other states we've already got acknowledgemetns for
            // all of the control flags we sent.
            _ => (false, false),
        };
        let control_len = (sent_syn as usize) + (sent_fin as usize);

        // Reject unacceptable acknowledgements.
        match (self.state, repr.control, repr.ack_number) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpControl::Rst, None) => {
                net_debug!(
                    "tcp:{}:{}: unacceptable RST (expecting RST|ACK) \
                            in response to initial SYN",
                    self.local_endpoint,
                    self.remote_endpoint
                );
                return Err(Error::Dropped);
            }
            (State::SynSent, TcpControl::Rst, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!(
                        "tcp:{}:{}: unacceptable RST|ACK in response to initial SYN",
                        self.local_endpoint,
                        self.remote_endpoint
                    );
                    return Err(Error::Dropped);
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpControl::Rst, _) => (),
            // The initial SYN cannot contain an acknowledgement.
            (State::Listen, _, None) => (),
            // This case is handled in `accepts()`.
            (State::Listen, _, Some(_)) => unreachable!(),
            // Every packet after the initial SYN must be an acknowledgement.
            (_, _, None) => {
                net_debug!(
                    "tcp:{}:{}: expecting an ACK",
                    self.local_endpoint,
                    self.remote_endpoint
                );
                return Err(Error::Dropped);
            }
            // SYN|ACK in the SYN-SENT state must have the exact ACK number.
            (State::SynSent, TcpControl::Syn, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!(
                        "tcp:{}:{}: unacceptable SYN|ACK in response to initial SYN",
                        self.local_endpoint,
                        self.remote_endpoint
                    );
                    return Ok(Some(Self::rst_reply(ip_repr, repr)));
                }
            }
            // ACKs in the SYN-SENT state are invalid.
            (State::SynSent, TcpControl::None, Some(ack_number)) => {
                // If the sequence number matches, ignore it instead of RSTing.
                // I'm not sure why, I think it may be a workaround for broken TCP
                // servers, or a defense against reordering. Either way, if Linux
                // does it, we do too.
                if ack_number == self.local_seq_no + 1 {
                    net_debug!(
                        "tcp:{}:{}: expecting a SYN|ACK, received an ACK with the right ack_number, ignoring.",
                                                self.local_endpoint,
                        self.remote_endpoint
                    );
                    return Err(Error::Dropped);
                }

                net_debug!(
                    "tcp:{}:{}: expecting a SYN|ACK, received an ACK with the wrong ack_number, sending RST.",
                                        self.local_endpoint,
                    self.remote_endpoint
                );
                return Ok(Some(Self::rst_reply(ip_repr, repr)));
            }
            // Anything else in the SYN-SENT state is invalid.
            (State::SynSent, _, _) => {
                net_debug!(
                    "tcp:{}:{}: expecting a SYN|ACK",
                    self.local_endpoint,
                    self.remote_endpoint
                );
                return Err(Error::Dropped);
            }
            // ACK in the SYN-RECEIVED state must have the exact ACK number, or we RST it.
            (State::SynReceived, _, Some(ack_number)) => {
                if ack_number != self.local_seq_no + 1 {
                    net_debug!(
                        "tcp:{}:{}: unacceptable ACK in response to SYN|ACK",
                        self.local_endpoint,
                        self.remote_endpoint
                    );
                    return Ok(Some(Self::rst_reply(ip_repr, repr)));
                }
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, _, Some(ack_number)) => {
                let unacknowledged = self.tx_buffer.len() + control_len;

                // Acceptable ACK range (both inclusive)
                let mut ack_min = self.local_seq_no;
                let ack_max = self.local_seq_no + unacknowledged;

                // If we have sent a SYN, it MUST be acknowledged.
                if sent_syn {
                    ack_min += 1;
                }

                if ack_number < ack_min {
                    net_debug!(
                        "tcp:{}:{}: duplicate ACK ({} not in {}...{})",
                        self.local_endpoint,
                        self.remote_endpoint,
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    return Err(Error::Dropped);
                }

                if ack_number > ack_max {
                    net_debug!(
                        "tcp:{}:{}: unacceptable ACK ({} not in {}...{})",
                        self.local_endpoint,
                        self.remote_endpoint,
                        ack_number,
                        ack_min,
                        ack_max
                    );
                    return Ok(self.challenge_ack_reply(cx, ip_repr, repr));
                }
            }
        }

        let window_start = self.remote_seq_no + self.rx_buffer.len();
        let window_end = self.remote_seq_no + self.rx_buffer.capacity();
        let segment_start = repr.seq_number;
        let segment_end = repr.seq_number + repr.segment_len();

        let payload_offset;
        match self.state {
            // In LISTEN and SYN-SENT states, we have not yet synchronized with the remote end.
            State::Listen | State::SynSent => payload_offset = 0,
            // In all other states, segments must occupy a valid portion of the receive window.
            _ => {
                let mut segment_in_window = true;

                if window_start == window_end && segment_start != segment_end {
                    net_debug!(
                        "tcp:{}:{}: non-zero-length segment with zero receive window, \
                                will only send an ACK",
                        self.local_endpoint,
                        self.remote_endpoint
                    );
                    segment_in_window = false;
                }

                if segment_start == segment_end && segment_end == window_start - 1 {
                    net_debug!(
                        "tcp:{}:{}: received a keep-alive or window probe packet, \
                                will send an ACK",
                        self.local_endpoint,
                        self.remote_endpoint
                    );
                    segment_in_window = false;
                } else if !((window_start <= segment_start && segment_start <= window_end)
                    && (window_start <= segment_end && segment_end <= window_end))
                {
                    net_debug!(
                        "tcp:{}:{}: segment not in receive window \
                                ({}..{} not intersecting {}..{}), will send challenge ACK",
                        self.local_endpoint,
                        self.remote_endpoint,
                        segment_start,
                        segment_end,
                        window_start,
                        window_end
                    );
                    segment_in_window = false;
                }

                if segment_in_window {
                    // We've checked that segment_start >= window_start above.
                    payload_offset = (segment_start - window_start) as usize;
                    self.local_rx_last_seq = Some(repr.seq_number);
                } else {
                    // If we're in the TIME-WAIT state, restart the TIME-WAIT timeout, since
                    // the remote end may not have realized we've closed the connection.
                    if self.state == State::TimeWait {
                        self.timer.set_for_close(cx.now());
                    }

                    return Ok(self.challenge_ack_reply(cx, ip_repr, repr));
                }
            }
        }

        // Compute the amount of acknowledged octets, removing the SYN and FIN bits
        // from the sequence space.
        let mut ack_len = 0;
        let mut ack_of_fin = false;
        if repr.control != TcpControl::Rst {
            if let Some(ack_number) = repr.ack_number {
                // Sequence number corresponding to the first byte in `tx_buffer`.
                // This normally equals `local_seq_no`, but is 1 higher if we ahve sent a SYN,
                // as the SYN occupies 1 sequence number "before" the data.
                let tx_buffer_start_seq = self.local_seq_no + (sent_syn as usize);

                if ack_number >= tx_buffer_start_seq {
                    ack_len = ack_number - tx_buffer_start_seq;

                    // We could've sent data before the FIN, so only remove FIN from the sequence
                    // space if all of that data is acknowledged.
                    if sent_fin && self.tx_buffer.len() + 1 == ack_len {
                        ack_len -= 1;
                        net_trace!(
                            "tcp:{}:{}: received ACK of FIN",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                        ack_of_fin = true;
                    }
                }

                self.rtte.on_ack(cx.now(), ack_number);
            }
        }

        // Disregard control flags we don't care about or shouldn't act on yet.
        let mut control = repr.control;
        control = control.quash_psh();

        // If a FIN is received at the end of the current segment but the start of the segment
        // is not at the start of the receive window, disregard this FIN.
        if control == TcpControl::Fin && window_start != segment_start {
            control = TcpControl::None;
        }

        // Validate and update the state.
        match (self.state, control) {
            // RSTs are not accepted in the LISTEN state.
            (State::Listen, TcpControl::Rst) => return Err(Error::Dropped),

            // RSTs in SYN-RECEIVED flip the socket back to the LISTEN state.
            (State::SynReceived, TcpControl::Rst) => {
                net_trace!(
                    "tcp:{}:{}: received RST",
                    self.local_endpoint,
                    self.remote_endpoint
                );
                self.local_endpoint.addr = self.listen_address;
                self.remote_endpoint = IpEndpoint::default();
                self.set_state(State::Listen);
                return Ok(None);
            }

            // RSTs in any other state close the socket.
            (_, TcpControl::Rst) => {
                net_trace!(
                    "tcp:{}:{}: received RST",
                    self.local_endpoint,
                    self.remote_endpoint
                );
                self.set_state(State::Closed);
                self.local_endpoint = IpEndpoint::default();
                self.remote_endpoint = IpEndpoint::default();
                return Ok(None);
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpControl::Syn) => {
                net_trace!("tcp:{}: received SYN", self.local_endpoint);
                if let Some(max_seg_size) = repr.max_seg_size {
                    if max_seg_size == 0 {
                        net_trace!(
                            "tcp:{}:{}: received SYNACK with zero MSS, ignoring",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                        return Ok(None);
                    }
                    self.remote_mss = max_seg_size as usize
                }

                self.local_endpoint = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
                self.remote_endpoint = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);
                self.local_seq_no = Self::random_seq_no(cx);
                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no;
                self.remote_has_sack = repr.sack_permitted;
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }
                self.set_state(State::SynReceived);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpControl::None) => {
                self.set_state(State::Established);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
            // It's not obvious from RFC 793 that this is permitted, but
            // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
            (State::SynReceived, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::CloseWait);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            (State::SynSent, TcpControl::Syn) => {
                net_trace!(
                    "tcp:{}:{}: received SYN|ACK",
                    self.local_endpoint,
                    self.remote_endpoint
                );
                if let Some(max_seg_size) = repr.max_seg_size {
                    if max_seg_size == 0 {
                        net_trace!(
                            "tcp:{}:{}: received SYNACK with zero MSS, ignoring",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                        return Ok(None);
                    }
                    self.remote_mss = max_seg_size as usize;
                }

                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no + 1;
                self.remote_last_ack = Some(repr.seq_number);
                self.remote_win_scale = repr.window_scale;
                // Remote doesn't support window scaling, don't do it.
                if self.remote_win_scale.is_none() {
                    self.remote_win_shift = 0;
                }

                self.set_state(State::Established);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // ACK packets in ESTABLISHED state reset the retransmit timer,
            // except for duplicate ACK packets which preserve it.
            (State::Established, TcpControl::None) => {
                if !self.timer.is_retransmit() || ack_len != 0 {
                    self.timer.set_for_idle(cx.now(), self.keep_alive);
                }
            }

            // FIN packets in ESTABLISHED state indicate the remote side has closed.
            (State::Established, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::CloseWait);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                }
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
            // if they also acknowledge our FIN.
            (State::FinWait1, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(cx.now());
                } else {
                    self.set_state(State::Closing);
                    self.timer.set_for_idle(cx.now(), self.keep_alive);
                }
            }

            // Data packets in FIN-WAIT-2 reset the idle timer.
            (State::FinWait2, TcpControl::None) => {
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
            (State::FinWait2, TcpControl::Fin) => {
                self.remote_seq_no += 1;
                self.rx_fin_received = true;
                self.set_state(State::TimeWait);
                self.timer.set_for_close(cx.now());
            }

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(cx.now());
                } else {
                    self.timer.set_for_idle(cx.now(), self.keep_alive);
                }
            }

            // ACK packets in CLOSE-WAIT state reset the retransmit timer.
            (State::CloseWait, TcpControl::None) => {
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpControl::None) => {
                if ack_of_fin {
                    // Clear the remote endpoint, or we'll send an RST there.
                    self.set_state(State::Closed);
                    self.local_endpoint = IpEndpoint::default();
                    self.remote_endpoint = IpEndpoint::default();
                } else {
                    self.timer.set_for_idle(cx.now(), self.keep_alive);
                }
            }

            _ => {
                net_debug!(
                    "tcp:{}:{}: unexpected packet {}",
                    self.local_endpoint,
                    self.remote_endpoint,
                    repr
                );
                return Err(Error::Dropped);
            }
        }

        // Update remote state.
        self.remote_last_ts = Some(cx.now());

        // RFC 1323: The window field (SEG.WND) in the header of every incoming segment, with the
        // exception of SYN segments, is left-shifted by Snd.Wind.Scale bits before updating SND.WND.
        let scale = match repr.control {
            TcpControl::Syn => 0,
            _ => self.remote_win_scale.unwrap_or(0),
        };
        self.remote_win_len = (repr.window_len as usize) << (scale as usize);

        if ack_len > 0 {
            // Dequeue acknowledged octets.
            debug_assert!(self.tx_buffer.len() >= ack_len);
            net_trace!(
                "tcp:{}:{}: tx buffer: dequeueing {} octets (now {})",
                self.local_endpoint,
                self.remote_endpoint,
                ack_len,
                self.tx_buffer.len() - ack_len
            );
            self.tx_buffer.dequeue_allocated(ack_len);

            // There's new room available in tx_buffer, wake the waiting task if any.
            #[cfg(feature = "async")]
            self.tx_waker.wake();
        }

        if let Some(ack_number) = repr.ack_number {
            // TODO: When flow control is implemented,
            // refractor the following block within that implementation

            // Detect and react to duplicate ACKs by:
            // 1. Check if duplicate ACK and change self.local_rx_dup_acks accordingly
            // 2. If exactly 3 duplicate ACKs recived, set for fast retransmit
            // 3. Update the last received ACK (self.local_rx_last_ack)
            match self.local_rx_last_ack {
                // Duplicate ACK if payload empty and ACK doesn't move send window ->
                // Increment duplicate ACK count and set for retransmit if we just recived
                // the third duplicate ACK
                Some(ref last_rx_ack)
                    if repr.payload.is_empty()
                        && *last_rx_ack == ack_number
                        && ack_number < self.remote_last_seq =>
                {
                    // Increment duplicate ACK count
                    self.local_rx_dup_acks = self.local_rx_dup_acks.saturating_add(1);

                    net_debug!(
                        "tcp:{}:{}: received duplicate ACK for seq {} (duplicate nr {}{})",
                        self.local_endpoint,
                        self.remote_endpoint,
                        ack_number,
                        self.local_rx_dup_acks,
                        if self.local_rx_dup_acks == u8::max_value() {
                            "+"
                        } else {
                            ""
                        }
                    );

                    if self.local_rx_dup_acks == 3 {
                        self.timer.set_for_fast_retransmit();
                        net_debug!(
                            "tcp:{}:{}: started fast retransmit",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                    }
                }
                // No duplicate ACK -> Reset state and update last recived ACK
                _ => {
                    if self.local_rx_dup_acks > 0 {
                        self.local_rx_dup_acks = 0;
                        net_debug!(
                            "tcp:{}:{}: reset duplicate ACK count",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                    }
                    self.local_rx_last_ack = Some(ack_number);
                }
            };
            // We've processed everything in the incoming segment, so advance the local
            // sequence number past it.
            self.local_seq_no = ack_number;
            // During retransmission, if an earlier segment got lost but later was
            // successfully received, self.local_seq_no can move past self.remote_last_seq.
            // Do not attempt to retransmit the latter segments; not only this is pointless
            // in theory but also impossible in practice, since they have been already
            // deallocated from the buffer.
            if self.remote_last_seq < self.local_seq_no {
                self.remote_last_seq = self.local_seq_no
            }
        }

        let payload_len = repr.payload.len();
        if payload_len == 0 {
            return Ok(None);
        }

        let assembler_was_empty = self.assembler.is_empty();

        // Try adding payload octets to the assembler.
        match self.assembler.add(payload_offset, payload_len) {
            Ok(_) => {
                debug_assert!(self.assembler.total_size() == self.rx_buffer.capacity());
                // Place payload octets into the buffer.
                net_trace!(
                    "tcp:{}:{}: rx buffer: receiving {} octets at offset {}",
                    self.local_endpoint,
                    self.remote_endpoint,
                    payload_len,
                    payload_offset
                );
                let len_written = self
                    .rx_buffer
                    .write_unallocated(payload_offset, repr.payload);
                debug_assert!(len_written == payload_len);
            }
            Err(_) => {
                net_debug!(
                    "tcp:{}:{}: assembler: too many holes to add {} octets at offset {}",
                    self.local_endpoint,
                    self.remote_endpoint,
                    payload_len,
                    payload_offset
                );
                return Err(Error::Dropped);
            }
        }

        if let Some(contig_len) = self.assembler.remove_front() {
            debug_assert!(self.assembler.total_size() == self.rx_buffer.capacity());
            // Enqueue the contiguous data octets in front of the buffer.
            net_trace!(
                "tcp:{}:{}: rx buffer: enqueueing {} octets (now {})",
                self.local_endpoint,
                self.remote_endpoint,
                contig_len,
                self.rx_buffer.len() + contig_len
            );
            self.rx_buffer.enqueue_unallocated(contig_len);

            // There's new data in rx_buffer, notify waiting task if any.
            #[cfg(feature = "async")]
            self.rx_waker.wake();
        }

        if !self.assembler.is_empty() {
            // Print the ranges recorded in the assembler.
            net_trace!(
                "tcp:{}:{}: assembler: {}",
                self.local_endpoint,
                self.remote_endpoint,
                self.assembler
            );
        }

        // Handle delayed acks
        if let Some(ack_delay) = self.ack_delay {
            if self.ack_to_transmit() || self.window_to_update() {
                self.ack_delay_timer = match self.ack_delay_timer {
                    AckDelayTimer::Idle => {
                        net_trace!(
                            "tcp:{}:{}: starting delayed ack timer",
                            self.local_endpoint,
                            self.remote_endpoint
                        );

                        AckDelayTimer::Waiting(cx.now() + ack_delay)
                    }
                    // RFC1122 says "in a stream of full-sized segments there SHOULD be an ACK
                    // for at least every second segment".
                    // For now, we send an ACK every second received packet, full-sized or not.
                    AckDelayTimer::Waiting(_) => {
                        net_trace!(
                            "tcp:{}:{}: delayed ack timer already started, forcing expiry",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                        AckDelayTimer::Immediate
                    }
                    AckDelayTimer::Immediate => {
                        net_trace!(
                            "tcp:{}:{}: delayed ack timer already force-expired",
                            self.local_endpoint,
                            self.remote_endpoint
                        );
                        AckDelayTimer::Immediate
                    }
                };
            }
        }

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if !self.assembler.is_empty() || !assembler_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because smoltcp assumes that it can always transmit zero or one
            // packets for every packet it receives.
            net_trace!(
                "tcp:{}:{}: ACKing incoming segment",
                self.local_endpoint,
                self.remote_endpoint
            );
            Ok(Some(self.ack_reply(ip_repr, repr)))
        } else {
            Ok(None)
        }
    }

    fn timed_out(&self, timestamp: Instant) -> bool {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) => timestamp >= remote_last_ts + timeout,
            (_, _) => false,
        }
    }

    fn seq_to_transmit(&self, cx: &mut Context) -> bool {
        let ip_header_len = match self.local_endpoint.addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) => crate::wire::IPV4_HEADER_LEN,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => crate::wire::IPV6_HEADER_LEN,
            IpAddress::Unspecified => unreachable!(),
        };

        // Max segment size we're able to send due to MTU limitations.
        let local_mss = cx.ip_mtu() - ip_header_len - TCP_HEADER_LEN;

        // The effective max segment size, taking into account our and remote's limits.
        let effective_mss = local_mss.min(self.remote_mss);

        // Have we sent data that hasn't been ACKed yet?
        let data_in_flight = self.remote_last_seq != self.local_seq_no;

        // If we want to send a SYN and we haven't done so, do it!
        if matches!(self.state, State::SynSent | State::SynReceived) && !data_in_flight {
            return true;
        }

        // max sequence number we can send.
        let max_send_seq =
            self.local_seq_no + core::cmp::min(self.remote_win_len, self.tx_buffer.len());

        // Max amount of octets we can send.
        let max_send = if max_send_seq >= self.remote_last_seq {
            max_send_seq - self.remote_last_seq
        } else {
            0
        };

        // Can we send at least 1 octet?
        let mut can_send = max_send != 0;
        // Can we send at least 1 full segment?
        let can_send_full = max_send >= effective_mss;

        // Do we have to send a FIN?
        let want_fin = match self.state {
            State::FinWait1 => true,
            State::Closing => true,
            State::LastAck => true,
            _ => false,
        };

        if self.nagle && data_in_flight && !can_send_full {
            can_send = false;
        }

        // Can we actually send the FIN? We can send it if:
        // 1. We have unsent data that fits in the remote window.
        // 2. We have no unsent data.
        // This condition matches only if #2, because #1 is already covered by can_data and we're ORing them.
        let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx_buffer.len();

        can_send || can_fin
    }

    fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
        match self.ack_delay_timer {
            AckDelayTimer::Idle => true,
            AckDelayTimer::Waiting(t) => t <= timestamp,
            AckDelayTimer::Immediate => true,
        }
    }

    fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
        } else {
            false
        }
    }

    fn window_to_update(&self) -> bool {
        match self.state {
            State::SynSent
            | State::SynReceived
            | State::Established
            | State::FinWait1
            | State::FinWait2 => self.scaled_window() > self.remote_last_win,
            _ => false,
        }
    }

    pub(crate) fn dispatch<F>(&mut self, cx: &mut Context, emit: F) -> Result<()>
    where
        F: FnOnce(&mut Context, (IpRepr, TcpRepr)) -> Result<()>,
    {
        if !self.remote_endpoint.is_specified() {
            return Err(Error::Exhausted);
        }

        if self.remote_last_ts.is_none() {
            // We get here in exactly two cases:
            //  1) This socket just transitioned into SYN-SENT.
            //  2) This socket had an empty transmit buffer and some data was added there.
            // Both are similar in that the socket has been quiet for an indefinite
            // period of time, it isn't anymore, and the local endpoint is talking.
            // So, we start counting the timeout not from the last received packet
            // but from the first transmitted one.
            self.remote_last_ts = Some(cx.now());
        }

        // Check if any state needs to be changed because of a timer.
        if self.timed_out(cx.now()) {
            // If a timeout expires, we should abort the connection.
            net_debug!(
                "tcp:{}:{}: timeout exceeded",
                self.local_endpoint,
                self.remote_endpoint
            );
            self.set_state(State::Closed);
        } else if !self.seq_to_transmit(cx) {
            if let Some(retransmit_delta) = self.timer.should_retransmit(cx.now()) {
                // If a retransmit timer expired, we should resend data starting at the last ACK.
                net_debug!(
                    "tcp:{}:{}: retransmitting at t+{}",
                    self.local_endpoint,
                    self.remote_endpoint,
                    retransmit_delta
                );

                // Rewind "last sequence number sent", as if we never
                // had sent them. This will cause all data in the queue
                // to be sent again.
                self.remote_last_seq = self.local_seq_no;

                // Clear the `should_retransmit` state. If we can't retransmit right
                // now for whatever reason (like zero window), this avoids an
                // infinite polling loop where `poll_at` returns `Now` but `dispatch`
                // can't actually do anything.
                self.timer.set_for_idle(cx.now(), self.keep_alive);

                // Inform RTTE, so that it can avoid bogus measurements.
                self.rtte.on_retransmit();
            }
        }

        // Decide whether we're sending a packet.
        if self.seq_to_transmit(cx) {
            // If we have data to transmit and it fits into partner's window, do it.
            net_trace!(
                "tcp:{}:{}: outgoing segment will send data or flags",
                self.local_endpoint,
                self.remote_endpoint
            );
        } else if self.ack_to_transmit() && self.delayed_ack_expired(cx.now()) {
            // If we have data to acknowledge, do it.
            net_trace!(
                "tcp:{}:{}: outgoing segment will acknowledge",
                self.local_endpoint,
                self.remote_endpoint
            );
        } else if self.window_to_update() && self.delayed_ack_expired(cx.now()) {
            // If we have window length increase to advertise, do it.
            net_trace!(
                "tcp:{}:{}: outgoing segment will update window",
                self.local_endpoint,
                self.remote_endpoint
            );
        } else if self.state == State::Closed {
            // If we need to abort the connection, do it.
            net_trace!(
                "tcp:{}:{}: outgoing segment will abort connection",
                self.local_endpoint,
                self.remote_endpoint
            );
        } else if self.timer.should_keep_alive(cx.now()) {
            // If we need to transmit a keep-alive packet, do it.
            net_trace!(
                "tcp:{}:{}: keep-alive timer expired",
                self.local_endpoint,
                self.remote_endpoint
            );
        } else if self.timer.should_close(cx.now()) {
            // If we have spent enough time in the TIME-WAIT state, close the socket.
            net_trace!(
                "tcp:{}:{}: TIME-WAIT timer expired",
                self.local_endpoint,
                self.remote_endpoint
            );
            self.reset();
            return Err(Error::Exhausted);
        } else {
            return Err(Error::Exhausted);
        }

        // Construct the lowered IP representation.
        // We might need this to calculate the MSS, so do it early.
        let mut ip_repr = IpRepr::new(
            self.local_endpoint.addr,
            self.remote_endpoint.addr,
            IpProtocol::Tcp,
            0,
            self.hop_limit.unwrap_or(64),
        );

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port: self.local_endpoint.port,
            dst_port: self.remote_endpoint.port,
            control: TcpControl::None,
            seq_number: self.remote_last_seq,
            ack_number: Some(self.remote_seq_no + self.rx_buffer.len()),
            window_len: self.scaled_window(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        };

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
            }

            // We never transmit anything in the LISTEN state.
            State::Listen => return Err(Error::Exhausted),

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state.
            State::SynSent | State::SynReceived => {
                repr.control = TcpControl::Syn;
                // window len must NOT be scaled in SYNs.
                repr.window_len = self.rx_buffer.window().min((1 << 16) - 1) as u16;
                if self.state == State::SynSent {
                    repr.ack_number = None;
                    repr.window_scale = Some(self.remote_win_shift);
                    repr.sack_permitted = true;
                } else {
                    repr.sack_permitted = self.remote_has_sack;
                    repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
                }
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open.
            State::Established
            | State::FinWait1
            | State::Closing
            | State::CloseWait
            | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.

                // Right edge of window, ie the max sequence number we're allowed to send.
                let win_right_edge = self.local_seq_no + self.remote_win_len;

                // Max amount of octets we're allowed to send according to the remote window.
                let win_limit = if win_right_edge >= self.remote_last_seq {
                    win_right_edge - self.remote_last_seq
                } else {
                    // This can happen if we've sent some data and later the remote side
                    // has shrunk its window so that data is no longer inside the window.
                    // This should be very rare and is strongly discouraged by the RFCs,
                    // but it does happen in practice.
                    // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
                    0
                };

                // Maximum size we're allowed to send. This can be limited by 3 factors:
                // 1. remote window
                // 2. MSS the remote is willing to accept, probably determined by their MTU
                // 3. MSS we can send, determined by our MTU.
                let size = win_limit
                    .min(self.remote_mss)
                    .min(cx.ip_mtu() - ip_repr.buffer_len() - TCP_HEADER_LEN);

                let offset = self.remote_last_seq - self.local_seq_no;
                repr.payload = self.tx_buffer.get_allocated(offset, size);

                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload.len() == self.tx_buffer.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck | State::Closing => {
                            repr.control = TcpControl::Fin
                        }
                        State::Established | State::CloseWait if !repr.payload.is_empty() => {
                            repr.control = TcpControl::Psh
                        }
                        _ => (),
                    }
                }
            }

            // In FIN-WAIT-2 and TIME-WAIT states we may only transmit ACKs for incoming data or FIN
            State::FinWait2 | State::TimeWait => {}
        }

        // There might be more than one reason to send a packet. E.g. the keep-alive timer
        // has expired, and we also have data in transmit buffer. Since any packet that occupies
        // sequence space will elicit an ACK, we only need to send an explicit packet if we
        // couldn't fill the sequence space with anything.
        let is_keep_alive;
        if self.timer.should_keep_alive(cx.now()) && repr.is_empty() {
            repr.seq_number = repr.seq_number - 1;
            repr.payload = b"\x00"; // RFC 1122 says we should do this
            is_keep_alive = true;
        } else {
            is_keep_alive = false;
        }

        // Trace a summary of what will be sent.
        if is_keep_alive {
            net_trace!(
                "tcp:{}:{}: sending a keep-alive",
                self.local_endpoint,
                self.remote_endpoint
            );
        } else if !repr.payload.is_empty() {
            net_trace!(
                "tcp:{}:{}: tx buffer: sending {} octets at offset {}",
                self.local_endpoint,
                self.remote_endpoint,
                repr.payload.len(),
                self.remote_last_seq - self.local_seq_no
            );
        }
        if repr.control != TcpControl::None || repr.payload.is_empty() {
            let flags = match (repr.control, repr.ack_number) {
                (TcpControl::Syn, None) => "SYN",
                (TcpControl::Syn, Some(_)) => "SYN|ACK",
                (TcpControl::Fin, Some(_)) => "FIN|ACK",
                (TcpControl::Rst, Some(_)) => "RST|ACK",
                (TcpControl::Psh, Some(_)) => "PSH|ACK",
                (TcpControl::None, Some(_)) => "ACK",
                _ => "<unreachable>",
            };
            net_trace!(
                "tcp:{}:{}: sending {}",
                self.local_endpoint,
                self.remote_endpoint,
                flags
            );
        }

        if repr.control == TcpControl::Syn {
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            let max_segment_size = cx.ip_mtu() - ip_repr.buffer_len() - TCP_HEADER_LEN;
            repr.max_seg_size = Some(max_segment_size as u16);
        }

        // Actually send the packet. If this succeeds, it means the packet is in
        // the device buffer, and its transmission is imminent. If not, we might have
        // a number of problems, e.g. we need neighbor discovery.
        //
        // Bailing out if the packet isn't placed in the device buffer allows us
        // to not waste time waiting for the retransmit timer on packets that we know
        // for sure will not be successfully transmitted.
        ip_repr.set_payload_len(repr.buffer_len());
        emit(cx, (ip_repr, repr))?;

        // We've sent something, whether useful data or a keep-alive packet, so rewind
        // the keep-alive timer.
        self.timer.rewind_keep_alive(cx.now(), self.keep_alive);

        // Reset delayed-ack timer
        match self.ack_delay_timer {
            AckDelayTimer::Idle => {}
            AckDelayTimer::Waiting(_) => {
                net_trace!(
                    "tcp:{}:{}: stop delayed ack timer",
                    self.local_endpoint,
                    self.remote_endpoint
                )
            }
            AckDelayTimer::Immediate => {
                net_trace!(
                    "tcp:{}:{}: stop delayed ack timer (was force-expired)",
                    self.local_endpoint,
                    self.remote_endpoint
                )
            }
        }
        self.ack_delay_timer = AckDelayTimer::Idle;

        // Leave the rest of the state intact if sending a keep-alive packet, since those
        // carry a fake segment.
        if is_keep_alive {
            return Ok(());
        }

        // We've sent a packet successfully, so we can update the internal state now.
        self.remote_last_seq = repr.seq_number + repr.segment_len();
        self.remote_last_ack = repr.ack_number;
        self.remote_last_win = repr.window_len;

        if repr.segment_len() > 0 {
            self.rtte
                .on_send(cx.now(), repr.seq_number + repr.segment_len());
        }

        if !self.seq_to_transmit(cx) && repr.segment_len() > 0 {
            // If we've transmitted all data we could (and there was something at all,
            // data or flag, to transmit, not just an ACK), wind up the retransmit timer.
            self.timer
                .set_for_retransmit(cx.now(), self.rtte.retransmission_timeout());
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.local_endpoint = IpEndpoint::default();
            self.remote_endpoint = IpEndpoint::default();
        }

        Ok(())
    }

    #[allow(clippy::if_same_then_else)]
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        // The logic here mirrors the beginning of dispatch() closely.
        if !self.remote_endpoint.is_specified() {
            // No one to talk to, nothing to transmit.
            PollAt::Ingress
        } else if self.remote_last_ts.is_none() {
            // Socket stopped being quiet recently, we need to acquire a timestamp.
            PollAt::Now
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            PollAt::Now
        } else if self.seq_to_transmit(cx) {
            // We have a data or flag packet to transmit.
            PollAt::Now
        } else {
            let want_ack = self.ack_to_transmit() || self.window_to_update();

            let delayed_ack_poll_at = match (want_ack, self.ack_delay_timer) {
                (false, _) => PollAt::Ingress,
                (true, AckDelayTimer::Idle) => PollAt::Now,
                (true, AckDelayTimer::Waiting(t)) => PollAt::Time(t),
                (true, AckDelayTimer::Immediate) => PollAt::Now,
            };

            let timeout_poll_at = match (self.remote_last_ts, self.timeout) {
                // If we're transmitting or retransmitting data, we need to poll at the moment
                // when the timeout would expire.
                (Some(remote_last_ts), Some(timeout)) => PollAt::Time(remote_last_ts + timeout),
                // Otherwise we have no timeout.
                (_, _) => PollAt::Ingress,
            };

            // We wait for the earliest of our timers to fire.
            *[self.timer.poll_at(), timeout_poll_at, delayed_ack_poll_at]
                .iter()
                .min()
                .unwrap_or(&PollAt::Ingress)
        }
    }
}

impl<'a> fmt::Write for TcpSocket<'a> {
    fn write_str(&mut self, slice: &str) -> fmt::Result {
        let slice = slice.as_bytes();
        if self.send_slice(slice) == Ok(slice.len()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::{IpAddress, IpRepr};
    use core::i32;
    use std::ops::{Deref, DerefMut};
    use std::vec::Vec;

    // =========================================================================================//
    // Constants
    // =========================================================================================//

    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const LOCAL_END: IpEndpoint = IpEndpoint {
        addr: LOCAL_ADDR.into_address(),
        port: LOCAL_PORT,
    };
    const REMOTE_END: IpEndpoint = IpEndpoint {
        addr: REMOTE_ADDR.into_address(),
        port: REMOTE_PORT,
    };
    const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;
            use crate::wire::Ipv4Repr as IpvXRepr;
            use IpRepr::Ipv4 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress([192, 168, 1, 1]);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress([192, 168, 1, 2]);
            const OTHER_ADDR: IpvXAddress = IpvXAddress([192, 168, 1, 3]);

            const BASE_MSS: u16 = 1460;
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;
            use crate::wire::Ipv6Repr as IpvXRepr;
            use IpRepr::Ipv6 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ]);
            const OTHER_ADDR: IpvXAddress = IpvXAddress([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
            ]);

            const BASE_MSS: u16 = 1440;
        }
    }

    const SEND_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload: &[],
    };
    const _RECV_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        payload: &[],
    };

    // =========================================================================================//
    // Helper functions
    // =========================================================================================//

    struct TestSocket {
        socket: TcpSocket<'static>,
        cx: Context<'static>,
    }

    impl Deref for TestSocket {
        type Target = TcpSocket<'static>;
        fn deref(&self) -> &Self::Target {
            &self.socket
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.socket
        }
    }

    fn send(
        socket: &mut TestSocket,
        timestamp: Instant,
        repr: &TcpRepr,
    ) -> Result<Option<TcpRepr<'static>>> {
        socket.cx.set_now(timestamp);

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });
        net_trace!("send: {}", repr);

        assert!(socket.socket.accepts(&mut socket.cx, &ip_repr, repr));

        match socket.socket.process(&mut socket.cx, &ip_repr, repr) {
            Ok(Some((_ip_repr, repr))) => {
                net_trace!("recv: {}", repr);
                Ok(Some(repr))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
    where
        F: FnMut(Result<TcpRepr>),
    {
        socket.cx.set_now(timestamp);

        let result = socket
            .socket
            .dispatch(&mut socket.cx, |_, (ip_repr, tcp_repr)| {
                assert_eq!(ip_repr.next_header(), IpProtocol::Tcp);
                assert_eq!(ip_repr.src_addr(), LOCAL_ADDR.into());
                assert_eq!(ip_repr.dst_addr(), REMOTE_ADDR.into());
                assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

                net_trace!("recv: {}", tcp_repr);
                Ok(f(Ok(tcp_repr)))
            });
        match result {
            Ok(()) => (),
            Err(e) => f(Err(e)),
        }
    }

    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, Ok(None)));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
    }

    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv!($socket, Err(Error::Exhausted))
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, Instant::from_millis($time), |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
    }

    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => {{
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state, s2.state, "state");
            assert_eq!(s1.listen_address, s2.listen_address, "listen_address");
            assert_eq!(s1.local_endpoint, s2.local_endpoint, "local_endpoint");
            assert_eq!(s1.remote_endpoint, s2.remote_endpoint, "remote_endpoint");
            assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
            assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
            assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_win, s2.remote_last_win, "remote_last_win");
            assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
            assert_eq!(s1.timer, s2.timer, "timer");
        }};
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let rx_buffer = SocketBuffer::new(vec![0; rx_len]);
        let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);
        socket.set_ack_delay(None);
        let cx = Context::mock();
        TestSocket { socket, cx }
    }

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynReceived;
        s.local_endpoint = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no = LOCAL_SEQ;
        s.remote_seq_no = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.remote_win_len = 256;
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynSent;
        s.local_endpoint = LOCAL_END;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_local_ipendpoint(local: IpEndpoint) -> TestSocket {
        let mut s = socket();
        s.state = State::SynSent;
        s.local_endpoint = local;
        s.remote_endpoint = REMOTE_END;
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.state = State::Established;
        s.local_seq_no = LOCAL_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win = 64;
        s
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    fn socket_fin_wait_1() -> TestSocket {
        let mut s = socket_established();
        s.state = State::FinWait1;
        s
    }

    fn socket_fin_wait_2() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::FinWait2;
        s.local_seq_no = LOCAL_SEQ + 1 + 1;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s
    }

    fn socket_closing() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s
    }

    fn socket_time_wait(from_closing: bool) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.state = State::TimeWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer = Timer::Close {
            expires_at: Instant::from_secs(1) + CLOSE_DELAY,
        };
        s
    }

    fn socket_close_wait() -> TestSocket {
        let mut s = socket_established();
        s.state = State::CloseWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    fn socket_last_ack() -> TestSocket {
        let mut s = socket_close_wait();
        s.state = State::LastAck;
        s
    }

    fn socket_recved() -> TestSocket {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//
    fn socket_listen() -> TestSocket {
        let mut s = socket();
        s.state = State::Listen;
        s.local_endpoint = IpEndpoint::new(IpAddress::default(), LOCAL_PORT);
        s
    }

    #[test]
    fn test_listen_sack_option() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );

        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_listen_syn_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.state = State::Listen;
            s.local_endpoint = IpEndpoint::new(IpAddress::default(), LOCAL_PORT);
            assert_eq!(s.remote_win_shift, *shift_amt);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_shift, *shift_amt);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: cmp::min(*buffer_size, 65535) as u16,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_sanity() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        sanity!(s, socket_listen());
    }

    #[test]
    fn test_listen_validation() {
        let mut s = socket();
        assert_eq!(s.listen(0), Err(Error::Unaddressable));
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        assert_eq!(s.listen(80), Err(Error::Illegal));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let mut s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            },
            Err(Error::Dropped)
        );
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win = 58;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);
        assert_eq!(
            s.local_endpoint,
            IpEndpoint::new(IpAddress::Unspecified, LOCAL_END.port)
        );
        assert_eq!(s.remote_endpoint, IpEndpoint::default());
    }

    #[test]
    fn test_syn_received_no_window_scaling() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.local_endpoint(), LOCAL_END);
        assert_eq!(s.remote_endpoint(), REMOTE_END);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
    }

    #[test]
    fn test_syn_received_window_scaling() {
        for scale in 0..14 {
            let mut s = socket_listen();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(scale),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state(), State::SynReceived);
            assert_eq!(s.local_endpoint(), LOCAL_END);
            assert_eq!(s.remote_endpoint(), REMOTE_END);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_scale: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_scale, Some(scale));
        }
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpAddress::Unspecified, 80), LOCAL_END),
            Err(Error::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
            Err(Error::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(Error::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpAddress::Unspecified, 80), LOCAL_END),
            Err(Error::Unaddressable)
        );
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.local_endpoint(), LOCAL_END);
        assert_eq!(s.remote_endpoint(), REMOTE_END);
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.local_endpoint, LOCAL_END);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.local_endpoint, LOCAL_END);
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 80)),
            Ok(())
        );
        s.abort();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpAddress::Unspecified, 80)),
            Ok(())
        );
        s.abort();
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
            Ok(())
        );
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpAddress::Unspecified, 80)),
            Ok(())
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpAddress::Unspecified, 80)),
            Err(Error::Illegal)
        );
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent_with_local_ipendpoint(LOCAL_END));
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv!(s, time 1000, Err(Error::Exhausted));
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            },
            Err(Error::Dropped)
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            },
            Err(Error::Dropped)
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            },
            Err(Error::Dropped)
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            }))
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            }))
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: cmp::min(*buffer_size, 65535) as u16,
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 65535,
                window_scale: Some(5),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
    }

    fn setup_rfc2018_cases() -> (TestSocket, Vec<u8>) {
        // This is a utility function used by the tests for RFC 2018 cases. It configures a socket
        // in a particular way suitable for those cases.
        //
        // RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
        // segments, each containing 500 data bytes.
        let mut s = socket_established_with_buffer_sizes(4000, 4000);
        s.remote_has_sack = true;

        // create a segment that is 500 bytes long
        let mut segment: Vec<u8> = Vec::with_capacity(500);

        // move the last ack to 5000 by sending ten of them
        for _ in 0..50 {
            segment.extend_from_slice(b"abcdefghij")
        }
        for offset in (0..5000).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                    window_len: 3500,
                    ..RECV_TEMPL
                }]
            );
            s.recv(|data| {
                assert_eq!(data.len(), 500);
                assert_eq!(data, segment.as_slice());
                (500, ())
            })
            .unwrap();
        }
        assert_eq!(s.remote_last_win, 3500);
        (s, segment)
    }

    #[test]
    fn test_established_rfc2018_cases() {
        // This test case verifies the exact scenarios described on pages 8-9 of RFC 2018. Please
        // ensure its behavior does not deviate from those scenarios.

        let (mut s, segment) = setup_rfc2018_cases();
        // RFC 2018:
        //
        // Case 2: The first segment is dropped but the remaining 7 are received.
        //
        // Upon receiving each of the last seven packets, the data receiver will return a TCP ACK
        // segment that acknowledges sequence number 5000 and contains a SACK option specifying one
        // block of queued data:
        //
        //   Triggering   ACK      Left Edge  Right Edge
        //   Segment
        //
        //   5000         (lost)
        //   5500         5000     5500       6000
        //   6000         5000     5500       6500
        //   6500         5000     5500       7000
        //   7000         5000     5500       7500
        //   7500         5000     5500       8000
        //   8000         5000     5500       8500
        //   8500         5000     5500       9000
        //
        for offset in (500..3500).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset + 5000,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Ok(Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len: 4000,
                    sack_ranges: [
                        Some((
                            REMOTE_SEQ.0 as u32 + 1 + 5500,
                            REMOTE_SEQ.0 as u32 + 1 + 5500 + offset as u32
                        )),
                        None,
                        None
                    ],
                    ..RECV_TEMPL
                }))
            );
        }
    }

    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established();
        // Update our scaling parameters for a TCP with a scaled buffer.
        assert_eq!(s.rx_buffer.len(), 0);
        s.rx_buffer = SocketBuffer::new(vec![0; 262143]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        s.remote_win_scale = Some(0);
        s.remote_last_win = 65535;
        s.remote_win_shift = 2;

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64 - 6,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            },
            Err(Error::Dropped)
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            },
            Err(Error::Dropped)
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Ok(None)
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_fin_after_missing() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 6),
                window_len: 52,
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );

        assert_eq!(s.state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // Send wrong rst again, check that the challenge ack is correctly updated
        // The ack number must be updated even if we don't call dispatch on the socket
        // See https://github.com/smoltcp-rs/smoltcp/issues/338
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 63,
                ..RECV_TEMPL
            }))
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Ok(Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        })));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, time 60_000, Err(Error::Exhausted));
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received that doesn't ack the FIN: socket should stay in LastAck.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(IpEndpoint::new(IpAddress::default(), LOCAL_PORT))
            .unwrap();
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.local_endpoint(), LOCAL_END);
        assert_eq!(s.remote_endpoint(), REMOTE_END);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }))
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Err(Error::Exhausted));
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Err(Error::Exhausted));

        recv!(s, time 50, Err(Error::Exhausted));

        recv!(s, time 1000, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1550, Err(Error::Exhausted));
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 750, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 2005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 2010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously recived segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously recieved "window_len"
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();
        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Third duplicate ACK
        // Should trigger a fast retransmit of dropped packet
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit packet
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));

        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1115, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // After all was send out, enter *normal* retransmission,
        // don't stay in fast retransmission.
        assert!(match s.timer {
            Timer::Retransmit { expires_at, .. } => expires_at > Instant::from_millis(1115),
            _ => false,
        });

        // ACK all recived segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously recieved segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when reciving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously recived segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when reciving ACK which updates send window"
        );

        // ACK all recived segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::max_value() - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::max_value(),
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv!(s, Err(Error::Exhausted));
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx_buffer = SocketBuffer::new(vec![0; 32767]);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(1000),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv!(s, Err(Error::Exhausted));
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv!(s, Err(Error::Exhausted));
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }))
        );
    }

    #[test]
    fn test_zero_window_ack_on_window_growth() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        recv!(s, time 0, Err(Error::Exhausted));
        s.recv(|buffer| {
            assert_eq!(&buffer[..3], b"abc");
            (3, ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 3,
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Err(Error::Exhausted));
        s.recv(|buffer| {
            assert_eq!(buffer, b"def");
            (buffer.len(), ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 6,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_announce_window_after_read() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 3,
                ..RECV_TEMPL
            }]
        );
        // Test that `dispatch` updates `remote_last_win`
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        // Provoke immediate ACK to test that `process` updates `remote_last_win`
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            }))
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 0,
                ..RECV_TEMPL
            }))
        );
        assert_eq!(s.remote_last_win, s.rx_buffer.window() as u16);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_listen_timeout() {
        let mut s = socket_listen();
        s.set_timeout(Some(Duration::from_millis(100)));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::SynSent);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(250))
        );
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            window_scale: None,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 250, Err(Error::Exhausted));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(1250))
        );
        s.send_slice(b"abcdef").unwrap();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(955))
        );
        recv!(s, time 955, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(1255))
        );
        recv!(s, time 1255, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(50)));
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv!(s, time 100, Err(Error::Exhausted));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(150))
        );
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(155))
        );
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv!(s, time 155, Err(Error::Exhausted));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(205))
        );
        recv!(s, time 200, Err(Error::Exhausted));
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 205, Err(Error::Exhausted));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(200)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.abort();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(100)));

        // drain the forced keep-alive packet
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(100))
        );
        recv!(s, time 95, Err(Error::Exhausted));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(200))
        );
        recv!(s, time 195, Err(Error::Exhausted));
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(350))
        );
        recv!(s, time 345, Err(Error::Exhausted));
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.set_hop_limit(Some(0x2a));
        assert_eq!(
            s.socket.dispatch(&mut s.cx, |_, (ip_repr, _)| {
                assert_eq!(ip_repr.hop_limit(), 0x2a);
                Ok(())
            }),
            Ok(())
        );

        // assert that user-configurable settings are kept,
        // see https://github.com/smoltcp-rs/smoltcp/issues/601.
        s.reset();
        assert_eq!(s.hop_limit(), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }))
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }))
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abcdef");
            (buffer.len(), ())
        })
        .unwrap();
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abc");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"defghi"[..],
                ..SEND_TEMPL
            }
        );
        let mut data = [0; 6];
        assert_eq!(s.recv_slice(&mut data[..]), Ok(6));
        assert_eq!(data, &b"defghi"[..]);
    }

    #[test]
    fn test_buffer_wraparound_tx() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);

        s.tx_buffer = SocketBuffer::new(vec![b'.'; 9]);
        assert_eq!(s.send_slice(b"xxxyyy"), Ok(6));
        assert_eq!(s.tx_buffer.dequeue_many(3), &b"xxx"[..]);
        assert_eq!(s.tx_buffer.len(), 3);

        // "abcdef" not contiguous in tx buffer
        assert_eq!(s.send_slice(b"abcdef"), Ok(6));
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"yyyabc"[..],
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"def"[..],
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(Error::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(Error::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(Error::Finished));
    }

    #[test]
    fn test_rx_close_fin_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            }))
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        s.recv(|data| {
            assert_eq!(data, b"");
            (0, ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Error must be `Illegal` even if we've received a FIN,
        // because we are missing data.
        assert_eq!(s.recv(|_| (0, ())), Err(Error::Illegal));
    }

    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(Error::Illegal));
    }

    #[test]
    fn test_rx_close_rst_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Ok(Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            }))
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(Error::Illegal));
    }

    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv!(s, Err(Error::Exhausted));

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // However, no ACK or window update is immediately sent.
        recv!(s, Err(Error::Exhausted));

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        s.send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_second_packet() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv!(s, Err(Error::Exhausted));

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            }
        );

        // Every 2nd packet, ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_three_packets() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv!(s, Err(Error::Exhausted));

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            }
        );

        // Every 2nd (or more) packet, ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 55,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for Nagle's Algorithm
    // =========================================================================================//

    #[test]
    fn test_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;

        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        // If there's data in flight, full segments get sent.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );

        s.send_slice(b"aaabbbccc").unwrap();
        // If there's data in flight, not-full segments don't get sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaabbb"[..],
                ..RECV_TEMPL
            }]
        );

        // Data gets ACKd, so there's no longer data in flight
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
                ..SEND_TEMPL
            }
        );

        // Now non-full segment gets sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"ccc"[..],
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = SocketBuffer::new(vec![0; 6]);
        s.assembler = Assembler::new(s.rx_buffer.capacity());

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert_eq!(r.should_retransmit(Instant::from_secs(1)), None);
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert_eq!(r.should_retransmit(Instant::from_millis(1000)), None);
        assert_eq!(r.should_retransmit(Instant::from_millis(1050)), None);
        assert_eq!(
            r.should_retransmit(Instant::from_millis(1101)),
            Some(Duration::from_millis(101))
        );
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert_eq!(r.should_retransmit(Instant::from_millis(1101)), None);
        assert_eq!(r.should_retransmit(Instant::from_millis(1150)), None);
        assert_eq!(r.should_retransmit(Instant::from_millis(1200)), None);
        assert_eq!(
            r.should_retransmit(Instant::from_millis(1301)),
            Some(Duration::from_millis(300))
        );
        r.set_for_idle(Instant::from_millis(1301), None);
        assert_eq!(r.should_retransmit(Instant::from_millis(1350)), None);
    }

    #[test]
    fn test_rtt_estimator() {
        let mut r = RttEstimator::default();

        let rtos = &[
            751, 766, 755, 731, 697, 656, 613, 567, 523, 484, 445, 411, 378, 350, 322, 299, 280,
            261, 243, 229, 215, 206, 197, 188,
        ];

        for &rto in rtos {
            r.sample(100);
            assert_eq!(r.retransmission_timeout(), Duration::from_millis(rto));
        }
    }
}

use std::collections::VecDeque;

use smoltcp::iface::*;
use smoltcp::phy::{ChecksumCapabilities, PcapLinkType, PcapSink};
use smoltcp::time::*;
use smoltcp::wire::*;

const TRANSMIT_SPEED: f32 = 250_000. / 8.;

pub fn topology(
    mut sim: NetworkSim,
    mop: RplModeOfOperation,
    nodes: usize,
    levels: usize,
) -> NetworkSim {
    let pos = Position((0., 0.));
    let root = sim.create_node(RplConfig::new(mop).add_root_config(RplRootConfig::new(
        RplInstanceId::from(30),
        Ipv6Address::default(),
    )));
    root.set_position(pos);

    let interval = (360. / 180. * std::f64::consts::PI / nodes as f64) as f32;
    for level in 0..levels {
        for node in 0..nodes {
            let node_p = (
                pos.x() + 100. * f32::cos(interval * node as f32) * (level + 1) as f32,
                pos.y() + 100. * f32::sin(interval * node as f32) * (level + 1) as f32,
            );
            let node = sim.create_node(RplConfig::new(mop));
            node.set_position(node_p.into());
        }
    }

    sim
}

pub fn udp_receiver_node(node: &mut Node, port: u16) {
    node.set_init(Box::new(|s| {
        let udp_rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY],
            vec![0; 1280],
        );
        let udp_tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY],
            vec![0; 1280],
        );
        let udp_socket = smoltcp::socket::udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

        vec![s.add(udp_socket)]
    }));

    node.set_application(Box::new(move |instant, sockets, handles, _| {
        let socket = sockets.get_mut::<smoltcp::socket::udp::Socket>(handles[0]);
        if !socket.is_open() {
            socket.bind(port).unwrap();
        }
    }));
}

pub fn udp_sender_node(node: &mut Node, port: u16, addr: Ipv6Address) {
    node.set_init(Box::new(|s| {
        let udp_rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY],
            vec![0; 1280],
        );
        let udp_tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY],
            vec![0; 1280],
        );
        let udp_socket = smoltcp::socket::udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

        vec![s.add(udp_socket)]
    }));

    node.set_application(Box::new(
        move |instant, sockets, handles, last_transmitted| {
            let socket = sockets.get_mut::<smoltcp::socket::udp::Socket>(handles[0]);
            if !socket.is_open() {
                socket.bind(port).unwrap();
            }

            if socket.can_send() && instant - *last_transmitted >= Duration::from_secs(60) {
                if let Ok(()) = socket.send_slice(
                    b"Hello World",
                    smoltcp::wire::IpEndpoint {
                        addr: addr.into(),
                        port,
                    },
                ) {
                    *last_transmitted = instant;
                }
            }
        },
    ));
}

#[derive(Debug)]
pub struct NetworkSim {
    pub nodes: Vec<Node>,
    pub messages: Vec<Message>,
    pub now: Instant,
}

impl Default for NetworkSim {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkSim {
    /// Create a new network simulation.
    pub fn new() -> Self {
        Self {
            nodes: vec![],
            messages: vec![],
            now: Instant::ZERO,
        }
    }

    pub fn add_node(&mut self, rpl: RplConfig) {
        _ = self.create_node(rpl);
    }

    /// Create a new node.
    pub fn create_node(&mut self, rpl: smoltcp::iface::RplConfig) -> &mut Node {
        let id = self.nodes.len();
        let node = Node::new(id, rpl);

        self.nodes.push(node);

        &mut self.nodes[id]
    }

    /// Get the nodes.
    pub fn get_nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Get the nodes.
    pub fn get_nodes_mut(&mut self) -> &mut [Node] {
        &mut self.nodes
    }

    /// Get a node from an IP address.
    pub fn get_node_from_ip_address(&self, address: smoltcp::wire::Ipv6Address) -> Option<&Node> {
        self.nodes.iter().find(|&node| node.ip_address == address)
    }

    /// Search for a node with a specific IEEE address and PAN ID.
    pub fn get_node_from_ieee(&self, destination: Ieee802154Address) -> Option<&Node> {
        self.nodes
            .iter()
            .find(|node| node.ieee_address == destination)
    }

    /// Search for a node with a specific IEEE address and PAN ID.
    fn get_node_from_ieee_mut(&mut self, destination: Ieee802154Address) -> Option<&mut Node> {
        self.nodes
            .iter_mut()
            .find(|node| node.ieee_address == destination)
    }

    /// Initialize the simulation.
    pub fn init(&mut self) {
        for node in &mut self.nodes {
            if let Some(init) = &node.init {
                let handles = init(&mut node.sockets);
                node.socket_handles = handles;
            }
        }
    }

    pub fn run(&mut self, step: Duration, duration: Duration) {
        let start = self.now;
        while self.now < start + duration {
            let (new_step, _, _) = self.on_tick(self.now, step);

            if new_step == Duration::ZERO {
                self.now += Duration::from_millis(1);
            } else if new_step <= step {
                self.now += new_step;
            } else {
                self.now += step;
            }
        }
    }

    /// Run the simulation.
    pub fn on_tick(
        &mut self,
        now: Instant,
        mut step: Duration,
    ) -> (Duration, Vec<Message>, Vec<Message>) {
        for node in &mut self.nodes {
            if node.enabled {
                if let Some(application) = &node.application {
                    application(
                        now,
                        &mut node.sockets,
                        &mut node.socket_handles,
                        &mut node.last_transmitted,
                    );
                }
            }
        }

        // Check for messages that need to be send between nodes.
        let mut unicast_msgs = vec![];
        let mut broadcast_msgs: Vec<Message> = vec![];

        for node in &mut self.nodes {
            if node.is_sending && node.sent_at < Instant::now() - Duration::from_millis(100) {
                node.is_sending = false;
            }
        }

        for node in &mut self.nodes {
            if node.enabled {
                if let Some(msg) = node.peek_tx_message() {
                    let delta =
                        Duration::from_secs((msg.data.len() as f32 / TRANSMIT_SPEED) as u64);

                    if now >= msg.at + delta {
                        let msg = node.get_tx_message().unwrap();

                        if msg.is_broadcast() {
                            node.is_sending = true;
                            node.sent_at = Instant::now();
                            broadcast_msgs.push(msg.clone());
                            self.messages.push(msg);
                        } else {
                            unicast_msgs.push(msg.clone());
                            self.messages.push(msg);
                        }
                    }
                }
            }
        }

        // Distribute all the broadcast messages.
        for msg in &broadcast_msgs {
            for node in self.nodes.iter_mut() {
                if node.enabled
                    && node.id != msg.from.0
                    && node.position.distance(&msg.from.1) < node.range
                {
                    node.receive_message(msg.clone());
                }
            }
        }

        // Check if messages can arrive at their destination.
        for msg in &unicast_msgs {
            let to_node = self.get_node_from_ieee_mut(msg.to).unwrap();

            if to_node.enabled && to_node.position.distance(&msg.from.1) < to_node.range {
                to_node.receive_message(msg.clone());
            }
        }

        // Poll the interfaces of the nodes.
        for node in &mut self.nodes {
            if node.enabled {
                let Node {
                    device,
                    interface,
                    sockets,
                    next_poll,
                    ..
                } = node;

                if next_poll.unwrap_or_else(|| now) <= now {
                    interface.poll(now, device, sockets);
                }

                if let Some(new_step) = interface.poll_delay(now, sockets) {
                    step = step.min(new_step);
                }
            }
        }

        (step, broadcast_msgs, unicast_msgs)
    }

    pub fn save_pcap(&self, path: &std::path::Path) -> std::io::Result<()> {
        let mut pcap_file = std::fs::File::create(path)?;
        PcapSink::global_header(&mut pcap_file, PcapLinkType::Ieee802154WithoutFcs);

        for msg in &self.messages {
            PcapSink::packet(&mut pcap_file, msg.at, &msg.data);
        }

        Ok(())
    }
}

pub struct Node {
    pub id: usize,
    pub range: f32,
    pub position: Position,
    pub enabled: bool,
    pub is_sending: bool,
    pub parent_changed: bool,
    pub previous_parent: Option<Ipv6Address>,
    pub sent_at: Instant,
    pub ieee_address: Ieee802154Address,
    pub ip_address: Ipv6Address,
    pub pan_id: Ieee802154Pan,
    pub device: NodeDevice,
    pub last_transmitted: Instant,
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    pub socket_handles: Vec<SocketHandle>,
    pub init:
        Option<Box<dyn Fn(&mut SocketSet<'static>) -> Vec<SocketHandle> + Send + Sync + 'static>>,
    pub application: Option<
        Box<
            dyn Fn(Instant, &mut SocketSet<'static>, &mut Vec<SocketHandle>, &mut Instant)
                + Send
                + Sync
                + 'static,
        >,
    >,
    pub next_poll: Option<Instant>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("id", &self.id)
            .field("range", &self.range)
            .field("position", &self.position)
            .field("enabled", &self.enabled)
            .field("is_sending", &self.is_sending)
            .field("parent_changed", &self.parent_changed)
            .field("previous_parent", &self.previous_parent)
            .field("sent_at", &self.sent_at)
            .field("ieee_address", &self.ieee_address)
            .field("ip_address", &self.ip_address)
            .field("pan_id", &self.pan_id)
            .field("sockets", &self.sockets)
            .field("socket_handles", &self.socket_handles)
            .field("next_poll", &self.next_poll)
            .finish()
    }
}

impl Node {
    pub fn new_default(id: usize) -> Self {
        Self::new(
            id,
            RplConfig::new(RplModeOfOperation::NoDownwardRoutesMaintained),
        )
    }

    /// Create a new node.
    pub fn new(id: usize, mut rpl: RplConfig) -> Self {
        let mut device = NodeDevice::new(id, Position::from((0., 0.)));

        let ieee_address = Ieee802154Address::Extended((id as u64 + 1).to_be_bytes());
        let ipv6_address = ieee_address.as_link_local_address().unwrap();

        let rpl = if let Some(ref mut root) = rpl.root {
            root.dodag_id = ipv6_address;
            rpl
        } else {
            rpl
        };

        let mut config = Config::new(ieee_address.into());
        config.pan_id = Some(Ieee802154Pan(0xbeef));
        config.rpl_config = Some(rpl);
        config.random_seed = Instant::now().total_micros() as u64;

        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::Ipv6(Ipv6Cidr::new(ipv6_address, 10)))
                .unwrap();
        });

        Self {
            id: id as usize,
            range: 101.,
            position: Position::from((0., 0.)),
            enabled: true,
            is_sending: false,
            parent_changed: false,
            previous_parent: None,
            sent_at: Instant::now(),
            ieee_address,
            ip_address: ipv6_address,
            pan_id: Ieee802154Pan(0xbeef),
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            socket_handles: vec![],
            init: None,
            application: None,
            next_poll: Some(Instant::ZERO),
            last_transmitted: Instant::ZERO,
        }
    }

    /// Set the position of the node.
    pub fn set_position(&mut self, position: Position) {
        self.position = position;
        self.device.position = position;
    }

    /// Set the IEEE802.15.4 address of the node.
    pub fn set_ieee_address(&mut self, address: Ieee802154Address) {
        self.ieee_address = address;
        self.ip_address = address.as_link_local_address().unwrap();
        self.interface.set_hardware_addr(address.into());
        self.interface.update_ip_addrs(|addresses| {
            addresses[0] = IpCidr::Ipv6(Ipv6Cidr::new(self.ip_address, 128));
        });
    }

    /// Set the PAN id of the node.
    pub fn set_pan_id(&mut self, pan: Ieee802154Pan) {
        self.pan_id = pan;
    }

    pub fn set_ip_address(&mut self, address: IpCidr) {
        self.interface.update_ip_addrs(|ip_addrs| {
            *ip_addrs.first_mut().unwrap() = address;
        });
    }

    /// Add a message to the list of messages the node is sending.
    pub fn send_message(&mut self, msg: Message) {
        self.device.tx_queue.push_back(msg);
    }

    /// Accept a message that was send to this node.
    pub(crate) fn receive_message(&mut self, msg: Message) {
        self.device.rx_queue.push_back(msg);
    }

    /// Check if the node has data to send.
    pub(crate) fn needs_to_send(&self) -> bool {
        !self.device.tx_queue.is_empty()
    }

    /// Peek a message that needs to be send.
    pub(crate) fn peek_tx_message(&mut self) -> Option<&Message> {
        self.device.tx_queue.front()
    }

    /// Get a message that needs to be send.
    pub(crate) fn get_tx_message(&mut self) -> Option<Message> {
        self.device.tx_queue.pop_front()
    }

    pub fn set_init(
        &mut self,
        init: Box<dyn Fn(&mut SocketSet) -> Vec<SocketHandle> + Send + Sync>,
    ) {
        self.init = Some(init);
    }

    pub fn set_application(
        &mut self,
        application: Box<
            dyn Fn(Instant, &mut SocketSet<'static>, &mut Vec<SocketHandle>, &mut Instant)
                + Send
                + Sync
                + 'static,
        >,
    ) {
        self.application = Some(application);
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

pub struct NodeDevice {
    pub id: usize,
    pub position: Position,
    pub rx_queue: VecDeque<Message>,
    pub tx_queue: VecDeque<Message>,
}

impl NodeDevice {
    pub fn new(id: usize, position: Position) -> Self {
        Self {
            id,
            position,
            rx_queue: Default::default(),
            tx_queue: Default::default(),
        }
    }
}

impl smoltcp::phy::Device for NodeDevice {
    type RxToken<'a> = RxToken where Self: 'a;
    type TxToken<'a> = TxToken<'a> where Self: 'a;

    fn receive(&mut self, timestamp: Instant) -> Option<(RxToken, TxToken)> {
        if let Some(data) = self.rx_queue.pop_front() {
            Some((
                RxToken {
                    buffer: data.data,
                    timestamp,
                },
                TxToken {
                    buffer: &mut self.tx_queue,
                    node_id: self.id,
                    position: self.position,
                    timestamp,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<TxToken> {
        Some(TxToken {
            buffer: &mut self.tx_queue,
            node_id: self.id,
            position: self.position,
            timestamp,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ieee802154;
        caps.max_transmission_unit = 125;
        caps
    }
}

pub struct RxToken {
    buffer: Vec<u8>,
    timestamp: Instant,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TxToken<'v> {
    buffer: &'v mut VecDeque<Message>,
    node_id: usize,
    position: Position,
    timestamp: Instant,
}

impl<'v> smoltcp::phy::TxToken for TxToken<'v> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let r = f(&mut buffer);

        let packet = Ieee802154Frame::new_unchecked(&buffer);
        let repr = Ieee802154Repr::parse(&packet).unwrap();

        self.buffer.push_back(Message {
            at: self.timestamp,
            to: repr.dst_addr.unwrap(),
            from: (self.node_id, self.position),
            data: buffer,
        });

        r
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub struct Position(pub (f32, f32));

impl Position {
    pub fn distance(&self, other: &Self) -> f32 {
        ((other.0 .0 - self.0 .0).powf(2.0) + (other.0 .1 - self.0 .1).powf(2.0)).sqrt()
    }

    pub fn x(&self) -> f32 {
        self.0 .0
    }

    pub fn y(&self) -> f32 {
        self.0 .1
    }
}

impl From<(f32, f32)> for Position {
    fn from(pos: (f32, f32)) -> Self {
        Position(pos)
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub at: Instant,
    pub to: Ieee802154Address,
    pub from: (usize, Position),
    pub data: Vec<u8>,
}

impl Message {
    pub fn is_broadcast(&self) -> bool {
        self.to == Ieee802154Address::BROADCAST
    }

    pub fn udp(&self) -> Result<Option<SixlowpanUdpNhcRepr>> {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data)?;
        let lowpan = SixlowpanIphcPacket::new_checked(ieee802154.payload().ok_or(Error)?)?;
        let src_addr = lowpan.src_addr()?.resolve(ieee802154.src_addr(), &[])?;
        let dst_addr = lowpan.dst_addr()?.resolve(ieee802154.src_addr(), &[])?;

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();
        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload)?;
                        next_hdr = ext_hdr.next_header();
                        payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                        continue;
                    }
                    SixlowpanNhcPacket::UdpHeader => {
                        let udp = SixlowpanUdpNhcPacket::new_checked(payload)?;
                        return Ok(Some(SixlowpanUdpNhcRepr::parse(
                            &udp,
                            &src_addr.into(),
                            &dst_addr.into(),
                            &ChecksumCapabilities::ignored(),
                        )?));
                    }
                },
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => return Ok(None),
                _ => unreachable!(),
            };
        }
    }

    pub fn icmp(&self) -> Result<Option<Icmpv6Repr<'_>>> {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data)?;
        let lowpan = SixlowpanIphcPacket::new_checked(ieee802154.payload().ok_or(Error)?)?;
        let src_addr = lowpan.src_addr()?.resolve(ieee802154.src_addr(), &[])?;
        let dst_addr = lowpan.dst_addr()?.resolve(ieee802154.src_addr(), &[])?;

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();
        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload)?;
                        next_hdr = ext_hdr.next_header();
                        payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                        continue;
                    }
                    SixlowpanNhcPacket::UdpHeader => return Ok(None),
                },
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                    let icmp = Icmpv6Packet::new_checked(payload).unwrap();

                    return Ok(Some(Icmpv6Repr::parse(
                        &src_addr.into(),
                        &dst_addr.into(),
                        &icmp,
                        &ChecksumCapabilities::ignored(),
                    )?));
                }
                _ => unreachable!(),
            };
        }
    }

    pub fn has_routing(&self) -> Result<bool> {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data)?;
        let lowpan = SixlowpanIphcPacket::new_checked(ieee802154.payload().ok_or(Error)?)?;
        let src_addr = lowpan.src_addr()?.resolve(ieee802154.src_addr(), &[])?;
        let dst_addr = lowpan.dst_addr()?.resolve(ieee802154.src_addr(), &[])?;

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();

        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload)?;
                        if ext_hdr.extension_header_id() == SixlowpanExtHeaderId::RoutingHeader {
                            return Ok(true);
                        }
                        next_hdr = ext_hdr.next_header();
                        payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                        continue;
                    }
                    SixlowpanNhcPacket::UdpHeader => return Ok(false),
                },
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                    return Ok(false);
                }
                _ => unreachable!(),
            };
        }

        Ok(false)
    }

    pub fn has_hbh(&self) -> Result<bool> {
        let ieee802154 = Ieee802154Frame::new_checked(&self.data)?;
        let lowpan = SixlowpanIphcPacket::new_checked(ieee802154.payload().ok_or(Error)?)?;
        let src_addr = lowpan.src_addr()?.resolve(ieee802154.src_addr(), &[])?;
        let dst_addr = lowpan.dst_addr()?.resolve(ieee802154.src_addr(), &[])?;

        let mut payload = lowpan.payload();
        let mut next_hdr = lowpan.next_header();

        loop {
            match next_hdr {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(payload)?;
                        if ext_hdr.extension_header_id() == SixlowpanExtHeaderId::HopByHopHeader {
                            return Ok(true);
                        }
                        next_hdr = ext_hdr.next_header();
                        payload = &payload[ext_hdr.header_len() + ext_hdr.payload().len()..];
                        continue;
                    }
                    SixlowpanNhcPacket::UdpHeader => return Ok(false),
                },
                SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6) => {
                    return Ok(false);
                }
                _ => unreachable!(),
            };
        }

        Ok(false)
    }

    pub fn is_udp(&self) -> Result<bool> {
        Ok(matches!(self.udp()?, Some(SixlowpanUdpNhcRepr(_))))
    }

    pub fn is_dis(&self) -> Result<bool> {
        Ok(matches!(
            self.icmp()?,
            Some(Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation(_)))
        ))
    }

    pub fn is_dio(&self) -> Result<bool> {
        Ok(matches!(
            self.icmp()?,
            Some(Icmpv6Repr::Rpl(RplRepr::DodagInformationObject(_)))
        ))
    }

    pub fn is_dao(&self) -> Result<bool> {
        Ok(matches!(
            self.icmp()?,
            Some(Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject(_)))
        ))
    }

    pub fn is_dao_ack(&self) -> Result<bool> {
        Ok(matches!(
            self.icmp()?,
            Some(Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObjectAck(
                _
            )))
        ))
    }
}

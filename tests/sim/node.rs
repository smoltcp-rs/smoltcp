use super::Message;
use super::Position;
use smoltcp::iface::*;
use smoltcp::time::*;
use smoltcp::wire::*;
use std::collections::VecDeque;
use std::fmt::Display;

type InitFn = Box<dyn Fn(&mut SocketSet<'static>) -> Vec<SocketHandle> + Send + Sync + 'static>;

type AppFn = Box<
    dyn Fn(Instant, &mut SocketSet<'static>, &mut Vec<SocketHandle>, &mut Instant)
        + Send
        + Sync
        + 'static,
>;

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
    pub init: Option<InitFn>,
    pub application: Option<AppFn>,
    pub next_poll: Option<Instant>,
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node[{}] with {}", self.id, self.device)?;
        Ok(())
    }
}

impl Node {
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
            id,
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

    /// Accept a message that was send to this node.
    pub(crate) fn rx_message(&mut self, msg: Message) {
        self.device.rx_queue.push_back(msg);
    }

    /// Peek a message that needs to be send.
    pub(crate) fn peek_tx_message(&mut self) -> Option<&Message> {
        self.device.tx_queue.front()
    }

    /// Get a message that needs to be send.
    pub(crate) fn tx_message(&mut self) -> Option<Message> {
        self.device.tx_queue.pop_front()
    }

    pub fn set_init(&mut self, init: InitFn) {
        self.init = Some(init);
    }

    pub fn set_application(&mut self, application: AppFn) {
        self.application = Some(application);
    }
}

pub struct NodeDevice {
    pub id: usize,
    pub position: Position,
    pub rx_queue: VecDeque<Message>,
    pub tx_queue: VecDeque<Message>,
}

impl Display for NodeDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NodeDevice[{}] at ({}, {})",
            self.id,
            self.position.x(),
            self.position.y()
        )?;

        Ok(())
    }
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
                RxToken { buffer: data.data },
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

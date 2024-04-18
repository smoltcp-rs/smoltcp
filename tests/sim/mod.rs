use std::fs::File;

use smoltcp::iface::*;
use smoltcp::phy::{PcapLinkType, PcapSink};
use smoltcp::time::*;
use smoltcp::wire::*;

mod message;
mod node;

use message::Message;
use node::*;

const TRANSMIT_SPEED: f32 = 250_000. / 8.;

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

    node.set_application(Box::new(move |_, sockets, handles, _| {
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

pub struct NetworkSim {
    nodes: Vec<Node>,
    messages: Vec<Message>,
    now: Instant,
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

    /// Create a new node.
    pub fn create_node(&mut self, rpl: smoltcp::iface::RplConfig) -> &mut Node {
        let id = self.nodes.len();
        let node = Node::new(id, rpl);

        self.nodes.push(node);

        &mut self.nodes[id]
    }

    /// Get a reference to the nodes.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Get a mutable reference to the nodes.
    pub fn nodes_mut(&mut self) -> &mut [Node] {
        &mut self.nodes
    }

    /// Get a reference to the transmitted messages.
    pub fn msgs(&self) -> &[Message] {
        &self.messages
    }

    /// Clear all transmitted messages.
    pub fn clear_msgs(&mut self) {
        self.messages.clear();
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

    /// Run the simluation for a specific duration with a specified step.
    /// *NOTE*: the simulation uses the step as a maximum step. If a smoltcp interface needs to be
    /// polled more often, then the simulation will do so.
    pub fn run(&mut self, step: Duration, duration: Duration, pcap_file: Option<&mut PcapFile>) {
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

        if let Some(file) = pcap_file {
            file.append_messages(self)
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
                        let msg = node.tx_message().unwrap();

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
                    node.rx_message(msg.clone());
                }
            }
        }

        // Check if messages can arrive at their destination.
        for msg in &unicast_msgs {
            let to_node = self.get_node_from_ieee_mut(msg.to).unwrap();

            if to_node.enabled && to_node.position.distance(&msg.from.1) < to_node.range {
                to_node.rx_message(msg.clone());
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
}

#[allow(unused)]
/// Helper for writing messages from the simulator to a PCAP file
pub struct PcapFile {
    file: File,
}

#[allow(unused)]
impl PcapFile {
    pub fn new(path: &std::path::Path) -> std::io::Result<Self> {
        let mut file = std::fs::File::create(path)?;
        PcapSink::global_header(&mut file, PcapLinkType::Ieee802154WithoutFcs);

        Ok(Self { file })
    }

    pub fn append_messages(&mut self, sim: &NetworkSim) {
        for msg in &sim.messages {
            PcapSink::packet(&mut self.file, msg.at, &msg.data);
        }
    }
}

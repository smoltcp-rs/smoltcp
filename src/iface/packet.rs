use crate::phy::{ChecksumCapabilities, DeviceCapabilities};
use crate::wire::*;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "medium-ethernet")]
pub(crate) enum EthernetPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    Ip(Packet<'a>),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Packet<'p> {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(PacketV4<'p>),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(PacketV6<'p>),
}

impl<'p> Packet<'p> {
    pub(crate) fn new(ip_repr: IpRepr, payload: IpPayload<'p>) -> Self {
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(header) => Self::new_ipv4(header, payload),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(header) => Self::new_ipv6(header, payload),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    pub(crate) fn new_ipv4(ip_repr: Ipv4Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv4(PacketV4 {
            header: ip_repr,
            payload,
        })
    }

    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn new_ipv6(ip_repr: Ipv6Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv6(PacketV6 {
            header: ip_repr,
            #[cfg(feature = "proto-ipv6-hbh")]
            hop_by_hop: None,
            #[cfg(feature = "proto-ipv6-fragmentation")]
            fragment: None,
            #[cfg(feature = "proto-ipv6-routing")]
            routing: None,
            payload,
        })
    }

    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => IpRepr::Ipv4(p.header),
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => IpRepr::Ipv6(p.header),
        }
    }

    pub(crate) fn payload(&self) -> &IpPayload<'p> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => &p.payload,
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => &p.payload,
        }
    }

    pub(crate) fn emit_payload(&self, payload: &mut [u8], caps: &DeviceCapabilities) {
        self.payload().emit(&self.ip_repr(), payload, caps);
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv4")]
pub(crate) struct PacketV4<'p> {
    header: Ipv4Repr,
    payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv6")]
pub(crate) struct PacketV6<'p> {
    header: Ipv6Repr,
    #[cfg(feature = "proto-ipv6-hbh")]
    hop_by_hop: Option<(IpProtocol, Ipv6HopByHopRepr<'p>)>,
    #[cfg(feature = "proto-ipv6-fragmentation")]
    fragment: Option<(IpProtocol, Ipv6FragmentRepr)>,
    #[cfg(feature = "proto-ipv6-routing")]
    routing: Option<(IpProtocol, Ipv6RoutingRepr)>,
    payload: IpPayload<'p>,
}

#[cfg(feature = "proto-ipv6")]
impl<'p> PacketV6<'p> {
    pub(crate) fn new(header: Ipv6Repr, payload: IpPayload<'p>) -> Self {
        Self {
            header,
            #[cfg(feature = "proto-ipv6-hbh")]
            hop_by_hop: None,
            #[cfg(feature = "proto-ipv6-fragmentation")]
            fragment: None,
            #[cfg(feature = "proto-ipv6-routing")]
            routing: None,
            payload,
        }
    }

    pub(crate) fn header(&self) -> &Ipv6Repr {
        &self.header
    }

    pub(crate) fn header_mut(&mut self) -> &mut Ipv6Repr {
        &mut self.header
    }

    #[cfg(feature = "proto-ipv6-hbh")]
    pub(crate) fn hop_by_hop(&self) -> Option<(IpProtocol, &Ipv6HopByHopRepr<'p>)> {
        #[cfg(feature = "proto-ipv6-hbh")]
        {
            self.hop_by_hop
                .as_ref()
                .map(|(next_header, repr)| (*next_header, repr))
        }
        #[cfg(not(feature = "proto-ipv6-hbh"))]
        {
            None
        }
    }

    #[cfg(feature = "proto-ipv6-hbh")]
    pub(crate) fn add_hop_by_hop(&mut self, repr: Ipv6HopByHopRepr<'p>) {
        self.header.payload_len += 2 + repr.buffer_len();
        let next_header = self.header.next_header;
        self.header.next_header = IpProtocol::HopByHop;
        self.hop_by_hop = Some((next_header, repr));
    }

    #[cfg(feature = "proto-ipv6-routing")]
    pub(crate) fn routing(&self) -> Option<(IpProtocol, &Ipv6RoutingRepr)> {
        #[cfg(feature = "proto-ipv6-routing")]
        {
            self.routing
                .as_ref()
                .map(|(next_header, repr)| (*next_header, repr))
        }
        #[cfg(not(feature = "proto-ipv6-routing"))]
        {
            None
        }
    }

    #[cfg(feature = "proto-ipv6-routing")]
    pub(crate) fn add_routing(&mut self, repr: Ipv6RoutingRepr) {
        self.header.payload_len += 2 + repr.buffer_len();
        let mut next_header = self.header.next_header;

        if let Some((hbh_next_header, _)) = &mut self.hop_by_hop {
            next_header = *hbh_next_header;
            *hbh_next_header = IpProtocol::Ipv6Route;
        } else {
            self.header.next_header = IpProtocol::Ipv6Route;
        }

        self.routing = Some((next_header, repr));
    }

    pub(crate) fn payload(&self) -> &IpPayload<'p> {
        &self.payload
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IpPayloadType {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4,
    #[cfg(feature = "proto-igmp")]
    Igmp,
    #[cfg(feature = "proto-ipv6")]
    Icmpv6,
    #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
    Raw,
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    Udp,
    #[cfg(feature = "socket-tcp")]
    Tcp,
    #[cfg(feature = "socket-dhcpv4")]
    Dhcpv4,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum IpPayload<'p> {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4(Icmpv4Repr<'p>),
    #[cfg(feature = "proto-igmp")]
    Igmp(IgmpRepr),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6(Icmpv6Repr<'p>),
    #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
    Raw(&'p [u8]),
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    Udp(UdpRepr, &'p [u8]),
    #[cfg(feature = "socket-tcp")]
    Tcp(TcpRepr<'p>),
    #[cfg(feature = "socket-dhcpv4")]
    Dhcpv4(UdpRepr, DhcpRepr<'p>),
}

impl<'a> IpPayload<'a> {
    pub fn buffer_len(&self) -> usize {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Self::Icmpv4(repr) => repr.buffer_len(),
            #[cfg(feature = "proto-igmp")]
            Self::Igmp(repr) => repr.buffer_len(),
            #[cfg(feature = "proto-ipv6")]
            Self::Icmpv6(repr) => repr.buffer_len(),
            #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
            Self::Raw(repr) => repr.len(),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            Self::Udp(repr, data) => repr.header_len() + data.len(),
            #[cfg(feature = "socket-tcp")]
            Self::Tcp(repr) => repr.buffer_len(),
            #[cfg(feature = "socket-dhcpv4")]
            Self::Dhcpv4(repr, data) => repr.header_len() + data.buffer_len(),
        }
    }

    pub fn parse_unchecked(
        buffer: &'a [u8],
        payload_type: IpPayloadType,
        header: &Ipv6Repr,
        checksum_caps: &ChecksumCapabilities,
    ) -> crate::wire::Result<Self> {
        match payload_type {
            #[cfg(feature = "proto-ipv4")]
            IpPayloadType::Icmpv4 => Ok(Self::Icmpv4(
                Icmpv4Repr::parse(&Icmpv4Packet::new_unchecked(buffer), checksum_caps)
                    .map_err(|_| crate::wire::Error)?,
            )),
            #[cfg(feature = "proto-igmp")]
            IpPayloadType::Igmp => Ok(Self::Igmp(IgmpRepr::parse(&IgmpPacket::new_unchecked(
                buffer,
            ))?)),
            #[cfg(feature = "proto-ipv6")]
            IpPayloadType::Icmpv6 => Ok(Self::Icmpv6(Icmpv6Repr::parse(
                &header.src_addr,
                &header.dst_addr,
                &Icmpv6Packet::new_unchecked(buffer),
                checksum_caps,
            )?)),
            #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
            IpPayloadType::Raw => Ok(Self::Raw(buffer)),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPayloadType::Udp => {
                let packet = &UdpPacket::new_unchecked(buffer);
                let repr = UdpRepr::parse(
                    packet,
                    &header.src_addr.into(),
                    &header.dst_addr.into(),
                    checksum_caps,
                )?;

                Ok(Self::Udp(repr, packet.payload()))
            }
            #[cfg(feature = "socket-tcp")]
            IpPayloadType::Tcp => Ok(Self::Tcp(TcpRepr::parse(
                &TcpPacket::new_unchecked(buffer),
                &header.src_addr.into(),
                &header.dst_addr.into(),
                checksum_caps,
            )?)),
            #[cfg(feature = "socket-dhcpv4")]
            IpPayloadType::Dhcpv4 => {
                // FIXME: actually use the DHCP repr
                let packet = &UdpPacket::new_unchecked(buffer);
                let repr = UdpRepr::parse(
                    packet,
                    &header.src_addr.into(),
                    &header.dst_addr.into(),
                    checksum_caps,
                )?;

                Ok(Self::Udp(repr, packet.payload()))
            }
        }
    }

    pub fn parse(
        buffer: &'a [u8],
        payload_type: IpPayloadType,
        header: &Ipv6Repr,
        checksum_caps: &ChecksumCapabilities,
    ) -> crate::wire::Result<Self> {
        match payload_type {
            #[cfg(feature = "proto-ipv4")]
            IpPayloadType::Icmpv4 => Ok(Self::Icmpv4(
                Icmpv4Repr::parse(&Icmpv4Packet::new_checked(buffer)?, checksum_caps)
                    .map_err(|_| crate::wire::Error)?,
            )),
            #[cfg(feature = "proto-igmp")]
            IpPayloadType::Igmp => Ok(Self::Igmp(IgmpRepr::parse(&IgmpPacket::new_checked(
                buffer,
            )?)?)),
            #[cfg(feature = "proto-ipv6")]
            IpPayloadType::Icmpv6 => Ok(Self::Icmpv6(Icmpv6Repr::parse(
                &header.src_addr,
                &header.dst_addr,
                &Icmpv6Packet::new_checked(buffer)?,
                checksum_caps,
            )?)),
            #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
            IpPayloadType::Raw => Ok(Self::Raw(buffer)),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPayloadType::Udp => {
                let packet = &UdpPacket::new_checked(buffer)?;
                let repr = UdpRepr::parse(
                    packet,
                    &header.src_addr.into(),
                    &header.dst_addr.into(),
                    checksum_caps,
                )?;

                Ok(Self::Udp(repr, packet.payload()))
            }
            #[cfg(feature = "socket-tcp")]
            IpPayloadType::Tcp => Ok(Self::Tcp(TcpRepr::parse(
                &TcpPacket::new_checked(buffer)?,
                &header.src_addr.into(),
                &header.dst_addr.into(),
                checksum_caps,
            )?)),
            #[cfg(feature = "socket-dhcpv4")]
            IpPayloadType::Dhcpv4 => {
                // FIXME and actually use the DHCP representation
                let packet = &UdpPacket::new_checked(buffer)?;
                let repr = UdpRepr::parse(
                    packet,
                    &header.src_addr.into(),
                    &header.dst_addr.into(),
                    checksum_caps,
                )?;

                Ok(Self::Udp(repr, packet.payload()))
            }
        }
    }

    pub fn payload_type(&self) -> IpPayloadType {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Self::Icmpv4(_) => IpPayloadType::Icmpv4,
            #[cfg(feature = "proto-igmp")]
            Self::Igmp(_) => IpPayloadType::Igmp,
            #[cfg(feature = "proto-ipv6")]
            Self::Icmpv6(_) => IpPayloadType::Icmpv6,
            #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
            Self::Raw(_) => IpPayloadType::Raw,
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            Self::Udp(_, _) => IpPayloadType::Udp,
            #[cfg(feature = "socket-tcp")]
            Self::Tcp(_) => IpPayloadType::Tcp,
            #[cfg(feature = "socket-dhcpv4")]
            Self::Dhcpv4(_, _) => IpPayloadType::Dhcpv4,
        }
    }

    pub(crate) fn emit(&self, header: &IpRepr, payload: &mut [u8], caps: &DeviceCapabilities) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            IpPayload::Icmpv4(icmpv4_repr) => {
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum)
            }
            #[cfg(feature = "proto-igmp")]
            IpPayload::Igmp(igmp_repr) => igmp_repr.emit(&mut IgmpPacket::new_unchecked(payload)),
            #[cfg(feature = "proto-ipv6")]
            IpPayload::Icmpv6(icmpv6_repr) => {
                let ipv6_repr = match header {
                    #[cfg(feature = "proto-ipv4")]
                    IpRepr::Ipv4(_) => unreachable!(),
                    IpRepr::Ipv6(repr) => repr,
                };

                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(payload),
                    &caps.checksum,
                )
            }
            #[cfg(any(feature = "socket-raw", feature = "proto-rpl"))]
            IpPayload::Raw(raw_packet) => payload.copy_from_slice(raw_packet),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPayload::Udp(udp_repr, inner_payload) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &header.src_addr(),
                &header.dst_addr(),
                inner_payload.len(),
                |buf| buf.copy_from_slice(inner_payload),
                &caps.checksum,
            ),
            #[cfg(feature = "socket-tcp")]
            IpPayload::Tcp(mut tcp_repr) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= header.header_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(payload),
                    &header.src_addr(),
                    &header.dst_addr(),
                    &caps.checksum,
                );
            }
            #[cfg(feature = "socket-dhcpv4")]
            IpPayload::Dhcpv4(udp_repr, dhcp_repr) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &header.src_addr(),
                &header.dst_addr(),
                dhcp_repr.buffer_len(),
                |buf| dhcp_repr.emit(&mut DhcpPacket::new_unchecked(buf)).unwrap(),
                &caps.checksum,
            ),
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
pub(crate) fn icmp_reply_payload_len(len: usize, mtu: usize, header_len: usize) -> usize {
    // Send back as much of the original payload as will fit within
    // the minimum MTU required by IPv4. See RFC 1812 § 4.3.2.3 for
    // more details.
    //
    // Since the entire network layer packet must fit within the minimum
    // MTU supported, the payload must not exceed the following:
    //
    // <min mtu> - IP Header Size * 2 - ICMPv4 DstUnreachable hdr size
    len.min(mtu - header_len * 2 - 8)
}

#[cfg(feature = "proto-igmp")]
pub(crate) enum IgmpReportState {
    Inactive,
    ToGeneralQuery {
        version: IgmpVersion,
        timeout: crate::time::Instant,
        interval: crate::time::Duration,
        next_index: usize,
    },
    ToSpecificQuery {
        version: IgmpVersion,
        timeout: crate::time::Instant,
        group: Ipv4Address,
    },
}

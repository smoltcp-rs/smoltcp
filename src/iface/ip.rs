#[cfg(not(feature = "proto-igmp"))]
use core::marker::PhantomData;

use phy::{DeviceCapabilities};
#[cfg(feature = "proto-igmp")]
use wire::{IpAddress, IpRepr};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6Repr};
#[cfg(feature = "proto-ipv4")]
use wire::{Ipv4Repr};
#[cfg(feature = "proto-ipv4")]
use wire::{Icmpv4Packet, Icmpv4Repr};
#[cfg(feature = "proto-igmp")]
use wire::{IgmpPacket, IgmpRepr};
#[cfg(feature = "proto-ipv6")]
use wire::{Icmpv6Packet, Icmpv6Repr};
#[cfg(feature = "socket-udp")]
use wire::{UdpPacket, UdpRepr};
#[cfg(feature = "socket-tcp")]
use wire::{TcpPacket, TcpRepr};


#[derive(Debug, PartialEq)]
pub(crate) enum Packet<'a> {
    #[cfg(feature = "proto-ipv4")]
    Icmpv4((Ipv4Repr, Icmpv4Repr<'a>)),
    #[cfg(feature = "proto-igmp")]
    Igmp((Ipv4Repr, IgmpRepr)),
    #[cfg(feature = "proto-ipv6")]
    Icmpv6((Ipv6Repr, Icmpv6Repr<'a>)),
    #[cfg(feature = "socket-raw")]
    Raw((IpRepr, &'a [u8])),
    #[cfg(feature = "socket-udp")]
    Udp((IpRepr, UdpRepr<'a>)),
    #[cfg(feature = "socket-tcp")]
    Tcp((IpRepr, TcpRepr<'a>))
}

impl<'a> Packet<'a> {
    pub(crate) fn neighbor_addr(&self) -> IpAddress {
        return self.ip_repr().dst_addr()
    }

    pub(crate) fn ip_repr(&self) -> IpRepr {
        match &self {
            #[cfg(feature = "proto-ipv4")]
            &Packet::Icmpv4((ipv4_repr, _)) => IpRepr::Ipv4(ipv4_repr.clone()),
            #[cfg(feature = "proto-igmp")]
            &Packet::Igmp((ipv4_repr, _)) => IpRepr::Ipv4(ipv4_repr.clone()),
            #[cfg(feature = "proto-ipv6")]
            &Packet::Icmpv6((ipv6_repr, _)) => IpRepr::Ipv6(ipv6_repr.clone()),
            #[cfg(feature = "socket-raw")]
            &Packet::Raw((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-udp")]
            &Packet::Udp((ip_repr, _)) => ip_repr.clone(),
            #[cfg(feature = "socket-tcp")]
            &Packet::Tcp((ip_repr, _)) => ip_repr.clone(),
        }
    }

    pub(crate) fn emit_payload(&self, _ip_repr: IpRepr, payload: &mut [u8], caps: &DeviceCapabilities) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Icmpv4((_, icmpv4_repr)) => 
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum),
            #[cfg(feature = "proto-igmp")]
            Packet::Igmp((_, igmp_repr)) =>
                igmp_repr.emit(&mut IgmpPacket::new_unchecked(payload)),
            #[cfg(feature = "proto-ipv6")]
            Packet::Icmpv6((_, icmpv6_repr)) =>
                icmpv6_repr.emit(&_ip_repr.src_addr(), &_ip_repr.dst_addr(),
                         &mut Icmpv6Packet::new_unchecked(payload), &caps.checksum),
            #[cfg(feature = "socket-raw")]
            Packet::Raw((_, raw_packet)) =>
                payload.copy_from_slice(raw_packet),
            #[cfg(feature = "socket-udp")]
            Packet::Udp((_, udp_repr)) =>
                udp_repr.emit(&mut UdpPacket::new_unchecked(payload),
                              &_ip_repr.src_addr(), &_ip_repr.dst_addr(), &caps.checksum),
            #[cfg(feature = "socket-tcp")]
            Packet::Tcp((_, mut tcp_repr)) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= _ip_repr.buffer_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(&mut TcpPacket::new_unchecked(payload),
                                &_ip_repr.src_addr(), &_ip_repr.dst_addr(),
                                &caps.checksum);
            }
        }
    }
}

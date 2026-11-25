use super::*;

use crate::socket::tcp::{Socket, State};

impl InterfaceInner {
    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());

        // Per RFC 1122 §3.2.1.3, the unspecified address must never appear as a source
        // or destination in any IP datagram. Drop such TCP segments early to avoid
        // creating sockets with unspecified peers (which would later panic on egress).
        // This is not done at the iface level because it might be useful with
        // UDP or raw sockets, but it's definitely not useful for TCP.
        if src_addr.is_unspecified() || dst_addr.is_unspecified() {
            return None;
        }

        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        let mut time_wait_reopen = None;

        // Prefer sockets bound to a connection, so a repeated SYN cannot be
        // intercepted by an earlier listening socket.
        for item in sockets.items_mut() {
            let handle = item.meta.handle;
            let Some(tcp_socket) = Socket::downcast_mut(&mut item.socket) else {
                continue;
            };
            if tcp_socket.remote_endpoint().is_none() {
                continue;
            }

            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                // RFC 1122 §4.2.2.13 permits a newer SYN to replace a TIME-WAIT connection.
                if tcp_socket.can_reopen_time_wait(&tcp_repr) {
                    time_wait_reopen = Some((handle, tcp_socket.time_wait_reopen_isn()));
                    break;
                }

                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
        }

        let mut listener_result = None;
        let mut reopened_time_wait = None;
        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
            .filter(|socket| socket.remote_endpoint().is_none())
        {
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                let result = tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));

                if let Some((handle, successor_isn)) = time_wait_reopen
                    && tcp_socket.state() == State::SynReceived
                {
                    tcp_socket.set_syn_received_isn(successor_isn);
                    reopened_time_wait = Some(handle);
                }
                listener_result = Some(result);
                break;
            }
        }

        if let Some(result) = listener_result {
            if let Some(handle) = reopened_time_wait {
                sockets.get_mut::<Socket>(handle).close_time_wait();
            }
            return result;
        }

        if let Some((handle, _)) = time_wait_reopen {
            return sockets
                .get_mut::<Socket>(handle)
                .process(self, &ip_repr, &tcp_repr)
                .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            // Never reply to a TCP RST packet with another TCP RST packet.
            // Never send a TCP RST packet with unspecified addresses.
            // Never send a TCP RST when packet has been handled by raw socket.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}

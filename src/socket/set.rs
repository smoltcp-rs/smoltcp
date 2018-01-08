use core::{fmt, slice};
use managed::ManagedSlice;

use super::{Socket, SocketRef, AnySocket};
#[cfg(feature = "socket-tcp")]
use super::{TcpState, TcpSocket};
#[cfg(feature = "socket-udp")]
use socket::UdpSocket;
#[cfg(feature = "socket-raw")]
use socket::RawSocket;
#[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
use socket::IcmpSocket;
use {Result, Error};
use iface::{PacketFilter, PacketEmitter};
use wire::{IpRepr, UdpRepr, TcpRepr, Icmpv4Repr};
use phy::{DeviceCapabilities, ChecksumCapabilities};

/// An item of a socket set.
///
/// The only reason this struct is public is to allow the socket set storage
/// to be allocated externally.
#[derive(Debug)]
pub struct Item<'a, 'b: 'a> {
    socket: Socket<'a, 'b>,
    refs:   usize
}

/// A handle, identifying a socket in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Handle(usize);

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetimes `'b` and `'c` are used when storing a `Socket<'b, 'c>`.
#[derive(Debug)]
pub struct Set<'a, 'b: 'a, 'c: 'a + 'b> {
    sockets: ManagedSlice<'a, Option<Item<'b, 'c>>>
}

impl<'a, 'b: 'a, 'c: 'a + 'b> Set<'a, 'b, 'c> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> Set<'a, 'b, 'c>
            where SocketsT: Into<ManagedSlice<'a, Option<Item<'b, 'c>>>> {
        let sockets = sockets.into();
        Set {
            sockets: sockets
        }
    }

    /// Add a socket to the set with the reference count 1, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add(&mut self, socket: Socket<'b, 'c>) -> Handle {
        fn put<'b, 'c>(index: usize, slot: &mut Option<Item<'b, 'c>>,
                       mut socket: Socket<'b, 'c>) -> Handle {
            net_trace!("[{}]: adding", index);
            let handle = Handle(index);
            socket.meta_mut().handle = handle;
            *slot = Some(Item { socket: socket, refs: 1 });
            handle
        }

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                return put(index, slot, socket)
            }
        }

        match self.sockets {
            ManagedSlice::Borrowed(_) => {
                panic!("adding a socket to a full SocketSet")
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(None);
                let index = sockets.len() - 1;
                return put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'b, 'c>>(&mut self, handle: Handle) -> SocketRef<T> {
        match self.sockets[handle.0].as_mut() {
            Some(item) => {
                T::downcast(SocketRef::new(&mut item.socket))
                  .expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket")
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: Handle) -> Socket<'b, 'c> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket")
        }
    }

    /// Increase reference count by 1.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn retain(&mut self, handle: Handle) {
        self.sockets[handle.0]
            .as_mut()
            .expect("handle does not refer to a valid socket")
            .refs += 1
    }

    /// Decrease reference count by 1.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set,
    /// or if the reference count is already zero.
    pub fn release(&mut self, handle: Handle) {
        let refs = &mut self.sockets[handle.0]
                            .as_mut()
                            .expect("handle does not refer to a valid socket")
                            .refs;
        if *refs == 0 { panic!("decreasing reference count past zero") }
        *refs -= 1
    }

    /// Prune the sockets in this set.
    ///
    /// Pruning affects sockets with reference count 0. Open sockets are closed.
    /// Closed sockets are removed and dropped.
    pub fn prune(&mut self) {
        for (index, item) in self.sockets.iter_mut().enumerate() {
            let mut may_remove = false;
            if let &mut Some(Item { refs: 0, ref mut socket }) = item {
                match socket {
                    #[cfg(feature = "socket-raw")]
                    &mut Socket::Raw(_) =>
                        may_remove = true,
                    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
                    &mut Socket::Icmp(_) =>
                        may_remove = true,
                    #[cfg(feature = "socket-udp")]
                    &mut Socket::Udp(_) =>
                        may_remove = true,
                    #[cfg(feature = "socket-tcp")]
                    &mut Socket::Tcp(ref mut socket) =>
                        if socket.state() == TcpState::Closed {
                            may_remove = true
                        } else {
                            socket.close()
                        },
                    &mut Socket::__Nonexhaustive(_) => unreachable!()
                }
            }
            if may_remove {
                net_trace!("[{}]: pruning", index);
                *item = None
            }
        }
    }

    /// Iterate every socket in this set.
    pub fn iter<'d>(&'d self) -> Iter<'d, 'b, 'c> {
        Iter { lower: self.sockets.iter() }
    }

    /// Iterate every socket in this set, as SocketRef.
    pub fn iter_mut<'d>(&'d mut self) -> IterMut<'d, 'b, 'c> {
        IterMut { lower: self.sockets.iter_mut() }
    }
}

impl<'a, 'b: 'a, 'c: 'a + 'b> PacketFilter for Set<'a, 'b, 'c> {
    fn process_udp(&mut self, ip_repr: &IpRepr, udp_repr: &UdpRepr) -> Result<()> {
        for mut udp_socket in self.iter_mut().filter_map(UdpSocket::downcast) {
            if !udp_socket.accepts(&ip_repr, &udp_repr) { continue }

            match udp_socket.process(&ip_repr, &udp_repr) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(()),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }
        Err(Error::Dropped)
    }

    fn process_tcp<'frame>(&mut self, timestamp: u64, ip_repr: &IpRepr, tcp_repr: &TcpRepr<'frame>) ->
        Result<Option<(IpRepr, TcpRepr<'static>)>>
    {
        for mut tcp_socket in self.iter_mut().filter_map(TcpSocket::downcast) {
            if !tcp_socket.accepts(&ip_repr, &tcp_repr) { continue }

            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e)
            }
        }
        Err(Error::Dropped)
    }

    fn process_icmpv4(&mut self, ip_repr: &IpRepr, icmp_repr: &Icmpv4Repr,
        checksum_caps: &ChecksumCapabilities) -> Result<bool>
    {
        let mut handled = false;
        for mut icmp_socket in self.iter_mut().filter_map(IcmpSocket::downcast) {
            if !icmp_socket.accepts(&ip_repr, &icmp_repr, &checksum_caps) { continue }

            match icmp_socket.process(&ip_repr, &icmp_repr, &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // ICMP sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }
        Ok(handled)
    }

    fn process_raw(&mut self, ip_repr: &IpRepr, ip_payload: &[u8],
        checksum_caps: &ChecksumCapabilities) -> Result<bool>
    {
        let mut handled = false;
        for mut raw_socket in self.iter_mut().filter_map(RawSocket::downcast) {
            if !raw_socket.accepts(&ip_repr) { continue }

            match raw_socket.process(&ip_repr, ip_payload, &checksum_caps) {
                // The packet is valid and handled by socket.
                Ok(()) => handled = true,
                // The socket buffer is full.
                Err(Error::Exhausted) => (),
                // Raw sockets don't validate the packets in any way.
                Err(_) => unreachable!(),
            }
        }
        Ok(handled)
    }

    fn egress<E>(&mut self, caps: &DeviceCapabilities, timestamp: u64, emitter: &mut E) -> Result<bool>
        where E: PacketEmitter
    {
        let mut emitted_any = false;
        for mut socket in self.iter_mut() {
            if !socket.meta_mut().egress_permitted(|ip_addr|
                    self.inner.has_neighbor(&ip_addr, timestamp)) {
                continue
            }

            let mut neighbor_addr = None;
            let mut device_result = Ok(());

            let socket_result =
                match *socket {
                    #[cfg(feature = "socket-raw")]
                    Socket::Raw(ref mut socket) =>
                        socket.dispatch(&caps.checksum, |response|
                            emitter.emit_raw(response, timestamp)),
                    #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
                    Socket::Icmp(ref mut socket) =>
                        socket.dispatch(&caps, |response| {
                            match response {
                                #[cfg(feature = "proto-ipv4")]
                                (IpRepr::Ipv4(ipv4_repr), icmpv4_repr) =>
                                    emitter.emit_icmpv4((ipv4_repr, icmpv4_repr), timestamp),
                                _ => Err(Error::Unaddressable)
                            }
                        }),
                    #[cfg(feature = "socket-udp")]
                    Socket::Udp(ref mut socket) =>
                        socket.dispatch(|response|
                            emitter.emit_udp(response, timestamp)),
                    #[cfg(feature = "socket-tcp")]
                    Socket::Tcp(ref mut socket) =>
                        socket.dispatch(timestamp, &caps, |response|
                            emitter.emit_tcp(response, timestamp)),
                    Socket::__Nonexhaustive(_) => unreachable!()
                };

            match (device_result, socket_result) {
                (Err(Error::Exhausted), _) => break,     // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (),   // nothing to transmit
                (Err(Error::Unaddressable), _) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighboor.
                    socket.meta_mut().neighbor_missing(timestamp,
                        neighbor_addr.expect("non-IP response packet"));
                    break
                }
                (Err(err), _) | (_, Err(err)) => {
                    net_debug!("{}: cannot dispatch egress packet: {}",
                               socket.meta().handle, err);
                    return Err(err)
                }
                (Ok(()), Ok(())) => emitted_any = true
            }
        }
        Ok(emitted_any)
    }

    fn poll_at(&self, timestamp: u64) -> Option<u64> {
        self.iter().filter_map(|socket| {
            let socket_poll_at = socket.poll_at();
            socket.meta().poll_at(socket_poll_at, |ip_addr|
                self.inner.has_neighbor(&ip_addr, timestamp))
        }).min()
    }
}

/// Immutable socket set iterator.
///
/// This struct is created by the [iter](struct.SocketSet.html#method.iter)
/// on [socket sets](struct.SocketSet.html).
pub struct Iter<'a, 'b: 'a, 'c: 'a + 'b> {
    lower: slice::Iter<'a, Option<Item<'b, 'c>>>
}

impl<'a, 'b: 'a, 'c: 'a + 'b> Iterator for Iter<'a, 'b, 'c> {
    type Item = &'a Socket<'b, 'c>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item_opt) = self.lower.next() {
            if let Some(item) = item_opt.as_ref() {
                return Some(&item.socket)
            }
        }
        None
    }
}

/// Mutable socket set iterator.
///
/// This struct is created by the [iter_mut](struct.SocketSet.html#method.iter_mut)
/// on [socket sets](struct.SocketSet.html).
pub struct IterMut<'a, 'b: 'a, 'c: 'a + 'b> {
    lower: slice::IterMut<'a, Option<Item<'b, 'c>>>,
}

impl<'a, 'b: 'a, 'c: 'a + 'b> Iterator for IterMut<'a, 'b, 'c> {
    type Item = SocketRef<'a, Socket<'b, 'c>>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item_opt) = self.lower.next() {
            if let Some(item) = item_opt.as_mut() {
                return Some(SocketRef::new(&mut item.socket))
            }
        }
        None
    }
}

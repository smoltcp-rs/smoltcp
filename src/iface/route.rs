use managed::ManagedMap;
use crate::time::Instant;
use core::ops::Bound;

use crate::{Error, Result};
use crate::wire::{IpCidr, IpAddress};
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Cidr};

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub via_router: IpAddress,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }
}

/// A routing table.
///
/// # Examples
///
/// On systems with heap, this table can be created with:
///
/// ```rust
/// use std::collections::BTreeMap;
/// use smoltcp::iface::Routes;
/// let mut routes = Routes::new(BTreeMap::new());
/// ```
///
/// On systems without heap, use:
///
/// ```rust
/// use smoltcp::iface::Routes;
/// let mut routes_storage = [];
/// let mut routes = Routes::new(&mut routes_storage[..]);
/// ```
#[derive(Debug)]
pub struct Routes<'a> {
    storage: ManagedMap<'a, IpCidr, Route>,
}

impl<'a> Routes<'a> {
    /// Creates a routing tables. The backing storage is **not** cleared
    /// upon creation.
    pub fn new<T>(storage: T) -> Routes<'a>
            where T: Into<ManagedMap<'a, IpCidr, Route>> {
        let storage = storage.into();
        Routes { storage }
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut ManagedMap<'a, IpCidr, Route>)>(&mut self, f: F) {
        f(&mut self.storage);
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn add_default_ipv4_route(&mut self, gateway: Ipv4Address) -> Result<Option<Route>> {
        let cidr = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
        let route = Route::new_ipv4_gateway(gateway);
        match self.storage.insert(cidr, route) {
            Ok(route) => Ok(route),
            Err((_cidr, _route)) => Err(Error::Exhausted)
        }
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn add_default_ipv6_route(&mut self, gateway: Ipv6Address) -> Result<Option<Route>> {
        let cidr = IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0);
        let route = Route::new_ipv6_gateway(gateway);
        match self.storage.insert(cidr, route) {
            Ok(route) => Ok(route),
            Err((_cidr, _route)) => Err(Error::Exhausted)
        }
    }

    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) ->
            Option<IpAddress> {
        assert!(addr.is_unicast());

        let cidr = match addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => IpCidr::Ipv4(Ipv4Cidr::new(*addr, 32)),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => IpCidr::Ipv6(Ipv6Cidr::new(*addr, 128)),
            _ => unimplemented!()
        };

        for (prefix, route) in self.storage.range((Bound::Unbounded::<IpCidr>, Bound::Included(cidr))).rev() {
            // TODO: do something with route.preferred_until
            if let Some(expires_at) = route.expires_at {
                if timestamp > expires_at {
                    continue;
                }
            }

            if prefix.contains_addr(addr) {
                return Some(route.via_router);
            }
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv6")]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1]);
        pub const ADDR_1B: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 13]);
        pub const ADDR_1C: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 42]);
        pub fn cidr_1() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address(
                    [0xfe, 0x80, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]), 64)
        }

        pub const ADDR_2A: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 51, 100, 0, 0, 0, 0, 0, 0, 0, 1]);
        pub const ADDR_2B: Ipv6Address = Ipv6Address(
                [0xfe, 0x80, 0, 0, 0, 0, 51, 100, 0, 0, 0, 0, 0, 0, 0, 21]);
        pub fn cidr_2() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address(
                    [0xfe, 0x80, 0, 0, 0, 0, 51, 100, 0, 0, 0, 0, 0, 0, 0, 0]), 64)
        }
    }

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
        pub const ADDR_1B: Ipv4Address = Ipv4Address([192, 0, 2, 13]);
        pub const ADDR_1C: Ipv4Address = Ipv4Address([192, 0, 2, 42]);
        pub fn cidr_1() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address([192, 0, 2, 0]), 24)
        }

        pub const ADDR_2A: Ipv4Address = Ipv4Address([198, 51, 100, 1]);
        pub const ADDR_2B: Ipv4Address = Ipv4Address([198, 51, 100, 21]);
        pub fn cidr_2() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address([198, 51, 100, 0]), 24)
        }
    }

    use self::mock::*;

    #[test]
    fn test_fill() {
        let mut routes_storage = [None, None, None];
        let mut routes = Routes::new(&mut routes_storage[..]);

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)), None);

        let route = Route {
            via_router: ADDR_1A.into(),
            preferred_until: None, expires_at: None,
        };
        routes.update(|storage| {
            storage.insert(cidr_1().into(), route).unwrap();
        });

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)), None);

        let route2 = Route {
            via_router: ADDR_2A.into(),
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        routes.update(|storage| {
            storage.insert(cidr_2().into(), route2).unwrap();
        });

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)), Some(ADDR_2A.into()));
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)), Some(ADDR_2A.into()));

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(10)), Some(ADDR_2A.into()));
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(10)), Some(ADDR_2A.into()));
    }
}

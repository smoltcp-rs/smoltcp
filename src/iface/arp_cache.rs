use managed::ManagedSlice;

use wire::{EthernetAddress, IpAddress};

/// An Address Resolution Protocol cache.
///
/// This interface maps protocol addresses to hardware addresses.
pub trait Cache {
    /// Update the cache to map given protocol address to given hardware address.
    fn fill(&mut self, protocol_addr: &IpAddress, hardware_addr: &EthernetAddress);

    /// Look up the hardware address corresponding for the given protocol address.
    fn lookup(&mut self, protocol_addr: &IpAddress) -> Option<EthernetAddress>;
}

/// An Address Resolution Protocol cache backed by a slice.
///
/// This cache uses a fixed-size storage, binary search, and a least recently used
/// eviction strategy.
///
/// # Examples
///
/// On systems with heap, this cache can be created with:
/// ```rust
/// use smoltcp::iface::SliceArpCache;
/// let mut arp_cache = SliceArpCache::new(vec![Default::default(); 8]);
/// ```
///
/// On systems without heap, use:
/// ```rust
/// use smoltcp::iface::SliceArpCache;
/// let mut arp_cache_storage = [Default::default(); 8]
/// let mut arp_cache = SliceArpCache::new(&mut arp_cache_storage[..]);
/// ```
pub struct SliceCache<'a> {
    storage: ManagedSlice<'a, (IpAddress, EthernetAddress, usize)>,
    counter: usize
}

impl<'a> SliceCache<'a> {
    /// Create a cache. The backing storage is cleared upon creation.
    ///
    /// # Panics
    /// This function panics if `storage.len() == 0`.
    pub fn new<T>(storage: T) -> SliceCache<'a>
            where T: Into<ManagedSlice<'a, (IpAddress, EthernetAddress, usize)>> {
        let mut storage = storage.into();
        if storage.len() == 0 {
            panic!("ARP slice cache created with empty storage")
        }

        for elem in storage.iter_mut() {
            *elem = Default::default()
        }
        SliceCache {
            storage: storage,
            counter: 0
        }
    }

    /// Find an entry for the given protocol address, if any.
    fn find(&self, protocol_addr: &IpAddress) -> Option<usize> {
        // The order of comparison is important: any valid IpAddress should
        // sort before IpAddress::Invalid.
        self.storage.binary_search_by_key(protocol_addr, |&(key, _, _)| key).ok()
    }

    /// Sort entries in an order suitable for `find`.
    fn sort(&mut self) {
        #[cfg(feature = "std")]
        fn sort(data: &mut [(IpAddress, EthernetAddress, usize)]) {
            data.sort_by_key(|&(key, _, _)| key)
        }

        #[cfg(not(feature = "std"))]
        fn sort(data: &mut [(IpAddress, EthernetAddress, usize)]) {
            // Use an insertion sort, which performs best on 10 elements and less.
            for i in 1..data.len() {
                let mut j = i;
                while j > 0 && data[j-1].0 > data[j].0 {
                    data.swap(j, j - 1);
                    j = j - 1;
                }
            }
        }

        sort(&mut self.storage)
    }

    /// Find the least recently used entry.
    fn lru(&self) -> usize {
        self.storage.iter().enumerate().min_by_key(|&(_, &(_, _, counter))| counter).unwrap().0
    }
}

impl<'a> Cache for SliceCache<'a> {
    fn fill(&mut self, protocol_addr: &IpAddress, hardware_addr: &EthernetAddress) {
        if let None = self.find(protocol_addr) {
            let lru_index = self.lru();
            self.storage[lru_index] =
                (*protocol_addr, *hardware_addr, self.counter);
            self.sort()
        }
    }

    fn lookup(&mut self, protocol_addr: &IpAddress) -> Option<EthernetAddress> {
        if let Some(index) = self.find(protocol_addr) {
            let (_protocol_addr, hardware_addr, ref mut counter) =
                self.storage[index];
            self.counter += 1;
            *counter = self.counter;
            Some(hardware_addr)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use wire::Ipv4Address;
    use super::*;

    const HADDR_A: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 1]);
    const HADDR_B: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 2]);
    const HADDR_C: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 3]);
    const HADDR_D: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 4]);

    const PADDR_A: IpAddress = IpAddress::Ipv4(Ipv4Address([0, 0, 0, 0]));
    const PADDR_B: IpAddress = IpAddress::Ipv4(Ipv4Address([0, 0, 0, 1]));
    const PADDR_C: IpAddress = IpAddress::Ipv4(Ipv4Address([0, 0, 0, 2]));
    const PADDR_D: IpAddress = IpAddress::Ipv4(Ipv4Address([0, 0, 0, 3]));

    #[test]
    fn test_slice_cache() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = SliceCache::new(&mut cache_storage[..]);

        cache.fill(&PADDR_A, &HADDR_A);
        assert_eq!(cache.lookup(&PADDR_A), Some(HADDR_A));
        assert_eq!(cache.lookup(&PADDR_B), None);

        cache.fill(&PADDR_B, &HADDR_B);
        cache.fill(&PADDR_C, &HADDR_C);
        assert_eq!(cache.lookup(&PADDR_A), Some(HADDR_A));
        assert_eq!(cache.lookup(&PADDR_B), Some(HADDR_B));
        assert_eq!(cache.lookup(&PADDR_C), Some(HADDR_C));

        cache.lookup(&PADDR_B);
        cache.lookup(&PADDR_A);
        cache.lookup(&PADDR_C);
        cache.fill(&PADDR_D, &HADDR_D);
        assert_eq!(cache.lookup(&PADDR_A), Some(HADDR_A));
        assert_eq!(cache.lookup(&PADDR_B), None);
        assert_eq!(cache.lookup(&PADDR_C), Some(HADDR_C));
        assert_eq!(cache.lookup(&PADDR_D), Some(HADDR_D));
    }
}


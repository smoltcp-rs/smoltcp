use core::borrow::BorrowMut;

use wire::{EthernetAddress, InternetAddress};

/// An Address Resolution Protocol cache.
///
/// This interface maps protocol addresses to hardware addresses.
pub trait Cache {
    /// Update the cache to map given protocol address to given hardware address.
    fn fill(&mut self, protocol_addr: InternetAddress, hardware_addr: EthernetAddress);

    /// Look up the hardware address corresponding for the given protocol address.
    fn lookup(&mut self, protocol_addr: InternetAddress) -> Option<EthernetAddress>;
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

pub struct SliceCache<
    StorageT: BorrowMut<[(InternetAddress, EthernetAddress, usize)]>
> {
    storage: StorageT,
    counter: usize
}

impl<
    StorageT: BorrowMut<[(InternetAddress, EthernetAddress, usize)]>
> SliceCache<StorageT> {
    /// Create a cache. The backing storage is cleared upon creation.
    ///
    /// # Panics
    /// This function panics if `storage.len() == 0`.
    pub fn new(mut storage: StorageT) -> SliceCache<StorageT> {
        if storage.borrow().len() == 0 {
            panic!("ARP slice cache created with empty storage")
        }

        for elem in storage.borrow_mut().iter_mut() {
            *elem = Default::default()
        }
        SliceCache {
            storage: storage,
            counter: 0
        }
    }

    /// Find an entry for the given protocol address, if any.
    fn find(&self, protocol_addr: InternetAddress) -> Option<usize> {
        // The order of comparison is important: any valid InternetAddress should
        // sort before InternetAddress::Invalid.
        let storage = self.storage.borrow();
        storage.binary_search_by_key(&protocol_addr, |&(key, _, _)| key).ok()
    }

    /// Sort entries in an order suitable for `find`.
    fn sort(&mut self) {
        let mut storage = self.storage.borrow_mut();
        storage.sort_by_key(|&(key, _, _)| key)
    }

    /// Find the least recently used entry.
    fn lru(&self) -> usize {
        let storage = self.storage.borrow();
        storage.iter().enumerate().min_by_key(|&(_, &(_, _, counter))| counter).unwrap().0
    }
}

impl<
    StorageT: BorrowMut<[(InternetAddress, EthernetAddress, usize)]>
> Cache for SliceCache<StorageT> {
    fn fill(&mut self, protocol_addr: InternetAddress, hardware_addr: EthernetAddress) {
        if let None = self.find(protocol_addr) {
            let lru_index = self.lru();
            self.storage.borrow_mut()[lru_index] =
                (protocol_addr, hardware_addr, self.counter);
            self.sort()
        }
    }

    fn lookup(&mut self, protocol_addr: InternetAddress) -> Option<EthernetAddress> {
        if let Some(index) = self.find(protocol_addr) {
            let (_protocol_addr, hardware_addr, ref mut counter) =
                self.storage.borrow_mut()[index];
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
    use super::*;

    const HADDR_A: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 1]);
    const HADDR_B: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 2]);
    const HADDR_C: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 3]);
    const HADDR_D: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 4]);

    const PADDR_A: InternetAddress = InternetAddress::ipv4([0, 0, 0, 0]);
    const PADDR_B: InternetAddress = InternetAddress::ipv4([0, 0, 0, 1]);
    const PADDR_C: InternetAddress = InternetAddress::ipv4([0, 0, 0, 2]);
    const PADDR_D: InternetAddress = InternetAddress::ipv4([0, 0, 0, 3]);

    #[test]
    fn test_slice_cache() {
        let mut cache_storage = [Default::default(); 3];
        let mut cache = SliceCache::new(&mut cache_storage[..]);

        cache.fill(PADDR_A, HADDR_A);
        assert_eq!(cache.lookup(PADDR_A), Some(HADDR_A));
        assert_eq!(cache.lookup(PADDR_B), None);

        cache.fill(PADDR_B, HADDR_B);
        cache.fill(PADDR_C, HADDR_C);
        assert_eq!(cache.lookup(PADDR_A), Some(HADDR_A));
        assert_eq!(cache.lookup(PADDR_B), Some(HADDR_B));
        assert_eq!(cache.lookup(PADDR_C), Some(HADDR_C));

        cache.lookup(PADDR_B);
        cache.lookup(PADDR_A);
        cache.lookup(PADDR_C);
        cache.fill(PADDR_D, HADDR_D);
        assert_eq!(cache.lookup(PADDR_A), Some(HADDR_A));
        assert_eq!(cache.lookup(PADDR_B), None);
        assert_eq!(cache.lookup(PADDR_C), Some(HADDR_C));
        assert_eq!(cache.lookup(PADDR_D), Some(HADDR_D));
    }
}

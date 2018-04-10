use storage::Assembler;
use time::Instant;
use managed::ManagedSlice;

/// Default timeout duration
const FRAGMENTATION_TIMEOUT_MS: i64 = 500;

#[allow(dead_code)]
pub struct Packet<'a, T: 'a> {
    assembler: Assembler,
    pub rx_buffer: ManagedSlice<'a, T>,
    id: u16,
    last_used: Instant,
    header: bool,
    header_len: usize,
    total_len: usize,
}


impl<'a, T: 'a> Packet<'a, T> {
    pub fn new<S>(storage: S) -> Packet<'a, T>
	    where S: Into<ManagedSlice<'a, T>>,
    {
    	let s = storage.into();
        Packet {
            assembler: Assembler::new(s.len()),
            rx_buffer: s,
            id: 0,
            last_used: Instant::from_millis(0),
            header: false,
            header_len: 0,
            total_len: 0,
        }
    }

    /// Reset packet
    pub fn reset(&mut self) {
        self.id = 0;
        self.last_used = Instant::from_millis(0);
        self.header = false;
        self.header_len = 0;
        self.total_len = 0;
        self.assembler.remove_front();
    }

    /// Add fragment into the packet
    pub fn add(&mut self, header_len: usize, offset: usize, payload_len: usize, data: &[T], time: Instant) -> Result<(), ()>
        where T: Clone
    {
        debug_assert!(time >= self.last_used);
        self.last_used = time;

        if !self.header { 
            self.assembler.add(0, header_len)?;
            let range = 0..header_len;
            self.rx_buffer[range].clone_from_slice(&data[0..header_len]);
            self.header_len = header_len;
            self.header = true;
        }

        self.assembler.add(offset+self.header_len, payload_len)?;
        let range = offset+self.header_len..offset+payload_len+self.header_len;
        self.rx_buffer[range].clone_from_slice(&data[header_len..]);
        Ok(())
    }

    /// Return `true` if the packet has all fragments,
    /// and can be reassmbled, and `false` otherwise
    pub fn check_contig_range(&self) -> bool {
        if self.total_len != 0 {
            match self.assembler.peek_front() {
                Some(front) => {
                    if front == self.total_len {
                        return true;
                    }
                }
                None => {       
                }
            }
        }
        false
    }

    pub fn front(&mut self) -> Option<usize> {
        self.assembler.remove_front()
    }

    pub fn is_empty(&self) -> bool {
        self.assembler.is_empty()
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn set_total_len(&mut self, len: usize) {
        self.total_len = len;
    }
}

pub struct Set<'a> {
	packets: ManagedSlice<'a, Packet<'a, u8>>,    
}

impl<'a> Set<'a> {
	/// Create a new set of packets
    pub fn new<S>(storage: S) -> Set<'a>
	    where S: Into<ManagedSlice<'a, Packet<'a, u8>>>,
    {
        Set { packets: storage.into() }
    }
    
    /// Add new packet into the set
    pub fn add(&mut self, new_packet: Packet<'a, u8>) {
    	match self.packets {
    		ManagedSlice::Borrowed(ref mut packets) => {
		    	for packet in packets.iter_mut() {
		            if packet.id == 0 {
		            	// empty packet
		            	*packet = new_packet;
		            	return;
		            }
		        }		
    		},
    		#[cfg(any(feature = "std", feature = "alloc"))]
    		ManagedSlice::Owned(ref mut packets) => {
    			packets.push(new_packet);
    		}
    	}
    }

    /// Check if the set contains a packet with given `id`
    pub fn contains(&self, id: u16) -> bool {
        for packet in self.packets.iter() {
            if packet.id == id {
                return true;
            }
        }
        false
    }

	/// Get a packet with given `id`
    fn get(&mut self, id: u16) -> Option<&mut Packet<'a, u8>> {
        for packet in self.packets.iter_mut() {
            if packet.id == id {
                return Some(packet);
            }
        }
        None
    }

    /// Remove stale packets
    fn purge_old_packets(&mut self, time: Instant) {
        for packet in self.packets.iter_mut() {
            if ((time.total_millis() - packet.last_used.millis) > FRAGMENTATION_TIMEOUT_MS) && (packet.id != 0) {
                packet.reset();
            }
        }
    }

    /// Get a packet with given `id`
    pub fn get_packet(&mut self, id: u16, time: Instant) -> Option<&mut Packet<'a, u8>> {
        self.purge_old_packets(time);
    	if self.contains(id) {
    	    self.get(id)
    	} else {
    	    self.get(0)
    	}
    }
}
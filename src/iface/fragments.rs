use storage::Assembler;
//use managed::ManagedSlice;
use wire::Ipv4Address;
use time::Instant;

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[allow(dead_code)]
pub struct Packet {
    pub assembler: Assembler,
    pub rx_buffer: Vec<u8>,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    pub id: u16,
    last_used: Instant,
}


impl Packet {
    pub fn new(rx_buffer: Vec<u8>) -> Packet
    {
        Packet {
            assembler: Assembler::new(rx_buffer.len()),
            rx_buffer: rx_buffer,
            src_addr: Ipv4Address::default(),
            dst_addr: Ipv4Address::default(),
            id: 0,
            last_used: Instant::from_millis(0),
        }
    }
}

pub struct Set {
	packets: Vec<Packet>,    
}

impl Set {
	/// Create a new set of packets
    pub fn new(packets: Vec<Packet>) -> Set
    {
        Set { packets: packets }
    }
    
    /// Check if the set contains given packet ID
    pub fn contains(&self, id: u16) -> bool {
        for packet in self.packets.iter() {
            if packet.id == id {
                return true;
            }
        }
        false
    }

	/// Get given packet ID
    pub fn get(&mut self, id: u16) -> Option<&mut Packet> {
        for packet in self.packets.iter_mut() {
            if packet.id == id {
                return Some(packet);
            }
        }
        None
    }
    
    /// Get an unused packet
    pub fn get_empty(&mut self) -> Option<&mut Packet> {
    	self.get(0)
    }
}

/* With ManagedSlice
pub struct Packet<'a, T: 'a> {
    pub assembler: Assembler,
    pub rx_buffer: ManagedSlice<'a, T>,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    pub id: u16,
    last_used: Instant,
}

impl<'a, T: 'a> Packet<'a, T> {
    pub fn new<T>(rx_buffer: T) -> Packet<'a, T>
    where
        T: Into<ManagedSlice<'a, T>>,
    {
        let rx_buffer = rx_buffer.into();
        Packet {
            assembler: Assembler::new(rx_buffer.len()),
            rx_buffer: rx_buffer,
            src_addr: Ipv4Address::default(),
            dst_addr: Ipv4Address::default(),
            id: 0,
            last_used: Instant::from_millis(0),
        }
        //
    }
}

#[allow(dead_code)]
pub struct Set<'a, 'b: 'a, T: 'b> {
packets: ManagedSlice<'a, Packet<'b, T>>,    
}

impl<'a, 'b: 'a> Set<'a, 'b> {
    pub fn new<T>(packets: T) -> Set<'a, 'b>
    where
        T: Into<ManagedSlice<'a, Packet<'b>>>,
    {
        let packets = packets.into();
        Set { packets: packets }
    }
    


    pub fn contains(&self, id: u16) -> bool {
        for packet in self.packets.iter() {
            if packet.id == id {
                return true;
            }
        }
        false
    }

	
    pub fn get(&mut self, id: u16) -> Option<&'b mut Packet> {
        let mut id = id;
        if !self.contains(id) {
            id = 0; // search for unused frame
        }
        for packet in self.packets.iter_mut() {
            if packet.id == id {
                return Some(packet);
            }
        }
        None
    }

    // other functions
    //
    // contains(id: u16) -> Result
    // whether ID x is in the set
    // return handle to the particular packet
    //
    // get_empty(timestamp) -> Result
    // either return handle to an empty FragmentedPacket, or throw an error
    //
    // remove_old(timestamp)
    // all packets older than some threshold will be erased
}
*/
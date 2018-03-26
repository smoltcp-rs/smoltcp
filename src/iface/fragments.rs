use storage::Assembler;
use managed::ManagedSlice;
use wire::Ipv4Address;
use time::Instant;

#[allow(dead_code)]
pub struct Packet<'a> {
    pub assembler: Assembler,
    pub rx_buffer: ManagedSlice<'a, u8>,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    pub id: u16,
    last_used: Instant,
}

impl<'a> Packet<'a> {
    pub fn new<T>(rx_buffer: T) -> Packet<'a>
    where
        T: Into<ManagedSlice<'a, u8>>,
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
pub struct Set<'a, 'b: 'a> {
    packets: ManagedSlice<'a, Packet<'b>>,
}

impl<'a, 'b: 'a> Set<'a, 'b> {
    pub fn new<T>(packets: T) -> Set<'a, 'b>
    where
        T: Into<ManagedSlice<'a, Packet<'b>>>,
    {
        let packets = packets.into();
        Set { packets: packets }
    }


	// better add -> so it works for no-std scenario
    pub fn add<T>(&mut self, packet: T)
    where
        T: Into<Packet<'b>>,
    {
        let packet = packet.into();

        match self.packets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut packets) => {
                packets.push(packet);
            }
        }
    }
    
    pub fn contains(&self, id: u16) -> bool {
    	for packet in self.packets.iter() {
	    	if packet.id == id {
	    		return true;
	    	}	
    	}
    	false
    }
    
    pub fn get(&mut self, id: u16) -> Option<&Packet> {
    	let mut id = id;
    	if !self.contains(id) {
    		id = 0; // search for unused frame
    	}
    	for packet in self.packets.iter() {
	    	if packet.id == id {
	    		return Some(&packet);
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

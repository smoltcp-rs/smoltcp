use core::{cmp, fmt};
use byteorder::{ByteOrder, NetworkEndian};

use Error;
use super::ip::checksum;

enum_with_unknown! {
    /// Internet protocol control message type.
    pub doc enum Type(u8) {
        /// Echo reply
        EchoReply      =  0,
        /// Destination unreachable
        DstUnreachable =  1,
        /// Message redirect
        Redirect       =  5,
        /// Echo request
        EchoRequest    =  8,
        /// Router advertisement
        RouterAdvert   =  9,
        /// Router solicitation
        RouterSolicit  = 10,
        /// Time exceeded
        TimeExceeded   = 11,
        /// Parameter problem
        ParamProblem   = 12,
        /// Timestamp
        Timestamp      = 13,
        /// Timestamp reply
        TimestampReply = 14
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Type::EchoReply      => write!(f, "echo reply"),
            &Type::DstUnreachable => write!(f, "destination unreachable"),
            &Type::Redirect       => write!(f, "message redirect"),
            &Type::EchoRequest    => write!(f, "echo request"),
            &Type::RouterAdvert   => write!(f, "router advertisement"),
            &Type::RouterSolicit  => write!(f, "router solicitation"),
            &Type::TimeExceeded   => write!(f, "time exceeded"),
            &Type::ParamProblem   => write!(f, "parameter problem"),
            &Type::Timestamp      => write!(f, "timestamp"),
            &Type::TimestampReply => write!(f, "timestamp reply"),
            &Type::Unknown(id) => write!(f, "{}", id)
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub doc enum DstUnreachable(u8) {
        /// Destination network unreachable
        NetUnreachable   =  0,
        /// Destination host unreachable
        HostUnreachable  =  1,
        /// Destination protocol unreachable
        ProtoUnreachable =  2,
        /// Destination port unreachable
        PortUnreachable  =  3,
        /// Fragmentation required, and DF flag set
        FragRequired     =  4,
        /// Source route failed
        SrcRouteFailed   =  5,
        /// Destination network unknown
        DstNetUnknown    =  6,
        /// Destination host unknown
        DstHostUnknown   =  7,
        /// Source host isolated
        SrcHostIsolated  =  8,
        /// Network administratively prohibited
        NetProhibited    =  9,
        /// Host administratively prohibited
        HostProhibited   = 10,
        /// Network unreachable for ToS
        NetUnreachToS    = 11,
        /// Host unreachable for ToS
        HostUnreachToS   = 12,
        /// Communication administratively prohibited
        CommProhibited   = 13,
        /// Host precedence violation
        HostPrecedViol   = 14,
        /// Precedence cutoff in effect
        PrecedCutoff     = 15
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Redirect Message".
    pub doc enum Redirect(u8) {
        /// Redirect Datagram for the Network
        Net     = 0,
        /// Redirect Datagram for the Host
        Host    = 1,
        /// Redirect Datagram for the ToS & network
        NetToS  = 2,
        /// Redirect Datagram for the ToS & host
        HostToS = 3
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Time Exceeded".
    pub doc enum TimeExceeded(u8) {
        /// TTL expired in transit
        TtlExpired  = 0,
        /// Fragment reassembly time exceeded
        FragExpired = 1
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Parameter Problem".
    pub doc enum ParamProblem(u8) {
        /// Pointer indicates the error
        AtPointer     = 0,
        /// Missing a required option
        MissingOption = 1,
        /// Bad length
        BadLength     = 2
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 4 packet buffer.
#[derive(Debug)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    use wire::field::*;

    pub const TYPE:       usize = 0;
    pub const CODE:       usize = 1;
    pub const CHECKSUM:   Field = 2..4;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Wrap a buffer with an ICMPv4 packet. Returns an error if the buffer
    /// is too small to contain one.
    pub fn new(buffer: T) -> Result<Packet<T>, Error> {
        let len = buffer.as_ref().len();
        if len < field::CHECKSUM.end {
            Err(Error::Truncated)
        } else {
            let packet = Packet { buffer: buffer };
            if len < packet.header_len() {
                Err(Error::Truncated)
            } else {
                Ok(packet)
            }
        }
    }

    /// Consumes the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[inline(always)]
    pub fn msg_type(&self) -> Type {
        let data = self.buffer.as_ref();
        Type::from(data[field::TYPE])
    }

    /// Return the message code field.
    #[inline(always)]
    pub fn msg_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CODE]
    }

    /// Return the checksum field.
    #[inline(always)]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline(always)]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline(always)]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_SEQNO])
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Type::EchoRequest => field::ECHO_SEQNO.end,
            Type::EchoReply   => field::ECHO_SEQNO.end,
            _ => field::CHECKSUM.end // make a conservative assumption
        }
    }

    /// Validate the header checksum.
    pub fn verify_checksum(&self) -> bool {
        let data = self.buffer.as_ref();
        checksum::data(data) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the type-specific data.
    #[inline(always)]
    pub fn data(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[inline(always)]
    pub fn set_msg_type(&mut self, value: Type) {
        let mut data = self.buffer.as_mut();
        data[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[inline(always)]
    pub fn set_msg_code(&mut self, value: u8) {
        let mut data = self.buffer.as_mut();
        data[field::CODE] = value
    }

    /// Set the checksum field.
    #[inline(always)]
    pub fn set_checksum(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline(always)]
    pub fn set_echo_ident(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_IDENT], value)
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline(always)]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        let mut data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_SEQNO], value)
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum)
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a mutable pointer to the type-specific data.
    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let mut data = self.buffer.as_mut();
        &mut data[range]
    }
}

/// A high-level representation of an Internet Control Message Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr<'a> {
    EchoRequest {
        ident:  u16,
        seq_no: u16,
        data:   &'a [u8]
    },
    EchoReply {
        ident:  u16,
        seq_no: u16,
        data:   &'a [u8]
    },
    #[doc(hidden)]
    __Nonexhaustive
}

impl<'a> Repr<'a> {
    /// Parse an Internet Control Message Protocol version 4 packet and return
    /// a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'a T>) -> Result<Repr<'a>, Error> {
        match (packet.msg_type(), packet.msg_code()) {
            (Type::EchoRequest, 0) => {
                Ok(Repr::EchoRequest {
                    ident:  packet.echo_ident(),
                    seq_no: packet.echo_seq_no(),
                    data:   packet.data()
                })
            },
            (Type::EchoReply, 0) => {
                Ok(Repr::EchoReply {
                    ident:  packet.echo_ident(),
                    seq_no: packet.echo_seq_no(),
                    data:   packet.data()
                })
            },
            _ => Err(Error::Unrecognized)
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::EchoRequest { data, .. } |
            &Repr::EchoReply { data, .. } => {
                field::ECHO_SEQNO.end + data.len()
            },
            &Repr::__Nonexhaustive => unreachable!()
        }
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 4
    /// packet.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, packet: &mut Packet<&mut T>) {
        packet.set_msg_code(0);
        match self {
            &Repr::EchoRequest { ident, seq_no, data } => {
                packet.set_msg_type(Type::EchoRequest);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let data_len = cmp::min(packet.data_mut().len(), data.len());
                packet.data_mut()[..data_len].copy_from_slice(&data[..data_len])
            },
            &Repr::EchoReply { ident, seq_no, data } => {
                packet.set_msg_type(Type::EchoReply);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let data_len = cmp::min(packet.data_mut().len(), data.len());
                packet.data_mut()[..data_len].copy_from_slice(&data[..data_len])
            },
            &Repr::__Nonexhaustive => unreachable!()
        }
        packet.fill_checksum()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{}", repr),
            _ => {
                try!(write!(f, "ICMPv4 (unrecognized)"));
                try!(write!(f, " type={} code={} cksum={:#04x}",
                            self.msg_type(), self.msg_code(), self.checksum()));
                Ok(())
            }
        }
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Repr::EchoRequest { ident, seq_no, data } =>
                write!(f, "ICMPv4 Echo Request id={} seq={} len={}",
                       ident, seq_no, data.len()),
            &Repr::EchoReply { ident, seq_no, data } =>
                write!(f, "ICMPv4 Echo Reply id={} seq={} len={}",
                       ident, seq_no, data.len()),
            &Repr::__Nonexhaustive => unreachable!()
        }
    }
}

use super::pretty_print::{PrettyPrint, PrettyIndent};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(buffer: &AsRef<[u8]>, f: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result {
        match Packet::new(buffer) {
            Err(err)   => write!(f, "{}({})\n", indent, err),
            Ok(packet) => write!(f, "{}{}\n", indent, packet)
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    static ECHO_PACKET_BYTES: [u8; 12] =
        [0x08, 0x00, 0x8e, 0xfe,
         0x12, 0x34, 0xab, 0xcd,
         0xaa, 0x00, 0x00, 0xff];

    static ECHO_DATA_BYTES: [u8; 4] =
        [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_echo_deconstruct() {
        let packet = Packet::new(&ECHO_PACKET_BYTES[..]).unwrap();
        assert_eq!(packet.msg_type(), Type::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x8efe);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.data(), &ECHO_DATA_BYTES[..]);
        assert_eq!(packet.verify_checksum(), true);
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = vec![0; 12];
        let mut packet = Packet::new(&mut bytes).unwrap();
        packet.set_msg_type(Type::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.data_mut().copy_from_slice(&ECHO_DATA_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(&packet.into_inner()[..], &ECHO_PACKET_BYTES[..]);
    }

    fn echo_packet_repr() -> Repr<'static> {
        Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &ECHO_DATA_BYTES
        }
    }

    #[test]
    fn test_echo_parse() {
        let packet = Packet::new(&ECHO_PACKET_BYTES[..]).unwrap();
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, echo_packet_repr());
    }

    #[test]
    fn test_echo_emit() {
        let mut bytes = vec![0; 12];
        let mut packet = Packet::new(&mut bytes).unwrap();
        echo_packet_repr().emit(&mut packet);
        assert_eq!(&packet.into_inner()[..], &ECHO_PACKET_BYTES[..]);
    }
}

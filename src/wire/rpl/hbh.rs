use super::{InstanceId, Result};
use byteorder::{ByteOrder, NetworkEndian};

mod field {
    use crate::wire::field::*;

    pub const FLAGS: usize = 0;
    pub const INSTANCE_ID: usize = 1;
    pub const SENDER_RANK: Field = 2..4;
}

/// A read/write wrapper around a RPL Packet Information send with
/// an IPv6 Hop-by-Hop option, defined in RFC6553.
/// ```txt
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///                                 |  Option Type  |  Opt Data Len |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |O|R|F|0|0|0|0|0| RPLInstanceID |          SenderRank           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         (sub-TLVs)                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with a RPL Hop-by-Hop option structure.
    #[inline]
    pub fn new_unchecked(buffer: T) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().len() == 4 {
            Ok(())
        } else {
            Err(crate::wire::Error)
        }
    }

    /// Consume the packet, returning the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the Down field.
    #[inline]
    pub fn is_down(&self) -> bool {
        get!(self.buffer, bool, field: field::FLAGS, shift: 7, mask: 0b1)
    }

    /// Return the Rank-Error field.
    #[inline]
    pub fn has_rank_error(&self) -> bool {
        get!(self.buffer, bool, field: field::FLAGS, shift: 6, mask: 0b1)
    }

    /// Return the Forwarding-Error field.
    #[inline]
    pub fn has_forwarding_error(&self) -> bool {
        get!(self.buffer, bool, field: field::FLAGS, shift: 5, mask: 0b1)
    }

    /// Return the Instance ID field.
    #[inline]
    pub fn rpl_instance_id(&self) -> InstanceId {
        get!(self.buffer, into: InstanceId, field: field::INSTANCE_ID)
    }

    /// Return the Sender Rank field.
    #[inline]
    pub fn sender_rank(&self) -> u16 {
        get!(self.buffer, u16, field: field::SENDER_RANK)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Down field.
    #[inline]
    pub fn set_is_down(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::FLAGS, shift: 7, mask: 0b1)
    }

    /// Set the Rank-Error field.
    #[inline]
    pub fn set_has_rank_error(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::FLAGS, shift: 6, mask: 0b1)
    }

    /// Set the Forwarding-Error field.
    #[inline]
    pub fn set_has_forwarding_error(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::FLAGS, shift: 5, mask: 0b1)
    }

    /// Set the Instance ID field.
    #[inline]
    pub fn set_rpl_instance_id(&mut self, value: u8) {
        set!(self.buffer, value, field: field::INSTANCE_ID)
    }

    /// Set the Sender Rank field.
    #[inline]
    pub fn set_sender_rank(&mut self, value: u16) {
        set!(self.buffer, value, u16, field: field::SENDER_RANK)
    }
}

/// A high-level representation of an RPL Hop-by-Hop Option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HopByHopOption {
    pub down: bool,
    pub rank_error: bool,
    pub forwarding_error: bool,
    pub instance_id: InstanceId,
    pub sender_rank: u16,
}

impl HopByHopOption {
    /// Parse an RPL Hop-by-Hop Option and return a high-level representation.
    pub fn parse<T>(opt: &Packet<&T>) -> Self
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Self {
            down: opt.is_down(),
            rank_error: opt.has_rank_error(),
            forwarding_error: opt.has_forwarding_error(),
            instance_id: opt.rpl_instance_id(),
            sender_rank: opt.sender_rank(),
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        4
    }

    /// Emit a high-level representation into an RPL Hop-by-Hop Option.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, opt: &mut Packet<&mut T>) {
        opt.set_is_down(self.down);
        opt.set_has_rank_error(self.rank_error);
        opt.set_has_forwarding_error(self.forwarding_error);
        opt.set_rpl_instance_id(self.instance_id.into());
        opt.set_sender_rank(self.sender_rank);
    }
}

impl core::fmt::Display for HopByHopOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "down={} rank_error={} forw_error={} IID={:?} sender_rank={}",
            self.down, self.rank_error, self.forwarding_error, self.instance_id, self.sender_rank
        )
    }
}

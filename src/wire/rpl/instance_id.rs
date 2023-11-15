
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum InstanceId {
    Global(u8),
    Local(u8),
}

impl From<u8> for InstanceId {
    fn from(val: u8) -> Self {
        const MASK: u8 = 0b0111_1111;

        if ((val >> 7) & 0xb1) == 0b0 {
            Self::Global(val & MASK)
        } else {
            Self::Local(val & MASK)
        }
    }
}

impl From<InstanceId> for u8 {
    fn from(val: InstanceId) -> Self {
        match val {
            InstanceId::Global(val) => 0b0000_0000 | val,
            InstanceId::Local(val) => 0b1000_0000 | val,
        }
    }
}

impl InstanceId {
    /// Return the real part of the ID.
    pub fn id(&self) -> u8 {
        match self {
            Self::Global(val) => *val,
            Self::Local(val) => *val,
        }
    }

    /// Returns `true` when the DODAG ID is the destination address of the IPv6 packet.
    #[inline]
    pub fn dodag_is_destination(&self) -> bool {
        match self {
            Self::Global(_) => false,
            Self::Local(val) => ((val >> 6) & 0b1) == 0b1,
        }
    }

    /// Returns `true` when the DODAG ID is the source address of the IPv6 packet.
    ///
    /// *NOTE*: this only makes sence when using a local RPL Instance ID and the packet is not a
    /// RPL control message.
    #[inline]
    pub fn dodag_is_source(&self) -> bool {
        !self.dodag_is_destination()
    }

    #[inline]
    pub fn is_local(&self) -> bool {
        matches!(self, InstanceId::Local(_))
    }

    #[inline]
    pub fn is_global(&self) -> bool {
        matches!(self, InstanceId::Global(_))
    }
}

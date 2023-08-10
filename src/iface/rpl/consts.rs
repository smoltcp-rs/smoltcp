pub(crate) const SEQUENCE_WINDOW: u8 = 16;

pub(crate) const DEFAULT_MIN_HOP_RANK_INCREASE: u16 = 256;

pub(crate) const DEFAULT_DIO_INTERVAL_MIN: u32 = 12;
pub(crate) const DEFAULT_DIO_REDUNDANCY_CONSTANT: usize = 10;
/// This is 20 in the standard, but in Contiki they use:
pub(crate) const DEFAULT_DIO_INTERVAL_DOUBLINGS: u32 = 8;

pub(crate) const DEFAULT_RPL_INSTANCE_ID: u8 = 0x1e;

#![feature(range_contains)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

extern crate byteorder;

macro_rules! enum_with_unknown {
    (#[$( $attr:meta ),*]
     pub enum $name:ident($ty:ty) { $( $variant:ident = $value:expr ),+ }) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        #[$( $attr ),*]
        pub enum $name {
            $( $variant ),*,
            Unknown($ty)
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                match value {
                    $( $value => $name::$variant ),*,
                    other => $name::Unknown(other)
                }
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                match value {
                    $( $name::$variant => $value ),*,
                    $name::Unknown(other) => other
                }
            }
        }
    }
}

mod field {
    pub type Field     = ::core::ops::Range<usize>;
    pub type FieldFrom = ::core::ops::RangeFrom<usize>;
}

mod ethernet;

pub use ethernet::ProtocolType as EthernetProtocolType;
pub use ethernet::Address as EthernetAddress;
pub use ethernet::Frame as EthernetFrame;

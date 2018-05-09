#[cfg(feature = "proto-ipv4")]
use super::icmpv4;
#[cfg(feature = "proto-ipv6")]
use super::icmpv6;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Repr<'a> {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(icmpv4::Repr<'a>),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(icmpv6::Repr<'a>),
}
#[cfg(feature = "proto-ipv4")]
impl<'a> From<icmpv4::Repr<'a>> for Repr<'a> {
    fn from(s: icmpv4::Repr<'a>) -> Self {
        Repr::Ipv4(s)
    }
}
#[cfg(feature = "proto-ipv6")]
impl<'a> From<icmpv6::Repr<'a>> for Repr<'a> {
    fn from(s: icmpv6::Repr<'a>) -> Self {
        Repr::Ipv6(s)
    }
}

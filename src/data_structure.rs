#[cfg(feature = "smallmap")]
pub use smallmap::SmallMap as LinearMap;
#[cfg(feature = "smallvec")]
pub use smallvec::Vec;

#[cfg(not(feature = "smallmap"))]
pub use heapless::LinearMap;
#[cfg(not(feature = "smallvec"))]
pub use heapless::Vec;

#[cfg(feature = "smallvec")]
pub mod smallvec;

#[cfg(feature = "smallmap")]
pub mod smallmap;

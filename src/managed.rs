use core::ops::{Deref, DerefMut};
use core::fmt;

#[cfg(feature = "use_std")]
use std::boxed::Box;
#[cfg(feature = "use_alloc")]
use alloc::boxed::Box;
#[cfg(feature = "use_std")]
use std::vec::Vec;

/// A managed object.
///
/// This enum can be used to represent exclusive access to objects. In Rust, exclusive access
/// to an object is obtained by either owning the object, or owning a mutable pointer
/// to the object; hence, "managed".
///
/// The purpose of this enum is providing good ergonomics with `std` present while making
/// it possible to avoid having a heap at all (which of course means that `std` is not present).
/// To achieve this, the `Managed::Boxed` variant is only available when the "use_std" or
/// "use_alloc" feature is enabled.
///
/// A function that requires a managed object should be generic over an `Into<Managed<'a, T>>`
/// argument; then, it will be possible to pass either a `Box<T>`, `Vec<T>`, or a `&'a mut T`
/// without any conversion at the call site.
pub enum Managed<'a, T: 'a + ?Sized> {
    /// Borrowed variant, either a single element or a slice.
    Borrowed(&'a mut T),
    /// Owned variant, only available with `std` present.
    #[cfg(any(feature = "use_std", feature = "use_alloc"))]
    Boxed(Box<T>)
}

impl<'a, T: 'a + fmt::Debug + ?Sized> fmt::Debug for Managed<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Managed::from({:?})", self.deref())
    }
}

impl<'a, T: 'a + ?Sized> From<&'a mut T> for Managed<'a, T> {
    fn from(value: &'a mut T) -> Self {
        Managed::Borrowed(value)
    }
}

#[cfg(any(feature = "use_std", feature = "use_alloc"))]
impl<T: ?Sized + 'static> From<Box<T>> for Managed<'static, T> {
    fn from(value: Box<T>) -> Self {
        Managed::Boxed(value)
    }
}

#[cfg(feature = "use_std")]
impl<T: 'static> From<Vec<T>> for Managed<'static, [T]> {
    fn from(value: Vec<T>) -> Self {
        Managed::Boxed(value.into_boxed_slice())
    }
}

impl<'a, T: 'a + ?Sized> Deref for Managed<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            &Managed::Borrowed(ref value) => value,
            #[cfg(any(feature = "use_std", feature = "use_alloc"))]
            &Managed::Boxed(ref value) => value
        }
    }
}

impl<'a, T: 'a + ?Sized> DerefMut for Managed<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            &mut Managed::Borrowed(ref mut value) => value,
            #[cfg(any(feature = "use_std", feature = "use_alloc"))]
            &mut Managed::Boxed(ref mut value) => value
        }
    }
}


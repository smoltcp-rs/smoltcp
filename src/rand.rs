#![allow(unsafe_code)]
#![allow(unused)]

#[cfg(not(any(test, feature = "std", feature = "rand-custom-impl")))]
compile_error!("None of the Cargo features `std` or `rand-custom-impl` is enabled. smoltcp needs a `rand` implementation to work. If your target supports `std`, enable the `std` feature to use the OS's RNG. Otherwise, you must enable the `rand-custom-impl` Cargo feature, and supply your own custom implementation using the `smoltcp::rand_custom_impl!()` macro");

pub fn rand_u32() -> u32 {
    let mut val = [0; 4];
    rand_bytes(&mut val);
    u32::from_ne_bytes(val)
}

/// Fill `buf` with random bytes.
pub fn rand_bytes(buf: &mut [u8]) {
    extern "Rust" {
        fn _smoltcp_rand(buf: &mut [u8]);
    }

    unsafe { _smoltcp_rand(buf) }
}

/// Methods required for a custom rand implementation.
///
/// This trait is not intended to be used directly, just to supply a custom rand implementation to smoltcp.
#[cfg(feature = "rand-custom-impl")]
pub trait Rand {
    /// Fill `buf` with random bytes.
    fn rand_bytes(buf: &mut [u8]);
}

/// Set the custom rand implementation.
///
/// # Example
///
/// ```
/// struct Rand;
/// smoltcp::rand_custom_impl!(Rand);
/// impl smoltcp::Rand for Rand {
///     fn rand_bytes(buf: &mut [u8]) {
///         // TODO
///     }
/// }
///
#[macro_export]
#[cfg(feature = "rand-custom-impl")]
macro_rules! rand_custom_impl {
    ($t: ty) => {
        #[no_mangle]
        fn _smoltcp_rand(buf: &mut [u8]) {
            <$t as $crate::Rand>::rand_bytes(buf)
        }
    };
}

#[cfg(all(feature = "std", not(feature = "rand-custom-impl"), not(test)))]
#[no_mangle]
fn _smoltcp_rand(buf: &mut [u8]) {
    use rand_core::RngCore;

    rand_core::OsRng.fill_bytes(buf)
}

#[cfg(test)]
#[no_mangle]
fn _smoltcp_rand(buf: &mut [u8]) {
    panic!("Rand should not be used when testing");
}

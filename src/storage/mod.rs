//! Specialized generic containers
//!
//! The `storage` module provides generic containers to be used in other modules.
//! The containers should work in pre-allocated memory, without the `std`
//! and `collections` crates being available.
pub mod ring_buffer;

/// A trait for setting a value to the default state.
///
/// In-place analog of Default.
/// Used by RingBuffer for initializing a storage.
pub trait Resettable {
    fn reset(&mut self);
}


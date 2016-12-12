//! Pretty-printing of packet representation.
//!
//! The `pretty_print` module provides bits and pieces for printing concise,
//! easily human readable packet listings.
//!
//! # Example
//!
//! A packet can be formatted using the `PrettyPrinter` wrapper:
//!
//! ```rust,ignore
//! print!("{}", PrettyPrinter::<EthernetFrame<_>>::new("", &buffer))
//! ```

use core::fmt;
use core::marker::PhantomData;

/// Indentation state.
#[derive(Debug)]
pub struct PrettyIndent {
    prefix: &'static str,
    level:  usize
}

impl PrettyIndent {
    /// Create an indentation state. The entire listing will be indented by the width
    /// of `prefix`, and `prefix` will appear at the start of the first line.
    pub fn new(prefix: &'static str) -> PrettyIndent {
        PrettyIndent { prefix: prefix, level: 0 }
    }

    /// Increase indentation level.
    pub fn increase(&mut self) {
        self.level += 1
    }
}

impl fmt::Display for PrettyIndent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.level == 0 {
            write!(f, "{}", self.prefix)
        } else {
            write!(f, "{0:1$}{0:2$}\\ ", "", self.prefix.len(), self.level - 1)
        }
    }
}

/// Interface for printing listings.
pub trait PrettyPrint {
    /// Write a concise, formatted representation of a packet contained in the provided
    /// buffer, and any nested packets it may contain.
    ///
    /// `pretty_print` accepts a buffer and not a packet wrapper because the packet might
    /// be truncated, and so it might not be possible to create the packet wrapper.
    fn pretty_print(buffer: &AsRef<[u8]>, fmt: &mut fmt::Formatter,
                    indent: &mut PrettyIndent) -> fmt::Result;
}

/// Wrapper for using a `PrettyPrint` where a `Display` is expected.
pub struct PrettyPrinter<'a, T: PrettyPrint> {
    prefix:  &'static str,
    buffer:  &'a AsRef<[u8]>,
    phantom: PhantomData<T>
}

impl<'a, T: PrettyPrint> PrettyPrinter<'a, T> {
    /// Format the listing with the recorded parameters when Display::fmt is called.
    pub fn new(prefix: &'static str, buffer: &'a AsRef<[u8]>) -> PrettyPrinter<'a, T> {
        PrettyPrinter {
            prefix:  prefix,
            buffer:  buffer,
            phantom: PhantomData
        }
    }
}

impl<'a, T: PrettyPrint> fmt::Display for PrettyPrinter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        T::pretty_print(&self.buffer, f, &mut PrettyIndent::new(self.prefix))
    }
}

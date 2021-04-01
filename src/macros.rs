
#[cfg(feature = "log")]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*); };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*); };
}

#[cfg(feature = "defmt")]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { defmt::trace!($($arg),*); };
    (debug, $($arg:expr),*) => { defmt::debug!($($arg),*); };
}

#[cfg(not(any(feature = "log", feature = "defmt")))]
#[macro_use]
macro_rules! net_log {
    ($level:ident, $($arg:expr),*) => { $( let _ = $arg; )* }
}

macro_rules! net_trace {
    ($($arg:expr),*) => (net_log!(trace, $($arg),*));
}

macro_rules! net_debug {
    ($($arg:expr),*) => (net_log!(debug, $($arg),*));
}

macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident = $value:expr
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        $( #[$enum_attr] )*
        pub enum $name {
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
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

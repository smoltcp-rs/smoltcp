#[cfg(not(test))]
#[cfg(feature = "log")]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*) };
}

#[cfg(test)]
#[cfg(feature = "log")]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { println!($($arg),*) };
    (debug, $($arg:expr),*) => { println!($($arg),*) };
}

#[cfg(feature = "defmt")]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { defmt::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { defmt::debug!($($arg),*) };
}

#[cfg(not(any(feature = "log", feature = "defmt")))]
macro_rules! net_log {
    ($level:ident, $($arg:expr),*) => {{ $( let _ = $arg; )* }}
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

macro_rules! error_code_enum {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[repr(u8)]
        $( #[$enum_attr] )*
        pub enum $name {
            OK = (ResultCode::OK as u8),
            $(
              $( #[$variant_attr] )*
              $variant
            ),*,
        }

        impl From<Result<(), $name>> for $name {
            fn from(res: Result<(), $name>) -> Self {
                match res {
                    Ok(_) => $name::OK,
                    Err(err) => {
                        err
                    }
                }
            }
        }
    }
}

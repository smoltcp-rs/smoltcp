#[cfg(feature = "log")]
macro_rules! net_log_enabled {
    (trace) => (log_enabled!($crate::log::LogLevel::Trace));
    (debug) => (log_enabled!($crate::log::LogLevel::Debug));
}

#[cfg(not(feature = "log"))]
macro_rules! net_log_enabled {
    (trace) => (false);
    (debug) => (false);
}

macro_rules! net_trace {
    ($($arg:expr),*) => {{
        #[cfg(feature = "log")]
        trace!($($arg),*);
        #[cfg(not(feature = "log"))]
        $( let _ = $arg );*; // suppress unused variable warnings
    }}
}

macro_rules! net_debug {
    ($($arg:expr),*) => {{
        #[cfg(feature = "log")]
        debug!($($arg),*);
        #[cfg(not(feature = "log"))]
        $( let _ = $arg );*; // suppress unused variable warnings
    }}
}

macro_rules! enum_with_unknown {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $( $variant:ident = $value:expr ),+
        }
    ) => {
        enum_with_unknown! {
            $( #[$enum_attr] )*
            pub doc enum $name($ty) {
                $( #[doc(shown)] $variant = $value ),+
            }
        }
    };
    (
        $( #[$enum_attr:meta] )*
        pub doc enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )+
              $variant:ident = $value:expr
            ),+
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
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

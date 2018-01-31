#![allow(unsafe_code, unused, non_camel_case_types, non_snake_case)]

use libc;

use std::{mem, ptr, io};
use std::os::unix::io::RawFd;

pub use libc::*;

cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else if #[cfg(all(target_os = "linux", target_env = "gnu"))] {
        mod linux;
        pub use self::linux::*;
    }
}

cfg_if! {
    if #[cfg(all(feature = "phy-raw_socket",
                 any(target_os = "macos",
                     all(target_os = "linux", target_env = "gnu"))))] {
        mod raw_socket;
        pub use self::raw_socket::RawSocket;
    }
}

cfg_if! {
    if #[cfg(all(feature = "phy-tap_interface", 
                 all(target_os = "linux", target_env = "gnu")))] {
        mod tap_interface;
        pub use self::tap_interface::TapInterfaceDesc;
    }
}

pub fn wait(fd: RawFd, millis: Option<u64>) -> io::Result<()> {
    unsafe {
        let mut readfds = mem::uninitialized::<libc::fd_set>();
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(fd, &mut readfds);

        let mut writefds = mem::uninitialized::<libc::fd_set>();
        libc::FD_ZERO(&mut writefds);

        let mut exceptfds = mem::uninitialized::<libc::fd_set>();
        libc::FD_ZERO(&mut exceptfds);

        let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let timeout_ptr =
            if let Some(millis) = millis {
                timeout.tv_usec = (millis * 1_000) as libc::suseconds_t;
                &mut timeout as *mut _
            } else {
                ptr::null_mut()
            };

        let res = libc::select(fd + 1, &mut readfds, &mut writefds, &mut exceptfds, timeout_ptr);
        if res == -1 { return Err(io::Error::last_os_error()) }
        Ok(())
    }
}

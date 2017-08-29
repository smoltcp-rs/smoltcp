use libc;
use std::{mem, ptr, io};
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;

#[cfg(feature = "raw_socket")]
pub mod raw_socket;
#[cfg(all(feature = "tap_interface", target_os = "linux"))]
pub mod tap_interface;

#[cfg(feature = "raw_socket")]
pub use self::raw_socket::RawSocketDesc;
#[cfg(all(feature = "tap_interface", target_os = "linux"))]
pub use self::tap_interface::TapInterfaceDesc;

/// Wait until given file descriptor becomes readable, but no longer than given timeout.
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

#[repr(C)]
#[derive(Debug)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int /* ifr_ifindex or ifr_mtu */
}

fn ifreq_for(name: &str) -> ifreq {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }
    ifreq
}

fn ifreq_ioctl(lower: libc::c_int, ifreq: &mut ifreq,
               cmd: libc::c_ulong) -> io::Result<libc::c_int> {
    unsafe {
        let res = libc::ioctl(lower, cmd, ifreq as *mut ifreq);
        if res == -1 { return Err(io::Error::last_os_error()) }
    }

    Ok(ifreq.ifr_data)
}

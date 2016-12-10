use libc;
use std::io;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;

pub mod raw_socket;
#[cfg(target_os = "linux")]
pub mod tap_interface;

pub use self::raw_socket::RawSocketDesc;
#[cfg(target_os = "linux")]
pub use self::tap_interface::TapInterfaceDesc;

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

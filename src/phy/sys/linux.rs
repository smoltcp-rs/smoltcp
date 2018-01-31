
use libc;

use phy::sys;


use std::io;
use std::ptr;
use std::mem;
use std::ffi::CString;

#[cfg(target_env = "gnu")]
type FLAG_TYPE = libc::c_ulong;
#[cfg(target_env = "musl")]
type FLAG_TYPE = libc::c_int;
pub const SIOCGIFADDR: FLAG_TYPE = 0x8915;

pub const SIOCGIFHWADDR: FLAG_TYPE = 0x8927;

pub const SIOCGIFFLAGS: FLAG_TYPE = 0x8913;
pub const SIOCSIFFLAGS: FLAG_TYPE = 0x8914;

pub const SIOCGIFMTU: FLAG_TYPE = 0x00008921;
pub const SIOCSIFMTU: FLAG_TYPE = 0x00008922;

pub const SIOCGIFMETRIC: FLAG_TYPE = 0x0000891d;
pub const SIOCSIFMETRIC: FLAG_TYPE = 0x0000891e;

pub const SIOCGIFINDEX: FLAG_TYPE = 0x8933;

pub const TUNSETIFF: FLAG_TYPE = 0x400454CA;


#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr:      libc::sockaddr,
    pub dstaddr:   libc::sockaddr,
    pub broadaddr: libc::sockaddr,
    pub netmask:   libc::sockaddr,
    pub hwaddr:    libc::sockaddr,
    pub flags:     libc::c_short,
    pub metric:    libc::c_int,
    pub mtu:       libc::c_int,
    pub data:      *mut libc::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    pub ifru: ifru,
}

pub fn if_name_to_mtu(name: &str) -> Result<usize, io::Error> {
    #[repr(C)]
    #[derive(Debug)]
    struct ifreq {
        ifr_name: [sys::c_char; sys::IF_NAMESIZE],
        ifr_mtu: sys::c_int
    }

    let mut ifreq = ifreq {
        ifr_name: [0; sys::IF_NAMESIZE],
        ifr_mtu: 0
    };

    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as sys::c_char
    }

    let fd = unsafe {
        sys::socket(sys::AF_PACKET,
                    sys::SOCK_RAW | sys::SOCK_NONBLOCK,
                    sys::ETH_P_ALL)
    };

    if fd == -1 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    
    let ret = unsafe {
        sys::ioctl(fd, sys::SIOCGIFMTU, &mut ifreq as *mut ifreq)
    };

    unsafe { libc::close(fd) };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ifreq.ifr_mtu as usize)
    }
}

pub fn if_name_to_index(ifname: &str) -> u32 {
    unsafe { sys::if_nametoindex(CString::new(ifname).unwrap().as_ptr()) }
}

pub fn if_name_to_flags(ifname: &str) -> Result<i32, io::Error> {
    let fd = unsafe { sys::socket(sys::AF_INET, sys::SOCK_DGRAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    #[repr(C)]
    struct ifreq {
        pub ifr_name: [sys::c_char; sys::IF_NAMESIZE],
        pub ifr_flags: sys::c_short,
    }
    
    let mut req: ifreq = unsafe { mem::zeroed() };
    unsafe {
        ptr::copy_nonoverlapping(ifname.as_ptr() as *const sys::c_char,
                                 req.ifr_name.as_mut_ptr(),
                                 ifname.len());
        let ret = sys::ioctl(fd, sys::SIOCGIFFLAGS, &req);
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(req.ifr_flags as i32)
}

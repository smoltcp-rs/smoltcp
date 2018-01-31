
use libc;
use phy::sys;

#[path = "bpf.rs"]
mod bpf;
pub use self::bpf::*;


use std::str;
use std::io;
use std::ffi::CStr;
use std::ffi::CString;
use std::string::String;
use std::string::ToString;


pub const SIOCSIFADDR: libc::c_ulong = 0x8020690c;
pub const SIOCGIFADDR: libc::c_ulong = 0xc0206921;
pub const SIOCSIFDSTADDR: libc::c_ulong = 0x8020690e;
pub const SIOCGIFDSTADDR: libc::c_ulong = 0xc0206922;
pub const SIOCSIFBRDADDR: libc::c_ulong = 0x80206913;
pub const SIOCGIFBRDADDR: libc::c_ulong = 0xc0206923;
pub const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;
pub const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;
pub const SIOCSIFNETMASK: libc::c_ulong = 0x80206916;
pub const SIOCGIFNETMASK: libc::c_ulong = 0xc0206925;
pub const SIOCGIFMETRIC: libc::c_ulong = 0xc0206917;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x80206918;
pub const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
pub const SIOCSIFMTU: libc::c_ulong = 0x80206934;
pub const SIOCSIFMEDIA: libc::c_ulong = 0xc0206937;
pub const SIOCGIFMEDIA: libc::c_ulong = 0xc02c6938;
pub const SIOCGIFSTATUS: libc::c_ulong = 0xc331693d;
pub const SIOCSIFLLADDR: libc::c_ulong = 0x8020693c;

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr:      libc::sockaddr,
    pub dstaddr:   libc::sockaddr,
    pub broadaddr: libc::sockaddr,
    pub flags:     libc::c_short,
    pub metric:    libc::c_int,
    pub mtu:       libc::c_int,
    pub media:     libc::c_int,
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

    let fd = unsafe { sys::socket(sys::AF_INET, sys::SOCK_DGRAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut ifreq = ifreq {
        ifr_name: [0; sys::IF_NAMESIZE],
        ifr_mtu: 0
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as sys::c_char
    }
    
    let ret = unsafe { sys::ioctl(fd, sys::SIOCGIFMTU, &mut ifreq as *mut ifreq) };
    
    unsafe { libc::close(fd) };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ifreq.ifr_mtu as usize)
    }
}

pub fn if_index_to_name(ifindex: u32) -> String {
    let ifname_buf: [u8; libc::IF_NAMESIZE] = [0u8; libc::IF_NAMESIZE];
    unsafe {
        let ifname_cstr = CStr::from_bytes_with_nul_unchecked(&ifname_buf);
        let ptr = ifname_cstr.as_ptr() as *mut i8;
        libc::if_indextoname(ifindex, ptr);

        let mut pos = ifname_buf.len() - 1;
        while pos != 0 {
            if ifname_buf[pos] != 0 {
                if pos + 1 < ifname_buf.len() {
                    pos += 1;
                }
                break;
            }
            pos -= 1;
        }
        str::from_utf8(&ifname_buf[..pos]).unwrap().to_string()
    }
}

pub fn if_name_to_index(ifname: &str) -> u32 {
    unsafe { libc::if_nametoindex(CString::new(ifname).unwrap().as_ptr()) }
}

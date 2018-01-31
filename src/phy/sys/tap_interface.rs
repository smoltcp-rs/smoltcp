use libc;

use phy::sys;

use std::io;
use std::os::unix::io::{RawFd, AsRawFd};

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


#[derive(Debug)]
pub struct TapInterfaceDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

impl AsRawFd for TapInterfaceDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl TapInterfaceDesc {
    pub fn new(name: &str) -> io::Result<TapInterfaceDesc> {
        let lower = unsafe {
            let lower = libc::open("/dev/net/tun\0".as_ptr() as *const libc::c_char,
                                   libc::O_RDWR | libc::O_NONBLOCK);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        Ok(TapInterfaceDesc {
            lower: lower,
            ifreq: ifreq_for(name)
        })
    }

    pub fn attach_interface(&mut self) -> io::Result<()> {
        self.ifreq.ifr_data = (sys::IFF_TAP as i32) | (sys::IFF_NO_PI as i32);
        ifreq_ioctl(self.lower, &mut self.ifreq, sys::TUNSETIFF).map(|_| ())
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        let lower = unsafe {
            let lower = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        let mtu = ifreq_ioctl(lower, &mut self.ifreq, sys::SIOCGIFMTU).map(|mtu| mtu as usize);

        unsafe { libc::close(lower); }

        mtu
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::read(self.lower, buffer.as_mut_ptr() as *mut libc::c_void,
                                 buffer.len());
            if len == -1 { return Err(io::Error::last_os_error()) }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::write(self.lower, buffer.as_ptr() as *const libc::c_void,
                                  buffer.len());
            if len == -1 { Err(io::Error::last_os_error()).unwrap() }
            Ok(len as usize)
        }
    }
}

impl Drop for TapInterfaceDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.lower); }
    }
}

use libc;
use std::io;
use super::*;

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct TapInterfaceDesc {
    lower: libc::c_int,
    ifreq: ifreq
}

impl TapInterfaceDesc {
    pub fn new(name: &str) -> io::Result<TapInterfaceDesc> {
        let lower = unsafe {
            let lower = libc::open("/dev/net/tun".as_ptr() as *const libc::c_char,
                                   libc::O_RDWR);
            if lower == -1 { return Err(io::Error::last_os_error()) }
            lower
        };

        Ok(TapInterfaceDesc {
            lower: lower,
            ifreq: ifreq_for(name)
        })
    }

    pub fn attach_interface(&mut self) -> io::Result<()> {
        self.ifreq.ifr_data = imp::IFF_TAP | imp::IFF_NO_PI;
        ifreq_ioctl(self.lower, &mut self.ifreq, imp::TUNSETIFF).map(|_| ())
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

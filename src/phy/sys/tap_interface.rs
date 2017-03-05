use std::mem;
use std::io;
use libc;
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

    fn wait(&mut self, ms: u32) -> io::Result<bool> {
        unsafe {
            let mut readfds = mem::uninitialized::<libc::fd_set>();
            libc::FD_ZERO(&mut readfds);
            libc::FD_SET(self.lower, &mut readfds);
            let mut writefds = mem::uninitialized::<libc::fd_set>();
            libc::FD_ZERO(&mut writefds);
            let mut exceptfds = mem::uninitialized::<libc::fd_set>();
            libc::FD_ZERO(&mut exceptfds);
            let mut timeout = libc::timeval { tv_sec: 0, tv_usec: (ms * 1_000) as i64 };
            let res = libc::select(self.lower + 1, &mut readfds, &mut writefds, &mut exceptfds,
                                   &mut timeout);
            if res == -1 { return Err(io::Error::last_os_error()) }
            Ok(res == 0)
        }
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // FIXME: here we don't wait forever, in case we need to send several packets in a row
        // ideally this would be implemented by going full nonblocking
        if self.wait(100)? { return Err(io::ErrorKind::TimedOut)? }

        unsafe {
            let len = libc::read(self.lower, buffer.as_mut_ptr() as *mut libc::c_void,
                                 buffer.len());
            if len == -1 { return Err(io::Error::last_os_error()) }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.wait(100)?;

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

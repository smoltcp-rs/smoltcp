#![allow(unsafe_code)]

use Result;
use phy::{self, sys, LinkLayer, DeviceCapabilities, Device};

use std::io;
use std::vec::Vec;
use std::rc::Rc;
use std::cell::RefCell;
use std::os::unix::io::{RawFd, AsRawFd};


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSocket {
    inner: Rc<RefCell<sys::RawSocket>>,
    mtu: usize,
    blen: usize,
    dt: LinkLayer,
    len: usize,
    offset: usize,
}

impl RawSocket {
    /// Creates a raw socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn with_ifname(ifname: &str) -> io::Result<RawSocket> {
        let inner = sys::RawSocket::with_ifname(ifname)?;
        let mtu = inner.mtu();
        let blen = inner.blen();
        let dt = inner.link_layer();

        Ok(RawSocket {
            inner: Rc::new(RefCell::new(inner)),
            mtu: mtu,
            blen: blen,
            dt: dt,
            len: 0,
            offset: 0,
        })
    }

    pub fn link_layer(&self) -> LinkLayer {
        let inner = self.inner.borrow_mut();
        inner.link_layer()
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.borrow().as_raw_fd()
    }
}


impl<'a> Device<'a> for RawSocket {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.mtu,
            ..DeviceCapabilities::default()
        }
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut inner = self.inner.borrow_mut();

        let mut buffer = vec![0; self.blen];

        match inner.recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken { lower: self.inner.clone() };
                Some((rx, tx))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                None
            }
            Err(err) => panic!("{}", err)
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut inner = self.inner.borrow_mut();

        let mut buffer = vec![0; self.blen];

        if self.len == 0 {
            match inner.recv(&mut buffer) {
                Ok(amt) => {
                    self.len = amt;
                    self.offset = 0;
                },
                Err(ref err) => {
                    if err.kind() == io::ErrorKind::WouldBlock {
                        return None;
                    } else {
                        panic!("{}", err);
                    }
                }
            }
        }

        if self.offset >= self.len {
            self.len = 0;
            self.offset = 0;
            return None;
        }

        let len = self.len;
        let offset = self.offset;

        let bpf_buf = &buffer[offset..offset+sys::BPF_HDR_SIZE];
        let bpf_packet = bpf_buf.as_ptr() as *const sys::bpf_hdr;
        let bh_hdrlen = unsafe { (*bpf_packet).bh_hdrlen } as usize ;
        let bh_datalen = unsafe { (*bpf_packet).bh_datalen } as usize;
        
        if bh_datalen + bh_hdrlen > len as usize {
            self.len = 0;
            self.offset = 0;
            None
        } else {
            self.offset = offset + sys::BPF_WORDALIGN((bh_datalen + bh_hdrlen) as isize) as usize;
            let bpos = offset + bh_hdrlen;
            let epos = offset + bh_hdrlen + bh_datalen;
            
            let packet = buffer[bpos..epos].to_vec();
            if packet.len() > 0 {
                let rx = RxToken { buffer: packet};
                let tx = TxToken { lower: self.inner.clone() };
                Some((rx, tx))
            } else {
                self.len = 0;
                self.offset = 0;
                None
            }
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            lower: self.inner.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, _timestamp: u64, f: F) -> Result<R> {
        f(&self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower:  Rc<RefCell<sys::RawSocket>>,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> Result<R>>(self, _timestamp: u64, len: usize, f: F)
        -> Result<R>
    {
        let lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        lower.send(&mut buffer[..]).unwrap();
        result
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl phy::TxToken for TxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> Result<R>>(self, _timestamp: u64, len: usize, f: F)
        -> Result<R>
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        lower.send(&mut buffer[..]).unwrap();
        result
    }
}


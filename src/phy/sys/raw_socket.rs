
use phy::LinkLayer;
use phy::sys;

use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::os::unix::io::AsRawFd;

cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "freebsd"))] {
        use std::ffi::CString;
        use std::time::Duration;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSocket {
    fd: sys::c_int,
    dt: LinkLayer,
    mtu: usize,
    blen: usize,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl RawSocket {
    pub fn with_ifname(ifname: &str) -> Result<RawSocket, io::Error> {
        let flags = sys::if_name_to_flags(ifname).unwrap();
        let link_layer = 
            if flags & sys::IFF_LOOPBACK != 0 {
                LinkLayer::Eth
            } else if flags & sys::IFF_BROADCAST != 0 {
                LinkLayer::Eth
            } else if flags & sys::IFF_POINTOPOINT != 0 {
                if flags & sys::IFF_NO_PI as i32 != 0 {
                    LinkLayer::Ip
                } else {
                    LinkLayer::Null
                }
            } else {
                return Err(io::Error::new(io::ErrorKind::Other, "Data Link Layer Unknow."))
            };
        let protocol = match link_layer {
            LinkLayer::Eth | LinkLayer::Null => (sys::ETH_P_ALL as u16).to_be(),
            LinkLayer::Ip => (sys::ETH_P_IP as u16).to_be()
        };

        let fd = unsafe {
            sys::socket(sys::AF_PACKET, sys::SOCK_RAW | sys::SOCK_NONBLOCK, protocol as i32)
        };

        if fd == -1 {
            return Err(io::Error::last_os_error())
        }
        
        let ifindex = sys::if_name_to_index(ifname);

        let sll = sys::sockaddr_ll {
            sll_family:   sys::AF_PACKET as u16,
            sll_protocol: protocol as u16,
            sll_ifindex:  ifindex as i32,
            sll_hatype:   1,
            sll_pkttype:  0,
            sll_halen:    6,
            sll_addr:     [0; 8]
        };
        
        let sa = &sll as *const sys::sockaddr_ll as *const sys::sockaddr;
        let ret = unsafe { sys::bind(fd, sa, mem::size_of::<sys::sockaddr_ll>() as u32) };

        if ret == -1 {
            unsafe { sys::close(fd) };
            return Err(io::Error::last_os_error())
        }
        
        let mtu = sys::if_name_to_mtu(ifname).unwrap();


        Ok(RawSocket { fd: fd, dt: link_layer, mtu: mtu, blen: mtu })
    }
    
    pub fn link_layer(&self) -> LinkLayer {
        self.dt
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn blen(&self) -> usize {
        self.blen
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let len = unsafe {
            sys::recv(self.fd, 
                      buf.as_mut_ptr() as *mut sys::c_void,
                      buf.len(), 0)
        };

        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let len = unsafe {
            sys::send(self.fd,
                      buf.as_ptr() as *const sys::c_void,
                      buf.len(),
                      0)
        };

        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }
}


#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl RawSocket {
    #[cfg(target_os = "macos")]
    pub fn open_bpf() -> Result<sys::c_int, io::Error> {
        for i in 0..50 {
            let filename = CString::new(format!("/dev/bpf{}", i)).unwrap();
            let fd = unsafe { sys::open(filename.as_ptr(), sys::O_RDWR) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::PermissionDenied => {
                        unsafe { sys::close(fd) };
                        return Err(err);
                    },
                    io::ErrorKind::NotFound => { },
                    _ => { }
                }
            } else {
                return Ok(fd);
            }
            unsafe { sys::close(fd) };
        }
        Err(io::Error::last_os_error())
    }

    #[cfg(target_os = "freebsd")]
    pub fn open_bpf() -> Result<sys::c_int, io::Error> {
        let filename = CString::new("/dev/bpf").unwrap();
        let fd = unsafe { sys::open(filename.as_ptr(), sys::O_RDWR) };
        if fd < 0 {
            unsafe { sys::close(fd) };
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    fn set_option(fd: sys::c_int, option: sys::c_ulong, value: sys::uint32_t) -> Result<(), io::Error>{
        let ret = unsafe { sys::ioctl(fd, option, &value) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn set_timeout(fd: sys::c_int, duration: Duration) -> Result<(), io::Error> {
        let tv_timeout = sys::BPF_TIMEVAL {
            tv_sec: duration.as_secs() as sys::BPF_TIMEVAL_SEC_T,
            tv_usec: 0
        };

        let ret = unsafe { sys::ioctl(fd, sys::BIOCSRTIMEOUT, &tv_timeout) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn get_link_layer(fd: sys::c_int) -> Result<sys::uint32_t, io::Error> {
        let dlt: sys::uint32_t = 0;

        let ret = unsafe { sys::ioctl(fd, sys::BIOCGDLT, &dlt) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(dlt)
        }
    }

    #[allow(dead_code)]
    fn set_link_layer(fd: sys::c_int, dlt: sys::uint32_t) -> Result<(), io::Error> {
        let ret = unsafe { sys::ioctl(fd, sys::BIOCSDLT, &dlt) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn get_blen(fd: sys::c_int) -> Result<usize, io::Error> {
        let blen: sys::size_t = 0;

        let ret = unsafe { sys::ioctl(fd, sys::BIOCGBLEN, &blen) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(blen)
        }
    }

    pub fn with_ifname(ifname: &str) -> Result<RawSocket, io::Error> {
        match RawSocket::open_bpf() {
            Ok(bpf_fd) => {
                // Set header complete mode
                RawSocket::set_option(bpf_fd, sys::BIOCSHDRCMPLT, 1).unwrap();
                // Monitor packets sent from our interface
                RawSocket::set_option(bpf_fd, sys::BIOCSSEESENT, 1).unwrap();
                // Return immediately when a packet received
                RawSocket::set_option(bpf_fd, sys::BIOCIMMEDIATE, 1).unwrap();
                // Set buffer length ( 100 KB )
                RawSocket::set_option(bpf_fd, sys::BIOCSBLEN, 1024*100).unwrap();
                // set the timeout
                RawSocket::set_timeout(bpf_fd, Duration::from_secs(3)).unwrap();
                // bind to netif
                #[repr(C)]
                struct ifreq {
                    pub ifr_name: [sys::c_char; sys::IF_NAMESIZE],
                    pub ifru_addr: sys::sockaddr,
                }

                let mut iface: ifreq = unsafe { mem::zeroed() };
                for (i, byte) in ifname.bytes().enumerate() {
                    iface.ifr_name[i] = byte as sys::c_char;
                }

                // non-blocking I/O.
                if unsafe { sys::ioctl(bpf_fd, sys::FIONBIO as u64, &iface) } < 0 {
                    return Err(io::Error::last_os_error());
                }

                if unsafe { sys::ioctl(bpf_fd, sys::BIOCSETIF, &iface) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                
                let link_layer = match RawSocket::get_link_layer(bpf_fd).unwrap() {
                    sys::DLT_NULL => LinkLayer::Null,
                    sys::DLT_EN10MB => LinkLayer::Eth,
                    sys::DLT_RAW => LinkLayer::Ip,
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "Data Link Layer Unknow."))
                };
                let mtu = sys::if_name_to_mtu(&ifname).unwrap();
                let blen = RawSocket::get_blen(bpf_fd).unwrap();
                Ok(RawSocket { fd: bpf_fd, dt: link_layer, mtu: mtu, blen: blen })
            },
            Err(e) => Err(e)
        }
    }

    pub fn link_layer(&self) -> LinkLayer {
        self.dt
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn blen(&self) -> usize {
        self.blen
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let len = unsafe { sys::read(self.fd, buf.as_mut_ptr() as *mut sys::c_void, self.blen) };

        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize, io::Error> {
        let ptr = buf.as_ptr();
        let size = buf.len();
        
        let ret = unsafe { sys::write(self.fd, ptr as *mut sys::c_void, size) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size)
        }
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { sys::close(self.fd) };
    }
}
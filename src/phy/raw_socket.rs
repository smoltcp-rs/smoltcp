extern crate std;
extern crate libc;

use self::std::{mem, vec, io};

#[repr(C)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int /* ifr_ifindex or ifr_mtu */
}

const SIOCGIFMTU:   libc::c_ulong = 0x8921;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

const ETH_P_ALL:    libc::c_short = 0x0003;

/// A raw socket: a socket that captures the entire packet, up to and including
/// the link layer header.
#[derive(Debug)]
pub struct RawSocket {
    sockfd: libc::c_int,
    buffer: vec::Vec<u8>
}

impl RawSocket {
    /// Creates and returns a raw socket, bound to the interface called `name`.
    pub fn new(name: &str) -> io::Result<RawSocket> {
        unsafe {
            let sockfd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32);
            if sockfd == -1 {
                return Err(io::Error::last_os_error())
            }

            let mut ifreq = ifreq {
                ifr_name: [0; libc::IF_NAMESIZE],
                ifr_data: 0
            };
            for (i, byte) in name.as_bytes().iter().enumerate() {
                ifreq.ifr_name[i] = *byte as libc::c_char
            }

            let res = libc::ioctl(sockfd, SIOCGIFINDEX, &mut ifreq as *mut ifreq);
            if res == -1 {
                libc::close(sockfd);
                return Err(io::Error::last_os_error())
            }
            let if_index = ifreq.ifr_data;

            let res = libc::ioctl(sockfd, SIOCGIFMTU, &mut ifreq as *mut ifreq);
            if res == -1 {
                libc::close(sockfd);
                return Err(io::Error::last_os_error())
            }
            let if_mtu = ifreq.ifr_data;

            let sockaddr = libc::sockaddr_ll {
                sll_family:   libc::AF_PACKET as u16,
                sll_protocol: ETH_P_ALL.to_be() as u16,
                sll_ifindex:  if_index as i32,
                sll_hatype:   1,
                sll_pkttype:  0,
                sll_halen:    6,
                sll_addr:     [0; 8]
            };
            libc::bind(sockfd,
                       &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                       mem::size_of::<libc::sockaddr_ll>() as u32);
            if res == -1 {
                libc::close(sockfd);
                return Err(io::Error::last_os_error())
            }

            let mut buffer = vec::Vec::new();
            buffer.resize(if_mtu as usize, 0);
            Ok(RawSocket {
                sockfd: sockfd,
                buffer: buffer
            })
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.sockfd); }
    }
}

impl super::Device for RawSocket {
    const MTU: usize = 1536;

    fn recv<F: FnOnce(&[u8])>(&mut self, handler: F) {
        let len = unsafe {
            let len = libc::recv(self.sockfd, self.buffer.as_mut_ptr() as *mut libc::c_void,
                                 self.buffer.len(), 0);
            if len == -1 { Err(io::Error::last_os_error()).unwrap() }
            len
        };

        handler(&self.buffer[..len as usize])
    }

    fn send<F: FnOnce(&mut [u8])>(&mut self, size: usize, handler: F) {
        handler(&mut self.buffer[..size]);

        unsafe {
            let len = libc::send(self.sockfd, self.buffer.as_ptr() as *const libc::c_void,
                                 size, 0);
            if len == -1 { Err(io::Error::last_os_error()).unwrap() }
        }
    }
}

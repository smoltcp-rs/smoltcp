
use libc;

use phy::sys;


pub const BIOCSETIF: libc::c_ulong = 0x8020426c;
pub const BIOCGETIF: libc::c_ulong = 0x4020426b;

pub const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;

pub const BIOCGBLEN: libc::c_ulong = 0x40044266;
pub const BIOCSBLEN: libc::c_ulong = 0xc0044266;

pub const BIOCGDLT: libc::c_ulong = 0x4004426a;
pub const BIOCSDLT: libc::c_ulong = 0x80044278;

pub const BIOCSHDRCMPLT: libc::c_ulong = 0x80044275;
pub const BIOCSRTIMEOUT: libc::c_ulong = 0x8010426d;

pub const BIOCGSEESENT: libc::c_ulong = 0x40044276;
pub const BIOCSSEESENT: libc::c_ulong = 0x80044277;

cfg_if! {
    if #[cfg(all(target_os = "macos", target_pointer_width = "32"))] {
        pub type BPF_TIMEVAL = libc::timeval;
        pub type BPF_TIMEVAL_SEC_T = i64;
    } else if #[cfg(all(target_os = "macos", target_pointer_width = "64"))] {
        pub type BPF_TIMEVAL = libc::timeval32;
        pub type BPF_TIMEVAL_SEC_T = i32;
    } else if #[cfg(target_os = "freebsd")] {
        pub type BPF_TIMEVAL = libc::timeval;
        pub type BPF_TIMEVAL_SEC_T = i32;
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub const BPF_HDR_SIZE: usize = ::std::mem::size_of::<sys::bpf_hdr>();

pub fn BPF_WORDALIGN(x: isize) -> isize {
    let bpf_alignment = libc::BPF_ALIGNMENT as isize;
    (x + (bpf_alignment - 1)) & !(bpf_alignment - 1)
}

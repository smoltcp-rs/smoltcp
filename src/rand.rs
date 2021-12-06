#![allow(unsafe_code)]
#![allow(unused)]

#[derive(Debug)]
pub(crate) struct Rand {
    state: u64,
}

impl Rand {
    pub(crate) const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn rand_u32(&mut self) -> u32 {
        // sPCG32 from https://www.pcg-random.org/paper.html
        // see also https://nullprogram.com/blog/2017/09/21/
        const M: u64 = 0xbb2efcec3c39611d;
        const A: u64 = 0x7590ef39;

        let s = self.state.wrapping_mul(M).wrapping_add(A);
        self.state = s;

        let shift = 29 - (s >> 61);
        (s >> shift) as u32
    }
}

use Error;
use super::Device;

// We use our own RNG to stay compatible with #![no_std].
// The use of the RNG below has a slight bias, but it doesn't matter.
fn xorshift32(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

fn check_rng(state: &mut u32, pct: u8) -> bool {
    xorshift32(state) % 100 < pct as u32
}

fn corrupt<T: AsMut<[u8]>>(state: &mut u32, mut buffer: T) {
    let mut buffer = buffer.as_mut();
    // We introduce a single bitflip, as the most likely, and the hardest to detect, error.
    let index = (xorshift32(state) as usize) % buffer.len();
    let bit   = 1 << (xorshift32(state) % 8) as u8;
    buffer[index] ^= bit;
}

// This could be fixed once associated consts are stable.
const MTU: usize = 1536;

#[derive(Debug, Clone, Copy)]
struct Config {
    corrupt_pct: u8,
    drop_pct:    u8,
    reorder_pct: u8
}

/// A fault injector device.
///
/// A fault injector is a device that randomly drops or corrupts packets traversing it,
/// according to preset probabilities.
#[derive(Debug)]
pub struct FaultInjector<T: Device> {
    lower:  T,
    state:  u32,
    config: Config
}

impl<T: Device> FaultInjector<T> {
    /// Create a tracer device, using the given random number generator seed.
    pub fn new(lower: T, seed: u32) -> FaultInjector<T> {
        FaultInjector {
            lower: lower,
            state: seed,
            config: Config {
                corrupt_pct: 0,
                drop_pct:    0,
                reorder_pct: 0
            }
        }
    }

    /// Return the underlying device, consuming the tracer.
    pub fn into_lower(self) -> T {
        self.lower
    }

    /// Return the probability of corrupting a packet, in percents.
    pub fn corrupt_chance(&self) -> u8 {
        self.config.corrupt_pct
    }

    /// Return the probability of dropping a packet, in percents.
    pub fn drop_chance(&self) -> u8 {
        self.config.drop_pct
    }

    /// Set the probability of corrupting a packet, in percents.
    ///
    /// # Panics
    /// This function panics if the probability is not between 0% and 100%.
    pub fn set_corrupt_chance(&mut self, pct: u8) {
        if pct > 100 { panic!("percentage out of range") }
        self.config.corrupt_pct = pct
    }

    /// Set the probability of dropping a packet, in percents.
    ///
    /// # Panics
    /// This function panics if the probability is not between 0% and 100%.
    pub fn set_drop_chance(&mut self, pct: u8) {
        if pct > 100 { panic!("percentage out of range") }
        self.config.drop_pct = pct
    }
}

impl<T: Device> Device for FaultInjector<T>
        where T::RxBuffer: AsMut<[u8]> {
    type RxBuffer = T::RxBuffer;
    type TxBuffer = TxBuffer<T::TxBuffer>;

    fn mtu(&self) -> usize {
        if self.lower.mtu() < MTU {
            self.lower.mtu()
        } else {
            MTU
        }
    }

    fn receive(&mut self) -> Result<Self::RxBuffer, Error> {
        let mut buffer = try!(self.lower.receive());
        if check_rng(&mut self.state, self.config.drop_pct) {
            net_trace!("rx: dropping a packet");
            return Err(Error::Exhausted)
        }
        if check_rng(&mut self.state, self.config.corrupt_pct) {
            net_trace!("rx: corrupting a packet");
            corrupt(&mut self.state, &mut buffer)
        }
        Ok(buffer)
    }

    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, Error> {
        let buffer;
        if check_rng(&mut self.state, self.config.drop_pct) {
            net_trace!("tx: dropping a packet");
            buffer = None;
        } else {
            buffer = Some(try!(self.lower.transmit(length)));
        }
        Ok(TxBuffer {
            buffer: buffer,
            state:  xorshift32(&mut self.state),
            config: self.config,
            junk:   [0; MTU],
            length: length
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer<T: AsRef<[u8]> + AsMut<[u8]>> {
    state:  u32,
    config: Config,
    buffer: Option<T>,
    junk:   [u8; MTU],
    length: usize
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsRef<[u8]>
        for TxBuffer<T> {
    fn as_ref(&self) -> &[u8] {
        match self.buffer {
            Some(ref buf) => buf.as_ref(),
            None => &self.junk[..self.length]
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]>
        for TxBuffer<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self.buffer {
            Some(ref mut buf) => buf.as_mut(),
            None => &mut self.junk[..self.length]
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Drop for TxBuffer<T> {
    fn drop(&mut self) {
        match self.buffer {
            Some(ref mut buf) => {
                if check_rng(&mut self.state, self.config.corrupt_pct) {
                    net_trace!("tx: corrupting a packet");
                    corrupt(&mut self.state, buf)
                }
            },
            None => ()
        }
    }
}

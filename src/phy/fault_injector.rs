use std::time::{Instant, Duration};

use Error;
use super::{DeviceLimits, Device};

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

// This could be fixed once associated consts are stable.
const MTU: usize = 1536;

#[derive(Debug, Clone, Copy, Default)]
struct Config {
    corrupt_pct: u8,
    drop_pct:    u8,
    reorder_pct: u8,
    max_size:    usize,
    max_tx_rate: u64,
    max_rx_rate: u64,
    interval:    Duration,
}

#[derive(Debug, Clone, Copy)]
struct State {
    rng_seed:    u32,
    refilled_at: Instant,
    tx_bucket:   u64,
    rx_bucket:   u64,
}

impl State {
    fn maybe(&mut self, pct: u8) -> bool {
        xorshift32(&mut self.rng_seed) % 100 < pct as u32
    }

    fn corrupt<T: AsMut<[u8]>>(&mut self, mut buffer: T) {
        let mut buffer = buffer.as_mut();
        // We introduce a single bitflip, as the most likely, and the hardest to detect, error.
        let index = (xorshift32(&mut self.rng_seed) as usize) % buffer.len();
        let bit   = 1 << (xorshift32(&mut self.rng_seed) % 8) as u8;
        buffer[index] ^= bit;
    }

    fn refill(&mut self, config: &Config) {
        if self.refilled_at.elapsed() > config.interval {
            self.tx_bucket = config.max_tx_rate;
            self.rx_bucket = config.max_rx_rate;
            self.refilled_at = Instant::now();
        }
    }

    fn maybe_transmit(&mut self, config: &Config) -> bool {
        if config.max_tx_rate == 0 { return true }

        self.refill(config);
        if self.tx_bucket > 0 {
            self.tx_bucket -= 1;
            true
        } else {
            false
        }
    }

    fn maybe_receive(&mut self, config: &Config) -> bool {
        if config.max_rx_rate == 0 { return true }

        self.refill(config);
        if self.rx_bucket > 0 {
            self.rx_bucket -= 1;
            true
        } else {
            false
        }
    }
}

/// A fault injector device.
///
/// A fault injector is a device that alters packets traversing through it to simulate
/// adverse network conditions (such as random packet loss or corruption), or software
/// or hardware limitations (such as a limited number or size of usable network buffers).
#[derive(Debug)]
pub struct FaultInjector<T: Device> {
    lower:  T,
    state:  State,
    config: Config
}

impl<T: Device> FaultInjector<T> {
    /// Create a fault injector device, using the given random number generator seed.
    pub fn new(lower: T, seed: u32) -> FaultInjector<T> {
        FaultInjector {
            lower: lower,
            state: State {
                rng_seed:    seed,
                refilled_at: Instant::now(),
                tx_bucket:   0,
                rx_bucket:   0,
            },
            config: Config::default()
        }
    }

    /// Return the underlying device, consuming the fault injector.
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

    /// Return the maximum packet size, in octets.
    pub fn max_packet_size(&self) -> usize {
        self.config.max_size
    }

    /// Return the maximum packet transmission rate, in packets per second.
    pub fn max_tx_rate(&self) -> u64 {
        self.config.max_rx_rate
    }

    /// Return the maximum packet reception rate, in packets per second.
    pub fn max_rx_rate(&self) -> u64 {
        self.config.max_tx_rate
    }

    /// Return the interval for packet rate limiting, in milliseconds.
    pub fn bucket_interval(&self) -> Duration {
        self.config.interval
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

    /// Set the maximum packet size, in octets.
    pub fn set_max_packet_size(&mut self, size: usize) {
        self.config.max_size = size
    }

    /// Set the maximum packet transmission rate, in packets per interval.
    pub fn set_max_tx_rate(&mut self, rate: u64) {
        self.config.max_tx_rate = rate
    }

    /// Set the maximum packet reception rate, in packets per interval.
    pub fn set_max_rx_rate(&mut self, rate: u64) {
        self.config.max_rx_rate = rate
    }

    /// Set the interval for packet rate limiting, in milliseconds.
    pub fn set_bucket_interval(&mut self, interval: Duration) {
        self.state.refilled_at = Instant::now() - self.config.interval;
        self.config.interval = interval
    }
}

impl<T: Device> Device for FaultInjector<T>
        where T::RxBuffer: AsMut<[u8]> {
    type RxBuffer = T::RxBuffer;
    type TxBuffer = TxBuffer<T::TxBuffer>;

    fn limits(&self) -> DeviceLimits {
        let mut limits = self.lower.limits();
        if limits.max_transmission_unit > MTU {
            limits.max_transmission_unit = MTU;
        }
        limits
    }

    fn receive(&mut self) -> Result<Self::RxBuffer, Error> {
        let mut buffer = try!(self.lower.receive());
        if self.state.maybe(self.config.drop_pct) {
            net_trace!("rx: randomly dropping a packet");
            return Err(Error::Exhausted)
        }
        if self.state.maybe(self.config.corrupt_pct) {
            net_trace!("rx: randomly corrupting a packet");
            self.state.corrupt(&mut buffer)
        }
        if self.config.max_size > 0 && buffer.as_ref().len() > self.config.max_size {
            net_trace!("rx: dropping a packet that is too large");
            return Err(Error::Exhausted)
        }
        if !self.state.maybe_receive(&self.config) {
            net_trace!("rx: dropping a packet because of rate limiting");
            return Err(Error::Exhausted)
        }
        Ok(buffer)
    }

    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, Error> {
        let buffer;
        if self.state.maybe(self.config.drop_pct) {
            net_trace!("tx: randomly dropping a packet");
            buffer = None;
        } else if self.config.max_size > 0 && length > self.config.max_size {
            net_trace!("tx: dropping a packet that is too large");
            buffer = None;
        } else if !self.state.maybe_transmit(&self.config) {
            net_trace!("tx: dropping a packet because of rate limiting");
            buffer = None;
        } else {
            buffer = Some(try!(self.lower.transmit(length)));
        }
        Ok(TxBuffer {
            buffer: buffer,
            state:  self.state.clone(),
            config: self.config,
            junk:   [0; MTU],
            length: length
        })
    }
}

#[doc(hidden)]
pub struct TxBuffer<T: AsRef<[u8]> + AsMut<[u8]>> {
    state:  State,
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
                if self.state.maybe(self.config.corrupt_pct) {
                    net_trace!("tx: corrupting a packet");
                    self.state.corrupt(buf)
                }
            },
            None => ()
        }
    }
}

use {Error, Result};
use super::{DeviceCapabilities, Device};
use phy;

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
    interval:    u64,
}

#[derive(Debug, Clone, Copy)]
struct State {
    rng_seed:    u32,
    refilled_at: u64,
    tx_bucket:   u64,
    rx_bucket:   u64,
}

impl State {
    fn maybe(&mut self, pct: u8) -> bool {
        xorshift32(&mut self.rng_seed) % 100 < pct as u32
    }

    fn corrupt<T: AsMut<[u8]>>(&mut self, mut buffer: T) {
        let buffer = buffer.as_mut();
        // We introduce a single bitflip, as the most likely, and the hardest to detect, error.
        let index = (xorshift32(&mut self.rng_seed) as usize) % buffer.len();
        let bit   = 1 << (xorshift32(&mut self.rng_seed) % 8) as u8;
        buffer[index] ^= bit;
    }

    fn refill(&mut self, config: &Config, timestamp: u64) {
        if timestamp - self.refilled_at > config.interval {
            self.tx_bucket = config.max_tx_rate;
            self.rx_bucket = config.max_rx_rate;
            self.refilled_at = timestamp;
        }
    }

    fn maybe_transmit(&mut self, config: &Config, timestamp: u64) -> bool {
        if config.max_tx_rate == 0 { return true }

        self.refill(config, timestamp);
        if self.tx_bucket > 0 {
            self.tx_bucket -= 1;
            true
        } else {
            false
        }
    }

    fn maybe_receive(&mut self, config: &Config, timestamp: u64) -> bool {
        if config.max_rx_rate == 0 { return true }

        self.refill(config, timestamp);
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
pub struct FaultInjector<D: for<'a> Device<'a>> {
    inner:      D,
    state:      State,
    config:     Config,
}

impl<D: for<'a> Device<'a>> FaultInjector<D> {
    /// Create a fault injector device, using the given random number generator seed.
    pub fn new(inner: D, seed: u32) -> FaultInjector<D> {
        let state = State {
            rng_seed:    seed,
            refilled_at: 0,
            tx_bucket:   0,
            rx_bucket:   0,
        };
        FaultInjector {
            inner: inner,
            state: state,
            config: Config::default(),
        }
    }

    /// Return the underlying device, consuming the fault injector.
    pub fn into_inner(self) -> D {
        self.inner
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
    pub fn bucket_interval(&self) -> u64 {
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
    pub fn set_bucket_interval(&mut self, interval: u64) {
        self.state.refilled_at = 0;
        self.config.interval = interval
    }
}

impl<'a, DR, DT, D> Device<'a> for FaultInjector<D>
    where D: for<'b> Device<'b, RxToken=DR, TxToken=DT>,
          DR: phy::RxToken,
          DT: phy::TxToken,
{
    type RxToken = RxToken<DR>;
    type TxToken = TxToken<DT>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = self.inner.capabilities();
        if caps.max_transmission_unit > MTU {
            caps.max_transmission_unit = MTU;
        }
        caps
    }

    // TODO clone state on each transmit/receive?
    // use refcell/mutex alternatively?

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken {
                state:          self.state.clone(),
                config:         self.config,
                token:          rx_token,
                corrupt_buffer: [0; MTU],
            };
            let tx = TxToken {
                state:  self.state.clone(),
                config: self.config,
                token:  tx_token,
                junk:   [0; MTU],
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken> {
        self.inner.transmit().map(|token| TxToken {
            state:  self.state.clone(),
            config: self.config,
            token: token,
            junk:   [0; MTU],
        })
    }
}

#[doc(hidden)]
pub struct RxToken<T: phy::RxToken> {
    state:          State,
    config:         Config,
    token:          T,
    corrupt_buffer: [u8; MTU],
}

impl<T: phy::RxToken> phy::RxToken for RxToken<T> {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(mut self, timestamp: u64, f: F) -> Result<R> {
        if self.state.maybe(self.config.drop_pct) {
            net_trace!("rx: randomly dropping a packet");
            return Err(Error::Exhausted)
        }
        if !self.state.maybe_receive(&self.config, timestamp) {
            net_trace!("rx: dropping a packet because of rate limiting");
            return Err(Error::Exhausted)
        }
        let Self {token, config, mut state, mut corrupt_buffer} = self;
        token.consume(timestamp, |buffer| {
            if config.max_size > 0 && buffer.as_ref().len() > config.max_size {
                net_trace!("rx: dropping a packet that is too large");
                return Err(Error::Exhausted)
            }
            if state.maybe(config.corrupt_pct) {
                net_trace!("rx: randomly corrupting a packet");
                let mut corrupt_buffer = &mut corrupt_buffer[..buffer.len()];
                corrupt_buffer.copy_from_slice(buffer);
                state.corrupt(&mut corrupt_buffer);
                f(&mut corrupt_buffer)
            } else {
                f(buffer)
            }
        })
    }
}

#[doc(hidden)]
pub struct TxToken<T: phy::TxToken> {
    state:  State,
    config: Config,
    token:  T,
    junk:   [u8; MTU],
}

impl<T: phy::TxToken> phy::TxToken for TxToken<T> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, timestamp: u64, len: usize, f: F) -> R {
        let drop = if self.state.maybe(self.config.drop_pct) {
            net_trace!("tx: randomly dropping a packet");
            true
        } else if self.config.max_size > 0 && len > self.config.max_size {
            net_trace!("tx: dropping a packet that is too large");
            true
        } else if !self.state.maybe_transmit(&self.config, timestamp) {
            net_trace!("tx: dropping a packet because of rate limiting");
            true
        } else {
            false
        };

        if drop {
            return f(&mut self.junk);
        }

        let Self {token, mut state, config, ..} = self;
        token.consume(timestamp, len, |mut buf| {
            if state.maybe(config.corrupt_pct) {
                net_trace!("tx: corrupting a packet");
                state.corrupt(&mut buf)
            }
            f(buf)
        })
    }
}

use core::cell::RefCell;

use crate::{Error, Result};
use crate::phy::{self, DeviceCapabilities, Device};
use crate::time::{Duration, Instant};

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

#[derive(Debug, Default, Clone, Copy)]
struct Config {
    corrupt_pct: u8,
    drop_pct:    u8,
    reorder_pct: u8,
    max_size:    usize,
    max_tx_rate: u64,
    max_rx_rate: u64,
    interval:    Duration,
}

#[derive(Debug, Clone)]
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
        let buffer = buffer.as_mut();
        // We introduce a single bitflip, as the most likely, and the hardest to detect, error.
        let index = (xorshift32(&mut self.rng_seed) as usize) % buffer.len();
        let bit   = 1 << (xorshift32(&mut self.rng_seed) % 8) as u8;
        buffer[index] ^= bit;
    }

    fn refill(&mut self, config: &Config, timestamp: Instant) {
        if timestamp - self.refilled_at > config.interval {
            self.tx_bucket = config.max_tx_rate;
            self.rx_bucket = config.max_rx_rate;
            self.refilled_at = timestamp;
        }
    }

    fn maybe_transmit(&mut self, config: &Config, timestamp: Instant) -> bool {
        if config.max_tx_rate == 0 { return true }

        self.refill(config, timestamp);
        if self.tx_bucket > 0 {
            self.tx_bucket -= 1;
            true
        } else {
            false
        }
    }

    fn maybe_receive(&mut self, config: &Config, timestamp: Instant) -> bool {
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
    state:      RefCell<State>,
    config:     Config,
}

impl<D: for<'a> Device<'a>> FaultInjector<D> {
    /// Create a fault injector device, using the given random number generator seed.
    pub fn new(inner: D, seed: u32) -> FaultInjector<D> {
        let state = State {
            rng_seed:    seed,
            refilled_at: Instant::from_millis(0),
            tx_bucket:   0,
            rx_bucket:   0,
        };
        FaultInjector {
            inner: inner,
            state: RefCell::new(state),
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
        self.state.borrow_mut().refilled_at = Instant::from_millis(0);
        self.config.interval = interval
    }
}

impl<'a, D> Device<'a> for FaultInjector<D>
    where D: for<'b> Device<'b>,
{
    type RxToken = RxToken<'a, <D as Device<'a>>::RxToken>;
    type TxToken = TxToken<'a, <D as Device<'a>>::TxToken>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = self.inner.capabilities();
        if caps.max_transmission_unit > MTU {
            caps.max_transmission_unit = MTU;
        }
        caps
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let &mut Self { ref mut inner, ref state, config } = self;
        inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken {
                state:   &state,
                config:  config,
                token:   rx_token,
                corrupt: [0; MTU],
            };
            let tx = TxToken {
                state:   &state,
                config:  config,
                token:   tx_token,
                junk:    [0; MTU],
            };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let &mut Self { ref mut inner, ref state, config } = self;
        inner.transmit().map(|token| TxToken {
            state:  &state,
            config: config,
            token: token,
            junk:   [0; MTU],
        })
    }
}

#[doc(hidden)]
pub struct RxToken<'a, Rx: phy::RxToken> {
    state:   &'a RefCell<State>,
    config:  Config,
    token:   Rx,
    corrupt: [u8; MTU],
}

impl<'a, Rx: phy::RxToken> phy::RxToken for RxToken<'a, Rx> {
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        if self.state.borrow_mut().maybe(self.config.drop_pct) {
            net_trace!("rx: randomly dropping a packet");
            return Err(Error::Exhausted)
        }
        if !self.state.borrow_mut().maybe_receive(&self.config, timestamp) {
            net_trace!("rx: dropping a packet because of rate limiting");
            return Err(Error::Exhausted)
        }
        let Self { token, config, state, mut corrupt } = self;
        token.consume(timestamp, |buffer| {
            if config.max_size > 0 && buffer.as_ref().len() > config.max_size {
                net_trace!("rx: dropping a packet that is too large");
                return Err(Error::Exhausted)
            }
            if state.borrow_mut().maybe(config.corrupt_pct) {
                net_trace!("rx: randomly corrupting a packet");
                let mut corrupt = &mut corrupt[..buffer.len()];
                corrupt.copy_from_slice(buffer);
                state.borrow_mut().corrupt(&mut corrupt);
                f(&mut corrupt)
            } else {
                f(buffer)
            }
        })
    }
}

#[doc(hidden)]
pub struct TxToken<'a, Tx: phy::TxToken> {
    state:  &'a RefCell<State>,
    config: Config,
    token:  Tx,
    junk:   [u8; MTU],
}

impl<'a, Tx: phy::TxToken> phy::TxToken for TxToken<'a, Tx> {
    fn consume<R, F>(mut self, timestamp: Instant, len: usize, f: F) -> Result<R>
        where F: FnOnce(&mut [u8]) -> Result<R>
    {
        let drop = if self.state.borrow_mut().maybe(self.config.drop_pct) {
            net_trace!("tx: randomly dropping a packet");
            true
        } else if self.config.max_size > 0 && len > self.config.max_size {
            net_trace!("tx: dropping a packet that is too large");
            true
        } else if !self.state.borrow_mut().maybe_transmit(&self.config, timestamp) {
            net_trace!("tx: dropping a packet because of rate limiting");
            true
        } else {
            false
        };

        if drop {
            return f(&mut self.junk);
        }

        let Self { token, state, config, .. } = self;
        token.consume(timestamp, len, |mut buf| {
            if state.borrow_mut().maybe(config.corrupt_pct) {
                net_trace!("tx: corrupting a packet");
                state.borrow_mut().corrupt(&mut buf)
            }
            f(buf)
        })
    }
}

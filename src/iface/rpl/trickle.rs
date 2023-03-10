use crate::{rand::Rand, time::Duration, time::Instant};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TrickleTimer {
    started: bool,

    i_min: u32,
    i_max: u32,
    k: usize,

    i: Duration,
    t: Duration,
    t_expiration: Instant,
    i_expiration: Instant,
    counter: usize,
}

impl Default for TrickleTimer {
    fn default() -> Self {
        Self::new(
            super::consts::DEFAULT_DIO_INTERVAL_MIN as u32,
            super::consts::DEFAULT_DIO_INTERVAL_MIN as u32
                + super::consts::DEFAULT_DIO_INTERVAL_DOUBLINGS as u32,
            super::consts::DEFAULT_DIO_REDUNDANCY_CONSTANT as usize,
        )
    }
}

impl TrickleTimer {
    /// Create a new Trickle timer.
    pub(crate) const fn new(i_min: u32, i_max: u32, k: usize) -> Self {
        Self {
            started: false,
            i_min,
            i_max,
            k,
            i: Duration::ZERO,
            t: Duration::ZERO,
            t_expiration: Instant::ZERO,
            i_expiration: Instant::ZERO,
            counter: 0,
        }
    }

    #[inline]
    pub(crate) fn start(&mut self, now: Instant, rand: &mut Rand) {
        if self.started {
            return;
        }

        // NOTE: the standard defines I as a random number between [Imin,Imax]. However, this could
        // result in a t value that is very close to Imax. Therefore, sending DIO messages will be
        // sporadic, which is not ideal when a network is started. Hence, we do not draw a random
        // number, but just use Imin for I. This only affects the start of the RPL tree and speeds
        // this up a little.
        //
        // It should have been:
        // ```
        // let i = Duration::from_millis(
        //     (2u32.pow(i_min) + rand.rand_u32() % (2u32.pow(i_max) - 2u32.pow(i_min) + 1)) as u64,
        // );
        // ```
        self.i = Duration::from_millis(2u32.pow(self.i_min) as u64);
        self.i_expiration = now + self.i;
        self.counter = 0;

        self.set_t(now, rand);

        self.started = true;
    }

    #[inline]
    pub(crate) fn poll(&mut self, now: Instant, rand: &mut Rand) -> bool {
        let can_transmit = self.can_transmit() && self.t_expired(now);

        if can_transmit {
            self.set_t(now, rand);
        }

        if self.i_expired(now) {
            self.expire(now, rand);
        }

        can_transmit
    }

    #[inline]
    pub(crate) fn poll_at(&self) -> Instant {
        self.t_expiration.min(self.i_expiration)
    }

    #[inline]
    pub(crate) fn set_t(&mut self, now: Instant, rand: &mut Rand) {
        let t = Duration::from_micros(
            self.i.total_micros() / 2
                + (rand.rand_u32() as u64
                    % (self.i.total_micros() - self.i.total_micros() / 2 + 1)),
        );

        self.t = t;
        self.t_expiration = now + t;
    }

    /// Check if the timer expired.
    #[inline]
    pub(crate) fn t_expired(&self, now: Instant) -> bool {
        now >= self.t_expiration
    }

    pub(crate) fn i_expired(&self, now: Instant) -> bool {
        now >= self.i_expiration
    }

    /// Signal the Trickle timer that a consistency has been heard.
    #[inline]
    pub(crate) fn hear_consistent(&mut self) {
        self.counter += 1;
    }

    /// Signal the Trickle timer that an inconsistency has been heard.
    pub(crate) fn hear_inconsistent(&mut self, now: Instant, rand: &mut Rand) {
        let i = Duration::from_millis(2u32.pow(self.i_min) as u64);
        if self.i > i {
            self.reset(i, now, rand);
        }
    }

    /// Check if the trickle timer can transmit.
    pub(crate) fn can_transmit(&self) -> bool {
        self.k != 0 && self.counter < self.k
    }

    /// Resets the Trickle timer, according to the standard, when it has expired.
    pub(crate) fn expire(&mut self, now: Instant, rand: &mut Rand) {
        let max_interval = Duration::from_millis(2u32.pow(self.i_max) as u64);
        let i = if self.i >= max_interval {
            max_interval
        } else {
            // Double the interval I
            self.i + self.i
        };

        self.reset(i, now, rand);
    }

    #[inline(always)]
    fn reset(&mut self, i: Duration, now: Instant, rand: &mut Rand) {
        self.i = i;
        self.i_expiration = now + self.i;
        self.counter = 0;
        self.set_t(now, rand);
    }

    pub(crate) const fn max_expiration(&self) -> Duration {
        Duration::from_millis(2u32.pow(self.i_max) as u64)
    }

    #[cfg(test)]
    pub(crate) const fn min_expiration(&self) -> Duration {
        Duration::from_millis(2u32.pow(self.i_min) as u64)
    }

    #[cfg(test)]
    pub(crate) fn get_i(&self) -> Duration {
        self.i
    }

    #[cfg(test)]
    pub(crate) fn get_t(&self) -> Duration {
        self.t
    }

    #[cfg(test)]
    pub(crate) fn get_counter(&self) -> usize {
        self.counter
    }

    #[cfg(test)]
    pub(crate) fn set_counter(&mut self, value: usize) {
        self.counter = value;
    }
}

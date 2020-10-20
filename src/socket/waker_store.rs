use core::task::Waker;

#[derive(Debug)]
pub struct WakerStore {
    waker: Option<Waker>,
}

impl WakerStore {
    pub const fn new() -> Self {
        Self { waker: None }
    }

    pub fn register(&mut self, w: &Waker) {
        match self.waker {
            Some(ref w2) if (w2.will_wake(w)) => {}
            _ => self.waker = Some(w.clone()),
        }
    }

    pub fn wake(&mut self) {
        self.waker.take().map(|w| w.wake());
    }
}
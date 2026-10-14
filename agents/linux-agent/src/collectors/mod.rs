//! Telemetry collectors. Each runs in its own task and pushes ACE events into a bounded queue.

pub mod auth;
pub mod file;
pub mod network;
pub mod process;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::event::Event;

/// Bounded, rate-limited handle to the sender queue. When the queue is full or the rate limit
/// is exceeded the event is dropped and counted: collection never blocks the host.
#[derive(Clone)]
pub struct Sink {
    tx: mpsc::Sender<Event>,
    pub dropped: Arc<AtomicU64>,
    limiter: Arc<std::sync::Mutex<TokenBucket>>,
}

impl Sink {
    pub fn new(tx: mpsc::Sender<Event>, max_per_second: u32) -> Self {
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            limiter: Arc::new(std::sync::Mutex::new(TokenBucket::new(max_per_second))),
        }
    }

    pub fn emit(&self, event: Event) {
        let allowed = self.limiter.lock().map(|mut b| b.take()).unwrap_or(false);
        if !allowed || self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    pub fn new(per_second: u32) -> Self {
        let rate = f64::from(per_second.max(1));
        Self {
            capacity: rate * 2.0,
            tokens: rate * 2.0,
            rate,
            last: std::time::Instant::now(),
        }
    }

    pub fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate)
            .min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limits_bursts() {
        let mut bucket = TokenBucket::new(5);
        let allowed = (0..100).filter(|_| bucket.take()).count();
        assert_eq!(allowed, 10); // burst capacity = 2x rate
    }
}

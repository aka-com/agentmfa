//! Rate limiting.
//!
//! - Per-identity sliding-window buckets on capability calls (60/min
//!   default), keyed on the verified identity UUID rather than the
//!   self-reported activity label. The bucket map is hard bounded and stale
//!   entries are pruned before new keys are admitted.
//! - **Global** windows on the unauthenticated endpoints (pairing at 3
//!   attempts per 5 s; discovery at 60/min), global because unauthenticated
//!   callers have no stable key to bucket on.
//!
//! Every refusal carries *how long to wait*: `check` returns
//! `Err(retry_after)` so the daemon can answer with `Retry-After` and a
//! `retry_after_seconds` body field instead of an opaque 429.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// When the oldest recorded hit leaves the window, a slot frees up.
fn window_retry_after(hits: &VecDeque<Instant>, window: Duration, now: Instant) -> Duration {
    hits.front()
        .map(|oldest| window.saturating_sub(now.duration_since(*oldest)))
        .unwrap_or(window)
}

/// Global sliding window: at most `max` hits per `window`.
pub struct WindowLimiter {
    window: Duration,
    max: u32,
    hits: Mutex<VecDeque<Instant>>,
}

impl WindowLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            window,
            max,
            hits: Mutex::new(VecDeque::new()),
        }
    }

    /// Record an attempt; over budget returns how long until a slot frees.
    pub fn check(&self) -> Result<(), Duration> {
        self.check_at(Instant::now())
    }

    fn check_at(&self, now: Instant) -> Result<(), Duration> {
        let mut hits = self.hits.lock().unwrap();
        while let Some(front) = hits.front() {
            if now.duration_since(*front) > self.window {
                hits.pop_front();
            } else {
                break;
            }
        }
        if hits.len() >= self.max as usize {
            return Err(window_retry_after(&hits, self.window, now));
        }
        hits.push_back(now);
        Ok(())
    }
}

const DEFAULT_MAX_KEYS: usize = 1024;

/// Keyed sliding window: at most `max` hits per `window`, per verified key.
pub struct KeyedLimiter {
    window: Duration,
    max: u32,
    max_keys: usize,
    map: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl KeyedLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            window,
            max,
            max_keys: DEFAULT_MAX_KEYS,
            map: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_max_keys(max: u32, window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max,
            max_keys,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt; over budget returns how long until a slot frees.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut map = self.map.lock().unwrap();
        // Prune all expired entries before considering a new bucket. This is
        // both lifecycle cleanup and the invariant that makes the key cap a
        // hard bound rather than a best-effort watermark.
        map.retain(|_, hits| {
            while hits
                .front()
                .is_some_and(|front| now.duration_since(*front) > self.window)
            {
                hits.pop_front();
            }
            !hits.is_empty()
        });
        if !map.contains_key(key) && map.len() >= self.max_keys {
            // Refuse admission instead of evicting an active bucket, which
            // would let key churn reset another caller's rate limit.
            return Err(self.window);
        }
        let hits = map.entry(key.to_string()).or_default();
        if hits.len() >= self.max as usize {
            return Err(window_retry_after(hits, self.window, now));
        }
        hits.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_limits_and_reports_retry_after() {
        let l = WindowLimiter::new(3, Duration::from_secs(5));
        assert!(l.check().is_ok());
        assert!(l.check().is_ok());
        assert!(l.check().is_ok());
        let wait = l.check().unwrap_err();
        assert!(wait <= Duration::from_secs(5));
        assert!(wait > Duration::from_secs(4));
    }

    #[test]
    fn window_slides() {
        let l = WindowLimiter::new(1, Duration::from_millis(10));
        let t0 = Instant::now();
        assert!(l.check_at(t0).is_ok());
        assert_eq!(
            l.check_at(t0 + Duration::from_millis(5)),
            Err(Duration::from_millis(5))
        );
        assert!(l.check_at(t0 + Duration::from_millis(20)).is_ok());
    }

    #[test]
    fn keyed_buckets_are_independent() {
        let l = KeyedLimiter::new(1, Duration::from_secs(60));
        assert!(l.check("a").is_ok());
        let wait = l.check("a").unwrap_err();
        assert!(wait <= Duration::from_secs(60));
        assert!(l.check("b").is_ok());
    }

    #[test]
    fn keyed_state_is_hard_bounded_and_pruned() {
        let window = Duration::from_secs(60);
        let l = KeyedLimiter::with_max_keys(10, window, 2);
        let t0 = Instant::now();
        assert!(l.check_at("a", t0).is_ok());
        assert!(l.check_at("b", t0).is_ok());
        assert_eq!(l.check_at("c", t0), Err(window));
        assert_eq!(l.map.lock().unwrap().len(), 2);

        let later = t0 + window + Duration::from_secs(1);
        assert!(l.check_at("c", later).is_ok());
        let map = l.map.lock().unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("c"));
    }
}

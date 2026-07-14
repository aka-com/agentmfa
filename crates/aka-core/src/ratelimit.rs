//! Rate limiting.
//!
//! - Per-token sliding-window buckets on capability calls (60/min default).
//! - **Global** windows on the unauthenticated endpoints, global rather
//!   than per-peer because a hostile local process can respawn to present a
//!   fresh audit token on every attempt, so any per-peer key is trivially
//!   evaded: pairing at 3 attempts per 5 s with a 30 s cooldown after a
//!   user denial; discovery at 60/min.
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

/// Keyed sliding window: at most `max` hits per `window`, per key
/// (per pair-token bucket).
pub struct KeyedLimiter {
    window: Duration,
    max: u32,
    map: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl KeyedLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            window,
            max,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt; over budget returns how long until a slot frees.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        // Opportunistic cleanup of idle keys so revoked tokens don't leak
        // buckets forever.
        if map.len() > 1024 {
            map.retain(|_, hits| {
                hits.back()
                    .is_some_and(|last| now.duration_since(*last) <= self.window)
            });
        }
        let hits = map.entry(key.to_string()).or_default();
        while let Some(front) = hits.front() {
            if now.duration_since(*front) > self.window {
                hits.pop_front();
            } else {
                break;
            }
        }
        if hits.len() >= self.max as usize {
            return Err(window_retry_after(hits, self.window, now));
        }
        hits.push_back(now);
        Ok(())
    }
}

/// Why a pairing attempt was refused. The two causes demand different agent
/// behavior: a full window means "slow down and retry"; the post-denial
/// cooldown means "the human just said no, ask them before trying again".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingBlock {
    /// Attempt window exhausted; retry after the given wait.
    Window(Duration),
    /// The user denied a pairing recently; armed for the given remainder.
    DeniedCooldown(Duration),
}

/// The pairing brake: a global window plus a cooldown armed whenever the
/// user *denies* a pairing.
pub struct PairingLimiter {
    window: WindowLimiter,
    cooldown: Duration,
    cooldown_until: Mutex<Option<Instant>>,
}

impl PairingLimiter {
    pub fn new(max: u32, window: Duration, cooldown: Duration) -> Self {
        Self {
            window: WindowLimiter::new(max, window),
            cooldown,
            cooldown_until: Mutex::new(None),
        }
    }

    pub fn check(&self) -> Result<(), PairingBlock> {
        {
            let mut until = self.cooldown_until.lock().unwrap();
            if let Some(t) = *until {
                let now = Instant::now();
                if now < t {
                    return Err(PairingBlock::DeniedCooldown(t - now));
                }
                *until = None;
            }
        }
        self.window.check().map_err(PairingBlock::Window)
    }

    /// Arm the post-denial cooldown.
    pub fn on_user_denied(&self) {
        *self.cooldown_until.lock().unwrap() = Some(Instant::now() + self.cooldown);
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
    fn pairing_cooldown_blocks_distinctly() {
        let l = PairingLimiter::new(10, Duration::from_secs(5), Duration::from_secs(60));
        assert!(l.check().is_ok());
        l.on_user_denied();
        match l.check().unwrap_err() {
            PairingBlock::DeniedCooldown(wait) => assert!(wait <= Duration::from_secs(60)),
            other => panic!("expected DeniedCooldown, got {other:?}"),
        }
    }

    #[test]
    fn pairing_window_blocks_as_window() {
        let l = PairingLimiter::new(1, Duration::from_secs(5), Duration::from_secs(60));
        assert!(l.check().is_ok());
        assert!(matches!(l.check().unwrap_err(), PairingBlock::Window(_)));
    }
}

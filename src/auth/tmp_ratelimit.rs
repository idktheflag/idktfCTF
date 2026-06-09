// auth/ratelimit.rs — sliding-window rate limiter for flag submission.
//
// A "sliding window" limiter tracks the timestamps of the last N requests.
// If there are already MAX_ATTEMPTS timestamps within the last WINDOW_SECS,
// the next request is rejected.
//
// Why per-user, not per-IP?
//   This is a CTF — most players are behind NAT (school networks, VPNs).
//   Per-IP limiting would accidentally block whole teams. Per-user is precise.
//
// Why not a crate like governor?
//   governor uses GCRA (Generic Cell Rate Algorithm) — great for production,
//   but the sliding window is simpler to understand and more than sufficient.
//   If you ever need strict burst control at scale, governor is the upgrade.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::AppError;

// ── Configuration constants ───────────────────────────────────────────────────

// Max flag submissions allowed per user within WINDOW.
const MAX_ATTEMPTS: usize = 10;

// The time window we look back across.
const WINDOW: Duration = Duration::from_secs(60);

// ── RateLimiter ───────────────────────────────────────────────────────────────

pub struct RateLimiter {
    // Maps user UUID → deque of timestamps for their recent attempts.
    //
    // tokio::sync::Mutex (not std::sync::Mutex) because we hold this lock
    // across .await points — std::Mutex is not safe to hold across awaits
    // since it blocks the thread, starving the async runtime.
    state: Mutex<HashMap<Uuid, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt for `user_id`. Returns Err if the rate limit is exceeded.
    ///
    /// This both checks AND records atomically (we hold the lock the whole time),
    /// so two simultaneous requests can't both slip through the check.
    pub async fn check(&self, user_id: Uuid) -> Result<(), AppError> {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        // Get or create the deque for this user.
        let attempts = state.entry(user_id).or_insert_with(VecDeque::new);

        // Drop timestamps that have fallen outside the window.
        // VecDeque::front() is the oldest entry — pop until it's within window.
        while let Some(&oldest) = attempts.front() {
            if now.duration_since(oldest) > WINDOW {
                attempts.pop_front();
            } else {
                break;
            }
        }

        // If we're at the limit, reject without recording.
        if attempts.len() >= MAX_ATTEMPTS {
            return Err(AppError::BadRequest(
                // Tell the client how long until the window clears.
                // The oldest entry will expire after WINDOW - elapsed(oldest).
                format!(
                    "rate limit exceeded: {} flag submissions per minute max",
                    MAX_ATTEMPTS
                ),
            ));
        }

        // Record this attempt.
        attempts.push_back(now);
        Ok(())
    }
}

// Arc<RateLimiter> can be cloned cheaply into each handler call.
// We need it to be Send + Sync so it can live in Arc<AppState>.
// tokio::sync::Mutex is Send + Sync, so this is satisfied automatically.

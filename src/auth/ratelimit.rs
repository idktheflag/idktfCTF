use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::AppError;

const MAX_ATTEMPTS: usize = 20;
const WINDOW: Duration = Duration::from_secs(60);

pub struct RateLimiter {
    state: Mutex<HashMap<Uuid, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            state: Mutex::new(HashMap::new()),
        }
    }
    pub async fn check(&self, user_id: Uuid) -> Result<(), AppError> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let attempts = state.entry(user_id).or_insert_with(VecDeque::new);
        while let Some(&oldest) = attempts.front() {
            if now.duration_since(oldest) > WINDOW {
                attempts.pop_front();
            } else {
                break;
            }
        }
        if attempts.len()>=MAX_ATTEMPTS {
            return Err(AppError::BadRequest(
                    format!(
                        "rate limit exceeded: {} flag submissions per minute max",
                        MAX_ATTEMPTS
                    ),
            ));
        }
        attepmts.push_back(now);
        Ok(())
    }
}

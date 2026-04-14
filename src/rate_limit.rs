use rmcp::ErrorData;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiters {
    limiters: Mutex<HashMap<&'static str, TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_per_minute: u32) -> Self {
        let max = max_per_minute as f64;
        Self {
            tokens: max,
            max_tokens: max,
            refill_per_sec: max / 60.0,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiters {
    pub fn new() -> Self {
        let mut limiters = HashMap::new();
        limiters.insert("mail_list_folders", TokenBucket::new(60));
        limiters.insert("mail_list_recent", TokenBucket::new(60));
        limiters.insert("mail_search", TokenBucket::new(30));
        limiters.insert("mail_get", TokenBucket::new(60));
        limiters.insert("mail_flag", TokenBucket::new(30));
        limiters.insert("mail_move", TokenBucket::new(30));
        limiters.insert("mail_draft", TokenBucket::new(10));
        limiters.insert("mail_send", TokenBucket::new(5));

        Self {
            limiters: Mutex::new(limiters),
        }
    }

    pub fn check(&self, tool: &'static str) -> Result<(), ErrorData> {
        let mut limiters = self.limiters.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bucket) = limiters.get_mut(tool) && !bucket.try_consume() {
            return Err(ErrorData::invalid_request(
                format!("Rate limit exceeded for '{tool}'. Try again shortly."),
                None,
            ));
        }
        Ok(())
    }
}

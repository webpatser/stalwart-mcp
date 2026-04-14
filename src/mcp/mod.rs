pub mod resources;
pub mod tools;

use crate::config::{Capabilities, NotificationsConfig};
use crate::jmap::AccountManager;
use crate::rate_limit::RateLimiters;
use std::sync::Arc;

#[derive(Clone)]
pub struct StalwartMcp {
    pub(crate) accounts: Arc<AccountManager>,
    pub(crate) capabilities: Capabilities,
    pub(crate) notifications: NotificationsConfig,
    pub(crate) rate_limiters: Arc<RateLimiters>,
}

impl StalwartMcp {
    pub fn new(
        accounts: AccountManager,
        capabilities: Capabilities,
        notifications: NotificationsConfig,
    ) -> Self {
        Self {
            accounts: Arc::new(accounts),
            capabilities,
            notifications,
            rate_limiters: Arc::new(RateLimiters::new()),
        }
    }

    pub fn accounts(&self) -> &Arc<AccountManager> {
        &self.accounts
    }

    pub fn notifications_config(&self) -> &NotificationsConfig {
        &self.notifications
    }
}

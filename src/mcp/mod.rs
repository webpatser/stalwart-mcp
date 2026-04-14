pub mod prompts;
pub mod resources;
pub mod tools;

use crate::config::{Capabilities, NotificationsConfig};
use crate::jmap::AccountManager;
use crate::rate_limit::RateLimiters;
use rmcp::handler::server::router::prompt::PromptRouter;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{
    GetPromptRequestParams, GetPromptResult, ListPromptsResult, PaginatedRequestParams,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, prompt_handler, tool_handler};
use std::sync::Arc;

#[derive(Clone)]
pub struct StalwartMcp {
    pub(crate) accounts: Arc<AccountManager>,
    pub(crate) capabilities: Capabilities,
    pub(crate) notifications: NotificationsConfig,
    pub(crate) rate_limiters: Arc<RateLimiters>,
    tool_router: ToolRouter<Self>,
    prompt_router: PromptRouter<Self>,
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
            tool_router: Self::create_tool_router(),
            prompt_router: Self::create_prompt_router(),
        }
    }

    pub fn accounts(&self) -> &Arc<AccountManager> {
        &self.accounts
    }

    pub fn notifications_config(&self) -> &NotificationsConfig {
        &self.notifications
    }
}

#[tool_handler(router = self.tool_router)]
#[prompt_handler(router = self.prompt_router)]
impl ServerHandler for StalwartMcp {}

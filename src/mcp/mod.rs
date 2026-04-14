pub mod prompts;
pub mod resources;
pub mod tools;

use crate::admin::AdminClient;
use crate::config::{Capabilities, NotificationsConfig};
use crate::jmap::AccountManager;
use crate::mcp::resources::{ResourceMatch, match_resource_uri};
use crate::rate_limit::RateLimiters;
use rmcp::handler::server::router::prompt::PromptRouter;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{
    Annotated, GetPromptRequestParams, GetPromptResult, Implementation, ListPromptsResult,
    ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams, RawResource,
    RawResourceTemplate, ReadResourceRequestParams, ReadResourceResult, ResourceContents,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, prompt_handler, tool_handler};
use std::sync::Arc;

#[derive(Clone)]
pub struct StalwartMcp {
    pub(crate) accounts: Arc<AccountManager>,
    pub(crate) capabilities: Capabilities,
    pub(crate) notifications: NotificationsConfig,
    pub(crate) rate_limiters: Arc<RateLimiters>,
    pub(crate) admin: Option<AdminClient>,
    tool_router: ToolRouter<Self>,
    prompt_router: PromptRouter<Self>,
}

impl StalwartMcp {
    pub fn new(
        accounts: AccountManager,
        capabilities: Capabilities,
        notifications: NotificationsConfig,
        admin: Option<AdminClient>,
    ) -> Self {
        Self {
            accounts: Arc::new(accounts),
            capabilities,
            notifications,
            rate_limiters: Arc::new(RateLimiters::new()),
            admin,
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
impl ServerHandler for StalwartMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::from_build_env())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let raw = RawResource::new("mail://accounts", "Configured mail accounts")
            .with_description(
                "List of all configured Stalwart accounts with id, username, and default status",
            )
            .with_mime_type("application/json");

        Ok(ListResourcesResult {
            resources: vec![Annotated::new(raw, None)],
            meta: None,
            next_cursor: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let folders = RawResourceTemplate::new("mail://{account}/folders", "Mail folders")
            .with_description("Mailbox list with message and unread counts for an account")
            .with_mime_type("application/json");

        let message = RawResourceTemplate::new("mail://{account}/messages/{id}", "Email message")
            .with_description("Full email content including headers, body, and attachment metadata")
            .with_mime_type("application/json");

        Ok(ListResourceTemplatesResult {
            resource_templates: vec![Annotated::new(folders, None), Annotated::new(message, None)],
            meta: None,
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = &request.uri;

        let matched = match_resource_uri(uri).ok_or_else(|| {
            ErrorData::resource_not_found("unknown_resource", Some(uri.clone().into()))
        })?;

        let json = match matched {
            ResourceMatch::Accounts => resources::accounts_resource(&self.accounts)
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?,
            ResourceMatch::Folders { account } => {
                resources::folders_resource(&self.accounts, Some(account))
                    .await
                    .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            }
            ResourceMatch::Message { account, id } => {
                resources::message_resource(&self.accounts, Some(account), id)
                    .await
                    .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            }
        };

        let contents = ResourceContents::text(json, uri.clone()).with_mime_type("application/json");

        Ok(ReadResourceResult::new(vec![contents]))
    }
}

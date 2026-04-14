use crate::jmap::mail::{ComposeEmail, SearchFilters};
use crate::mcp::StalwartMcp;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFoldersArgs {
    /// Account to list folders for. Omit to use the default account.
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListRecentArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Mailbox name (e.g. "INBOX", "Drafts") or mailbox ID. Omit for all mailboxes.
    pub folder: Option<String>,
    /// Maximum number of messages to return (default: 20, max: 100)
    pub count: Option<usize>,
    /// Only return unread messages
    #[serde(default)]
    pub unread_only: bool,
    /// Only return emails received after this UTC timestamp (seconds since epoch)
    pub after: Option<i64>,
    /// Only return emails received before this UTC timestamp (seconds since epoch)
    pub before: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Full-text search query (uses Stalwart's Meilisearch FTS)
    pub query: Option<String>,
    /// Filter by sender name or email address
    pub from: Option<String>,
    /// Filter by recipient name or email address
    pub to: Option<String>,
    /// Filter by subject line
    pub subject: Option<String>,
    /// Restrict search to this mailbox name or ID
    pub folder: Option<String>,
    /// Only return emails received after this UTC timestamp (seconds since epoch)
    pub after: Option<i64>,
    /// Only return emails received before this UTC timestamp (seconds since epoch)
    pub before: Option<i64>,
    /// Only return emails with attachments
    pub has_attachment: Option<bool>,
    /// Maximum number of results (default: 20, max: 100)
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetEmailArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// The email message ID to retrieve
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlagArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// The email message ID
    pub id: String,
    /// Action: "read", "unread", "flag", or "unflag"
    pub action: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MoveArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// The email message ID
    pub id: String,
    /// Target folder name (e.g. "Archive", "Trash") or mailbox ID
    pub folder: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DraftArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Recipient email addresses
    pub to: Vec<String>,
    /// Email subject
    pub subject: String,
    /// Plain text email body
    pub body: String,
    /// CC email addresses
    #[serde(default)]
    pub cc: Vec<String>,
    /// Email ID to reply to (sets In-Reply-To header for threading)
    pub reply_to_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Recipient email addresses
    pub to: Vec<String>,
    /// Email subject
    pub subject: String,
    /// Plain text email body
    pub body: String,
    /// CC email addresses
    #[serde(default)]
    pub cc: Vec<String>,
    /// Email ID to reply to (sets In-Reply-To header for threading)
    pub reply_to_id: Option<String>,
}

fn validate_timestamps(after: Option<i64>, before: Option<i64>) -> Result<(), ErrorData> {
    if let (Some(a), Some(b)) = (after, before)
        && a >= b
    {
        return Err(ErrorData::invalid_params(
            "'after' must be before 'before'",
            None,
        ));
    }
    Ok(())
}

fn validate_recipients(addrs: &[String]) -> Result<(), ErrorData> {
    for addr in addrs {
        if !addr.contains('@') || addr.len() < 3 {
            return Err(ErrorData::invalid_params(
                format!("Invalid email address: '{addr}'"),
                None,
            ));
        }
    }
    Ok(())
}

#[tool_router]
impl StalwartMcp {
    pub(crate) fn create_tool_router() -> rmcp::handler::server::router::tool::ToolRouter<Self> {
        Self::tool_router()
    }

    #[tool(description = "List mail folders/mailboxes with message counts")]
    pub async fn mail_list_folders(
        &self,
        Parameters(args): Parameters<ListFoldersArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_list_folders")?;
        tracing::info!(event = "mail_list_folders", account = ?args.account, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let mailboxes = client.list_mailboxes().await.map_err(ErrorData::from)?;

        let json = serde_json::to_string_pretty(&mailboxes)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "List recent emails in a folder, optionally filtered to unread only")]
    pub async fn mail_list_recent(
        &self,
        Parameters(args): Parameters<ListRecentArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_list_recent")?;
        tracing::info!(event = "mail_list_recent", account = ?args.account, folder = ?args.folder, "Tool called");
        validate_timestamps(args.after, args.before)?;

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let count = args.count.unwrap_or(20).min(100);

        let mailbox_id = if let Some(ref folder) = args.folder {
            client
                .resolve_mailbox_id(folder)
                .await
                .map_err(ErrorData::from)?
                .or_else(|| Some(folder.clone()))
        } else {
            None
        };

        let emails = client
            .list_recent_emails(
                mailbox_id.as_deref(),
                count,
                args.unread_only,
                args.after,
                args.before,
            )
            .await
            .map_err(ErrorData::from)?;

        let json = serde_json::to_string_pretty(&emails)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Search emails with filters. Supports full-text search (Meilisearch FTS), sender/recipient/subject filters, date range, and attachment filter. At least one filter must be provided."
    )]
    pub async fn mail_search(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Require at least one filter
        if args.query.is_none()
            && args.from.is_none()
            && args.to.is_none()
            && args.subject.is_none()
            && args.folder.is_none()
            && args.after.is_none()
            && args.before.is_none()
            && args.has_attachment.is_none()
        {
            return Err(ErrorData::invalid_params(
                "At least one search filter must be provided",
                None,
            ));
        }

        self.rate_limiters.check("mail_search")?;
        tracing::info!(event = "mail_search", account = ?args.account, query = ?args.query, from = ?args.from, "Tool called");
        validate_timestamps(args.after, args.before)?;

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let limit = args.limit.unwrap_or(20).min(100);

        let mailbox_id = if let Some(ref folder) = args.folder {
            client
                .resolve_mailbox_id(folder)
                .await
                .map_err(ErrorData::from)?
                .or_else(|| Some(folder.clone()))
        } else {
            None
        };

        let emails = client
            .search_emails(&SearchFilters {
                text: args.query.as_deref(),
                from: args.from.as_deref(),
                to: args.to.as_deref(),
                subject: args.subject.as_deref(),
                mailbox_id: mailbox_id.as_deref(),
                after: args.after,
                before: args.before,
                has_attachment: args.has_attachment,
                limit,
            })
            .await
            .map_err(ErrorData::from)?;

        let json = serde_json::to_string_pretty(&emails)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Get a full email message by ID, including body text and attachment metadata"
    )]
    pub async fn mail_get(
        &self,
        Parameters(args): Parameters<GetEmailArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_get")?;
        tracing::info!(event = "mail_get", account = ?args.account, id = %args.id, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let email = client.get_email(&args.id).await.map_err(ErrorData::from)?;

        let json = serde_json::to_string_pretty(&email)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Set or unset email flags. Actions: 'read', 'unread', 'flag', 'unflag'")]
    pub async fn mail_flag(
        &self,
        Parameters(args): Parameters<FlagArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_flag")?;
        tracing::info!(event = "mail_flag", account = ?args.account, id = %args.id, action = %args.action, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let (keyword, set) = match args.action.as_str() {
            "read" => ("$seen", true),
            "unread" => ("$seen", false),
            "flag" => ("$flagged", true),
            "unflag" => ("$flagged", false),
            other => {
                return Err(ErrorData::invalid_params(
                    format!("Unknown action '{other}'. Use: read, unread, flag, unflag"),
                    None,
                ));
            }
        };

        client
            .set_email_keyword(&args.id, keyword, set)
            .await
            .map_err(ErrorData::from)?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email {} marked as {}",
            args.id, args.action
        ))]))
    }

    #[tool(description = "Move an email to a different folder (e.g. 'Archive', 'Trash', 'INBOX')")]
    pub async fn mail_move(
        &self,
        Parameters(args): Parameters<MoveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_move")?;
        tracing::info!(event = "mail_move", account = ?args.account, id = %args.id, folder = %args.folder, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let target_id = client
            .resolve_mailbox_id(&args.folder)
            .await
            .map_err(ErrorData::from)?
            .unwrap_or_else(|| args.folder.clone());

        client
            .move_email(&args.id, &target_id)
            .await
            .map_err(ErrorData::from)?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email {} moved to {}",
            args.id, args.folder
        ))]))
    }

    #[tool(description = "Save a draft email in the Drafts folder. Returns the draft email ID.")]
    pub async fn mail_draft(
        &self,
        Parameters(args): Parameters<DraftArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_draft")?;
        tracing::info!(event = "mail_draft", account = ?args.account, to = ?args.to, subject = %args.subject, "Tool called");
        validate_recipients(&args.to)?;
        validate_recipients(&args.cc)?;

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let from = client.username().to_string();

        // Get threading headers if replying
        let (in_reply_to, references) = if let Some(ref reply_id) = args.reply_to_id {
            let msg_id = client
                .get_message_id(reply_id)
                .await
                .map_err(ErrorData::from)?;
            (msg_id.clone(), msg_id)
        } else {
            (None, None)
        };

        let draft_id = client
            .create_draft(&ComposeEmail {
                from: &from,
                to: &args.to,
                cc: &args.cc,
                subject: &args.subject,
                body: &args.body,
                in_reply_to: in_reply_to.as_deref(),
                references: references.as_deref(),
            })
            .await
            .map_err(ErrorData::from)?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Draft saved with ID: {draft_id}"
        ))]))
    }

    #[tool(
        description = "Send an email. Requires 'send' capability to be enabled in server config."
    )]
    pub async fn mail_send(
        &self,
        Parameters(args): Parameters<SendArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_send")?;

        if !self.capabilities.send {
            return Err(ErrorData::invalid_request(
                "Sending emails is disabled. Enable 'capabilities.send = true' in config.",
                None,
            ));
        }

        validate_recipients(&args.to)?;
        validate_recipients(&args.cc)?;

        tracing::info!(event = "mail_send", account = ?args.account, to = ?args.to, subject = %args.subject, "Sending email");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;

        let from = client.username().to_string();

        let (in_reply_to, references) = if let Some(ref reply_id) = args.reply_to_id {
            let msg_id = client
                .get_message_id(reply_id)
                .await
                .map_err(ErrorData::from)?;
            (msg_id.clone(), msg_id)
        } else {
            (None, None)
        };

        let email_id = client
            .send_email(&ComposeEmail {
                from: &from,
                to: &args.to,
                cc: &args.cc,
                subject: &args.subject,
                body: &args.body,
                in_reply_to: in_reply_to.as_deref(),
                references: references.as_deref(),
            })
            .await
            .map_err(ErrorData::from)?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email sent successfully (ID: {email_id})"
        ))]))
    }
}

//! Read-only contacts lookup: `contacts_search` over the account's JMAP
//! address books (RFC 9610).

use crate::mcp::StalwartMcp;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

/// Contacts returned when `limit` is omitted.
pub const DEFAULT_LIMIT: usize = 20;
/// Most contacts one call returns; a larger `limit` is lowered to this.
pub const MAX_LIMIT: usize = 50;
/// Longest search text accepted, in characters.
pub const MAX_QUERY_CHARS: usize = 256;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ContactsSearchArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Text to match against contact names, email addresses and organisations. Omit to list contacts.
    pub query: Option<String>,
    /// Maximum contacts to return (default 20, at most 50)
    pub limit: Option<usize>,
}

/// The effective limit: [`DEFAULT_LIMIT`] when absent, at least 1, at most
/// [`MAX_LIMIT`].
fn effective_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// The search text to send: trimmed, `None` when empty, refused when longer
/// than [`MAX_QUERY_CHARS`].
fn check_query(query: Option<&str>) -> Result<Option<&str>, ErrorData> {
    let Some(query) = query.map(str::trim).filter(|q| !q.is_empty()) else {
        return Ok(None);
    };
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(ErrorData::invalid_params(
            format!("'query' must be at most {MAX_QUERY_CHARS} characters"),
            None,
        ));
    }
    Ok(Some(query))
}

#[tool_router(router = contacts_tool_router)]
impl StalwartMcp {
    pub(crate) fn create_contacts_tool_router() -> ToolRouter<Self> {
        Self::contacts_tool_router()
    }

    #[tool(
        description = "Search the account's contacts (address books) by text; the server matches whole words in names, email addresses, organisations and other card fields. Returns per contact only its name, email addresses, organisations and the names of the address books it is in. Omit 'query' to list contacts. At most 50 results."
    )]
    pub async fn contacts_search(
        &self,
        Parameters(args): Parameters<ContactsSearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("contacts_search")?;
        let query = check_query(args.query.as_deref())?;
        let limit = effective_limit(args.limit);
        tracing::info!(event = "contacts_search", account = ?args.account, has_query = query.is_some(), limit, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let contacts = client
            .search_contacts(query, limit)
            .await
            .map_err(ErrorData::from)?;
        let json = serde_json::to_string_pretty(&contacts)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_defaults_and_is_capped() {
        assert_eq!(effective_limit(None), DEFAULT_LIMIT);
        assert_eq!(effective_limit(Some(5)), 5);
        assert_eq!(effective_limit(Some(0)), 1);
        assert_eq!(effective_limit(Some(MAX_LIMIT + 1)), MAX_LIMIT);
        assert_eq!(effective_limit(Some(usize::MAX)), MAX_LIMIT);
    }

    #[test]
    fn query_is_trimmed_and_capped() {
        assert_eq!(check_query(None).expect("none"), None);
        assert_eq!(check_query(Some("  ")).expect("blank"), None);
        assert_eq!(check_query(Some(" ada ")).expect("text"), Some("ada"));
        assert!(check_query(Some(&"a".repeat(MAX_QUERY_CHARS))).is_ok());
        let err = check_query(Some(&"a".repeat(MAX_QUERY_CHARS + 1))).expect_err("too long");
        assert!(err.message.contains("256 characters"), "{err:?}");
    }

    #[test]
    fn contacts_search_is_registered() {
        let router = StalwartMcp::create_contacts_tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(names, vec!["contacts_search".to_string()]);
    }
}

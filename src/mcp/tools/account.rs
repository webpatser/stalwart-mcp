//! Account-level tools: masked addresses, vacation response, quota and identities.

use crate::jmap::account::VacationResponse;
use crate::jmap::masked_email::NewMaskedEmail;
use crate::mcp::StalwartMcp;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccountArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MaskedCreateArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// What the address is for (e.g. "newsletter signup at example.com"). Must not be empty.
    pub description: Option<String>,
    /// Domain of the site the address is given to (e.g. "shop.example.com")
    pub for_domain: Option<String>,
    /// URL of the site the address is given to
    pub url: Option<String>,
    /// Expiry as an RFC 3339 timestamp (e.g. "2027-01-01T00:00:00Z"). Can only be set at creation.
    pub expires_at: Option<String>,
    /// Local part prefix of the generated address: 1 to 64 letters, digits or underscores, not starting with an underscore. Omit for a random address.
    pub email_prefix: Option<String>,
    /// One of the account's own domains to create the address under. Omit for the account's primary domain.
    pub email_domain: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MaskedDisableArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// The masked address ID (from mail_masked_list)
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VacationSetArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Whether the server sends auto-replies
    pub is_enabled: bool,
    /// Start of the vacation as an RFC 3339 timestamp. Omit for no start date.
    pub from_date: Option<String>,
    /// End of the vacation as an RFC 3339 timestamp. Omit for no end date.
    pub to_date: Option<String>,
    /// Subject of the auto-reply. Omit to let the server choose one.
    pub subject: Option<String>,
    /// Plain text body of the auto-reply
    pub text_body: Option<String>,
    /// HTML body of the auto-reply
    pub html_body: Option<String>,
}

/// Normalise an RFC 3339 timestamp to the JMAP UTCDate form.
fn utc_date(field: &str, value: Option<&str>) -> Result<Option<String>, ErrorData> {
    value
        .map(|v| {
            chrono::DateTime::parse_from_rfc3339(v)
                .map(|d| {
                    d.with_timezone(&chrono::Utc)
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string()
                })
                .map_err(|_| {
                    ErrorData::invalid_params(
                        format!(
                            "'{field}' must be an RFC 3339 timestamp like 2027-01-01T00:00:00Z"
                        ),
                        None,
                    )
                })
        })
        .transpose()
}

fn validate_prefix(prefix: &str) -> Result<(), ErrorData> {
    let valid = (1..=64).contains(&prefix.len())
        && !prefix.starts_with('_')
        && prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(ErrorData::invalid_params(
            "'email_prefix' must be 1 to 64 letters, digits or underscores and not start with an underscore",
            None,
        ))
    }
}

fn json_result(value: &impl Serialize) -> Result<CallToolResult, ErrorData> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
}

#[tool_router(router = account_tool_router)]
impl StalwartMcp {
    pub(crate) fn create_account_tool_router() -> ToolRouter<Self> {
        Self::account_tool_router()
    }

    #[tool(
        description = "List the account's masked email addresses (Stalwart 1.1+): generated aliases that forward to the account, with their description, site, expiry and whether they are enabled"
    )]
    pub async fn mail_masked_list(
        &self,
        Parameters(args): Parameters<AccountArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_masked_list")?;
        tracing::info!(event = "mail_masked_list", account = ?args.account, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let list = client.list_masked_emails().await.map_err(ErrorData::from)?;
        json_result(&list)
    }

    #[tool(
        description = "Create a masked email address (Stalwart 1.1+). The server generates the address; returns it with its ID. The server limits how many masked addresses an account may have. Requires 'masked_email' capability enabled in config."
    )]
    pub async fn mail_masked_create(
        &self,
        Parameters(args): Parameters<MaskedCreateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_masked_create")?;

        if !self.capabilities.masked_email {
            return Err(ErrorData::invalid_request(
                "Masked email changes are disabled. Enable 'capabilities.masked_email = true' in config.",
                None,
            ));
        }

        if args.description.as_deref().is_some_and(str::is_empty) {
            return Err(ErrorData::invalid_params(
                "'description' must not be empty; omit it instead",
                None,
            ));
        }
        if let Some(prefix) = args.email_prefix.as_deref() {
            validate_prefix(prefix)?;
        }
        let expires_at = utc_date("expires_at", args.expires_at.as_deref())?;

        tracing::info!(event = "mail_masked_create", account = ?args.account, for_domain = ?args.for_domain, "Creating masked email");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let created = client
            .create_masked_email(&NewMaskedEmail {
                description: args.description.as_deref(),
                for_domain: args.for_domain.as_deref(),
                url: args.url.as_deref(),
                expires_at: expires_at.as_deref(),
                email_prefix: args.email_prefix.as_deref(),
                email_domain: args.email_domain.as_deref(),
            })
            .await
            .map_err(ErrorData::from)?;
        json_result(&created)
    }

    #[tool(
        description = "Disable a masked email address (Stalwart 1.1+) so mail to it is no longer delivered. The address is kept. Requires 'masked_email' capability enabled in config."
    )]
    pub async fn mail_masked_disable(
        &self,
        Parameters(args): Parameters<MaskedDisableArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_masked_disable")?;

        if !self.capabilities.masked_email {
            return Err(ErrorData::invalid_request(
                "Masked email changes are disabled. Enable 'capabilities.masked_email = true' in config.",
                None,
            ));
        }

        tracing::info!(event = "mail_masked_disable", account = ?args.account, id = %args.id, "Disabling masked email");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let updated = client
            .set_masked_email_enabled(&args.id, false)
            .await
            .map_err(ErrorData::from)?;
        json_result(&updated)
    }

    #[tool(
        description = "Get the account's vacation response (out-of-office auto-reply): whether it is enabled, its date range, subject and body"
    )]
    pub async fn mail_vacation_get(
        &self,
        Parameters(args): Parameters<AccountArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_vacation_get")?;
        tracing::info!(event = "mail_vacation_get", account = ?args.account, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let vacation = client
            .get_vacation_response()
            .await
            .map_err(ErrorData::from)?;
        json_result(&vacation)
    }

    #[tool(
        description = "Replace the account's vacation response (out-of-office auto-reply). Every field is set as given: omitted fields are cleared. When enabled, the server sends auto-replies to incoming mail. Returns the stored vacation response. Requires 'vacation' capability enabled in config."
    )]
    pub async fn mail_vacation_set(
        &self,
        Parameters(args): Parameters<VacationSetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("mail_vacation_set")?;

        if !self.capabilities.vacation {
            return Err(ErrorData::invalid_request(
                "Vacation response changes are disabled. Enable 'capabilities.vacation = true' in config.",
                None,
            ));
        }

        let vacation = VacationResponse {
            is_enabled: args.is_enabled,
            from_date: utc_date("from_date", args.from_date.as_deref())?,
            to_date: utc_date("to_date", args.to_date.as_deref())?,
            subject: args.subject,
            text_body: args.text_body,
            html_body: args.html_body,
        };
        if let (Some(from), Some(to)) = (&vacation.from_date, &vacation.to_date)
            && from >= to
        {
            return Err(ErrorData::invalid_params(
                "'from_date' must be before 'to_date'",
                None,
            ));
        }

        tracing::info!(event = "mail_vacation_set", account = ?args.account, is_enabled = vacation.is_enabled, "Setting vacation response");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let stored = client
            .set_vacation_response(&vacation)
            .await
            .map_err(ErrorData::from)?;
        json_result(&stored)
    }

    #[tool(
        description = "Get the account's storage quotas: used and limit in bytes (resource type 'octets') or object counts, with their scope"
    )]
    pub async fn quota_get(
        &self,
        Parameters(args): Parameters<AccountArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("quota_get")?;
        tracing::info!(event = "quota_get", account = ?args.account, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let quotas = client.list_quotas().await.map_err(ErrorData::from)?;
        json_result(&quotas)
    }

    #[tool(
        description = "List the account's sending identities: the From names and addresses the account may send as, with reply-to, bcc and signatures"
    )]
    pub async fn identity_list(
        &self,
        Parameters(args): Parameters<AccountArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("identity_list")?;
        tracing::info!(event = "identity_list", account = ?args.account, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let identities = client.list_identities().await.map_err(ErrorData::from)?;
        json_result(&identities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_date_normalises_offsets() {
        assert_eq!(
            utc_date("d", Some("2027-01-01T01:00:00+01:00")).expect("date"),
            Some("2027-01-01T00:00:00Z".to_string())
        );
        assert_eq!(utc_date("d", None).expect("none"), None);
        assert!(utc_date("d", Some("next week")).is_err());
    }

    #[test]
    fn prefix_rules_match_the_server() {
        assert!(validate_prefix("shop_2026").is_ok());
        for bad in ["", "_shop", "shop-1", "shöp", &"a".repeat(65)] {
            assert!(validate_prefix(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn account_tools_are_registered() {
        let router = StalwartMcp::create_account_tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        for name in [
            "mail_masked_list",
            "mail_masked_create",
            "mail_masked_disable",
            "mail_vacation_get",
            "mail_vacation_set",
            "quota_get",
            "identity_list",
        ] {
            assert!(names.iter().any(|n| n == name), "{name} missing");
        }
    }
}

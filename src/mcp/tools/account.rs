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
    /// End of the vacation as an RFC 3339 timestamp. Required when enabling: in the future and at most 90 days ahead.
    pub to_date: Option<String>,
    /// Subject of the auto-reply. Omit to let the server choose one.
    pub subject: Option<String>,
    /// Plain text body of the auto-reply
    pub text_body: Option<String>,
    /// HTML body of the auto-reply
    pub html_body: Option<String>,
}

/// Longest time ahead an enabled vacation response may end.
const MAX_VACATION_DAYS: i64 = 90;

/// A maximum input length, in characters or in bytes.
#[derive(Debug, Clone, Copy)]
enum Limit {
    Chars(usize),
    Bytes(usize),
}

const MAX_MASKED_DESCRIPTION: Limit = Limit::Chars(256);
const MAX_MASKED_URL: Limit = Limit::Chars(2048);
const MAX_MASKED_FOR_DOMAIN: Limit = Limit::Chars(255);
const MAX_VACATION_SUBJECT: Limit = Limit::Chars(998);
const MAX_VACATION_BODY: Limit = Limit::Bytes(64 * 1024);

/// Reject `value` when it is longer than `limit`.
fn check_len(field: &str, value: Option<&str>, limit: Limit) -> Result<(), ErrorData> {
    let Some(value) = value else {
        return Ok(());
    };
    let (len, max, unit) = match limit {
        Limit::Chars(max) => (value.chars().count(), max, "characters"),
        Limit::Bytes(max) => (value.len(), max, "bytes"),
    };
    if len > max {
        return Err(ErrorData::invalid_params(
            format!("'{field}' must be at most {max} {unit}"),
            None,
        ));
    }
    Ok(())
}

type UtcDateTime = chrono::DateTime<chrono::Utc>;

fn parse_utc(field: &str, value: Option<&str>) -> Result<Option<UtcDateTime>, ErrorData> {
    value
        .map(|v| {
            chrono::DateTime::parse_from_rfc3339(v)
                .map(|d| d.with_timezone(&chrono::Utc))
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

fn format_utc(date: UtcDateTime) -> String {
    date.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Normalise an RFC 3339 timestamp to the JMAP UTCDate form.
fn utc_date(field: &str, value: Option<&str>) -> Result<Option<String>, ErrorData> {
    Ok(parse_utc(field, value)?.map(format_utc))
}

/// Check the vacation date range. An enabled response needs a `to_date` in
/// the future and at most [`MAX_VACATION_DAYS`] ahead of `now`, so an
/// auto-reply can never run without an end.
fn validate_vacation_dates(
    is_enabled: bool,
    from: Option<UtcDateTime>,
    to: Option<UtcDateTime>,
    now: UtcDateTime,
) -> Result<(), ErrorData> {
    if let (Some(from), Some(to)) = (from, to)
        && from >= to
    {
        return Err(ErrorData::invalid_params(
            "'from_date' must be before 'to_date'",
            None,
        ));
    }
    if !is_enabled {
        return Ok(());
    }
    let Some(to) = to else {
        return Err(ErrorData::invalid_params(
            "'to_date' is required when 'is_enabled' is true",
            None,
        ));
    };
    if to <= now {
        return Err(ErrorData::invalid_params(
            "'to_date' must be in the future",
            None,
        ));
    }
    if to > now + chrono::Duration::days(MAX_VACATION_DAYS) {
        return Err(ErrorData::invalid_params(
            format!("'to_date' must be at most {MAX_VACATION_DAYS} days from now"),
            None,
        ));
    }
    Ok(())
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
        check_len(
            "description",
            args.description.as_deref(),
            MAX_MASKED_DESCRIPTION,
        )?;
        check_len("url", args.url.as_deref(), MAX_MASKED_URL)?;
        check_len(
            "for_domain",
            args.for_domain.as_deref(),
            MAX_MASKED_FOR_DOMAIN,
        )?;
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
        description = "Replace the account's vacation response (out-of-office auto-reply). Enabling it makes the mail server send an automatic reply to anyone who mails this account, and it keeps doing so after this session ends, until 'to_date'. Only enable it when the user explicitly asks for an auto-reply, and call mail_vacation_get first to see the current one. The subject and body go to every sender, so they must not contain private data. The call replaces the whole response: every field is set as given and omitted fields are cleared. When 'is_enabled' is true, 'to_date' is required and must be in the future and at most 90 days ahead; disabling needs no dates. Returns the stored vacation response. Requires 'vacation' capability enabled in config."
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

        check_len("subject", args.subject.as_deref(), MAX_VACATION_SUBJECT)?;
        check_len("text_body", args.text_body.as_deref(), MAX_VACATION_BODY)?;
        check_len("html_body", args.html_body.as_deref(), MAX_VACATION_BODY)?;
        let from_date = parse_utc("from_date", args.from_date.as_deref())?;
        let to_date = parse_utc("to_date", args.to_date.as_deref())?;
        validate_vacation_dates(args.is_enabled, from_date, to_date, chrono::Utc::now())?;

        let vacation = VacationResponse {
            is_enabled: args.is_enabled,
            from_date: from_date.map(format_utc),
            to_date: to_date.map(format_utc),
            subject: args.subject,
            text_body: args.text_body,
            html_body: args.html_body,
        };

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

    fn at(s: &str) -> UtcDateTime {
        parse_utc("d", Some(s)).expect("parse").expect("some")
    }

    #[test]
    fn enabled_vacation_needs_a_bounded_future_end() {
        let now = at("2026-11-20T12:00:00Z");
        let ok = |enabled, from: Option<&str>, to: Option<&str>| {
            validate_vacation_dates(enabled, from.map(at), to.map(at), now).is_ok()
        };
        // Disabling needs no dates, and past dates are fine when disabled.
        assert!(ok(false, None, None));
        assert!(ok(false, None, Some("2020-01-01T00:00:00Z")));
        // Enabling requires a to_date, in the future, within 90 days.
        assert!(!ok(true, None, None));
        assert!(!ok(true, Some("2026-11-21T00:00:00Z"), None));
        assert!(!ok(true, None, Some("2026-11-20T11:59:59Z")));
        assert!(!ok(true, None, Some("2026-11-20T12:00:00Z")));
        assert!(ok(true, None, Some("2026-11-21T00:00:00Z")));
        assert!(ok(true, None, Some("2027-02-18T12:00:00Z")));
        assert!(!ok(true, None, Some("2027-02-18T12:00:01Z")));
        // The range check still applies either way.
        assert!(!ok(
            true,
            Some("2026-12-02T00:00:00Z"),
            Some("2026-12-01T00:00:00Z")
        ));
        assert!(!ok(
            false,
            Some("2026-12-01T00:00:00Z"),
            Some("2026-12-01T00:00:00Z")
        ));
    }

    #[test]
    fn input_lengths_are_capped() {
        assert!(check_len("f", None, Limit::Chars(1)).is_ok());
        assert!(
            check_len(
                "description",
                Some(&"é".repeat(256)),
                MAX_MASKED_DESCRIPTION
            )
            .is_ok()
        );
        let err = check_len(
            "description",
            Some(&"a".repeat(257)),
            MAX_MASKED_DESCRIPTION,
        )
        .expect_err("too long");
        assert_eq!(err.message, "'description' must be at most 256 characters");
        assert!(check_len("url", Some(&"a".repeat(2049)), MAX_MASKED_URL).is_err());
        assert!(check_len("for_domain", Some(&"a".repeat(256)), MAX_MASKED_FOR_DOMAIN).is_err());
        assert!(check_len("subject", Some(&"a".repeat(998)), MAX_VACATION_SUBJECT).is_ok());
        assert!(check_len("subject", Some(&"a".repeat(999)), MAX_VACATION_SUBJECT).is_err());
        assert!(check_len("text_body", Some(&"a".repeat(65536)), MAX_VACATION_BODY).is_ok());
        // Bodies count bytes: 32769 two-byte characters exceed 64 KiB.
        let err = check_len("html_body", Some(&"é".repeat(32769)), MAX_VACATION_BODY)
            .expect_err("too long");
        assert_eq!(err.message, "'html_body' must be at most 65536 bytes");
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

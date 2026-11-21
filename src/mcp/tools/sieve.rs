//! Sieve filter tools: list, read and validate scripts, and (behind
//! `capabilities.sieve`) create or replace one.

use crate::jmap::sieve::{RESERVED_NAME, SievePut};
use crate::mcp::StalwartMcp;
use crate::mcp::tools::account::AccountArgs;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Largest script accepted by `sieve_validate` and `sieve_put`, in bytes.
/// Checked before any network call.
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
/// Longest script name accepted, in bytes (Stalwart 1.1.1 allows more).
pub const MAX_SCRIPT_NAME_BYTES: usize = 128;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SieveGetArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// The script ID (from sieve_list)
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SieveValidateArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Sieve script source (RFC 5228), at most 65536 bytes
    pub script: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SievePutArgs {
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// ID of an existing script to replace (from sieve_list). Omit to create a new script.
    pub id: Option<String>,
    /// Script name. Required when creating; omit on replace to keep the current name. Must not be "vacation".
    pub name: Option<String>,
    /// Sieve script source (RFC 5228), at most 65536 bytes
    pub script: String,
    /// Make this the active script after storing it, replacing the currently active one. Default false: the script is stored inactive and filters nothing.
    #[serde(default)]
    pub activate: bool,
}

/// Reject a script above [`MAX_SCRIPT_BYTES`].
fn check_script(script: &str) -> Result<(), ErrorData> {
    if script.len() > MAX_SCRIPT_BYTES {
        return Err(ErrorData::invalid_params(
            format!("'script' must be at most {MAX_SCRIPT_BYTES} bytes"),
            None,
        ));
    }
    Ok(())
}

/// A create needs a name; any given name must be non-empty, within
/// [`MAX_SCRIPT_NAME_BYTES`], not made only of dots (`.`, `..`), free of `/`
/// and control characters, and not the server-managed `vacation`.
fn check_name(name: Option<&str>, creating: bool) -> Result<(), ErrorData> {
    let Some(name) = name else {
        return if creating {
            Err(ErrorData::invalid_params(
                "'name' is required when creating a script",
                None,
            ))
        } else {
            Ok(())
        };
    };
    if name.trim().is_empty() {
        return Err(ErrorData::invalid_params("'name' must not be empty", None));
    }
    if name.len() > MAX_SCRIPT_NAME_BYTES {
        return Err(ErrorData::invalid_params(
            format!("'name' must be at most {MAX_SCRIPT_NAME_BYTES} bytes"),
            None,
        ));
    }
    if name.bytes().all(|b| b == b'.') {
        return Err(ErrorData::invalid_params(
            "'name' must not be '.' or '..'",
            None,
        ));
    }
    if name.chars().any(|c| c == '/' || c.is_control()) {
        return Err(ErrorData::invalid_params(
            "'name' must not contain '/' or control characters",
            None,
        ));
    }
    if name.eq_ignore_ascii_case(RESERVED_NAME) {
        return Err(ErrorData::invalid_params(
            "'vacation' is reserved for the vacation response; use mail_vacation_set",
            None,
        ));
    }
    Ok(())
}

/// Every check `sieve_put` makes before its first network call: the
/// capability gate first, then the size cap and the name rules.
fn check_put_allowed(args: &SievePutArgs, sieve_enabled: bool) -> Result<(), ErrorData> {
    if !sieve_enabled {
        return Err(ErrorData::invalid_request(
            "Sieve script changes are disabled. Enable 'capabilities.sieve = true' in config.",
            None,
        ));
    }
    check_script(&args.script)?;
    check_name(args.name.as_deref(), args.id.is_none())
}

fn json_result(value: &impl Serialize) -> Result<CallToolResult, ErrorData> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
}

#[tool_router(router = sieve_tool_router)]
impl StalwartMcp {
    pub(crate) fn create_sieve_tool_router() -> ToolRouter<Self> {
        Self::sieve_tool_router()
    }

    #[tool(
        description = "List the account's Sieve filter scripts: ID, name and whether it is the active one (at most one script is active). Content is not included; use sieve_get."
    )]
    pub async fn sieve_list(
        &self,
        Parameters(args): Parameters<AccountArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("sieve_list")?;
        tracing::info!(event = "sieve_list", account = ?args.account, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let scripts = client.list_sieve_scripts().await.map_err(ErrorData::from)?;
        json_result(&scripts)
    }

    #[tool(
        description = "Get one Sieve filter script by ID with its source, name and whether it is active"
    )]
    pub async fn sieve_get(
        &self,
        Parameters(args): Parameters<SieveGetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("sieve_get")?;
        tracing::info!(event = "sieve_get", account = ?args.account, id = %args.id, "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let script = client
            .get_sieve_script(&args.id)
            .await
            .map_err(ErrorData::from)?;
        json_result(&script)
    }

    #[tool(
        description = "Check a Sieve script with the mail server's compiler without storing it. Returns {valid, error}; error is the server's message when the script does not compile."
    )]
    pub async fn sieve_validate(
        &self,
        Parameters(args): Parameters<SieveValidateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("sieve_validate")?;
        check_script(&args.script)?;
        tracing::info!(event = "sieve_validate", account = ?args.account, bytes = args.script.len(), "Tool called");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let validation = client
            .validate_sieve_script(&args.script)
            .await
            .map_err(ErrorData::from)?;
        json_result(&validation)
    }

    #[tool(
        description = "Create a Sieve filter script, or replace the source of an existing one by 'id'. A wrong script can silently discard, reject or redirect incoming mail, so only do this when the user explicitly asks, show them the script first, and call sieve_list to see the active script. The script is always validated by the server first and refused if it does not compile. It is stored inactive unless 'activate' is true; activating it replaces the currently active script. Replacing by 'id' is refused for an unknown id and for the server-managed 'vacation' script (use mail_vacation_set); replacing the currently active script changes live filtering immediately and is refused unless 'activate' is true. Returns the stored script. Requires 'sieve' capability enabled in config."
    )]
    pub async fn sieve_put(
        &self,
        Parameters(args): Parameters<SievePutArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rate_limiters.check("sieve_put")?;
        check_put_allowed(&args, self.capabilities.sieve)?;

        tracing::info!(event = "sieve_put", account = ?args.account, id = ?args.id, activate = args.activate, bytes = args.script.len(), "Storing Sieve script");

        let client = self
            .accounts
            .get(args.account.as_deref())
            .map_err(ErrorData::from)?;
        let stored = client
            .put_sieve_script(&SievePut {
                id: args.id.as_deref(),
                name: args.name.as_deref(),
                content: &args.script,
                activate: args.activate,
            })
            .await
            .map_err(ErrorData::from)?;
        json_result(&stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_size_is_capped() {
        assert!(check_script(&"a".repeat(MAX_SCRIPT_BYTES)).is_ok());
        let err = check_script(&"a".repeat(MAX_SCRIPT_BYTES + 1)).expect_err("too large");
        assert_eq!(err.message, "'script' must be at most 65536 bytes");
        // Bytes, not characters.
        assert!(check_script(&"é".repeat(MAX_SCRIPT_BYTES / 2 + 1)).is_err());
    }

    #[test]
    fn name_rules() {
        assert!(check_name(None, true).is_err());
        assert!(check_name(None, false).is_ok());
        assert!(check_name(Some("filters"), true).is_ok());
        assert!(check_name(Some("  "), false).is_err());
        assert!(check_name(Some("Vacation"), true).is_err());
        assert!(check_name(Some("vacation"), false).is_err());
        assert!(check_name(Some(&"a".repeat(MAX_SCRIPT_NAME_BYTES)), true).is_ok());
        assert!(check_name(Some(&"a".repeat(MAX_SCRIPT_NAME_BYTES + 1)), true).is_err());
    }

    #[test]
    fn name_length_is_counted_in_bytes() {
        let err = check_name(Some(&"é".repeat(MAX_SCRIPT_NAME_BYTES / 2 + 1)), true)
            .expect_err("too long");
        assert_eq!(err.message, "'name' must be at most 128 bytes");
        assert!(check_name(Some(&"é".repeat(MAX_SCRIPT_NAME_BYTES / 2)), true).is_ok());
    }

    #[test]
    fn dot_names_are_refused() {
        for bad in [".", "..", "..."] {
            assert!(check_name(Some(bad), true).is_err(), "{bad}");
        }
        assert!(check_name(Some(".filters"), true).is_ok());
        assert!(check_name(Some("a..b"), true).is_ok());
    }

    #[test]
    fn slash_and_control_characters_are_refused() {
        for bad in ["a/b", "/", "../x", "a\nb", "a\tb", "a\u{0}b", "a\u{7f}b"] {
            let err = check_name(Some(bad), true).expect_err(bad);
            assert!(
                err.message.contains("'/'") || err.message.contains("'.'"),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn put_is_gated_by_the_sieve_capability_first() {
        let args = SievePutArgs {
            account: None,
            id: None,
            name: Some("filters".into()),
            script: "keep;".into(),
            activate: false,
        };
        let err = check_put_allowed(&args, false).expect_err("gated");
        assert!(err.message.contains("capabilities.sieve = true"), "{err:?}");
        assert!(check_put_allowed(&args, true).is_ok());

        // The gate wins over input errors, so a disabled server says so.
        let oversized = SievePutArgs {
            script: "a".repeat(MAX_SCRIPT_BYTES + 1),
            name: None,
            ..args
        };
        let err = check_put_allowed(&oversized, false).expect_err("gated");
        assert!(err.message.contains("capabilities.sieve"), "{err:?}");
        let err = check_put_allowed(&oversized, true).expect_err("too large");
        assert!(err.message.contains("65536 bytes"), "{err:?}");
    }

    #[test]
    fn activate_defaults_to_false() {
        let args: SievePutArgs =
            serde_json::from_str(r#"{"name": "n", "script": "keep;"}"#).expect("args");
        assert!(!args.activate);
        assert!(args.id.is_none());
    }

    #[test]
    fn sieve_tools_are_registered() {
        let router = StalwartMcp::create_sieve_tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        for name in ["sieve_list", "sieve_get", "sieve_validate", "sieve_put"] {
            assert!(names.iter().any(|n| n == name), "{name} missing");
        }
    }
}

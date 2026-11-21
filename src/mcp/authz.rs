//! Authorization for tool calls and resource reads.
//!
//! The HTTP auth middleware stores an [`AuthContext`] in the request extensions.
//! rmcp copies the request's `http::request::Parts` into the MCP request
//! context, so the handler reads it back with [`resolve`]. The tool-to-scope
//! table [`TOOL_SCOPES`] is the single source of truth for which scope a tool
//! needs; a tool missing from it is refused.

use crate::auth::Claims;
use crate::error::AppError;
use axum::http::request::Parts;
use rmcp::model::{CallToolRequestParams, Extensions};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use serde_json::Value;

/// A permission a token can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Read mail, folders, identities, quota and settings.
    Read,
    /// Change mailbox state: flags, moves, drafts, bulk actions, masked addresses, spam training.
    Modify,
    /// Anything that makes the server send mail: `mail_send`, vacation auto-replies.
    Send,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "mail:read",
            Scope::Modify => "mail:modify",
            Scope::Send => "mail:send",
        }
    }
}

/// Scope strings accepted by `token create`. `*` grants every scope.
pub const VALID_SCOPES: &[&str] = &["mail:read", "mail:modify", "mail:send", "*"];

/// Required scope per tool. Every tool in the router must appear here; a unit
/// test enforces that, and a tool missing from the table is refused at runtime.
pub const TOOL_SCOPES: &[(&str, Scope)] = &[
    ("mail_list_folders", Scope::Read),
    ("mail_list_recent", Scope::Read),
    ("mail_search", Scope::Read),
    ("mail_get", Scope::Read),
    ("mail_get_thread", Scope::Read),
    ("mail_masked_list", Scope::Read),
    ("mail_vacation_get", Scope::Read),
    ("quota_get", Scope::Read),
    ("identity_list", Scope::Read),
    ("sieve_list", Scope::Read),
    ("sieve_get", Scope::Read),
    ("sieve_validate", Scope::Read),
    ("contacts_search", Scope::Read),
    ("mail_flag", Scope::Modify),
    ("mail_move", Scope::Modify),
    ("mail_draft", Scope::Modify),
    ("mail_bulk_read", Scope::Modify),
    ("mail_bulk_junk", Scope::Modify),
    ("mail_bulk_delete", Scope::Modify),
    ("mail_masked_create", Scope::Modify),
    ("mail_masked_disable", Scope::Modify),
    ("spam_train", Scope::Modify),
    ("mail_send", Scope::Send),
    ("mail_vacation_set", Scope::Send),
    // A Sieve script can redirect mail to any address.
    ("sieve_put", Scope::Send),
];

/// Look up the scope a tool requires. `None` means the tool is unknown.
pub fn required_scope(tool: &str) -> Option<Scope> {
    TOOL_SCOPES
        .iter()
        .find(|(name, _)| *name == tool)
        .map(|(_, scope)| *scope)
}

/// Check scope strings given to `token create`.
pub fn validate_scopes(scopes: &[String]) -> Result<(), AppError> {
    if scopes.is_empty() {
        return Err(AppError::Config("at least one scope is required".into()));
    }
    match scopes.iter().find(|s| !VALID_SCOPES.contains(&s.as_str())) {
        Some(unknown) => Err(AppError::Config(format!(
            "unknown scope '{unknown}'; accepted: {}",
            VALID_SCOPES.join(", ")
        ))),
        None => Ok(()),
    }
}

/// Which accounts a caller may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountScope {
    /// Every configured account.
    Any,
    /// Only the named account (exact match).
    Named(String),
}

/// The caller's permissions, stored in the HTTP request extensions by the auth middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub account: AccountScope,
    pub scopes: Vec<String>,
}

impl AuthContext {
    /// Full access: stdio, and the secret-less loopback HTTP case.
    pub fn unrestricted() -> Self {
        Self {
            account: AccountScope::Any,
            scopes: vec!["*".into()],
        }
    }

    /// Permissions from validated JWT claims. `sub` of `*` means every account.
    pub fn from_claims(claims: &Claims) -> Self {
        let account = if claims.sub == "*" {
            AccountScope::Any
        } else {
            AccountScope::Named(claims.sub.clone())
        };
        Self {
            account,
            scopes: claims.scopes.clone(),
        }
    }

    /// Same rule as `Claims::has_scope`: the exact scope or `*`.
    pub fn allows(&self, scope: Scope) -> bool {
        self.scopes.iter().any(|s| s == scope.as_str() || s == "*")
    }

    /// Whether the named account may be reached.
    pub fn permits_account(&self, name: &str) -> bool {
        match &self.account {
            AccountScope::Any => true,
            AccountScope::Named(allowed) => allowed == name,
        }
    }

    /// The single permitted account, if the caller is restricted to one.
    pub fn restricted_account(&self) -> Option<&str> {
        match &self.account {
            AccountScope::Any => None,
            AccountScope::Named(name) => Some(name),
        }
    }

    /// Refuse unless the caller holds `scope`.
    pub fn require(&self, scope: Scope) -> Result<(), ErrorData> {
        if self.allows(scope) {
            Ok(())
        } else {
            tracing::warn!(scope = scope.as_str(), "Request refused: missing scope");
            Err(ErrorData::invalid_request(
                format!("Forbidden: this token lacks the '{}' scope", scope.as_str()),
                None,
            ))
        }
    }

    /// Refuse unless the caller may reach `account`.
    pub fn require_account(&self, account: &str) -> Result<(), ErrorData> {
        if self.permits_account(account) {
            Ok(())
        } else {
            Err(account_refused())
        }
    }

    /// Check a tool call before it runs: the tool must be known, the scope held,
    /// and with a restricted account a missing (or null) `account` argument is set
    /// to that account while any other value is refused.
    pub fn authorize_tool_call(
        &self,
        request: &mut CallToolRequestParams,
    ) -> Result<(), ErrorData> {
        let scope = required_scope(&request.name).ok_or_else(|| {
            ErrorData::invalid_params(format!("Unknown tool '{}'", request.name), None)
        })?;
        self.require(scope)?;

        let Some(allowed) = self.restricted_account() else {
            return Ok(());
        };
        let args = request.arguments.get_or_insert_with(Default::default);
        match args.get("account") {
            None | Some(Value::Null) => {
                args.insert("account".into(), Value::String(allowed.to_string()));
                Ok(())
            }
            Some(Value::String(given)) if given == allowed => Ok(()),
            Some(_) => Err(account_refused()),
        }
    }
}

fn account_refused() -> ErrorData {
    tracing::warn!("Request refused: account outside the token's restriction");
    ErrorData::invalid_request(
        "Forbidden: this token is restricted to another account",
        None,
    )
}

/// The transport a server instance was built for. Authorization is decided by
/// this, never by the shape of an individual request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Local stdio: the client is the process owner, full access.
    Stdio,
    /// Streamable HTTP: every request must carry an [`AuthContext`].
    Http,
}

/// A server handler that can be switched to a transport, so the HTTP service
/// factory can force [`Transport::Http`] on every instance it hands out.
pub trait WithTransport {
    fn with_transport(self, transport: Transport) -> Self;
}

/// Resolve the caller's permissions from MCP request extensions.
///
/// `Stdio` is unrestricted. `Http` requires the request's `Parts` carrying an
/// [`AuthContext`] from the middleware; a missing `Parts` or a missing context
/// is denied (fail closed).
pub fn resolve_from_extensions(
    transport: Transport,
    extensions: &Extensions,
) -> Result<AuthContext, ErrorData> {
    match transport {
        Transport::Stdio => Ok(AuthContext::unrestricted()),
        Transport::Http => extensions
            .get::<Parts>()
            .and_then(|parts| parts.extensions.get::<AuthContext>())
            .cloned()
            .ok_or_else(|| {
                tracing::error!("HTTP request without auth context; refusing");
                ErrorData::invalid_request("Forbidden: no authorization context", None)
            }),
    }
}

/// Resolve the caller's permissions for a request context.
pub fn resolve(
    transport: Transport,
    context: &RequestContext<RoleServer>,
) -> Result<AuthContext, ErrorData> {
    resolve_from_extensions(transport, &context.extensions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::StalwartMcp;
    use serde_json::json;

    fn ctx(account: AccountScope, scopes: &[&str]) -> AuthContext {
        AuthContext {
            account,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn call(name: &str, args: Value) -> CallToolRequestParams {
        let mut request = CallToolRequestParams::new(name.to_string());
        if let Value::Object(map) = args {
            request.arguments = Some(map);
        }
        request
    }

    /// Collect every schema property whose name contains "account", at any depth
    /// (nested objects, `items`, `$defs`, combinators), except the root's own
    /// `properties.account`.
    fn collect_account_like_properties(schema: &Value, out: &mut Vec<String>) {
        fn walk(value: &Value, root: bool, path: &str, out: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    for (key, child) in map {
                        if key == "properties"
                            && let Value::Object(props) = child
                        {
                            for (name, sub) in props {
                                let here = format!("{path}/{name}");
                                let allowed = root && name == "account";
                                if !allowed && name.to_ascii_lowercase().contains("account") {
                                    out.push(here.clone());
                                }
                                walk(sub, false, &here, out);
                            }
                        } else {
                            walk(child, false, &format!("{path}/{key}"), out);
                        }
                    }
                }
                Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        walk(item, false, &format!("{path}/{i}"), out);
                    }
                }
                _ => {}
            }
        }
        walk(schema, true, "", out);
    }

    #[test]
    fn account_like_property_detection() {
        let mut out = Vec::new();
        collect_account_like_properties(
            &json!({"properties": {"account": {"type": "string"}, "id": {}}}),
            &mut out,
        );
        assert!(out.is_empty(), "{out:?}");
        for bad in [
            json!({"properties": {"account": {}, "from_account": {}}}),
            json!({"properties": {"targetAccount": {}}}),
            json!({"properties": {"opts": {"properties": {"account": {}}}}}),
            json!({"properties": {}, "$defs": {"X": {"properties": {"account_id": {}}}}}),
            json!({"properties": {"list": {"items": {"properties": {"Account": {}}}}}}),
        ] {
            let mut out = Vec::new();
            collect_account_like_properties(&bad, &mut out);
            assert!(!out.is_empty(), "{bad}");
        }
    }

    #[test]
    fn every_router_tool_has_a_scope_and_an_account_property() {
        let router = StalwartMcp::create_tool_router()
            + StalwartMcp::create_account_tool_router()
            + StalwartMcp::create_sieve_tool_router()
            + StalwartMcp::create_contacts_tool_router();
        let tools = router.list_all();
        assert!(!tools.is_empty());
        for tool in &tools {
            assert!(
                required_scope(&tool.name).is_some(),
                "tool '{}' has no scope mapping",
                tool.name
            );
            let has_account = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.get("account"))
                .is_some();
            assert!(
                has_account,
                "tool '{}' has no 'account' property",
                tool.name
            );
            // The account rule only inspects top-level `account`; any other
            // account-like selector anywhere in the schema would bypass it.
            let mut stray = Vec::new();
            collect_account_like_properties(
                &Value::Object((*tool.input_schema).clone()),
                &mut stray,
            );
            assert!(
                stray.is_empty(),
                "tool '{}' has account-like properties outside top-level 'account': {stray:?}",
                tool.name
            );
        }
        for (name, _) in TOOL_SCOPES {
            assert!(
                tools.iter().any(|t| t.name == *name),
                "scope table names unknown tool '{name}'"
            );
        }
        assert_eq!(tools.len(), TOOL_SCOPES.len());
    }

    #[test]
    fn allows_table() {
        let cases: &[(&[&str], Scope, bool)] = &[
            (&["mail:read"], Scope::Read, true),
            (&["mail:read"], Scope::Modify, false),
            (&["mail:read"], Scope::Send, false),
            (&["mail:modify"], Scope::Read, false),
            (&["mail:modify"], Scope::Modify, true),
            (&["mail:read", "mail:send"], Scope::Send, true),
            (&["*"], Scope::Send, true),
            (&[], Scope::Read, false),
            (&["MAIL:READ"], Scope::Read, false),
        ];
        for (scopes, scope, expected) in cases {
            assert_eq!(
                ctx(AccountScope::Any, scopes).allows(*scope),
                *expected,
                "{scopes:?} {scope:?}"
            );
        }
    }

    #[test]
    fn from_claims_maps_star_to_any() {
        let claims = |sub: &str| Claims {
            sub: sub.into(),
            scopes: vec!["mail:read".into()],
            exp: 0,
            iat: 0,
        };
        assert_eq!(
            AuthContext::from_claims(&claims("*")).account,
            AccountScope::Any
        );
        assert_eq!(
            AuthContext::from_claims(&claims("work")).account,
            AccountScope::Named("work".into())
        );
    }

    #[test]
    fn scope_is_checked_and_unknown_tools_refused() {
        let read = ctx(AccountScope::Any, &["mail:read"]);
        assert!(
            read.authorize_tool_call(&mut call("mail_get", json!({})))
                .is_ok()
        );
        assert!(
            read.authorize_tool_call(&mut call("mail_draft", json!({})))
                .is_err()
        );
        assert!(
            read.authorize_tool_call(&mut call("mail_send", json!({})))
                .is_err()
        );
        let all = AuthContext::unrestricted();
        assert!(
            all.authorize_tool_call(&mut call("no_such_tool", json!({})))
                .is_err()
        );
    }

    #[test]
    fn account_rule_table() {
        let restricted = ctx(AccountScope::Named("work".into()), &["*"]);
        let cases = [
            (json!({}), Ok(Some(json!("work")))),
            (json!({"account": null}), Ok(Some(json!("work")))),
            (json!({"account": "work"}), Ok(Some(json!("work")))),
            (json!({"account": "personal"}), Err(())),
            (json!({"account": "Work"}), Err(())),
            (json!({"account": 1}), Err(())),
            (json!({"account": ["work"]}), Err(())),
        ];
        for (args, expected) in cases {
            let mut request = call("mail_get", args.clone());
            let result = restricted
                .authorize_tool_call(&mut request)
                .map(|()| request.arguments.and_then(|a| a.get("account").cloned()))
                .map_err(|_| ());
            assert_eq!(result, expected, "{args}");
        }

        let mut no_args = CallToolRequestParams::new("mail_get");
        restricted.authorize_tool_call(&mut no_args).unwrap();
        assert_eq!(no_args.arguments.unwrap()["account"], json!("work"));

        let mut any = call("mail_get", json!({"account": "personal"}));
        AuthContext::unrestricted()
            .authorize_tool_call(&mut any)
            .unwrap();
        assert_eq!(any.arguments.unwrap()["account"], json!("personal"));
    }

    #[test]
    fn resolve_follows_the_transport_and_fails_closed_over_http() {
        let restricted = ctx(AccountScope::Named("work".into()), &["mail:read"]);
        let mut request = axum::http::Request::new(());
        request.extensions_mut().insert(restricted.clone());
        let (with_context, ()) = request.into_parts();
        let mut full = Extensions::new();
        full.insert(with_context);

        let (bare, ()) = axum::http::Request::new(()).into_parts();
        let mut no_context = Extensions::new();
        no_context.insert(bare);

        // Stdio is unrestricted whatever the request carries.
        for ext in [&Extensions::new(), &no_context, &full] {
            assert_eq!(
                resolve_from_extensions(Transport::Stdio, ext).unwrap(),
                AuthContext::unrestricted()
            );
        }

        // Http: no Parts is denied, Parts without a context is denied.
        assert!(resolve_from_extensions(Transport::Http, &Extensions::new()).is_err());
        assert!(resolve_from_extensions(Transport::Http, &no_context).is_err());
        assert_eq!(
            resolve_from_extensions(Transport::Http, &full).unwrap(),
            restricted
        );
    }

    #[test]
    fn validate_scopes_accepts_known_and_rejects_others() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(validate_scopes(&s(&["mail:read", "mail:modify", "mail:send"])).is_ok());
        assert!(validate_scopes(&s(&["*"])).is_ok());
        assert!(validate_scopes(&s(&["mail:write"])).is_err());
        assert!(validate_scopes(&s(&[""])).is_err());
        assert!(validate_scopes(&[]).is_err());
    }
}

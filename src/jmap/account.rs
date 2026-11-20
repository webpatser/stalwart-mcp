//! Account-level JMAP objects: vacation response (RFC 8621 section 8),
//! quotas (RFC 9425) and sending identities (RFC 8621 section 6).
//!
//! These are raw calls: jmap-client 0.4 has no Quota support, and its
//! VacationResponse builder skips `None` values, so it cannot set a property
//! back to `null`, which an exact restore of a prior state needs.

use crate::error::AppError;
use crate::jmap::JmapClient;
use crate::jmap::raw::{SetResponse, parse_args};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const VACATION_CAPABILITY: &str = "urn:ietf:params:jmap:vacationresponse";
pub const QUOTA_CAPABILITY: &str = "urn:ietf:params:jmap:quota";
pub const SUBMISSION_CAPABILITY: &str = "urn:ietf:params:jmap:submission";
const VACATION_GET: &str = "VacationResponse/get";
const VACATION_SET: &str = "VacationResponse/set";
const QUOTA_GET: &str = "Quota/get";
const IDENTITY_GET: &str = "Identity/get";
/// The only VacationResponse id (RFC 8621 section 8).
const SINGLETON: &str = "singleton";

/// The full vacation response. Every property is always sent on update, so
/// `None` clears it on the server. Dates are UTCDate strings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VacationResponse {
    #[serde(default)]
    pub is_enabled: bool,
    #[serde(default)]
    pub from_date: Option<String>,
    #[serde(default)]
    pub to_date: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub text_body: Option<String>,
    #[serde(default)]
    pub html_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quota {
    pub id: String,
    /// `count` or `octets`.
    pub resource_type: String,
    pub used: u64,
    pub hard_limit: u64,
    #[serde(default)]
    pub warn_limit: Option<u64>,
    #[serde(default)]
    pub soft_limit: Option<u64>,
    /// `account`, `domain` or `global`.
    pub scope: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Data types counted against the quota (e.g. `Email`, `SieveScript`).
    #[serde(default)]
    pub types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailAddress {
    #[serde(default)]
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub email: String,
    #[serde(default)]
    pub reply_to: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub bcc: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub text_signature: Option<String>,
    #[serde(default)]
    pub html_signature: Option<String>,
    #[serde(default)]
    pub may_delete: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct GetResponse<T> {
    list: Vec<T>,
}

pub fn get_args(account_id: &str, ids: Option<&[&str]>) -> Value {
    json!({ "accountId": account_id, "ids": ids })
}

pub fn vacation_set_args(account_id: &str, vacation: &VacationResponse) -> Value {
    json!({ "accountId": account_id, "update": { SINGLETON: vacation } })
}

/// The singleton from a `VacationResponse/get` response. Stalwart backs the
/// vacation response with a Sieve script; an account that never had one
/// reads as disabled with every property unset.
pub fn parse_vacation(response: Value) -> Result<VacationResponse, AppError> {
    let get: GetResponse<VacationResponse> = parse_args(VACATION_GET, response)?;
    Ok(get.list.into_iter().next().unwrap_or_default())
}

pub fn parse_quotas(response: Value) -> Result<Vec<Quota>, AppError> {
    Ok(parse_args::<GetResponse<Quota>>(QUOTA_GET, response)?.list)
}

pub fn parse_identities(response: Value) -> Result<Vec<Identity>, AppError> {
    Ok(parse_args::<GetResponse<Identity>>(IDENTITY_GET, response)?.list)
}

impl JmapClient {
    pub async fn get_vacation_response(&self) -> Result<VacationResponse, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(
                &[VACATION_CAPABILITY],
                VACATION_GET,
                get_args(raw.account_id(), Some(&[SINGLETON])),
            )
            .await?;
        parse_vacation(response)
    }

    /// Replace the whole vacation response and return what the server stored.
    pub async fn set_vacation_response(
        &self,
        vacation: &VacationResponse,
    ) -> Result<VacationResponse, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(
                &[VACATION_CAPABILITY],
                VACATION_SET,
                vacation_set_args(raw.account_id(), vacation),
            )
            .await?;
        let set: SetResponse = parse_args(VACATION_SET, response)?;
        set.updated_one(VACATION_SET, SINGLETON)?;
        self.get_vacation_response().await
    }

    /// All quotas of the account. Empty when the account has no disk quota.
    pub async fn list_quotas(&self) -> Result<Vec<Quota>, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(
                &[QUOTA_CAPABILITY],
                QUOTA_GET,
                get_args(raw.account_id(), None),
            )
            .await?;
        parse_quotas(response)
    }

    /// All sending identities of the account.
    pub async fn list_identities(&self) -> Result<Vec<Identity>, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(
                &[SUBMISSION_CAPABILITY],
                IDENTITY_GET,
                get_args(raw.account_id(), None),
            )
            .await?;
        parse_identities(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vacation_update_sends_every_property_including_nulls() {
        let vacation = VacationResponse {
            is_enabled: false,
            subject: Some("Away".into()),
            ..Default::default()
        };
        assert_eq!(
            vacation_set_args("a1", &vacation),
            json!({"accountId": "a1", "update": {"singleton": {
                "isEnabled": false,
                "fromDate": null,
                "toDate": null,
                "subject": "Away",
                "textBody": null,
                "htmlBody": null
            }}})
        );
    }

    #[test]
    fn vacation_get_asks_for_the_singleton() {
        assert_eq!(
            get_args("a1", Some(&["singleton"])),
            json!({"accountId": "a1", "ids": ["singleton"]})
        );
    }

    #[test]
    fn parses_vacation_and_defaults_when_absent() {
        let response = json!({"accountId": "a1", "state": "s", "list": [{
            "id": "singleton",
            "isEnabled": true,
            "fromDate": "2026-12-20T00:00:00Z",
            "toDate": null,
            "subject": "Out of office",
            "textBody": "Back in January.",
            "htmlBody": null
        }], "notFound": []});
        let vacation = parse_vacation(response).expect("vacation");
        assert!(vacation.is_enabled);
        assert_eq!(vacation.from_date.as_deref(), Some("2026-12-20T00:00:00Z"));
        assert_eq!(vacation.text_body.as_deref(), Some("Back in January."));

        let empty = json!({"accountId": "a1", "state": "s", "list": [], "notFound": []});
        assert_eq!(
            parse_vacation(empty).expect("empty"),
            VacationResponse::default()
        );
    }

    /// Captured from Stalwart 1.1.1: an account that never had a vacation response.
    #[test]
    fn parses_live_unset_vacation() {
        let response = json!({"accountId": "b", "list": [{"fromDate": null, "htmlBody": null,
            "id": "singleton", "isEnabled": false, "subject": null, "textBody": null,
            "toDate": null}], "notFound": [], "state": "n"});
        assert_eq!(
            parse_vacation(response).expect("vacation"),
            VacationResponse::default()
        );
    }

    /// Captured from Stalwart 1.1.1: an account without a disk quota has no Quota object.
    #[test]
    fn parses_live_empty_quota_list() {
        let response = json!({"accountId": "b", "list": [], "notFound": [], "state": "n"});
        assert!(parse_quotas(response).expect("quotas").is_empty());
    }

    /// Captured from Stalwart 1.1.1 (address and name replaced).
    #[test]
    fn parses_live_identity() {
        let response = json!({"accountId": "b", "list": [{"bcc": null, "email": "user@example.com",
            "htmlSignature": "", "id": "b", "mayDelete": true, "name": "Example User",
            "replyTo": null, "textSignature": ""}], "notFound": [], "state": "syapq"});
        let identities = parse_identities(response).expect("identities");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].id, "b");
        assert_eq!(identities[0].email, "user@example.com");
        assert!(identities[0].bcc.is_none());
        assert_eq!(identities[0].may_delete, Some(true));
    }

    /// Shape per RFC 9425 and Stalwart 1.1.1's `quota/get.rs` (not captured live:
    /// the test account has no disk quota).
    #[test]
    fn parses_quotas() {
        let response = json!({"accountId": "a1", "state": "s", "list": [{
            "id": "0",
            "resourceType": "octets",
            "used": 1024,
            "hardLimit": 1073741824,
            "warnLimit": null,
            "softLimit": null,
            "scope": "account",
            "name": "user@example.com",
            "description": null,
            "types": ["Email", "SieveScript"]
        }], "notFound": []});
        let quotas = parse_quotas(response).expect("quotas");
        assert_eq!(quotas.len(), 1);
        assert_eq!(quotas[0].used, 1024);
        assert_eq!(quotas[0].hard_limit, 1_073_741_824);
        assert_eq!(quotas[0].types, ["Email", "SieveScript"]);
    }

    #[test]
    fn parses_identities() {
        let response = json!({"accountId": "a1", "state": "s", "list": [{
            "id": "i1",
            "name": "Example User",
            "email": "user@example.com",
            "replyTo": null,
            "bcc": [{"name": null, "email": "archive@example.com"}],
            "textSignature": "",
            "htmlSignature": "",
            "mayDelete": true
        }], "notFound": []});
        let identities = parse_identities(response).expect("identities");
        assert_eq!(identities[0].email, "user@example.com");
        assert_eq!(identities[0].bcc.as_ref().map(Vec::len), Some(1));
        assert!(identities[0].reply_to.is_none());
    }
}

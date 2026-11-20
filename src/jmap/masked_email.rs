//! Stalwart masked email addresses (`x:MaskedEmail`, capability
//! `urn:stalwart:jmap`, Stalwart 1.1+).
//!
//! The server generates the address. A create may name a local-part prefix
//! (`emailPrefix`) and one of the account's own domains (`emailDomain`); both
//! are create-only inputs and are not stored. `expiresAt` can only be set on
//! create. Disabling is an update of `enable` to false. A per-account quota
//! (`maxMaskedAddresses`) makes a create fail with `overQuota`.

use crate::error::AppError;
use crate::jmap::JmapClient;
use crate::jmap::raw::{SetResponse, parse_args};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const STALWART_JMAP: &str = "urn:stalwart:jmap";
const GET: &str = "x:MaskedEmail/get";
const SET: &str = "x:MaskedEmail/set";
const CREATE_ID: &str = "k0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskedEmail {
    pub id: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Whether mail to the address is delivered. Server default: true.
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub for_domain: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Client-settable properties for a new masked address. `None` leaves the
/// property out of the request.
#[derive(Debug, Default)]
pub struct NewMaskedEmail<'a> {
    pub description: Option<&'a str>,
    pub for_domain: Option<&'a str>,
    pub url: Option<&'a str>,
    /// UTCDate, e.g. `2027-01-01T00:00:00Z`.
    pub expires_at: Option<&'a str>,
    /// Local-part prefix, 1 to 64 of `[A-Za-z0-9_]`, not starting with `_`.
    pub email_prefix: Option<&'a str>,
    /// One of the account's own domains.
    pub email_domain: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct GetResponse {
    list: Vec<MaskedEmail>,
    #[serde(default, rename = "notFound")]
    not_found: Vec<String>,
}

pub fn get_args(account_id: &str, ids: Option<&[String]>) -> Value {
    json!({ "accountId": account_id, "ids": ids })
}

pub fn create_args(account_id: &str, new: &NewMaskedEmail<'_>) -> Value {
    let mut object = Map::new();
    let fields = [
        ("description", new.description),
        ("forDomain", new.for_domain),
        ("url", new.url),
        ("expiresAt", new.expires_at),
        ("emailPrefix", new.email_prefix),
        ("emailDomain", new.email_domain),
    ];
    for (key, value) in fields {
        if let Some(value) = value {
            object.insert(key.to_string(), Value::from(value));
        }
    }
    json!({ "accountId": account_id, "create": { CREATE_ID: object } })
}

pub fn set_enable_args(account_id: &str, id: &str, enable: bool) -> Value {
    json!({ "accountId": account_id, "update": { id: { "enable": enable } } })
}

pub fn destroy_args(account_id: &str, id: &str) -> Value {
    json!({ "accountId": account_id, "destroy": [id] })
}

/// The id of the address created by [`create_args`].
pub fn parse_created_id(response: Value) -> Result<String, AppError> {
    let mut set: SetResponse = parse_args(SET, response)?;
    let created = set.created_one(SET, CREATE_ID)?;
    created
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AppError::JmapRequest(format!("{SET}: created without an id")))
}

fn parse_list(response: Value) -> Result<(Vec<MaskedEmail>, Vec<String>), AppError> {
    let get: GetResponse = parse_args(GET, response)?;
    Ok((get.list, get.not_found))
}

impl JmapClient {
    /// All masked addresses of the account.
    pub async fn list_masked_emails(&self) -> Result<Vec<MaskedEmail>, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(&[STALWART_JMAP], GET, get_args(raw.account_id(), None))
            .await?;
        Ok(parse_list(response)?.0)
    }

    /// One masked address by id.
    pub async fn get_masked_email(&self, id: &str) -> Result<MaskedEmail, AppError> {
        let raw = self.raw()?;
        let ids = [id.to_string()];
        let response = raw
            .call(
                &[STALWART_JMAP],
                GET,
                get_args(raw.account_id(), Some(&ids)),
            )
            .await?;
        parse_list(response)?
            .0
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Masked email {id} not found")))
    }

    /// Create a masked address and return it as the server stored it.
    pub async fn create_masked_email(
        &self,
        new: &NewMaskedEmail<'_>,
    ) -> Result<MaskedEmail, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(&[STALWART_JMAP], SET, create_args(raw.account_id(), new))
            .await?;
        let id = parse_created_id(response)?;
        self.get_masked_email(&id).await
    }

    /// Enable or disable delivery to a masked address; returns the stored object.
    pub async fn set_masked_email_enabled(
        &self,
        id: &str,
        enable: bool,
    ) -> Result<MaskedEmail, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(
                &[STALWART_JMAP],
                SET,
                set_enable_args(raw.account_id(), id, enable),
            )
            .await?;
        let set: SetResponse = parse_args(SET, response)?;
        set.updated_one(SET, id)?;
        self.get_masked_email(id).await
    }

    /// Permanently remove a masked address. Not exposed as a tool; used by the
    /// live tests to clean up after themselves.
    pub async fn destroy_masked_email(&self, id: &str) -> Result<(), AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(&[STALWART_JMAP], SET, destroy_args(raw.account_id(), id))
            .await?;
        let set: SetResponse = parse_args(SET, response)?;
        set.destroyed_one(SET, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_all_sends_null_ids() {
        assert_eq!(
            get_args("a1", None),
            json!({"accountId": "a1", "ids": null})
        );
        let ids = ["m1".to_string()];
        assert_eq!(get_args("a1", Some(&ids))["ids"], json!(["m1"]));
    }

    #[test]
    fn create_sends_only_given_properties() {
        let args = create_args(
            "a1",
            &NewMaskedEmail {
                description: Some("shop"),
                for_domain: Some("shop.example.com"),
                email_prefix: Some("shop_1"),
                ..Default::default()
            },
        );
        assert_eq!(
            args,
            json!({"accountId": "a1", "create": {"k0": {
                "description": "shop",
                "forDomain": "shop.example.com",
                "emailPrefix": "shop_1"
            }}})
        );
        assert_eq!(
            create_args("a1", &NewMaskedEmail::default())["create"]["k0"],
            json!({})
        );
    }

    #[test]
    fn disable_and_destroy_requests() {
        assert_eq!(
            set_enable_args("a1", "m1", false),
            json!({"accountId": "a1", "update": {"m1": {"enable": false}}})
        );
        assert_eq!(
            destroy_args("a1", "m1"),
            json!({"accountId": "a1", "destroy": ["m1"]})
        );
    }

    #[test]
    fn parses_get_response() {
        // Captured from Stalwart 1.1.1 (address, description and domain replaced).
        let response = json!({"accountId": "b", "list": [{"createdAt": "2026-11-20T10:53:08Z",
            "createdBy": null, "description": "stalwart-mcp integration test",
            "email": "abc123@example.com", "enable": true, "expiresAt": null,
            "forDomain": "example.com", "id": "jpndz3e1abaa", "url": null}],
            "notFound": ["m9"]});
        let (list, not_found) = parse_list(response).expect("list");
        assert_eq!(not_found, ["m9"]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "jpndz3e1abaa");
        assert_eq!(list[0].email.as_deref(), Some("abc123@example.com"));
        assert_eq!(list[0].enable, Some(true));
        assert_eq!(list[0].for_domain.as_deref(), Some("example.com"));
        assert_eq!(list[0].created_at.as_deref(), Some("2026-11-20T10:53:08Z"));

        let empty = json!({"accountId": "b", "list": [], "notFound": []});
        assert!(parse_list(empty).expect("empty").0.is_empty());
    }

    #[test]
    fn created_id_and_quota_rejection() {
        let ok =
            json!({"accountId": "a1", "created": {"k0": {"id": "m1", "email": "x@example.com"}}});
        assert_eq!(parse_created_id(ok).expect("id"), "m1");

        let quota = json!({"accountId": "a1", "notCreated": {"k0": {
            "type": "overQuota",
            "description": "You have exceeded your quota of 10 masked addresses."
        }}});
        let err = parse_created_id(quota).expect_err("quota");
        assert!(matches!(err, AppError::Rejected(_)));
        assert!(
            err.to_string().contains("quota of 10 masked addresses"),
            "{err}"
        );
    }
}

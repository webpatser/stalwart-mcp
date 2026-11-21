//! Sieve scripts over JMAP (RFC 9661, capability `urn:ietf:params:jmap:sieve`).
//!
//! Checked against Stalwart 1.1.1 (`crates/jmap/src/sieve/`):
//! - `SieveScript` has `id`, `name`, `blobId` and `isActive`; script content is
//!   a blob, read through the session's download URL and written through its
//!   upload URL.
//! - `SieveScript/validate` takes a `blobId` and answers `error: null` or a
//!   SetError of type `invalidScript` with the compiler message.
//! - `SieveScript/set` compiles the script again and refuses a broken one
//!   (`invalidScript`), a duplicate name (`alreadyExists`, case-insensitive),
//!   the reserved name `vacation` (`forbidden`) and destroying the active
//!   script (`scriptIsActive`). `onSuccessActivateScript` activates a script
//!   after a successful set; this module only sends it when asked to.

use crate::error::AppError;
use crate::jmap::JmapClient;
use crate::jmap::raw::{RawJmap, SetResponse, describe_error, parse_args};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const JMAP_SIEVE: &str = "urn:ietf:params:jmap:sieve";
const GET: &str = "SieveScript/get";
const SET: &str = "SieveScript/set";
const VALIDATE: &str = "SieveScript/validate";
const CREATE_ID: &str = "k0";
/// Media type of a Sieve script (RFC 5228 section 8.3).
pub const SIEVE_MEDIA_TYPE: &str = "application/sieve";
/// Script name the server manages for the vacation response.
pub const RESERVED_NAME: &str = "vacation";
/// Fixed `{name}` for script downloads; the server-provided script name never
/// enters the download URL.
const DOWNLOAD_NAME: &str = "script.sieve";

fn is_reserved(name: Option<&str>) -> bool {
    name.is_some_and(|n| n.eq_ignore_ascii_case(RESERVED_NAME))
}

/// Whether an update by id may replace the existing script, decided from the
/// target's current metadata before anything is uploaded. Refuses the
/// server-managed `vacation` script (it belongs to `mail_vacation_set`), a
/// rename to `vacation`, and replacing the active script without `activate`,
/// because that changes live filtering.
pub fn check_update_target(
    existing_name: Option<&str>,
    existing_is_active: bool,
    activate: bool,
    new_name: Option<&str>,
) -> Result<(), AppError> {
    if is_reserved(existing_name) {
        return Err(AppError::Refused(
            "the 'vacation' script is managed by the server for the vacation response; use mail_vacation_set".into(),
        ));
    }
    if is_reserved(new_name) {
        return Err(AppError::Refused(
            "the name 'vacation' is reserved for the vacation response".into(),
        ));
    }
    if existing_is_active && !activate {
        return Err(AppError::Refused(
            "this is the active script: replacing it changes live filtering immediately; repeat with 'activate: true' to confirm".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SieveScript {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub blob_id: String,
    #[serde(default)]
    pub is_active: bool,
}

/// A script with its content, as returned by [`JmapClient::get_sieve_script`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SieveScriptContent {
    #[serde(flatten)]
    pub script: SieveScript,
    pub content: String,
}

/// Outcome of `SieveScript/validate`: `error` holds the server's reason when
/// the script does not compile.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SieveValidation {
    pub valid: bool,
    pub error: Option<String>,
}

/// What [`JmapClient::put_sieve_script`] writes.
#[derive(Debug)]
pub struct SievePut<'a> {
    /// Existing script to replace; `None` creates a new one.
    pub id: Option<&'a str>,
    /// Name to set. Required for a create; `None` keeps the name on update.
    pub name: Option<&'a str>,
    pub content: &'a str,
    /// Activate the script after a successful set. Never implied.
    pub activate: bool,
}

#[derive(Debug, Deserialize)]
struct GetResponse {
    list: Vec<SieveScript>,
}

#[derive(Debug, Deserialize)]
struct ValidateResponse {
    #[serde(default)]
    error: Option<Value>,
}

pub fn get_args(account_id: &str, ids: Option<&[String]>) -> Value {
    json!({ "accountId": account_id, "ids": ids })
}

pub fn validate_args(account_id: &str, blob_id: &str) -> Value {
    json!({ "accountId": account_id, "blobId": blob_id })
}

/// `SieveScript/set` for a create (no `id`) or an update. Activation is only
/// requested when `activate` is true; deactivation is never requested.
pub fn put_args(
    account_id: &str,
    id: Option<&str>,
    name: Option<&str>,
    blob_id: &str,
    activate: bool,
) -> Value {
    let mut object = Map::new();
    if let Some(name) = name {
        object.insert("name".into(), Value::from(name));
    }
    object.insert("blobId".into(), Value::from(blob_id));
    let mut args = Map::new();
    args.insert("accountId".into(), Value::from(account_id));
    let target = match id {
        Some(id) => {
            args.insert("update".into(), json!({ id: object }));
            id.to_string()
        }
        None => {
            args.insert("create".into(), json!({ CREATE_ID: object }));
            format!("#{CREATE_ID}")
        }
    };
    if activate {
        args.insert("onSuccessActivateScript".into(), Value::from(target));
    }
    Value::Object(args)
}

pub fn destroy_args(account_id: &str, id: &str) -> Value {
    json!({ "accountId": account_id, "destroy": [id] })
}

fn parse_list(response: Value) -> Result<Vec<SieveScript>, AppError> {
    Ok(parse_args::<GetResponse>(GET, response)?.list)
}

pub fn parse_validation(response: Value) -> Result<SieveValidation, AppError> {
    let response: ValidateResponse = parse_args(VALIDATE, response)?;
    Ok(match response.error {
        None | Some(Value::Null) => SieveValidation {
            valid: true,
            error: None,
        },
        Some(err) => SieveValidation {
            valid: false,
            error: Some(describe_error(&err)),
        },
    })
}

/// The id written by [`put_args`]: the created id, or `id` after an update.
pub fn parse_put(response: Value, id: Option<&str>) -> Result<String, AppError> {
    let mut set: SetResponse = parse_args(SET, response)?;
    match id {
        Some(id) => {
            set.updated_one(SET, id)?;
            Ok(id.to_string())
        }
        None => set
            .created_one(SET, CREATE_ID)?
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| AppError::JmapRequest(format!("{SET}: created without an id"))),
    }
}

impl JmapClient {
    /// All Sieve scripts of the account (without content).
    pub async fn list_sieve_scripts(&self) -> Result<Vec<SieveScript>, AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(&[JMAP_SIEVE], GET, get_args(raw.account_id(), None))
            .await?;
        parse_list(response)
    }

    /// One script by id, without content.
    pub async fn get_sieve_script_meta(&self, id: &str) -> Result<SieveScript, AppError> {
        let raw = self.raw()?;
        let ids = [id.to_string()];
        let response = raw
            .call(&[JMAP_SIEVE], GET, get_args(raw.account_id(), Some(&ids)))
            .await?;
        parse_list(response)?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Sieve script {id} not found")))
    }

    /// One script by id with its content, downloaded from its blob.
    pub async fn get_sieve_script(&self, id: &str) -> Result<SieveScriptContent, AppError> {
        let script = self.get_sieve_script_meta(id).await?;
        let raw = self.raw()?;
        let bytes = raw
            .download(
                self.client.session().download_url(),
                &script.blob_id,
                SIEVE_MEDIA_TYPE,
                DOWNLOAD_NAME,
            )
            .await?;
        let content = String::from_utf8(bytes)
            .map_err(|_| AppError::JmapRequest(format!("Sieve script {id} is not valid UTF-8")))?;
        Ok(SieveScriptContent { script, content })
    }

    async fn upload_sieve(&self, raw: &RawJmap, content: &str) -> Result<String, AppError> {
        let uploaded = raw
            .upload(
                self.client.session().upload_url(),
                SIEVE_MEDIA_TYPE,
                content.as_bytes().to_vec(),
            )
            .await?;
        Ok(uploaded.blob_id)
    }

    async fn validate_blob(
        &self,
        raw: &RawJmap,
        blob_id: &str,
    ) -> Result<SieveValidation, AppError> {
        let response = raw
            .call(
                &[JMAP_SIEVE],
                VALIDATE,
                validate_args(raw.account_id(), blob_id),
            )
            .await?;
        parse_validation(response)
    }

    /// Upload `content` and let the server compile it. Stores no script.
    pub async fn validate_sieve_script(&self, content: &str) -> Result<SieveValidation, AppError> {
        let raw = self.raw()?;
        let blob_id = self.upload_sieve(&raw, content).await?;
        self.validate_blob(&raw, &blob_id).await
    }

    /// Validate, then create or replace a script. On replace the target is
    /// fetched first and checked with [`check_update_target`]; an unknown id is
    /// not found. A script the server does not accept is refused before
    /// `SieveScript/set`. Activates only when `put.activate` is true. Returns
    /// the stored script.
    pub async fn put_sieve_script(&self, put: &SievePut<'_>) -> Result<SieveScript, AppError> {
        if let Some(id) = put.id {
            let existing = self.get_sieve_script_meta(id).await?;
            check_update_target(
                existing.name.as_deref(),
                existing.is_active,
                put.activate,
                put.name,
            )?;
        }
        let raw = self.raw()?;
        let blob_id = self.upload_sieve(&raw, put.content).await?;
        let validation = self.validate_blob(&raw, &blob_id).await?;
        if !validation.valid {
            return Err(AppError::Rejected(format!(
                "{VALIDATE}: {}",
                validation.error.as_deref().unwrap_or("invalidScript")
            )));
        }
        let response = raw
            .call(
                &[JMAP_SIEVE],
                SET,
                put_args(raw.account_id(), put.id, put.name, &blob_id, put.activate),
            )
            .await?;
        let id = parse_put(response, put.id)?;
        self.get_sieve_script_meta(&id).await
    }

    /// Permanently remove a script. Not exposed as a tool; used by the live
    /// tests to clean up after themselves. The server refuses the active one.
    pub async fn destroy_sieve_script(&self, id: &str) -> Result<(), AppError> {
        let raw = self.raw()?;
        let response = raw
            .call(&[JMAP_SIEVE], SET, destroy_args(raw.account_id(), id))
            .await?;
        let set: SetResponse = parse_args(SET, response)?;
        set.destroyed_one(SET, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_sends_null_or_given_ids() {
        assert_eq!(
            get_args("a1", None),
            json!({"accountId": "a1", "ids": null})
        );
        let ids = ["s1".to_string()];
        assert_eq!(get_args("a1", Some(&ids))["ids"], json!(["s1"]));
    }

    #[test]
    fn create_never_activates_unless_asked() {
        let args = put_args("a1", None, Some("filters"), "b1", false);
        assert_eq!(
            args,
            json!({"accountId": "a1", "create": {"k0": {"name": "filters", "blobId": "b1"}}})
        );
        assert!(args.get("onSuccessActivateScript").is_none());
        assert!(args.get("onSuccessDeactivateScript").is_none());

        let args = put_args("a1", None, Some("filters"), "b1", true);
        assert_eq!(args["onSuccessActivateScript"], json!("#k0"));
    }

    #[test]
    fn update_replaces_the_blob_and_keeps_the_name_when_omitted() {
        let args = put_args("a1", Some("s1"), None, "b2", false);
        assert_eq!(
            args,
            json!({"accountId": "a1", "update": {"s1": {"blobId": "b2"}}})
        );
        let args = put_args("a1", Some("s1"), Some("n"), "b2", true);
        assert_eq!(args["update"]["s1"]["name"], json!("n"));
        assert_eq!(args["onSuccessActivateScript"], json!("s1"));
        assert!(args.get("onSuccessDeactivateScript").is_none());
    }

    #[test]
    fn destroy_request() {
        assert_eq!(
            destroy_args("a1", "s1"),
            json!({"accountId": "a1", "destroy": ["s1"]})
        );
    }

    #[test]
    fn parses_get_response() {
        // Shape of a Stalwart 1.1.1 answer (ids and names replaced).
        let response = json!({"accountId": "b", "state": "s0", "list": [
            {"id": "a", "name": "<redacted>", "blobId": "bl1", "isActive": true},
            {"id": "b", "name": null, "blobId": "bl2", "isActive": false}
        ], "notFound": []});
        let list = parse_list(response).expect("list");
        assert_eq!(list.len(), 2);
        assert!(list[0].is_active);
        assert_eq!(list[1].name, None);
        assert_eq!(list[1].blob_id, "bl2");
    }

    #[test]
    fn validation_outcomes() {
        assert_eq!(
            parse_validation(json!({"accountId": "a1", "error": null})).expect("ok"),
            SieveValidation {
                valid: true,
                error: None
            }
        );
        let invalid = parse_validation(json!({"accountId": "a1", "error": {
            "type": "invalidScript", "description": "unexpected token"
        }}))
        .expect("invalid");
        assert!(!invalid.valid);
        assert_eq!(
            invalid.error.as_deref(),
            Some("invalidScript: unexpected token")
        );
    }

    fn rejected(result: Result<(), AppError>, needle: &str) -> bool {
        matches!(result, Err(AppError::Refused(ref m)) if m.contains(needle))
    }

    #[test]
    fn update_of_an_inactive_script_is_allowed() {
        assert!(check_update_target(Some("filters"), false, false, None).is_ok());
        assert!(check_update_target(Some("filters"), false, true, Some("other")).is_ok());
        assert!(check_update_target(None, false, false, None).is_ok());
    }

    #[test]
    fn update_of_the_vacation_script_is_refused() {
        for name in ["vacation", "Vacation", "VACATION"] {
            for (active, activate) in [(false, false), (true, true), (false, true)] {
                assert!(
                    rejected(
                        check_update_target(Some(name), active, activate, None),
                        "mail_vacation_set"
                    ),
                    "{name} {active} {activate}"
                );
            }
        }
    }

    #[test]
    fn rename_to_vacation_is_refused() {
        assert!(rejected(
            check_update_target(Some("filters"), false, false, Some("Vacation")),
            "reserved"
        ));
    }

    #[test]
    fn update_of_the_active_script_needs_activate() {
        assert!(rejected(
            check_update_target(Some("filters"), true, false, None),
            "activate: true"
        ));
        assert!(check_update_target(Some("filters"), true, true, None).is_ok());
    }

    #[test]
    fn put_outcomes() {
        let created = json!({"accountId": "a1", "created": {"k0": {"id": "s9"}}});
        assert_eq!(parse_put(created, None).expect("created"), "s9");
        let updated = json!({"accountId": "a1", "updated": {"s1": null}});
        assert_eq!(parse_put(updated, Some("s1")).expect("updated"), "s1");
        let reserved = json!({"accountId": "a1", "notCreated": {"k0": {
            "type": "forbidden", "description": "The 'vacation' name is reserved"
        }}});
        assert!(matches!(
            parse_put(reserved, None),
            Err(AppError::Rejected(_))
        ));
    }
}

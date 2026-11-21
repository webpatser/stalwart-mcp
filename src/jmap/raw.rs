//! Untyped JMAP method calls for objects jmap-client 0.4 does not model, or
//! models in a way that cannot express what a tool needs (for example setting
//! a VacationResponse property back to `null`).
//!
//! One call per request, call id `c0`. Server refusals (a method-level
//! `error` response, a SetError, or an HTTP problem document) become
//! [`AppError::Rejected`] with the server's own reason; transport and parse
//! failures stay [`AppError::JmapRequest`].

use crate::error::AppError;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

pub const JMAP_CORE: &str = "urn:ietf:params:jmap:core";
const CALL_ID: &str = "c0";

/// Largest JMAP response body read into memory (8 MB).
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Shares the account's JMAP API URL and Basic-auth headers.
#[derive(Clone)]
pub struct RawJmap {
    http: reqwest::Client,
    api_url: String,
    account_id: String,
}

/// Prints no HTTP client: its default headers carry the account credentials.
impl std::fmt::Debug for RawJmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawJmap")
            .field("api_url", &self.api_url)
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// Reject a declared `Content-Length` above [`MAX_RESPONSE_BYTES`].
fn check_content_length(method: &str, length: Option<u64>) -> Result<(), AppError> {
    match length {
        Some(n) if n > MAX_RESPONSE_BYTES as u64 => Err(too_large(method)),
        _ => Ok(()),
    }
}

/// Append `chunk` to `body` unless that takes it past [`MAX_RESPONSE_BYTES`].
fn push_capped(method: &str, body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), AppError> {
    if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
        return Err(too_large(method));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

fn too_large(method: &str) -> AppError {
    AppError::JmapRequest(format!(
        "{method} response exceeds {MAX_RESPONSE_BYTES} bytes"
    ))
}

/// Read a response body in chunks, failing once it exceeds [`MAX_RESPONSE_BYTES`].
pub(crate) async fn read_body_capped(
    method: &str,
    mut response: reqwest::Response,
) -> Result<Vec<u8>, AppError> {
    check_content_length(method, response.content_length())?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| AppError::JmapRequest(format!("{method} response body failed: {e}")))?
    {
        push_capped(method, &mut body, &chunk)?;
    }
    Ok(body)
}

impl RawJmap {
    pub(crate) fn new(http: reqwest::Client, api_url: String, account_id: String) -> Self {
        Self {
            http,
            api_url,
            account_id,
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Send one method call and return its response arguments.
    pub async fn call(
        &self,
        capabilities: &[&str],
        method: &str,
        args: Value,
    ) -> Result<Value, AppError> {
        let request = build_request(capabilities, method, args);
        let response = self
            .http
            .post(&self.api_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::JmapRequest(format!("{method} request failed: {e}")))?;
        let status = response.status();
        let body = read_body_capped(method, response).await?;
        if !status.is_success() {
            return Err(http_error(
                method,
                status.as_u16(),
                &String::from_utf8_lossy(&body),
            ));
        }
        let body: Value = serde_json::from_slice(&body)
            .map_err(|e| AppError::JmapRequest(format!("{method} returned invalid JSON: {e}")))?;
        parse_response(method, body)
    }

    /// Upload `body` to the session's `uploadUrl` template (RFC 8620 section
    /// 6.1). The URL must sit on the API URL's origin; redirects are never
    /// followed, because the client is built with `Policy::none()`.
    pub async fn upload(
        &self,
        upload_template: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<UploadedBlob, AppError> {
        const WHAT: &str = "Blob upload";
        let url = expand_template(upload_template, &[("accountId", &self.account_id)])?;
        let url = same_origin_url(&self.api_url, &url, WHAT)?;
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::JmapRequest(format!("{WHAT} failed: {e}")))?;
        let status = response.status();
        let body = read_body_capped(WHAT, response).await?;
        if !status.is_success() {
            return Err(http_error(
                WHAT,
                status.as_u16(),
                &String::from_utf8_lossy(&body),
            ));
        }
        let uploaded: UploadedBlob = serde_json::from_slice(&body)
            .map_err(|e| AppError::JmapRequest(format!("{WHAT} returned invalid JSON: {e}")))?;
        if uploaded.blob_id.is_empty() {
            return Err(AppError::JmapRequest(format!("{WHAT} returned no blobId")));
        }
        Ok(uploaded)
    }

    /// Download a blob through the session's `downloadUrl` template, read up
    /// to [`MAX_RESPONSE_BYTES`]. Same origin rule and no redirects, as
    /// [`Self::upload`].
    pub async fn download(
        &self,
        download_template: &str,
        blob_id: &str,
        content_type: &str,
        name: &str,
    ) -> Result<Vec<u8>, AppError> {
        const WHAT: &str = "Blob download";
        let url = expand_template(
            download_template,
            &[
                ("accountId", &self.account_id),
                ("blobId", blob_id),
                ("type", content_type),
                ("name", name),
            ],
        )?;
        let url = same_origin_url(&self.api_url, &url, WHAT)?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::JmapRequest(format!("{WHAT} failed: {e}")))?;
        let status = response.status();
        let body = read_body_capped(WHAT, response).await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::NotFound(format!("Blob {blob_id} not found")));
        }
        if !status.is_success() {
            return Err(http_error(
                WHAT,
                status.as_u16(),
                &String::from_utf8_lossy(&body),
            ));
        }
        Ok(body)
    }

    /// [`Self::call`] and deserialize the response arguments into `T`.
    pub async fn call_as<T: DeserializeOwned>(
        &self,
        capabilities: &[&str],
        method: &str,
        args: Value,
    ) -> Result<T, AppError> {
        let value = self.call(capabilities, method, args).await?;
        parse_args(method, value)
    }
}

/// The upload endpoint's answer (RFC 8620 section 6.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadedBlob {
    pub blob_id: String,
    #[serde(default)]
    pub size: u64,
}

/// Percent-encode everything except RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Fill the `{variable}`s of a session URL template (RFC 6570 level 1),
/// percent-encoding each value (`%` included, so an encoded `%2e` stays
/// literal). A value made only of dots is refused: as a path segment it would
/// be resolved as `.` or `..` and move the URL to another path.
pub fn expand_template(template: &str, vars: &[(&str, &str)]) -> Result<String, AppError> {
    let mut url = template.to_string();
    for (name, value) in vars {
        if !value.is_empty() && value.bytes().all(|b| b == b'.') {
            return Err(AppError::JmapRequest(format!(
                "URL template value for {name} consists only of dots"
            )));
        }
        url = url.replace(&format!("{{{name}}}"), &percent_encode(value));
    }
    Ok(url)
}

/// Resolve `candidate` against the API URL and require the same scheme, host
/// and port and no user information, so credentials never go to another
/// origin and the URL cannot carry its own.
pub fn same_origin_url(api_url: &str, candidate: &str, what: &str) -> Result<url::Url, AppError> {
    let base = url::Url::parse(api_url)
        .map_err(|e| AppError::JmapRequest(format!("{what}: invalid API URL: {e}")))?;
    let target = base
        .join(candidate)
        .map_err(|e| AppError::JmapRequest(format!("{what}: invalid session URL: {e}")))?;
    let web = matches!(target.scheme(), "http" | "https");
    if !web || target.origin() != base.origin() {
        return Err(AppError::JmapRequest(format!(
            "{what}: session URL is not on the JMAP API origin"
        )));
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err(AppError::JmapRequest(format!(
            "{what}: session URL must not carry a username or password"
        )));
    }
    Ok(target)
}

/// Build a single-call JMAP request. `urn:ietf:params:jmap:core` is always used.
pub fn build_request(capabilities: &[&str], method: &str, args: Value) -> Value {
    let mut using = vec![JMAP_CORE];
    for capability in capabilities {
        if !using.contains(capability) {
            using.push(capability);
        }
    }
    json!({
        "using": using,
        "methodCalls": [[method, args, CALL_ID]],
    })
}

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "methodResponses")]
    method_responses: Vec<(String, Value, String)>,
}

/// Extract the response arguments of the single call in `body`.
pub fn parse_response(method: &str, body: Value) -> Result<Value, AppError> {
    let envelope: Envelope = serde_json::from_value(body)
        .map_err(|e| AppError::JmapRequest(format!("{method} returned no methodResponses: {e}")))?;
    let (name, args, _) = envelope
        .method_responses
        .into_iter()
        .next()
        .ok_or_else(|| AppError::JmapRequest(format!("{method}: empty methodResponses")))?;
    if name == "error" {
        return Err(AppError::Rejected(format!(
            "{method}: {}",
            describe_error(&args)
        )));
    }
    if name != method {
        return Err(AppError::JmapRequest(format!(
            "{method}: unexpected response {name}"
        )));
    }
    Ok(args)
}

pub fn parse_args<T: DeserializeOwned>(method: &str, value: Value) -> Result<T, AppError> {
    serde_json::from_value(value)
        .map_err(|e| AppError::JmapRequest(format!("{method}: unexpected response shape: {e}")))
}

/// `type: description (properties: a, b)` of a JMAP method error or SetError.
pub fn describe_error(err: &Value) -> String {
    let kind = err
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown error");
    let mut text = match err.get("description").and_then(Value::as_str) {
        Some(description) if !description.is_empty() => format!("{kind}: {description}"),
        _ => kind.to_string(),
    };
    if let Some(properties) = err.get("properties").and_then(Value::as_array) {
        let names: Vec<&str> = properties.iter().filter_map(Value::as_str).collect();
        if !names.is_empty() {
            text.push_str(&format!(" (properties: {})", names.join(", ")));
        }
    }
    text
}

/// A non-2xx answer. A JMAP problem document (RFC 8620 section 3.6.1, for
/// example an unknown capability) is a server refusal and keeps its detail.
fn http_error(method: &str, status: u16, body: &str) -> AppError {
    let problem: Option<Value> = serde_json::from_str(body).ok();
    let detail = problem.as_ref().and_then(|p| {
        ["detail", "title", "type"]
            .iter()
            .find_map(|key| p.get(*key).and_then(Value::as_str))
            .map(str::to_string)
    });
    match detail {
        Some(detail) if (400..500).contains(&status) => {
            AppError::Rejected(format!("{method}: HTTP {status}: {detail}"))
        }
        _ => AppError::JmapRequest(format!("{method} returned HTTP {status}")),
    }
}

/// The `/set` response fields a tool needs to judge one object's outcome.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetResponse {
    #[serde(default)]
    pub created: Option<Map<String, Value>>,
    #[serde(default)]
    pub updated: Option<Map<String, Value>>,
    #[serde(default)]
    pub destroyed: Option<Vec<String>>,
    #[serde(default)]
    pub not_created: Option<Map<String, Value>>,
    #[serde(default)]
    pub not_updated: Option<Map<String, Value>>,
    #[serde(default)]
    pub not_destroyed: Option<Map<String, Value>>,
}

impl SetResponse {
    fn rejection(method: &str, verb: &str, key: &str, err: &Value) -> AppError {
        AppError::Rejected(format!("{method} {verb} {key}: {}", describe_error(err)))
    }

    /// The server-set properties of the created object (always including `id`).
    pub fn created_one(&mut self, method: &str, create_id: &str) -> Result<Value, AppError> {
        if let Some(err) = self.not_created.as_ref().and_then(|m| m.get(create_id)) {
            return Err(Self::rejection(method, "create", create_id, err));
        }
        let created = self
            .created
            .as_mut()
            .and_then(|m| m.remove(create_id))
            .ok_or_else(|| {
                AppError::JmapRequest(format!("{method}: server did not report {create_id}"))
            })?;
        match created.get("id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => Ok(created),
            _ => Err(AppError::JmapRequest(format!(
                "{method}: created {create_id} without an id"
            ))),
        }
    }

    pub fn updated_one(&self, method: &str, id: &str) -> Result<(), AppError> {
        if let Some(err) = self.not_updated.as_ref().and_then(|m| m.get(id)) {
            return Err(Self::rejection(method, "update", id, err));
        }
        if self.updated.as_ref().is_some_and(|m| m.contains_key(id)) {
            Ok(())
        } else {
            Err(AppError::JmapRequest(format!(
                "{method}: server did not report the update of {id}"
            )))
        }
    }

    pub fn destroyed_one(&self, method: &str, id: &str) -> Result<(), AppError> {
        if let Some(err) = self.not_destroyed.as_ref().and_then(|m| m.get(id)) {
            return Err(Self::rejection(method, "destroy", id, err));
        }
        if self
            .destroyed
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|d| d == id))
        {
            Ok(())
        } else {
            Err(AppError::JmapRequest(format!(
                "{method}: server did not report the destroy of {id}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(value: Value) -> SetResponse {
        serde_json::from_value(value).expect("set response")
    }

    #[test]
    fn request_always_uses_core_once() {
        let request = build_request(
            &["urn:stalwart:jmap", JMAP_CORE],
            "x:MaskedEmail/get",
            json!({"accountId": "a"}),
        );
        assert_eq!(
            request["using"],
            json!(["urn:ietf:params:jmap:core", "urn:stalwart:jmap"])
        );
        assert_eq!(
            request["methodCalls"],
            json!([["x:MaskedEmail/get", {"accountId": "a"}, "c0"]])
        );
    }

    #[test]
    fn method_error_is_a_rejection_with_the_server_reason() {
        let body = json!({"methodResponses": [["error", {"type": "unknownMethod", "description": "nope"}, "c0"]]});
        let err = parse_response("x:MaskedEmail/get", body).expect_err("error");
        assert!(matches!(err, AppError::Rejected(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "Rejected by the server: x:MaskedEmail/get: unknownMethod: nope"
        );
    }

    #[test]
    fn unexpected_method_name_is_an_error() {
        let body = json!({"methodResponses": [["Other/get", {}, "c0"]]});
        assert!(parse_response("Quota/get", body).is_err());
    }

    #[test]
    fn describe_error_lists_properties() {
        let err = json!({"type": "invalidProperties", "properties": ["email", "url"]});
        assert_eq!(
            describe_error(&err),
            "invalidProperties (properties: email, url)"
        );
    }

    #[test]
    fn problem_document_is_a_rejection() {
        let body = r#"{"type":"urn:ietf:params:jmap:error:unknownCapability","status":400,"detail":"Unknown capability"}"#;
        let err = http_error("Quota/get", 400, body);
        assert!(matches!(err, AppError::Rejected(ref m) if m.contains("Unknown capability")));
        assert!(matches!(
            http_error("Quota/get", 502, "bad gateway"),
            AppError::JmapRequest(_)
        ));
    }

    #[test]
    fn oversized_responses_are_opaque_errors() {
        assert!(check_content_length("M/get", None).is_ok());
        assert!(check_content_length("M/get", Some(MAX_RESPONSE_BYTES as u64)).is_ok());
        assert!(matches!(
            check_content_length("M/get", Some(MAX_RESPONSE_BYTES as u64 + 1)),
            Err(AppError::JmapRequest(_))
        ));

        let mut body = vec![0u8; MAX_RESPONSE_BYTES - 1];
        assert!(push_capped("M/get", &mut body, b"x").is_ok());
        assert_eq!(body.len(), MAX_RESPONSE_BYTES);
        assert!(matches!(
            push_capped("M/get", &mut body, b"y"),
            Err(AppError::JmapRequest(_))
        ));
        assert_eq!(body.len(), MAX_RESPONSE_BYTES);
    }

    #[test]
    fn debug_does_not_print_credentials() {
        let headers = crate::jmap::api_headers(&reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Basic c2VjcmV0LWNyZWRlbnRpYWw="),
        )]));
        assert!(headers[reqwest::header::AUTHORIZATION].is_sensitive());
        let http = crate::jmap::api_http_client(headers).expect("client");
        let raw = RawJmap::new(http, "https://mail.example.com/jmap".into(), "a1".into());
        let debug = format!("{raw:?}");
        assert!(!debug.contains("c2VjcmV0"), "{debug}");
        assert!(!debug.to_lowercase().contains("authorization"), "{debug}");
        assert!(debug.contains("a1"), "{debug}");
    }

    #[test]
    fn templates_are_expanded_and_encoded() {
        let url = expand_template(
            "https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
            &[
                ("accountId", "a1"),
                ("blobId", "b/2"),
                ("name", "my script"),
                ("type", "application/sieve"),
            ],
        )
        .expect("expanded");
        assert_eq!(
            url,
            "https://mail.example.com/jmap/download/a1/b%2F2/my%20script?accept=application%2Fsieve"
        );
    }

    #[test]
    fn template_values_of_only_dots_are_refused() {
        let template = "https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}";
        for bad in [".", "..", "...."] {
            assert!(
                matches!(
                    expand_template(template, &[("accountId", "a1"), ("blobId", bad)]),
                    Err(AppError::JmapRequest(_))
                ),
                "{bad}"
            );
        }
        let url = expand_template(template, &[("name", "a..b"), ("blobId", ".b")])
            .expect("dots with other characters");
        assert!(url.ends_with("/.b/a..b"), "{url}");
    }

    #[test]
    fn template_values_encode_percent_itself() {
        let url = expand_template("https://h/d/{name}", &[("name", "%2e%2E")]).expect("expanded");
        assert_eq!(url, "https://h/d/%252e%252E");
    }

    #[test]
    fn session_urls_must_stay_on_the_api_origin() {
        let api = "https://mail.example.com/jmap/";
        assert!(same_origin_url(api, "https://mail.example.com/jmap/upload/a1/", "u").is_ok());
        assert!(same_origin_url(api, "https://mail.example.com:443/x", "u").is_ok());
        assert_eq!(
            same_origin_url(api, "/jmap/upload/a1/", "u")
                .expect("relative")
                .as_str(),
            "https://mail.example.com/jmap/upload/a1/"
        );
        for bad in [
            "http://mail.example.com/jmap/upload/a1/",
            "https://mail.example.com:8443/jmap/upload/a1/",
            "https://evil.example.com/jmap/upload/a1/",
            "https://mail.example.com.evil.test/",
            "//evil.example.com/x",
            "file:///etc/passwd",
            "https://user:pw@mail.example.com/",
            "https://user@mail.example.com/",
            "https://:pw@mail.example.com/",
        ] {
            assert!(
                matches!(
                    same_origin_url(api, bad, "u"),
                    Err(AppError::JmapRequest(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn upload_response_parses() {
        let blob: UploadedBlob = serde_json::from_value(json!({
            "accountId": "a1", "blobId": "b1", "type": "application/sieve", "size": 42
        }))
        .expect("upload");
        assert_eq!(blob.blob_id, "b1");
        assert_eq!(blob.size, 42);
    }

    #[test]
    fn set_outcomes_surface_rejections() {
        let mut response = set(json!({
            "created": {"k0": {"id": "m1", "email": "x@example.com"}},
            "updated": {"m2": null},
            "destroyed": ["m3"],
            "notCreated": {"k1": {"type": "overQuota", "description": "limit reached"}},
            "notUpdated": {"m4": {"type": "notFound"}},
            "notDestroyed": {"m5": {"type": "forbidden"}}
        }));
        assert_eq!(
            response.created_one("M/set", "k0").expect("created")["id"],
            "m1"
        );
        let err = response.created_one("M/set", "k1").expect_err("quota");
        assert_eq!(
            err.to_string(),
            "Rejected by the server: M/set create k1: overQuota: limit reached"
        );
        assert!(response.updated_one("M/set", "m2").is_ok());
        assert!(matches!(
            response.updated_one("M/set", "m4"),
            Err(AppError::Rejected(_))
        ));
        assert!(response.destroyed_one("M/set", "m3").is_ok());
        assert!(matches!(
            response.destroyed_one("M/set", "m5"),
            Err(AppError::Rejected(_))
        ));
        assert!(matches!(
            response.destroyed_one("M/set", "m9"),
            Err(AppError::JmapRequest(_))
        ));
    }
}

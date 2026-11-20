use crate::error::AppError;
use crate::jmap::raw::read_body_capped;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const STALWART_JMAP_CAPABILITY: &str = "urn:stalwart:jmap";
const JMAP_CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";
const SPAM_TRAINING_SET: &str = "SpamTrainingSample/set";

/// Client for Stalwart v0.16's JMAP `SpamTrainingSample/set` method.
///
/// Training runs under the user's own account credentials: no admin auth required.
/// The server downloads the referenced email blob, parses it, and stores it as
/// a training sample for the Bayes classifier.
#[derive(Clone)]
pub struct SpamFilterClient {
    pub(crate) http: Client,
    pub(crate) api_url: String,
    pub(crate) account_id: String,
}

/// Prints no HTTP client: its default headers carry the account credentials.
impl std::fmt::Debug for SpamFilterClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpamFilterClient")
            .field("api_url", &self.api_url)
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
pub struct TrainResult {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
}

impl SpamFilterClient {
    /// Submit a batch of email blob IDs to the Bayes classifier in a single JMAP call.
    pub async fn train_batch(
        &self,
        blob_ids: &[String],
        is_spam: bool,
    ) -> Result<TrainResult, AppError> {
        if blob_ids.is_empty() {
            return Ok(TrainResult {
                total: 0,
                success: 0,
                failed: 0,
            });
        }

        let mut create = serde_json::Map::with_capacity(blob_ids.len());
        for (i, blob_id) in blob_ids.iter().enumerate() {
            create.insert(
                format!("s{i}"),
                serde_json::json!({
                    "blobId": blob_id,
                    "isSpam": is_spam,
                }),
            );
        }

        let request = serde_json::json!({
            "using": [JMAP_CORE_CAPABILITY, STALWART_JMAP_CAPABILITY],
            "methodCalls": [[
                "SpamTrainingSample/set",
                {
                    "accountId": self.account_id,
                    "create": create,
                },
                "c0",
            ]],
        });

        let response = self
            .http
            .post(&self.api_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                AppError::JmapRequest(format!("SpamTrainingSample/set request failed: {e}"))
            })?;

        let status = response.status();
        let body = read_body_capped(SPAM_TRAINING_SET, response).await?;

        if !status.is_success() {
            return Err(AppError::JmapRequest(format!(
                "SpamTrainingSample/set returned {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }

        let body: JmapResponse = serde_json::from_slice(&body).map_err(|e| {
            AppError::JmapRequest(format!(
                "Invalid JSON response from SpamTrainingSample/set: {e}"
            ))
        })?;

        let MethodCall(name, value, _) = body
            .method_responses
            .into_iter()
            .next()
            .ok_or_else(|| AppError::JmapRequest("Empty methodResponses array".into()))?;

        if name == "error" {
            return Err(AppError::JmapRequest(format!(
                "JMAP request-level error: {value}"
            )));
        }

        let set_response: SetResponse = serde_json::from_value(value).map_err(|e| {
            AppError::JmapRequest(format!(
                "Failed to parse SpamTrainingSample/set response: {e}"
            ))
        })?;

        let success = set_response.created.as_ref().map_or(0, HashMap::len);
        let failed = set_response.not_created.as_ref().map_or(0, HashMap::len);

        if let Some(not_created) = &set_response.not_created {
            for (create_id, err) in not_created {
                tracing::warn!(
                    create_id = %create_id,
                    error = ?err,
                    "SpamTrainingSample creation failed"
                );
            }
        }

        Ok(TrainResult {
            total: blob_ids.len(),
            success,
            failed,
        })
    }
}

#[derive(Debug, Deserialize)]
struct JmapResponse {
    #[serde(rename = "methodResponses")]
    method_responses: Vec<MethodCall>,
}

#[derive(Debug, Deserialize)]
struct MethodCall(String, serde_json::Value, #[allow(dead_code)] String);

#[derive(Debug, Deserialize)]
struct SetResponse {
    #[serde(default)]
    created: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "notCreated", default)]
    not_created: Option<HashMap<String, serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_credentials() {
        let headers = crate::jmap::api_headers(&reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Basic c2VjcmV0LWNyZWRlbnRpYWw="),
        )]));
        let client = SpamFilterClient {
            http: crate::jmap::api_http_client(headers).expect("client"),
            api_url: "https://mail.example.com/jmap".into(),
            account_id: "a1".into(),
        };
        let debug = format!("{client:?}");
        assert!(!debug.contains("c2VjcmV0"), "{debug}");
        assert!(!debug.to_lowercase().contains("authorization"), "{debug}");
    }

    #[test]
    fn train_request_has_expected_shape() {
        let blob_ids = ["blob1".to_string(), "blob2".to_string()];
        let is_spam = true;

        let mut create = serde_json::Map::with_capacity(blob_ids.len());
        for (i, blob_id) in blob_ids.iter().enumerate() {
            create.insert(
                format!("s{i}"),
                serde_json::json!({
                    "blobId": blob_id,
                    "isSpam": is_spam,
                }),
            );
        }

        let request = serde_json::json!({
            "using": [JMAP_CORE_CAPABILITY, STALWART_JMAP_CAPABILITY],
            "methodCalls": [[
                "SpamTrainingSample/set",
                { "accountId": "acct-1", "create": create },
                "c0",
            ]],
        });

        let using = request["using"].as_array().unwrap();
        assert_eq!(using[0], "urn:ietf:params:jmap:core");
        assert_eq!(using[1], "urn:stalwart:jmap");

        let call = &request["methodCalls"][0];
        assert_eq!(call[0], "SpamTrainingSample/set");
        assert_eq!(call[1]["accountId"], "acct-1");
        assert_eq!(call[1]["create"]["s0"]["blobId"], "blob1");
        assert_eq!(call[1]["create"]["s0"]["isSpam"], true);
        assert_eq!(call[1]["create"]["s1"]["blobId"], "blob2");
    }

    #[test]
    fn parses_set_response_with_created_and_not_created() {
        let json = serde_json::json!({
            "methodResponses": [[
                "SpamTrainingSample/set",
                {
                    "accountId": "acct-1",
                    "created": { "s0": { "id": "sample-1" } },
                    "notCreated": {
                        "s1": { "type": "invalidProperties", "properties": ["blobId"] }
                    }
                },
                "c0"
            ]]
        });

        let body: JmapResponse = serde_json::from_value(json).unwrap();
        let MethodCall(name, value, call_id) = body.method_responses.into_iter().next().unwrap();
        assert_eq!(name, "SpamTrainingSample/set");
        assert_eq!(call_id, "c0");

        let set: SetResponse = serde_json::from_value(value).unwrap();
        assert_eq!(set.created.unwrap().len(), 1);
        assert_eq!(set.not_created.unwrap().len(), 1);
    }

    #[test]
    fn parses_set_response_without_not_created_field() {
        let json = serde_json::json!({
            "methodResponses": [[
                "SpamTrainingSample/set",
                {
                    "accountId": "acct-1",
                    "created": { "s0": { "id": "sample-1" } }
                },
                "c0"
            ]]
        });

        let body: JmapResponse = serde_json::from_value(json).unwrap();
        let MethodCall(_, value, _) = body.method_responses.into_iter().next().unwrap();
        let set: SetResponse = serde_json::from_value(value).unwrap();
        assert_eq!(set.created.unwrap().len(), 1);
        assert!(set.not_created.is_none());
    }
}

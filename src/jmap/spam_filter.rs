use crate::error::AppError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const STALWART_JMAP_CAPABILITY: &str = "urn:stalwart:jmap";
const JMAP_CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";

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

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "no body".to_string());
            return Err(AppError::JmapRequest(format!(
                "SpamTrainingSample/set returned {status}: {body}"
            )));
        }

        let body: JmapResponse = response.json().await.map_err(|e| {
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

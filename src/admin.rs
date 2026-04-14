use crate::config::AdminApiConfig;
use crate::error::AppError;
use reqwest::Client;
use serde::Serialize;

#[derive(Clone)]
pub struct AdminClient {
    client: Client,
    base_url: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct TrainResult {
    pub total: usize,
    pub success: usize,
    pub failed: usize,
}

impl AdminClient {
    pub fn new(base_url: &str, config: &AdminApiConfig) -> Result<Self, AppError> {
        let password = config.password()?;

        // Strip trailing slash from base URL
        let base_url = base_url.trim_end_matches('/').to_string();

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Config(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            base_url,
            username: config.username.clone(),
            password,
        })
    }

    /// Train a single email as spam or ham
    pub async fn train(&self, raw_email: &[u8], is_spam: bool) -> Result<(), AppError> {
        let endpoint = if is_spam {
            "spam-filter/upload/spam"
        } else {
            "spam-filter/upload/ham"
        };

        let url = format!("{}/api/{}", self.base_url, endpoint);

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Content-Type", "text/plain")
            .body(raw_email.to_vec())
            .send()
            .await
            .map_err(|e| AppError::JmapRequest(format!("Admin API request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "no body".to_string());
            return Err(AppError::JmapRequest(format!(
                "Admin API returned {status}: {body}"
            )));
        }

        Ok(())
    }

    /// Train a batch of emails as spam or ham
    pub async fn train_batch(
        &self,
        emails: Vec<Vec<u8>>,
        is_spam: bool,
    ) -> Result<TrainResult, AppError> {
        let total = emails.len();
        let mut success = 0;
        let mut failed = 0;

        for raw_email in &emails {
            match self.train(raw_email, is_spam).await {
                Ok(()) => success += 1,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to train email");
                    failed += 1;
                }
            }
        }

        Ok(TrainResult {
            total,
            success,
            failed,
        })
    }
}

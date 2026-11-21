pub mod account;
pub mod mail;
pub mod masked_email;
pub mod raw;
pub mod sieve;
pub mod spam_filter;

use crate::config::AccountConfig;
use crate::error::AppError;
use jmap_client::client::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap};
use reqwest::redirect::Policy;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use raw::RawJmap;
use spam_filter::SpamFilterClient;

pub struct JmapClient {
    client: Client,
    /// Shared by [`Self::raw`] and [`Self::spam_filter`]; carries the credentials.
    api_http: reqwest::Client,
    account_id: String,
    username: String,
}

/// A copy of jmap-client's default headers with the Authorization value marked
/// sensitive, so it is never printed by `Debug`.
pub(crate) fn api_headers(headers: &HeaderMap) -> HeaderMap {
    let mut headers = headers.clone();
    if let Some(value) = headers.get_mut(AUTHORIZATION) {
        value.set_sensitive(true);
    }
    headers
}

/// HTTP client for JMAP API posts. Redirects are never followed, so a 307 or
/// 308 cannot re-post a JMAP body (with its credentials) to another host.
pub(crate) fn api_http_client(headers: HeaderMap) -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .default_headers(headers)
        .build()
        .map_err(|e| AppError::JmapConnection(format!("Failed to build JMAP HTTP client: {e}")))
}

impl JmapClient {
    pub async fn connect(config: &AccountConfig) -> Result<Self, AppError> {
        let password = config.password()?;

        let url_parsed = url::Url::parse(&config.url)
            .map_err(|e| AppError::JmapConnection(format!("Invalid URL: {e}")))?;
        let host = url_parsed
            .host_str()
            .ok_or_else(|| AppError::JmapConnection("No host in URL".into()))?
            .to_string();

        let client = Client::new()
            .credentials((config.username.as_str(), password.as_str()))
            .follow_redirects([host])
            .connect(&config.url)
            .await
            .map_err(|e| AppError::JmapConnection(e.to_string()))?;

        let account_id = client.default_account_id().to_string();
        let username = client.session().username().to_string();
        let api_http = api_http_client(api_headers(client.headers()))?;

        tracing::info!(
            name = %config.name,
            url = %config.url,
            account_id = %account_id,
            "Connected to Stalwart via JMAP"
        );

        Ok(Self {
            client,
            api_http,
            account_id,
            username,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// Build a Stalwart spam-filter client that shares this account's JMAP
    /// endpoint and Basic-auth credentials. Used by the `spam_train` tool to
    /// call `SpamTrainingSample/set` (Stalwart v0.16+).
    ///
    /// Shares the HTTP client built at connect time (no redirects followed).
    pub fn spam_filter(&self) -> Result<SpamFilterClient, AppError> {
        Ok(SpamFilterClient {
            http: self.api_http.clone(),
            api_url: self.client.session().api_url().to_string(),
            account_id: self.account_id.clone(),
        })
    }

    /// Build an untyped JMAP caller that shares this account's API URL and
    /// Basic-auth credentials. Used for masked email, vacation response, quota
    /// and identity calls. Shares the HTTP client built at connect time (no
    /// redirects followed).
    pub fn raw(&self) -> Result<RawJmap, AppError> {
        Ok(RawJmap::new(
            self.api_http.clone(),
            self.client.session().api_url().to_string(),
            self.account_id.clone(),
        ))
    }

    /// Start an EventSource stream for real-time change notifications.
    /// Uses our own reqwest client with HTTP/1.1 forced, because jmap-client's
    /// built-in event_source() may use HTTP/2 which doesn't stream SSE correctly
    /// with some servers.
    pub async fn event_source(
        &self,
        ping_interval: u32,
    ) -> Result<
        impl futures::Stream<Item = jmap_client::Result<jmap_client::event_source::PushNotification>>
        + Unpin,
        AppError,
    > {
        use jmap_client::core::session::URLPart;
        use jmap_client::event_source::parser::EventParser;
        use reqwest::header::{ACCEPT, HeaderValue};

        // Build the EventSource URL from the JMAP session
        let mut url = String::new();
        for part in self.client.event_source_url() {
            match part {
                URLPart::Value(value) => url.push_str(value),
                URLPart::Parameter(param) => match param {
                    jmap_client::event_source::URLParameter::Types => {
                        url.push_str("Email,Mailbox,EmailDelivery");
                    }
                    jmap_client::event_source::URLParameter::CloseAfter => {
                        url.push_str("no");
                    }
                    jmap_client::event_source::URLParameter::Ping => {
                        url.push_str(&ping_interval.to_string());
                    }
                },
            }
        }

        // Build HTTP/1.1-only client: critical for SSE streaming
        let headers = api_headers(self.client.headers());
        let http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .http1_only()
            .default_headers(headers)
            .build()
            .map_err(|e| AppError::JmapConnection(format!("Failed to build HTTP client: {e}")))?;

        let response = http_client
            .get(&url)
            .header(ACCEPT, HeaderValue::from_static("text/event-stream"))
            .send()
            .await
            .map_err(|e| AppError::JmapConnection(format!("EventSource request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(AppError::JmapConnection(format!(
                "EventSource returned HTTP {}",
                response.status()
            )));
        }

        tracing::debug!(url = %url, "EventSource SSE connection established");

        let mut stream = response.bytes_stream();
        let mut parser = EventParser::default();

        Ok(Box::pin(async_stream::stream! {
            loop {
                if let Some(notification) = parser.filter_notification() {
                    yield notification;
                    continue;
                }
                if let Some(result) = futures::StreamExt::next(&mut stream).await {
                    match result {
                        Ok(bytes) => {
                            parser.push_bytes(bytes.to_vec());
                            continue;
                        }
                        Err(err) => {
                            yield Err(err.into());
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        }))
    }
}

pub struct AccountManager {
    accounts: HashMap<String, Arc<JmapClient>>,
    default: String,
}

impl AccountManager {
    pub async fn connect_all(
        configs: &[AccountConfig],
        default_account: Option<&str>,
    ) -> Result<Self, AppError> {
        if configs.is_empty() {
            return Err(AppError::Config("No accounts configured".into()));
        }

        let mut accounts = HashMap::new();
        for config in configs {
            match JmapClient::connect(config).await {
                Ok(client) => {
                    accounts.insert(config.name.clone(), Arc::new(client));
                }
                Err(e) => {
                    tracing::warn!(
                        account = %config.name,
                        error = %e,
                        "Skipping account, connection failed"
                    );
                }
            }
        }

        if accounts.is_empty() {
            return Err(AppError::Config("No accounts could be connected".into()));
        }

        let default = default_account
            .map(String::from)
            .filter(|name| accounts.contains_key(name))
            .unwrap_or_else(|| accounts.keys().next().unwrap().clone());

        Ok(Self { accounts, default })
    }

    /// Get a client by account name. Returns an error if the account doesn't exist.
    /// This enforces account isolation: only accounts configured at startup are accessible,
    /// and each request is validated against the known account list.
    pub fn get(&self, name: Option<&str>) -> Result<&Arc<JmapClient>, AppError> {
        let name = name.unwrap_or(&self.default);
        self.accounts
            .get(name)
            .ok_or_else(|| AppError::NotFound(format!("Account '{}' not found", name)))
    }

    pub fn list(&self) -> Vec<(&str, &Arc<JmapClient>)> {
        self.accounts
            .iter()
            .map(|(name, client)| (name.as_str(), client))
            .collect()
    }

    pub fn default_name(&self) -> &str {
        &self.default
    }
}

//! Read a whole conversation: `Thread/get` (RFC 8621 section 3) for a
//! message's `threadId`, then `Email/get` for the thread's messages.
//!
//! Checked against Stalwart 1.1.1 (`crates/jmap/src/thread/get.rs`):
//! `Thread/get` returns `list` of `{id, emailIds}` and puts an unknown thread
//! in `notFound`; `emailIds` come in the server's own order, which is kept.
//! The typed `jmap-client` models both methods, so no raw call is needed.

use crate::error::AppError;
use crate::jmap::JmapClient;
use crate::jmap::mail::{EmailSummary, email_to_summary};
use jmap_client::email;
use serde::Serialize;
use std::collections::HashMap;

/// Messages returned when `limit` is omitted.
pub const DEFAULT_LIMIT: usize = 20;
/// Most messages one call returns; a larger `limit` is lowered to this.
pub const MAX_LIMIT: usize = 50;

/// A conversation, oldest message first (the server's thread order).
#[derive(Debug, Serialize)]
pub struct ThreadView {
    pub thread_id: String,
    /// Messages in the thread, including the omitted ones.
    pub total: usize,
    /// Older messages left out because the thread is longer than the limit.
    pub omitted: usize,
    pub messages: Vec<EmailSummary>,
}

/// The effective limit: [`DEFAULT_LIMIT`] when absent, at least 1, at most
/// [`MAX_LIMIT`].
pub fn effective_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// The most recent `limit` ids (the tail of the thread order) and how many
/// older ones were left out.
pub fn recent_ids(ids: &[String], limit: usize) -> (&[String], usize) {
    let omitted = ids.len().saturating_sub(limit);
    (&ids[omitted..], omitted)
}

/// Order `summaries` like `ids`; ids the server did not return are dropped.
pub fn in_thread_order(ids: &[String], summaries: Vec<EmailSummary>) -> Vec<EmailSummary> {
    let mut by_id: HashMap<String, EmailSummary> =
        summaries.into_iter().map(|s| (s.id.clone(), s)).collect();
    ids.iter().filter_map(|id| by_id.remove(id)).collect()
}

impl JmapClient {
    /// The thread of message `email_id`, at most `limit` most recent messages.
    pub async fn get_thread(&self, email_id: &str, limit: usize) -> Result<ThreadView, AppError> {
        let thread_id = self.thread_id_of(email_id).await?;

        let mut request = self.client.build();
        request
            .get_thread()
            .account_id(&self.account_id)
            .ids([thread_id.as_str()]);
        let response = request
            .send_get_thread()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;
        let all_ids: Vec<String> = response
            .list()
            .first()
            .ok_or_else(|| AppError::NotFound("Thread not found".into()))?
            .email_ids()
            .to_vec();

        let (ids, omitted) = recent_ids(&all_ids, limit);
        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids(ids.iter().map(String::as_str))
            .properties([
                email::Property::Id,
                email::Property::Subject,
                email::Property::From,
                email::Property::To,
                email::Property::ReceivedAt,
                email::Property::Keywords,
                email::Property::Preview,
            ]);
        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;
        let summaries = response.list().iter().map(email_to_summary).collect();

        Ok(ThreadView {
            thread_id,
            total: all_ids.len(),
            omitted,
            messages: in_thread_order(ids, summaries),
        })
    }

    async fn thread_id_of(&self, email_id: &str) -> Result<String, AppError> {
        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids([email_id])
            .properties([email::Property::Id, email::Property::ThreadId]);
        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;
        response
            .list()
            .first()
            .and_then(|e| e.thread_id())
            .map(str::to_string)
            .ok_or_else(|| AppError::NotFound("Email not found".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("m{i}")).collect()
    }

    fn summary(id: &str) -> EmailSummary {
        EmailSummary {
            id: id.into(),
            subject: Some("Re: Plans".into()),
            from: vec!["Ada <ada@example.org>".into()],
            to: vec!["bob@example.org".into()],
            received_at: Some(1_700_000_000),
            is_unread: false,
            is_flagged: false,
            preview: Some("See you at noon".into()),
        }
    }

    #[test]
    fn limit_defaults_and_is_capped() {
        assert_eq!(effective_limit(None), DEFAULT_LIMIT);
        assert_eq!(effective_limit(Some(5)), 5);
        assert_eq!(effective_limit(Some(0)), 1);
        assert_eq!(effective_limit(Some(MAX_LIMIT + 1)), MAX_LIMIT);
    }

    #[test]
    fn keeps_the_most_recent_and_counts_the_omitted() {
        let all = ids(5);
        let (kept, omitted) = recent_ids(&all, 3);
        assert_eq!(kept, ["m3", "m4", "m5"]);
        assert_eq!(omitted, 2);
        let (kept, omitted) = recent_ids(&all, 5);
        assert_eq!((kept.len(), omitted), (5, 0));
        let (kept, omitted) = recent_ids(&all, 50);
        assert_eq!((kept.len(), omitted), (5, 0));
        let (kept, omitted) = recent_ids(&[], 3);
        assert_eq!((kept.len(), omitted), (0, 0));
    }

    #[test]
    fn messages_follow_the_thread_order() {
        let order = ids(3);
        let got = in_thread_order(&order, vec![summary("m3"), summary("m1"), summary("x9")]);
        let got: Vec<&str> = got.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(got, ["m1", "m3"]);
    }

    #[test]
    fn thread_response_shape_parses() {
        // Thread/get as Stalwart 1.1.1 answers it.
        let response: jmap_client::core::response::ThreadGetResponse =
            serde_json::from_value(serde_json::json!({
                "accountId": "a1", "state": "s1",
                "list": [{"id": "t1", "emailIds": ["m1", "m2"]}],
                "notFound": []
            }))
            .expect("thread response");
        let thread = response.list().first().expect("thread");
        assert_eq!(thread.email_ids(), ["m1", "m2"]);
    }

    #[test]
    fn view_serializes_counts_and_messages() {
        let view = ThreadView {
            thread_id: "t1".into(),
            total: 3,
            omitted: 2,
            messages: vec![summary("m3")],
        };
        let out = serde_json::to_value(&view).expect("json");
        assert_eq!(out["total"], 3);
        assert_eq!(out["omitted"], 2);
        assert_eq!(out["messages"][0]["subject"], "Re: Plans");
        assert_eq!(out["messages"][0]["preview"], "See you at noon");
    }
}

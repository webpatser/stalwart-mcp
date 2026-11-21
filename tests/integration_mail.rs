//! Integration tests against a real Stalwart instance.
//!
//! These tests require a running Stalwart server. Set the following env vars:
//! - STALWART_TEST_URL: Stalwart server URL (e.g. https://mail.example.com)
//! - STALWART_TEST_USER: Username to authenticate with
//! - STALWART_PASSWORD: Password for the test user
//!
//! Optional:
//! - STALWART_TEST_ADDRESS: mail address of the test user, used as From and To
//!   of the self-addressed drafts (defaults to STALWART_TEST_USER)
//! - STALWART_TEST_SPAM_TRAIN=1: also run `test_spam_training` and
//!   `test_bulk_junk`. Both create training samples on the server (the first
//!   one by `SpamTrainingSample/set`, the second because Stalwart trains on a
//!   move into and out of Junk) and destroy exactly the samples they caused.
//!   Destroying a sample does not undo training the classifier already did.
//! - STALWART_TEST_SEND_TO: the one address `test_send_email` may send a real
//!   message to (one plain-text message per run, no cc or bcc). Without it
//!   the send test is skipped. Never commit the address.
//!
//! The draft tests only create drafts addressed to the test user (nothing is
//! sent). Every write test only ever deletes the message it created, found by
//! its id or, when the id is gone, by its unique subject in Drafts and Trash;
//! the send test removes its own copy from Sent after the checks.
//!
//! Run with: cargo test --test integration_mail -- --ignored --nocapture

use serde_json::json;
use stalwart_mcp::config::AccountConfig;
use stalwart_mcp::error::AppError;
use stalwart_mcp::jmap::JmapClient;
use stalwart_mcp::jmap::mail::{ComposeEmail, SearchFilters};
use stalwart_mcp::jmap::raw::RawJmap;
use std::collections::HashSet;
use std::time::Duration;

fn test_config() -> Option<AccountConfig> {
    let url = std::env::var("STALWART_TEST_URL").ok()?;
    let username = std::env::var("STALWART_TEST_USER").ok()?;

    Some(AccountConfig {
        name: "test".to_string(),
        url,
        username,
        password_env: Some("STALWART_PASSWORD".to_string()),
        password_command: None,
    })
}

/// Unwrap a JMAP result, naming the method and including the server's error text.
fn ok<T>(method: &str, result: Result<T, AppError>) -> T {
    match result {
        Ok(value) => value,
        Err(e) => panic!("{method} failed: {e}"),
    }
}

async fn connect(config: &AccountConfig) -> JmapClient {
    ok("Session/connect", JmapClient::connect(config).await)
}

fn self_address(config: &AccountConfig) -> String {
    std::env::var("STALWART_TEST_ADDRESS").unwrap_or_else(|_| config.username.clone())
}

fn unique_subject(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("stalwart-mcp integration test {tag} {nanos}")
}

/// Create a draft addressed to the test user itself. Nothing is sent.
async fn create_self_draft(
    client: &JmapClient,
    config: &AccountConfig,
    subject: &str,
) -> Result<String, AppError> {
    let address = self_address(config);
    let to = [address.clone()];
    client
        .create_draft(&ComposeEmail {
            from: &address,
            to: &to,
            subject,
            body: "Automated stalwart-mcp integration test message. Safe to delete.",
            ..Default::default()
        })
        .await
}

/// How many of the newest messages per mailbox the subject sweep inspects.
const SWEEP_LIMIT: usize = 100;

/// Destroy the test message. If `id` is gone or carries another subject, fall
/// back to [`cleanup_by_subject`] so a wrong id can never silently leave the
/// message behind. Returns how many messages were destroyed.
async fn cleanup(client: &JmapClient, id: &str, subject: &str) -> Result<usize, String> {
    match client.get_email(id).await {
        Ok(detail) if detail.subject.as_deref() == Some(subject) => {
            let n = client
                .bulk_destroy(&[id.to_string()])
                .await
                .map_err(|e| format!("cleanup: Email/set destroy of {id} failed: {e}"))?;
            eprintln!("cleanup: destroyed {id}");
            Ok(n)
        }
        Ok(detail) => {
            eprintln!(
                "cleanup: {id} has subject {:?}, not ours; sweeping Drafts and Trash by subject",
                detail.subject
            );
            cleanup_by_subject(client, subject).await
        }
        Err(_) => {
            eprintln!("cleanup: {id} does not exist; sweeping Drafts and Trash by subject");
            cleanup_by_subject(client, subject).await
        }
    }
}

/// Destroy every message in Drafts and Trash whose subject is exactly `subject`.
/// Uses a plain mailbox listing (no full-text search) and compares the subject
/// client-side, so nothing with another subject is ever touched.
async fn cleanup_by_subject(client: &JmapClient, subject: &str) -> Result<usize, String> {
    let mut destroyed = 0;
    for role in ["Drafts", "Trash"] {
        let mailbox = client
            .resolve_mailbox_by_role(role)
            .await
            .map_err(|e| format!("cleanup: Mailbox/get failed: {e}"))?
            .ok_or_else(|| format!("cleanup: no {role} mailbox by role"))?;
        let ids: Vec<String> = client
            .list_recent_emails(Some(&mailbox), SWEEP_LIMIT, false, None, None, None)
            .await
            .map_err(|e| format!("cleanup: Email/query in {role} failed: {e}"))?
            .into_iter()
            .filter(|e| e.subject.as_deref() == Some(subject))
            .map(|e| e.id)
            .collect();
        if ids.is_empty() {
            continue;
        }
        let n = client
            .bulk_destroy(&ids)
            .await
            .map_err(|e| format!("cleanup: Email/set destroy of {ids:?} failed: {e}"))?;
        eprintln!("cleanup: destroyed {n} of {ids:?} in {role} by exact subject {subject:?}");
        destroyed += n;
    }
    if destroyed == 0 {
        eprintln!("cleanup: no message with subject {subject:?} left in Drafts or Trash");
    }
    Ok(destroyed)
}

/// Whether `id` is among the newest messages of a mailbox (plain listing, no
/// full-text search).
async fn listed_in_mailbox(
    client: &JmapClient,
    mailbox_id: &str,
    id: &str,
) -> Result<bool, String> {
    client
        .list_recent_emails(Some(mailbox_id), SWEEP_LIMIT, false, None, None, None)
        .await
        .map(|found| found.iter().any(|e| e.id == id))
        .map_err(|e| format!("Email/query inMailbox failed: {e}"))
}

/// Search by the unique subject, retrying while the server indexes the message.
async fn find_by_subject(
    client: &JmapClient,
    subject: &str,
    mailbox_id: Option<&str>,
    id: &str,
) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 1..=SEARCH_ATTEMPTS {
        match client
            .search_emails(&SearchFilters {
                subject: Some(subject),
                mailbox_id,
                limit: 10,
                ..Default::default()
            })
            .await
        {
            Ok(found) => {
                if found.iter().any(|e| e.id == id) {
                    eprintln!("Email/query by subject found {id} on attempt {attempt}");
                    return Ok(());
                }
                last = format!(
                    "not found among {} results {:?}",
                    found.len(),
                    found.iter().map(|e| e.id.as_str()).collect::<Vec<_>>()
                );
            }
            Err(e) => last = format!("Email/query failed: {e}"),
        }
        tokio::time::sleep(SEARCH_INTERVAL).await;
    }
    Err(format!(
        "Email/query by subject {subject:?} never returned {id} within {:?}: {last}",
        SEARCH_INTERVAL * SEARCH_ATTEMPTS
    ))
}

/// Stalwart indexes full text asynchronously: a subject query on a new message
/// came back empty for about 26 seconds on 1.1.1. Give it up to a minute.
const SEARCH_ATTEMPTS: u32 = 60;
const SEARCH_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_connect() {
    let config = test_config().expect("STALWART_TEST_URL and STALWART_TEST_USER must be set");
    let client = JmapClient::connect(&config)
        .await
        .expect("Failed to connect");
    assert!(!client.account_id().is_empty());
}

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_list_mailboxes() {
    let config = test_config().expect("STALWART_TEST_URL and STALWART_TEST_USER must be set");
    let client = JmapClient::connect(&config)
        .await
        .expect("Failed to connect");

    let mailboxes = client
        .list_mailboxes()
        .await
        .expect("Failed to list mailboxes");
    assert!(!mailboxes.is_empty(), "Expected at least one mailbox");

    // Every Stalwart account has an INBOX
    let has_inbox = mailboxes
        .iter()
        .any(|mb| mb.name == "Inbox" || mb.name == "INBOX");
    assert!(has_inbox, "Expected to find INBOX");
}

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_list_recent() {
    let config = test_config().expect("STALWART_TEST_URL and STALWART_TEST_USER must be set");
    let client = JmapClient::connect(&config)
        .await
        .expect("Failed to connect");

    // Should not error even if empty
    let emails = client
        .list_recent_emails(None, 5, false, None, None, None)
        .await
        .expect("Failed to list recent emails");

    // Just verify it returns without error; mailbox may be empty
    let _ = emails;
}

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_search() {
    let config = test_config().expect("STALWART_TEST_URL and STALWART_TEST_USER must be set");
    let client = JmapClient::connect(&config)
        .await
        .expect("Failed to connect");

    // Search for a common word; may return empty results
    let results = client
        .search_emails(&SearchFilters {
            text: Some("test"),
            limit: 5,
            ..Default::default()
        })
        .await
        .expect("Failed to search emails");

    let _ = results;
}

/// Mailbox/get role lookup for the special mailboxes.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_special_mailboxes_by_role() {
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;
    let mailboxes = ok("Mailbox/get", client.list_mailboxes().await);
    eprintln!("mailbox roles:");
    for mb in &mailboxes {
        eprintln!("  {:?} role={} id={}", mb.name, mb.role, mb.id);
    }

    // Sent and Drafts are required by create_draft and send_email.
    for role in ["Drafts", "Sent"] {
        let id = ok(
            "Mailbox/get (resolve_mailbox_by_role)",
            client.resolve_mailbox_by_role(role).await,
        );
        assert!(
            id.is_some(),
            "Mailbox/get returned no mailbox with role {role}; roles seen: {:?}",
            mailboxes
                .iter()
                .map(|m| m.role.as_str())
                .collect::<Vec<_>>()
        );
    }

    // Inbox, Junk and Trash are used by the move and spam tools.
    for role in ["Inbox", "Junk", "Trash"] {
        let id = ok(
            "Mailbox/get (resolve_mailbox_by_role)",
            client.resolve_mailbox_by_role(role).await,
        );
        assert!(
            id.is_some(),
            "Mailbox/get returned no mailbox with role {role}"
        );
    }

    // The name lookup must agree with the role lookup for the Inbox.
    let by_role = ok("Mailbox/get", client.resolve_mailbox_by_role("Inbox").await);
    let by_name = ok("Mailbox/get", client.resolve_mailbox_id("Inbox").await);
    if by_name.is_some() {
        assert_eq!(by_role, by_name, "Inbox role and name resolve differently");
    }
}

/// Email/query, Email/get (summary and full), blob download and Message-ID.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_read_path() {
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;

    let recent = ok(
        "Email/query + Email/get (list_recent_emails)",
        client
            .list_recent_emails(None, 5, false, None, None, None)
            .await,
    );
    eprintln!("list_recent_emails returned {} emails", recent.len());
    let Some(first) = recent.first() else {
        eprintln!("mailbox is empty, skipping the full fetch");
        return;
    };

    let detail = ok("Email/get (get_email)", client.get_email(&first.id).await);
    assert_eq!(detail.id, first.id, "Email/get returned a different email");
    assert_eq!(
        detail.subject, first.subject,
        "subject differs between summary and detail"
    );
    assert!(
        detail.text_body.is_some() || detail.html_body.is_some(),
        "Email/get returned no body values for {}",
        first.id
    );
    eprintln!(
        "email {}: subject={:?} from={:?} attachments={}",
        detail.id,
        detail.subject,
        detail.from,
        detail.attachments.len()
    );

    // Headers: the raw message must be an RFC 5322 message with headers.
    let raw = ok(
        "Blob/download (get_email_raw)",
        client.get_email_raw(&first.id).await,
    );
    assert!(!raw.is_empty(), "Blob/download returned an empty message");
    let head = String::from_utf8_lossy(&raw[..raw.len().min(4096)]).to_lowercase();
    assert!(
        head.contains("\nfrom:") || head.starts_with("from:") || head.contains("\nreceived:"),
        "raw message has no recognisable headers"
    );

    let message_id = ok(
        "Email/get messageId (get_message_id)",
        client.get_message_id(&first.id).await,
    );
    eprintln!("message-id: {message_id:?}");

    let blobs = ok(
        "Email/get blobId (get_email_blob_ids)",
        client
            .get_email_blob_ids(std::slice::from_ref(&first.id))
            .await,
    );
    assert_eq!(
        blobs.len(),
        1,
        "Email/get blobId returned {} entries",
        blobs.len()
    );
    assert_eq!(blobs[0].0, first.id);

    // Unread-only and mailbox-scoped listing paths.
    let inbox = ok("Mailbox/get", client.resolve_mailbox_by_role("Inbox").await);
    let _ = ok(
        "Email/query (unread, inbox)",
        client
            .list_recent_emails(inbox.as_deref(), 5, true, None, None, None)
            .await,
    );

    // There is no thread method on JmapClient (Thread/get is not used).
}

/// Draft create, search, keyword toggle, then both `mail_bulk_delete` modes:
/// bulk move to Trash (default), then permanent destroy.
/// Nothing is sent; only the created message is ever destroyed.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_draft_lifecycle() {
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;
    let subject = unique_subject("lifecycle");

    let id = ok(
        "Email/set create (create_draft)",
        create_self_draft(&client, &config, &subject).await,
    );
    eprintln!("created draft {id} with subject {subject:?}");

    let outcome = draft_steps(&client, &id, &subject).await;
    let cleaned = cleanup(&client, &id, &subject).await;
    if let Err(msg) = outcome {
        panic!("{msg} ({cleaned:?})");
    }
    // The steps destroy the draft themselves, so cleanup must find nothing left.
    assert_eq!(
        cleaned,
        Ok(0),
        "the lifecycle left its draft behind; cleanup removed it"
    );
}

async fn draft_steps(client: &JmapClient, id: &str, subject: &str) -> Result<(), String> {
    let drafts = client
        .resolve_mailbox_by_role("Drafts")
        .await
        .map_err(|e| format!("Mailbox/get failed: {e}"))?
        .ok_or("no Drafts mailbox by role")?;
    let trash = client
        .resolve_mailbox_by_role("Trash")
        .await
        .map_err(|e| format!("Mailbox/get failed: {e}"))?
        .ok_or("no Trash mailbox by role")?;

    if !listed_in_mailbox(client, &drafts, id).await? {
        return Err(format!("Email/query inMailbox Drafts does not list {id}"));
    }
    find_by_subject(client, subject, Some(&drafts), id).await?;

    let detail = client
        .get_email(id)
        .await
        .map_err(|e| format!("Email/get failed: {e}"))?;
    if detail.subject.as_deref() != Some(subject) {
        return Err(format!("Email/get subject mismatch: {:?}", detail.subject));
    }
    // From must be the identity's address, not the login name (not printed).
    if detail.from.len() != 1 || !detail.from.iter().all(|f| f.contains('@')) {
        return Err(format!(
            "draft From is not one email address ({} entries)",
            detail.from.len()
        ));
    }
    if !detail
        .text_body
        .as_deref()
        .unwrap_or_default()
        .contains("integration test")
    {
        return Err("Email/get returned the wrong body".to_string());
    }

    // Mark unread, then read again.
    client
        .set_email_keyword(id, "$seen", false)
        .await
        .map_err(|e| format!("Email/set update $seen=false failed: {e}"))?;
    let unread = client
        .get_email(id)
        .await
        .map_err(|e| format!("Email/get failed: {e}"))?;
    if !unread.is_unread {
        return Err("Email/set $seen=false did not mark the email unread".to_string());
    }
    client
        .set_email_keyword(id, "$seen", true)
        .await
        .map_err(|e| format!("Email/set update $seen=true failed: {e}"))?;
    let read = client
        .get_email(id)
        .await
        .map_err(|e| format!("Email/get failed: {e}"))?;
    if read.is_unread {
        return Err("Email/set $seen=true did not mark the email read".to_string());
    }

    // mail_bulk_delete default (Trash mode): moved, not destroyed.
    let moved = client
        .bulk_move_to_trash(&[id.to_string()])
        .await
        .map_err(|e| format!("Email/set update mailboxIds (bulk move to Trash) failed: {e}"))?;
    if moved != 1 {
        return Err(format!(
            "bulk move to Trash reported {moved} moved, expected 1"
        ));
    }
    if !listed_in_mailbox(client, &trash, id).await? {
        return Err(format!("Email/query inMailbox Trash does not list {id}"));
    }
    if listed_in_mailbox(client, &drafts, id).await? {
        return Err(format!("{id} is still in Drafts after the move to Trash"));
    }
    find_by_subject(client, subject, Some(&trash), id).await?;
    client
        .get_email(id)
        .await
        .map_err(|e| format!("Trash mode destroyed {id}: {e}"))?;

    // mail_bulk_delete permanent: true, then confirm it is gone.
    let destroyed = client
        .bulk_destroy(&[id.to_string()])
        .await
        .map_err(|e| format!("Email/set destroy failed: {e}"))?;
    if destroyed != 1 {
        return Err(format!(
            "Email/set destroy reported {destroyed}, expected 1"
        ));
    }
    if client.get_email(id).await.is_ok() {
        return Err(format!(
            "Email/set destroy reported success but {id} still exists"
        ));
    }
    Ok(())
}

/// Whether `id` looks like a client creation id (`c0`, `c1`, ...) rather than a
/// server-assigned email id.
fn is_creation_id(id: &str) -> bool {
    id.strip_prefix('c')
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Domain part of an address, so the test output never shows a local part.
fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map_or("(no domain)", |(_, d)| d)
}

/// EmailSubmission/set for real: sends ONE plain-text message to the address
/// in STALWART_TEST_SEND_TO, from the login name as the `mail_send` tool does.
/// Afterwards the sent copy (and only that id) is removed from Sent.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_send_email() {
    let Ok(send_to) = std::env::var("STALWART_TEST_SEND_TO") else {
        eprintln!("skipped: set STALWART_TEST_SEND_TO to send one real test message");
        return;
    };
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;
    let subject = unique_subject("send");
    let from = self_address(&config);
    let to = [send_to];

    let id = ok(
        "Email/set + EmailSubmission/set (send_email)",
        client
            .send_email(&ComposeEmail {
                from: &from,
                to: &to,
                subject: &subject,
                body: "Automated stalwart-mcp integration test message. Safe to delete.",
                ..Default::default()
            })
            .await,
    );
    eprintln!("sent one message, stored as {id} with subject {subject:?}");

    let outcome = sent_checks(&client, &from, &id, &subject).await;
    let cleaned = cleanup(&client, &id, &subject).await;
    if let Err(msg) = outcome {
        panic!("{msg} ({cleaned:?})");
    }
    match cleaned {
        Ok(1) => eprintln!("removed the sent copy {id} from Sent"),
        other => panic!("cleanup of the sent copy {id} failed: {other:?}"),
    }
}

async fn sent_checks(
    client: &JmapClient,
    from: &str,
    id: &str,
    subject: &str,
) -> Result<(), String> {
    if is_creation_id(id) {
        return Err(format!(
            "send_email returned the creation id {id}, not a server id"
        ));
    }

    let detail = client
        .get_email(id)
        .await
        .map_err(|e| format!("Email/get of the sent id {id} failed: {e}"))?;
    if detail.subject.as_deref() != Some(subject) {
        return Err(format!("Email/get subject mismatch: {:?}", detail.subject));
    }

    let sent = client
        .resolve_mailbox_by_role("Sent")
        .await
        .map_err(|e| format!("Mailbox/get failed: {e}"))?
        .ok_or("no Sent mailbox by role")?;
    let drafts = client
        .resolve_mailbox_by_role("Drafts")
        .await
        .map_err(|e| format!("Mailbox/get failed: {e}"))?
        .ok_or("no Drafts mailbox by role")?;

    // mailboxIds, keywords and from are not in EmailDetail: ask the server.
    let raw = client
        .raw()
        .map_err(|e| format!("raw JMAP client setup failed: {e}"))?;
    let response = raw
        .call(
            &["urn:ietf:params:jmap:mail"],
            "Email/get",
            serde_json::json!({
                "accountId": raw.account_id(),
                "ids": [id],
                "properties": ["mailboxIds", "keywords", "from"],
            }),
        )
        .await
        .map_err(|e| format!("Email/get mailboxIds/keywords failed: {e}"))?;
    let email = &response["list"][0];
    if email["mailboxIds"][sent.as_str()] != serde_json::json!(true) {
        return Err(format!(
            "{id} is not in Sent: mailboxIds={}",
            email["mailboxIds"]
        ));
    }
    let keywords = email["keywords"].as_object().cloned().unwrap_or_default();
    if keywords.contains_key("$draft") {
        return Err(format!("{id} still carries $draft: {:?}", keywords.keys()));
    }

    // send_email puts the matching (else the first) identity's address in From.
    let identities = client
        .list_identities()
        .await
        .map_err(|e| format!("Identity/get failed: {e}"))?;
    let expected = identities
        .iter()
        .find(|i| i.email.eq_ignore_ascii_case(from))
        .or_else(|| identities.first())
        .map(|i| i.email.as_str())
        .ok_or("Identity/get returned no identity")?;
    let actual = email["from"][0]["email"].as_str().unwrap_or_default();
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "From is at {} but the identity is at {}",
            domain_of(actual),
            domain_of(expected)
        ));
    }
    eprintln!("From is the identity address at {}", domain_of(actual));

    // Nothing with this subject may be left in Drafts.
    let left: Vec<String> = client
        .list_recent_emails(Some(&drafts), SWEEP_LIMIT, false, None, None, None)
        .await
        .map_err(|e| format!("Email/query in Drafts failed: {e}"))?
        .into_iter()
        .filter(|e| e.subject.as_deref() == Some(subject))
        .map(|e| e.id)
        .collect();
    if !left.is_empty() {
        return Err(format!("Drafts still holds {left:?} with the test subject"));
    }
    Ok(())
}

/// Capabilities and methods of Stalwart's spam training samples. They are
/// registry objects, which Stalwart 1.1.1 dispatches only under the `x:` prefix.
const SAMPLE_USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];
const SAMPLE_QUERY: &str = "x:SpamTrainingSample/query";
const SAMPLE_GET: &str = "x:SpamTrainingSample/get";
const SAMPLE_SET: &str = "x:SpamTrainingSample/set";
/// Requested `/query` page size; the server may cap it lower.
const SAMPLE_PAGE: usize = 256;
const SAMPLE_MAX_PAGES: usize = 10_000;
/// Ids per `/get` call, well below the server's `maxGetResults`.
const SAMPLE_GET_CHUNK: usize = 50;

fn spam_train_opted_in() -> bool {
    std::env::var("STALWART_TEST_SPAM_TRAIN").as_deref() == Ok("1")
}

/// The unique part of a [`unique_subject`]: its trailing timestamp. Stalwart
/// stores a sample's subject normalised as a thread name, so samples are
/// matched on this token rather than on the full subject.
fn subject_token(subject: &str) -> &str {
    subject.rsplit(' ').next().unwrap_or(subject)
}

/// Ids of every spam training sample of the account, paged through `/query`
/// because `/get` with `ids: null` silently truncates at the server's cap.
async fn sample_ids(raw: &RawJmap) -> Result<HashSet<String>, String> {
    let mut ids = HashSet::new();
    let mut position = 0usize;
    for _ in 0..SAMPLE_MAX_PAGES {
        let page = raw
            .call(
                &SAMPLE_USING,
                SAMPLE_QUERY,
                json!({
                    "accountId": raw.account_id(),
                    "position": position,
                    "limit": SAMPLE_PAGE,
                    "calculateTotal": true,
                }),
            )
            .await
            .map_err(|e| format!("{SAMPLE_QUERY} failed: {e}"))?;
        let batch = page["ids"]
            .as_array()
            .ok_or_else(|| format!("{SAMPLE_QUERY} returned no ids array"))?;
        if batch.is_empty() {
            return Ok(ids);
        }
        position += batch.len();
        ids.extend(batch.iter().filter_map(|v| v.as_str().map(str::to_owned)));
        if page["total"]
            .as_u64()
            .is_some_and(|total| position as u64 >= total)
        {
            return Ok(ids);
        }
    }
    Err(format!(
        "{SAMPLE_QUERY} did not finish within {SAMPLE_MAX_PAGES} pages"
    ))
}

/// Split the samples created since `before` into this run's own (subject
/// carries `token`) and everything else. Only the first list is ever destroyed.
async fn new_samples(
    raw: &RawJmap,
    before: &HashSet<String>,
    token: &str,
) -> Result<(Vec<String>, Vec<String>), String> {
    let new: Vec<String> = sample_ids(raw)
        .await?
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect();
    let mut own = Vec::new();
    for chunk in new.chunks(SAMPLE_GET_CHUNK) {
        let got = raw
            .call(
                &SAMPLE_USING,
                SAMPLE_GET,
                json!({
                    "accountId": raw.account_id(),
                    "ids": chunk,
                    "properties": ["id", "subject"],
                }),
            )
            .await
            .map_err(|e| format!("{SAMPLE_GET} failed: {e}"))?;
        for item in got["list"].as_array().into_iter().flatten() {
            let is_own = item["subject"]
                .as_str()
                .is_some_and(|subject| subject.contains(token));
            if let (true, Some(id)) = (is_own, item["id"].as_str()) {
                own.push(id.to_owned());
            }
        }
    }
    let foreign = new.into_iter().filter(|id| !own.contains(id)).collect();
    Ok((own, foreign))
}

/// Destroy the given samples and fail unless the server destroyed every one.
async fn destroy_samples(raw: &RawJmap, ids: &[String]) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }
    let response = raw
        .call(
            &SAMPLE_USING,
            SAMPLE_SET,
            json!({ "accountId": raw.account_id(), "destroy": ids }),
        )
        .await
        .map_err(|e| format!("{SAMPLE_SET} destroy failed: {e}"))?;
    let destroyed: HashSet<&str> = response["destroyed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let missing: Vec<&String> = ids
        .iter()
        .filter(|id| !destroyed.contains(id.as_str()))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{SAMPLE_SET} did not destroy {missing:?}: notDestroyed {}",
            response["notDestroyed"]
        ))
    }
}

/// Destroy the samples this run caused (new since `before`, subject carries
/// `token`) and check that afterwards the account holds only samples from
/// `before` plus new ones that are not ours, which are left untouched.
/// Returns how many samples were ours.
async fn restore_samples(
    raw: &RawJmap,
    before: &HashSet<String>,
    token: &str,
) -> Result<usize, String> {
    // Email/set writes its samples within the request; allow a moment anyway.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (own, foreign) = new_samples(raw, before, token).await?;
    eprintln!(
        "samples: {} before, {} caused by this test {own:?}, {} new from elsewhere (untouched)",
        before.len(),
        own.len(),
        foreign.len()
    );
    destroy_samples(raw, &own).await?;
    let after = sample_ids(raw).await?;
    let gone_elsewhere = before.difference(&after).count();
    eprintln!(
        "samples after cleanup: {} (prior {}, {gone_elsewhere} prior ones consumed or expired meanwhile)",
        after.len(),
        before.len()
    );
    let left: Vec<&String> = own.iter().filter(|id| after.contains(*id)).collect();
    if !left.is_empty() {
        return Err(format!("our samples {left:?} still exist after destroy"));
    }
    let unexpected: Vec<&String> = after
        .iter()
        .filter(|id| !before.contains(*id) && !foreign.contains(*id))
        .collect();
    if !unexpected.is_empty() {
        return Err(format!(
            "samples {unexpected:?} appeared during cleanup; not touched"
        ));
    }
    if foreign.is_empty() && gone_elsewhere == 0 && after.len() != before.len() {
        return Err(format!(
            "sample count is {} after cleanup, expected the prior {}",
            after.len(),
            before.len()
        ));
    }
    Ok(own.len())
}

/// `spam_train` (`x:SpamTrainingSample/set`) on a self-created draft: train
/// once, find the sample it created, destroy it, check the sample count is
/// back, delete the draft. Only runs with STALWART_TEST_SPAM_TRAIN=1.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_spam_training() {
    if !spam_train_opted_in() {
        eprintln!("skipped: set STALWART_TEST_SPAM_TRAIN=1 to train the spam model");
        return;
    }
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;
    let raw = ok("raw JMAP client", client.raw());
    let before = sample_ids(&raw)
        .await
        .unwrap_or_else(|e| panic!("{e} (nothing was created)"));
    eprintln!("samples before: {}", before.len());
    let subject = unique_subject("spam-train");

    let id = ok(
        "Email/set create (create_draft)",
        create_self_draft(&client, &config, &subject).await,
    );
    eprintln!("created draft {id}");

    let outcome: Result<(), String> = async {
        let blobs = client
            .get_email_blob_ids(std::slice::from_ref(&id))
            .await
            .map_err(|e| format!("Email/get blobId failed: {e}"))?;
        let blob_id = blobs
            .into_iter()
            .find(|(email_id, _)| *email_id == id)
            .map(|(_, blob)| blob)
            .ok_or("Email/get blobId returned no blob for the draft")?;

        let spam = client
            .spam_filter()
            .map_err(|e| format!("spam_filter client setup failed: {e}"))?;
        let result = spam
            .train_batch(&[blob_id], true)
            .await
            .map_err(|e| format!("x:SpamTrainingSample/set failed: {e}"))?;
        eprintln!("x:SpamTrainingSample/set result: {result:?}");
        if result.success != 1 || result.failed != 0 {
            return Err(format!(
                "x:SpamTrainingSample/set did not create the sample: {result:?}"
            ));
        }
        Ok(())
    }
    .await;

    let samples = restore_samples(&raw, &before, subject_token(&subject)).await;
    let cleaned = cleanup(&client, &id, &subject).await;
    if let Err(msg) = outcome {
        panic!("{msg} (samples: {samples:?}, draft cleanup: {cleaned:?})");
    }
    let own = samples.unwrap_or_else(|e| panic!("{e} (draft cleanup: {cleaned:?})"));
    assert_eq!(
        own, 1,
        "expected exactly one sample from this test, found {own}"
    );
    assert_eq!(cleaned, Ok(1), "the draft was not destroyed exactly once");
}

/// `mail_bulk_junk`'s JMAP path (`bulk_keyword_and_move` with `$junk`, target
/// resolved by role) on a self-created draft: into Junk, then back to Drafts,
/// then destroyed. Stalwart 1.1.1 stores a training sample on each move (spam
/// into Junk, ham out of it), so the test also destroys exactly the samples it
/// caused. Only runs with STALWART_TEST_SPAM_TRAIN=1.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_bulk_junk() {
    if !spam_train_opted_in() {
        eprintln!("skipped: set STALWART_TEST_SPAM_TRAIN=1 to train the spam model");
        return;
    }
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;
    let raw = ok("raw JMAP client", client.raw());
    let drafts = ok(
        "Mailbox/get",
        client.resolve_mailbox_by_role("Drafts").await,
    )
    .expect("no Drafts mailbox by role (nothing was created)");
    let junk = ok("Mailbox/get", client.resolve_mailbox_by_role("Junk").await)
        .expect("no Junk mailbox by role (nothing was created)");
    let before = sample_ids(&raw)
        .await
        .unwrap_or_else(|e| panic!("{e} (nothing was created)"));
    eprintln!("samples before: {}", before.len());
    let subject = unique_subject("bulk-junk");

    let id = ok(
        "Email/set create (create_draft)",
        create_self_draft(&client, &config, &subject).await,
    );
    eprintln!("created draft {id}");

    let outcome = junk_steps(&client, &id, &drafts, &junk).await;
    let samples = restore_samples(&raw, &before, subject_token(&subject)).await;
    // `cleanup` finds the message by id in any mailbox, Junk included.
    let cleaned = cleanup(&client, &id, &subject).await;
    let in_junk = listed_in_mailbox(&client, &junk, &id).await;
    let exists = client.get_email(&id).await.is_ok();
    eprintln!("after cleanup: exists {exists}, listed in Junk {in_junk:?}");

    if let Err(msg) = outcome {
        panic!("{msg} (samples: {samples:?}, draft cleanup: {cleaned:?})");
    }
    let own = samples.unwrap_or_else(|e| panic!("{e} (draft cleanup: {cleaned:?})"));
    eprintln!("destroyed {own} samples caused by the two moves");
    assert_eq!(cleaned, Ok(1), "the draft was not destroyed exactly once");
    assert!(!exists, "{id} still exists after cleanup");
    assert_eq!(in_junk, Ok(false), "{id} is still listed in Junk");
}

async fn junk_steps(client: &JmapClient, id: &str, drafts: &str, junk: &str) -> Result<(), String> {
    let ids = [id.to_string()];
    let moved = client
        .bulk_keyword_and_move(&ids, "$junk", true, junk)
        .await
        .map_err(|e| format!("Email/set $junk + move to Junk failed: {e}"))?;
    if moved != 1 {
        return Err(format!("move to Junk reported {moved} updated, expected 1"));
    }
    if !listed_in_mailbox(client, junk, id).await? {
        return Err(format!("Email/query inMailbox Junk does not list {id}"));
    }
    if listed_in_mailbox(client, drafts, id).await? {
        return Err(format!("{id} is still in Drafts after the move to Junk"));
    }

    let back = client
        .bulk_keyword_and_move(&ids, "$junk", false, drafts)
        .await
        .map_err(|e| format!("Email/set $junk removed + move to Drafts failed: {e}"))?;
    if back != 1 {
        return Err(format!(
            "move back to Drafts reported {back} updated, expected 1"
        ));
    }
    if !listed_in_mailbox(client, drafts, id).await? {
        return Err(format!("Email/query inMailbox Drafts does not list {id}"));
    }
    if listed_in_mailbox(client, junk, id).await? {
        return Err(format!("{id} is still in Junk after the move back"));
    }
    Ok(())
}

/// Print the JMAP session capabilities and any product/version the server
/// exposes. JmapClient does not expose its session, so this fetches
/// /.well-known/jmap directly with the same credentials.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_session_capabilities() {
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let Ok(password) = std::env::var("STALWART_PASSWORD") else {
        eprintln!("skipped: STALWART_PASSWORD not set");
        return;
    };

    let url = format!("{}/.well-known/jmap", config.url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .get(&url)
        .basic_auth(&config.username, Some(password))
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url} (JMAP session) failed: {e}"));
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|e| panic!("GET {url} (JMAP session) body failed: {e}"));
    assert!(
        status.is_success(),
        "GET {url} (JMAP session) returned {status}: {body}"
    );

    let session: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("JMAP session is not JSON: {e}: {body}"));

    let capabilities = session["capabilities"]
        .as_object()
        .unwrap_or_else(|| panic!("JMAP session has no capabilities object: {body}"));
    eprintln!(
        "session top-level keys: {:?}",
        session.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
    eprintln!("capabilities ({}):", capabilities.len());
    for urn in capabilities.keys() {
        eprintln!("  {urn}");
    }
    for (urn, value) in capabilities {
        if urn.contains("stalwart") {
            eprintln!("{urn} = {value}");
        }
    }

    // Product/version are not part of the JMAP spec; report whatever shows up.
    let mut found = false;
    for key in [
        "productName",
        "product",
        "serverName",
        "version",
        "serverVersion",
    ] {
        if let Some(v) = session.get(key) {
            eprintln!("session.{key} = {v}");
            found = true;
        }
        for (urn, cap) in capabilities {
            if let Some(v) = cap.get(key) {
                eprintln!("{urn}.{key} = {v}");
                found = true;
            }
        }
    }
    if !found {
        eprintln!("server exposes no product or version in the session");
    }

    assert!(
        capabilities.contains_key("urn:ietf:params:jmap:mail"),
        "session lacks urn:ietf:params:jmap:mail"
    );
}

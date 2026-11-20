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
//! - STALWART_TEST_SPAM_TRAIN=1: also run the spam training test, which
//!   changes the server's spam model
//!
//! The write tests only create drafts addressed to the test user (nothing is
//! sent) and only ever delete the message they created.
//!
//! Run with: cargo test --test integration_mail -- --ignored --nocapture

use stalwart_mcp::config::AccountConfig;
use stalwart_mcp::error::AppError;
use stalwart_mcp::jmap::JmapClient;
use stalwart_mcp::jmap::mail::{ComposeEmail, SearchFilters};
use std::time::Duration;

fn test_config() -> Option<AccountConfig> {
    let url = std::env::var("STALWART_TEST_URL").ok()?;
    let username = std::env::var("STALWART_TEST_USER").ok()?;

    Some(AccountConfig {
        name: "test".to_string(),
        url,
        username,
        password_env: "STALWART_PASSWORD".to_string(),
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

/// Destroy the message only if it still exists and carries the unique subject.
async fn cleanup(client: &JmapClient, id: &str, subject: &str) {
    match client.get_email(id).await {
        Ok(detail) if detail.subject.as_deref() == Some(subject) => {
            match client.bulk_destroy(&[id.to_string()]).await {
                Ok(_) => eprintln!("cleanup: destroyed {id}"),
                Err(e) => eprintln!("cleanup: Email/set destroy of {id} failed: {e}"),
            }
        }
        Ok(detail) => eprintln!(
            "cleanup: refusing to delete {id}, subject {:?} does not match",
            detail.subject
        ),
        Err(_) => eprintln!("cleanup: {id} no longer exists"),
    }
}

/// Search by the unique subject, retrying while the server indexes the message.
async fn find_by_subject(
    client: &JmapClient,
    subject: &str,
    mailbox_id: Option<&str>,
    id: &str,
) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..10 {
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
                    return Ok(());
                }
                last = format!("not found among {} results", found.len());
            }
            Err(e) => last = format!("Email/query failed: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "Email/query by subject {subject:?} never returned {id}: {last}"
    ))
}

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

/// Draft create, search, keyword toggle, move to Trash, permanent delete.
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
    cleanup(&client, &id, &subject).await;
    if let Err(msg) = outcome {
        panic!("{msg}");
    }
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

    find_by_subject(client, subject, Some(&drafts), id).await?;

    let detail = client
        .get_email(id)
        .await
        .map_err(|e| format!("Email/get failed: {e}"))?;
    if detail.subject.as_deref() != Some(subject) {
        return Err(format!("Email/get subject mismatch: {:?}", detail.subject));
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

    // Move to Trash and confirm it shows up there.
    client
        .move_email(id, &trash)
        .await
        .map_err(|e| format!("Email/set update mailboxIds (move to Trash) failed: {e}"))?;
    find_by_subject(client, subject, Some(&trash), id).await?;

    // Permanent delete, then confirm it is gone.
    client
        .bulk_destroy(&[id.to_string()])
        .await
        .map_err(|e| format!("Email/set destroy failed: {e}"))?;
    if client.get_email(id).await.is_ok() {
        return Err(format!(
            "Email/set destroy reported success but {id} still exists"
        ));
    }
    Ok(())
}

/// SpamTrainingSample/set via a self-created draft. Changes the spam model, so
/// it only runs with STALWART_TEST_SPAM_TRAIN=1.
#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_spam_training() {
    if std::env::var("STALWART_TEST_SPAM_TRAIN").as_deref() != Ok("1") {
        eprintln!("skipped: set STALWART_TEST_SPAM_TRAIN=1 to train the spam model");
        return;
    }
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return;
    };
    let client = connect(&config).await;
    let subject = unique_subject("spam-train");

    let id = ok(
        "Email/set create (create_draft)",
        create_self_draft(&client, &config, &subject).await,
    );
    eprintln!("created draft {id} with subject {subject:?}");

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
            .map_err(|e| format!("SpamTrainingSample/set failed: {e}"))?;
        eprintln!("SpamTrainingSample/set result: {result:?}");
        if result.success != 1 || result.failed != 0 {
            return Err(format!(
                "SpamTrainingSample/set did not create the sample: {result:?}"
            ));
        }
        Ok(())
    }
    .await;

    cleanup(&client, &id, &subject).await;
    if let Err(msg) = outcome {
        panic!("{msg}");
    }
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

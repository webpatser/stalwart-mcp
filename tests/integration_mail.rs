//! Integration tests against a real Stalwart instance.
//!
//! These tests require a running Stalwart server. Set the following env vars:
//! - STALWART_TEST_URL: Stalwart server URL (e.g. https://mail.example.com)
//! - STALWART_TEST_USER: Username to authenticate with
//! - STALWART_PASSWORD: Password for the test user
//!
//! Run with: cargo test --test integration_mail -- --ignored

use stalwart_mcp::config::AccountConfig;
use stalwart_mcp::jmap::JmapClient;
use stalwart_mcp::jmap::mail::SearchFilters;

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

//! Live tests for the account-level tools: masked email, vacation response,
//! quota and identities. Same env vars as `integration_mail.rs`:
//! STALWART_TEST_URL, STALWART_TEST_USER, STALWART_PASSWORD.
//!
//! They run against a real person's account, so every write restores what it
//! touched and asserts it did:
//! - masked email: only the address this test created (matched by id and its
//!   unique description) is disabled and then destroyed;
//! - vacation response: written only with `isEnabled: false`, then restored to
//!   the exact prior state. Skipped when an auto-reply is active, so a real
//!   out-of-office is never interrupted. A Sieve script the update had to
//!   create is destroyed again.
//!
//! Output holds counts and redacted response shapes only, no addresses.
//!
//! Run with: cargo test --test integration_account -- --ignored --nocapture --test-threads=1

use serde_json::{Value, json};
use stalwart_mcp::config::AccountConfig;
use stalwart_mcp::error::AppError;
use stalwart_mcp::jmap::JmapClient;
use stalwart_mcp::jmap::account::VacationResponse;
use stalwart_mcp::jmap::masked_email::NewMaskedEmail;

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

fn ok<T>(method: &str, result: Result<T, AppError>) -> T {
    match result {
        Ok(value) => value,
        Err(e) => panic!("{method} failed: {e}"),
    }
}

async fn connect() -> Option<JmapClient> {
    let Some(config) = test_config() else {
        eprintln!("skipped: STALWART_TEST_URL and STALWART_TEST_USER not set");
        return None;
    };
    Some(ok("Session/connect", JmapClient::connect(&config).await))
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

/// Keys whose values may carry personal data; their string values are masked.
const PERSONAL_KEYS: &[&str] = &[
    "accountId",
    "email",
    "name",
    "description",
    "forDomain",
    "url",
    "subject",
    "textBody",
    "htmlBody",
    "textSignature",
    "htmlSignature",
    "createdBy",
];

/// Mask personal string values so the output can serve as a test fixture.
fn redacted(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = match v {
                        Value::String(s) if PERSONAL_KEYS.contains(&k.as_str()) => {
                            if s.contains('@') {
                                json!("user@example.com")
                            } else if s.is_empty() {
                                json!("")
                            } else {
                                json!("<redacted>")
                            }
                        }
                        Value::String(s) if s.contains('@') => json!("user@example.com"),
                        other => redacted(other),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redacted).collect()),
        Value::String(s) if s.contains('@') => json!("user@example.com"),
        other => other.clone(),
    }
}

/// Print one raw response, redacted, with long lists cut to their first entry.
async fn print_raw_shape(client: &JmapClient, capability: &str, method: &str, args: Value) {
    let raw = ok("raw client", client.raw());
    let mut args = args;
    args["accountId"] = json!(raw.account_id());
    match raw.call(&[capability], method, args).await {
        Ok(mut response) => {
            if let Some(list) = response.get_mut("list").and_then(Value::as_array_mut) {
                let total = list.len();
                list.truncate(1);
                eprintln!("{method}: {total} objects, first one shown");
            }
            eprintln!("{method} response shape: {}", redacted(&response));
        }
        Err(e) => eprintln!("{method} raw call failed: {e}"),
    }
}

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_masked_email_lifecycle() {
    let Some(client) = connect().await else {
        return;
    };
    print_raw_shape(
        &client,
        "urn:stalwart:jmap",
        "x:MaskedEmail/get",
        json!({"ids": null}),
    )
    .await;

    let before = ok("x:MaskedEmail/get", client.list_masked_emails().await);
    eprintln!("masked addresses before: {}", before.len());

    let description = format!("stalwart-mcp integration test {}", nanos());
    let created = ok(
        "x:MaskedEmail/set create",
        client
            .create_masked_email(&NewMaskedEmail {
                description: Some(&description),
                for_domain: Some("example.com"),
                ..Default::default()
            })
            .await,
    );
    let id = created.id.clone();
    eprintln!(
        "created masked address {id}: has email {}, enable {:?}",
        created.email.is_some(),
        created.enable
    );

    print_raw_shape(
        &client,
        "urn:stalwart:jmap",
        "x:MaskedEmail/get",
        json!({"ids": [id]}),
    )
    .await;

    let outcome = masked_steps(&client, &id, &description).await;
    let cleaned = masked_cleanup(&client, &id, &description).await;
    if let Err(msg) = outcome {
        panic!("{msg} (cleanup: {cleaned:?})");
    }
    if let Err(msg) = cleaned {
        panic!("{msg}");
    }

    let after = ok("x:MaskedEmail/get", client.list_masked_emails().await);
    eprintln!("masked addresses after: {}", after.len());
    assert!(
        after.iter().all(|m| m.id != id),
        "the test address is still listed"
    );
    assert_eq!(
        after.len(),
        before.len(),
        "masked address count changed across the test"
    );
}

async fn masked_steps(client: &JmapClient, id: &str, description: &str) -> Result<(), String> {
    let listed = client
        .list_masked_emails()
        .await
        .map_err(|e| format!("x:MaskedEmail/get failed: {e}"))?;
    let ours = listed
        .iter()
        .find(|m| m.id == id)
        .ok_or_else(|| format!("x:MaskedEmail/get does not list {id}"))?;
    if ours.description.as_deref() != Some(description) {
        return Err(format!("{id} carries another description"));
    }
    if ours.email.as_deref().is_none_or(|e| !e.contains('@')) {
        return Err(format!("{id} has no generated address"));
    }
    if ours.enable == Some(false) {
        return Err(format!("{id} was created disabled"));
    }
    if ours.for_domain.as_deref() != Some("example.com") {
        return Err(format!("{id} forDomain is {:?}", ours.for_domain));
    }

    let disabled = client
        .set_masked_email_enabled(id, false)
        .await
        .map_err(|e| format!("x:MaskedEmail/set update enable=false failed: {e}"))?;
    if disabled.enable != Some(false) {
        return Err(format!(
            "x:MaskedEmail/set reported success but enable is {:?}",
            disabled.enable
        ));
    }
    eprintln!("disabled {id}");
    Ok(())
}

/// Destroy the test address, only if `id` still carries our description.
/// When destroy is refused, leave it disabled and say so loudly.
async fn masked_cleanup(client: &JmapClient, id: &str, description: &str) -> Result<(), String> {
    match client.get_masked_email(id).await {
        Ok(m) if m.description.as_deref() == Some(description) => {}
        Ok(_) => return Err(format!("cleanup: {id} is not ours, not touching it")),
        Err(AppError::NotFound(_)) => {
            eprintln!("cleanup: {id} is already gone");
            return Ok(());
        }
        Err(e) => return Err(format!("cleanup: x:MaskedEmail/get failed: {e}")),
    }
    match client.destroy_masked_email(id).await {
        Ok(()) => {
            eprintln!("cleanup: destroyed {id}");
        }
        Err(e) => {
            let disabled = client.set_masked_email_enabled(id, false).await;
            eprintln!(
                "!!!!! cleanup: x:MaskedEmail/set destroy of {id} FAILED ({e}); \
                 the test address is LEFT BEHIND, disabled: {:?} !!!!!",
                disabled.map(|m| m.enable)
            );
            return Err(format!("cleanup: destroy of {id} failed: {e}"));
        }
    }
    match client.get_masked_email(id).await {
        Err(AppError::NotFound(_)) => Ok(()),
        Ok(_) => Err(format!("cleanup: destroy reported success but {id} exists")),
        Err(e) => Err(format!(
            "cleanup: x:MaskedEmail/get after destroy failed: {e}"
        )),
    }
}

const SIEVE_CAPABILITY: &str = "urn:ietf:params:jmap:sieve";

/// Ids, names and active flags of the account's Sieve scripts.
async fn sieve_scripts(client: &JmapClient) -> Result<Vec<(String, String, bool)>, String> {
    let raw = client.raw().map_err(|e| e.to_string())?;
    let response = raw
        .call(
            &[SIEVE_CAPABILITY],
            "SieveScript/get",
            json!({"accountId": raw.account_id(), "ids": null, "properties": ["id", "name", "isActive"]}),
        )
        .await
        .map_err(|e| format!("SieveScript/get failed: {e}"))?;
    Ok(response["list"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            (
                s["id"].as_str().unwrap_or_default().to_string(),
                s["name"].as_str().unwrap_or_default().to_string(),
                s["isActive"].as_bool().unwrap_or_default(),
            )
        })
        .collect())
}

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_vacation_roundtrip_restores_state() {
    let Some(client) = connect().await else {
        return;
    };
    print_raw_shape(
        &client,
        "urn:ietf:params:jmap:vacationresponse",
        "VacationResponse/get",
        json!({"ids": ["singleton"]}),
    )
    .await;

    let original = ok("VacationResponse/get", client.get_vacation_response().await);
    eprintln!(
        "vacation before: enabled {}, dates set {}/{}, subject set {}, bodies set {}/{}",
        original.is_enabled,
        original.from_date.is_some(),
        original.to_date.is_some(),
        original.subject.is_some(),
        original.text_body.is_some(),
        original.html_body.is_some()
    );
    if original.is_enabled {
        eprintln!(
            "skipped the write: an auto-reply is active on this account and is left untouched"
        );
        return;
    }

    let scripts_before = sieve_scripts(&client).await;
    match &scripts_before {
        Ok(s) => eprintln!(
            "sieve scripts before: {} ({} active)",
            s.len(),
            s.iter().filter(|x| x.2).count()
        ),
        Err(e) => eprintln!("sieve scripts before: unavailable ({e})"),
    }

    let test_state = VacationResponse {
        is_enabled: false,
        from_date: Some("2099-01-01T00:00:00Z".into()),
        to_date: Some("2099-01-02T00:00:00Z".into()),
        subject: Some(format!("stalwart-mcp integration test {}", nanos())),
        text_body: Some("Automated stalwart-mcp test. Never enabled.".into()),
        html_body: None,
    };
    let stored = client.set_vacation_response(&test_state).await;

    // Restore no matter what the write did.
    let restored = client.set_vacation_response(&original).await;
    let final_state = client.get_vacation_response().await;

    // Restore first, so a failed write check never hides a failed restore.
    ok("VacationResponse/set (restore)", restored);
    let final_state = ok("VacationResponse/get (after restore)", final_state);
    assert_eq!(
        final_state, original,
        "vacation response NOT restored to its prior state"
    );
    eprintln!("vacation restored and equal to the prior state");
    let stored = ok("VacationResponse/set (test state)", stored);

    // An account without a vacation script gets one on the first update.
    if let (Ok(before), Ok(after)) = (scripts_before, sieve_scripts(&client).await) {
        let added: Vec<_> = after
            .iter()
            .filter(|s| before.iter().all(|b| b.0 != s.0))
            .collect();
        for (id, name, active) in &added {
            assert!(
                name == "vacation" && !active,
                "unexpected new sieve script {name:?} (active {active})"
            );
            let raw = ok("raw client", client.raw());
            let response = raw
                .call(
                    &[SIEVE_CAPABILITY],
                    "SieveScript/set",
                    json!({"accountId": raw.account_id(), "destroy": [id]}),
                )
                .await;
            match response {
                Ok(r)
                    if r["destroyed"]
                        .as_array()
                        .is_some_and(|d| d.iter().any(|x| x == id.as_str())) =>
                {
                    eprintln!("destroyed the inactive 'vacation' sieve script the update created");
                }
                other => eprintln!(
                    "!!!!! could not destroy the 'vacation' sieve script the update created: {other:?} !!!!!"
                ),
            }
        }
        let now = sieve_scripts(&client).await.unwrap_or_default();
        assert_eq!(
            now.iter().map(|s| (&s.0, s.2)).collect::<Vec<_>>(),
            before.iter().map(|s| (&s.0, s.2)).collect::<Vec<_>>(),
            "sieve scripts differ from before the test"
        );
        let again = ok("VacationResponse/get", client.get_vacation_response().await);
        assert_eq!(again, original, "vacation changed after script cleanup");
        eprintln!(
            "sieve scripts equal to before ({}), vacation still equal",
            now.len()
        );
    }

    assert_eq!(stored, test_state, "VacationResponse/get after set differs");
    eprintln!("test state had been written and read back equal (isEnabled false)");
}

#[tokio::test]
#[ignore = "requires running Stalwart instance"]
async fn test_quota_and_identities() {
    let Some(client) = connect().await else {
        return;
    };
    print_raw_shape(
        &client,
        "urn:ietf:params:jmap:quota",
        "Quota/get",
        json!({"ids": null}),
    )
    .await;
    print_raw_shape(
        &client,
        "urn:ietf:params:jmap:submission",
        "Identity/get",
        json!({"ids": null}),
    )
    .await;

    let quotas = ok("Quota/get", client.list_quotas().await);
    eprintln!("quotas: {}", quotas.len());
    for q in &quotas {
        eprintln!(
            "  quota {} {} scope {}: used {} of {}",
            q.id, q.resource_type, q.scope, q.used, q.hard_limit
        );
    }

    let identities = ok("Identity/get", client.list_identities().await);
    eprintln!("identities: {}", identities.len());
    assert!(
        !identities.is_empty(),
        "Identity/get returned no identities; mail_send needs one"
    );
    assert!(identities.iter().all(|i| i.email.contains('@')));
}

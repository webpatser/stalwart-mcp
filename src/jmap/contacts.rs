//! Read-only contacts lookup over JMAP (RFC 9610, capability
//! `urn:ietf:params:jmap:contacts`), cards in JSContact form (RFC 9553).
//!
//! Checked against Stalwart 1.1.1 (`crates/jmap/src/contact/`,
//! `crates/jmap/src/addressbook/`, `crates/calcard/src/jscontact/`):
//! - the capability is advertised in the session and per account; the
//!   per-account entry is withheld from users without contact permissions;
//! - `ContactCard/query` takes a `text` filter, a keyword match over name,
//!   nickname, organization, email and more, and caps `limit` at the server's
//!   `maxQueryResults`;
//! - `ContactCard/get` converts the stored vCard to JSContact on demand and
//!   honours `properties`, so only the fields in [`CARD_PROPERTIES`] are
//!   requested. `name.full` is set from the vCard FN; a card without it may
//!   only have `name.components`.
//!
//! Cards are third-party data of varying quality, so every field is
//! extracted defensively and a malformed card yields empty fields instead
//! of failing the result.

use crate::error::AppError;
use crate::jmap::JmapClient;
use crate::jmap::raw::parse_args;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

pub const JMAP_CONTACTS: &str = "urn:ietf:params:jmap:contacts";
const QUERY: &str = "ContactCard/query";
const GET: &str = "ContactCard/get";
const BOOKS: &str = "AddressBook/get";
/// The only card properties requested: no notes, photos, phone numbers or
/// postal addresses ever leave the server.
pub const CARD_PROPERTIES: &[&str] = &["id", "name", "emails", "organizations", "addressBookIds"];
const BOOK_PROPERTIES: &[&str] = &["id", "name"];

/// One contact as returned by `contacts_search`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactSummary {
    pub name: Option<String>,
    pub emails: Vec<String>,
    pub organizations: Vec<String>,
    pub address_books: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QueryResponse {
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    list: Vec<Value>,
}

pub fn query_args(account_id: &str, text: Option<&str>, limit: usize) -> Value {
    let mut args = Map::new();
    args.insert("accountId".into(), Value::from(account_id));
    if let Some(text) = text {
        args.insert("filter".into(), json!({ "text": text }));
    }
    args.insert("limit".into(), Value::from(limit));
    Value::Object(args)
}

pub fn get_args(account_id: &str, ids: &[String]) -> Value {
    json!({ "accountId": account_id, "ids": ids, "properties": CARD_PROPERTIES })
}

pub fn books_args(account_id: &str) -> Value {
    json!({ "accountId": account_id, "ids": null, "properties": BOOK_PROPERTIES })
}

fn non_empty(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Values of a JSContact map (`{"<id>": {...}}`); also accepts an array.
fn map_values(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Object(map)) => map.values().collect(),
        Some(Value::Array(list)) => list.iter().collect(),
        _ => Vec::new(),
    }
}

/// `name.full`, else the non-separator `name.components` joined by spaces.
fn card_name(card: &Value) -> Option<String> {
    let name = card.get("name")?;
    if let Some(full) = name.get("full").and_then(non_empty) {
        return Some(full);
    }
    let parts: Vec<String> = name
        .get("components")
        .and_then(Value::as_array)?
        .iter()
        .filter(|c| c.get("kind").and_then(Value::as_str) != Some("separator"))
        .filter_map(|c| c.get("value").and_then(non_empty))
        .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn card_field(card: &Value, map: &str, field: &str) -> Vec<String> {
    map_values(card.get(map))
        .into_iter()
        .filter_map(|entry| entry.get(field).and_then(non_empty))
        .collect()
}

/// Names of the address books in `addressBookIds` (ids whose value is
/// `true`); an unknown id is shown as-is.
fn card_books(card: &Value, books: &HashMap<String, String>) -> Vec<String> {
    let Some(ids) = card.get("addressBookIds").and_then(Value::as_object) else {
        return Vec::new();
    };
    ids.iter()
        .filter(|(_, member)| member.as_bool() == Some(true))
        .map(|(id, _)| books.get(id).cloned().unwrap_or_else(|| id.clone()))
        .collect()
}

/// Turn one card into a summary. Never fails: missing or odd fields are empty.
pub fn summarize(card: &Value, books: &HashMap<String, String>) -> ContactSummary {
    ContactSummary {
        name: card_name(card),
        emails: card_field(card, "emails", "address"),
        organizations: card_field(card, "organizations", "name"),
        address_books: card_books(card, books),
    }
}

fn parse_ids(response: Value) -> Result<Vec<String>, AppError> {
    Ok(parse_args::<QueryResponse>(QUERY, response)?.ids)
}

/// Cards in the order of `ids` (the query order); entries without an `id`
/// or not asked for are dropped.
fn parse_cards(response: Value, ids: &[String]) -> Result<Vec<Value>, AppError> {
    let mut by_id: HashMap<String, Value> = parse_args::<ListResponse>(GET, response)?
        .list
        .into_iter()
        .filter_map(|card| {
            let id = card.get("id")?.as_str()?.to_string();
            Some((id, card))
        })
        .collect();
    Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
}

/// Address book id to name; a book without a name maps to its id.
fn parse_books(response: Value) -> Result<HashMap<String, String>, AppError> {
    Ok(parse_args::<ListResponse>(BOOKS, response)?
        .list
        .iter()
        .filter_map(|book| {
            let id = book.get("id")?.as_str()?.to_string();
            let name = book
                .get("name")
                .and_then(non_empty)
                .unwrap_or_else(|| id.clone());
            Some((id, name))
        })
        .collect())
}

impl JmapClient {
    /// Whether the session and this account offer contacts.
    pub fn has_contacts(&self) -> bool {
        let session = self.client.session();
        session.has_capability(JMAP_CONTACTS)
            && session
                .account(&self.account_id)
                .is_some_and(|a| a.capability(JMAP_CONTACTS).is_some())
    }

    fn require_contacts(&self) -> Result<(), AppError> {
        if self.has_contacts() {
            Ok(())
        } else {
            Err(AppError::Rejected(format!(
                "this account does not offer contacts ({JMAP_CONTACTS} is not in the JMAP session)"
            )))
        }
    }

    /// All address books of the account, id to name.
    pub async fn address_books(&self) -> Result<HashMap<String, String>, AppError> {
        self.require_contacts()?;
        let raw = self.raw()?;
        let response = raw
            .call(&[JMAP_CONTACTS], BOOKS, books_args(raw.account_id()))
            .await?;
        parse_books(response)
    }

    /// Up to `limit` contacts matching `text` (all contacts when `None`),
    /// reduced to name, emails, organisations and address book names.
    pub async fn search_contacts(
        &self,
        text: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ContactSummary>, AppError> {
        self.require_contacts()?;
        let raw = self.raw()?;
        let response = raw
            .call(
                &[JMAP_CONTACTS],
                QUERY,
                query_args(raw.account_id(), text, limit),
            )
            .await?;
        let mut ids = parse_ids(response)?;
        ids.truncate(limit);
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let response = raw
            .call(&[JMAP_CONTACTS], GET, get_args(raw.account_id(), &ids))
            .await?;
        let cards = parse_cards(response, &ids)?;
        let books = self.address_books().await?;
        Ok(cards.iter().map(|card| summarize(card, &books)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn books() -> HashMap<String, String> {
        HashMap::from([("b1".to_string(), "Personal".to_string())])
    }

    #[test]
    fn query_sends_text_filter_and_limit() {
        assert_eq!(
            query_args("a1", Some("ada"), 20),
            json!({"accountId": "a1", "filter": {"text": "ada"}, "limit": 20})
        );
        assert_eq!(
            query_args("a1", None, 5),
            json!({"accountId": "a1", "limit": 5})
        );
    }

    #[test]
    fn get_requests_only_the_returned_properties() {
        let args = get_args("a1", &["c1".to_string()]);
        assert_eq!(
            args["properties"],
            json!(["id", "name", "emails", "organizations", "addressBookIds"])
        );
        for forbidden in ["notes", "media", "phones", "addresses"] {
            assert!(!CARD_PROPERTIES.contains(&forbidden), "{forbidden}");
        }
        assert_eq!(
            books_args("a1"),
            json!({"accountId": "a1", "ids": null, "properties": ["id", "name"]})
        );
    }

    #[test]
    fn summarizes_a_jscontact_card() {
        // RFC 9553 shape as Stalwart 1.1.1 converts it from vCard.
        let card = json!({
            "@type": "Card", "id": "c1",
            "addressBookIds": {"b1": true, "b9": true},
            "name": {"@type": "Name", "full": "Ada Example", "components": [
                {"kind": "given", "value": "Ada"}, {"kind": "surname", "value": "Example"}
            ]},
            "emails": {
                "e1": {"@type": "EmailAddress", "address": "ada@example.org"},
                "e2": {"@type": "EmailAddress", "address": "  "}
            },
            "organizations": {"o1": {"@type": "Organization", "name": "Example Org"}},
            "notes": {"n1": {"note": "must not appear"}}
        });
        let summary = summarize(&card, &books());
        assert_eq!(
            summary,
            ContactSummary {
                name: Some("Ada Example".into()),
                emails: vec!["ada@example.org".into()],
                organizations: vec!["Example Org".into()],
                address_books: vec!["Personal".into(), "b9".into()],
            }
        );
        let out = serde_json::to_value(&summary).expect("json");
        assert_eq!(
            out.as_object().map(|o| o.len()),
            Some(4),
            "only the four fields: {out}"
        );
        assert!(!out.to_string().contains("must not appear"));
    }

    #[test]
    fn name_falls_back_to_components() {
        let card = json!({"name": {"components": [
            {"kind": "given", "value": "Bob"},
            {"kind": "separator", "value": ","},
            {"kind": "surname", "value": "Sample"}
        ]}});
        assert_eq!(card_name(&card).as_deref(), Some("Bob Sample"));
        assert_eq!(card_name(&json!({"name": {"full": ""}})), None);
    }

    #[test]
    fn odd_cards_never_fail() {
        for card in [
            json!({}),
            json!(null),
            json!("text"),
            json!({"name": 7, "emails": "x", "organizations": [1, {"name": 2}], "addressBookIds": ["b1"]}),
            json!({"name": {"components": "x"}, "emails": {"e1": null}, "addressBookIds": {"b1": false}}),
        ] {
            let summary = summarize(&card, &books());
            assert_eq!(summary.name, None, "{card}");
            assert!(summary.emails.is_empty(), "{card}");
            assert!(summary.organizations.is_empty(), "{card}");
            assert!(summary.address_books.is_empty(), "{card}");
        }
        let listed = json!({"emails": [{"address": "carol@example.org"}]});
        assert_eq!(
            summarize(&listed, &books()).emails,
            vec!["carol@example.org"]
        );
    }

    #[test]
    fn parses_query_get_and_books() {
        let ids =
            parse_ids(json!({"accountId": "a1", "ids": ["c2", "c1"], "position": 0})).expect("ids");
        assert_eq!(ids, vec!["c2", "c1"]);
        let cards = parse_cards(
            json!({"accountId": "a1", "list": [{"id": "c1"}, {"no": "id"}, {"id": "c2"}, {"id": "c3"}], "notFound": []}),
            &ids,
        )
        .expect("cards");
        let order: Vec<_> = cards.iter().map(|c| c["id"].clone()).collect();
        assert_eq!(order, vec![json!("c2"), json!("c1")]);
        let books = parse_books(json!({"accountId": "a1", "list": [
            {"id": "b1", "name": "Personal"}, {"id": "b2"}, {"name": "no id"}
        ]}))
        .expect("books");
        assert_eq!(books.len(), 2);
        assert_eq!(books["b2"], "b2");
    }
}

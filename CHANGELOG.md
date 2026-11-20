# Changelog

## [1.1.1-2] - 2026-11-20

### Fixed
- `mail_send` uses the sending identity's address as From instead of the login name (a plain login name is not a valid From and does not match the identity the server submits as). It picks the identity whose address matches the account's username, else the first one.
- `mail_send` returns the id of the sent email in Sent, not the EmailSubmission id, and reports a rejected submission with the server's reason. A copy stored in Sent whose submission was rejected is removed again.
- `mail_draft` uses the same identity lookup as `mail_send`, so a draft's From is the identity's address (with its display name) instead of the plain login name.

## [1.1.1-1] - 2026-11-20

Tested against Stalwart 1.1.1.

### Added
- `mail_masked_list`, `mail_masked_create` and `mail_masked_disable`: Stalwart masked email addresses (`x:MaskedEmail/get` and `x:MaskedEmail/set` under `urn:stalwart:jmap`, Stalwart 1.1+). The server generates the address; a create may name a prefix, one of the account's domains, a description, the site it is for and an expiry. Disabling keeps the address.
- `mail_vacation_get` and `mail_vacation_set`: the RFC 8621 vacation response. A set replaces the whole response, so omitted fields are cleared.
- `quota_get` (`Quota/get`, RFC 9425) and `identity_list` (`Identity/get`).
- New capability flags `capabilities.masked_email` (create and disable masked addresses) and `capabilities.vacation` (change the vacation response, which makes the server send auto-replies). Both default to false; the list and get tools are always available.
- Server refusals from the new tools (for example the per-account masked address quota, `overQuota`) are passed to the client with the server's reason instead of a generic upstream error.
- `mail_vacation_set` refuses to enable an auto-reply without an end: `to_date` is required when `is_enabled` is true and must be in the future and at most 90 days ahead. Disabling needs no dates. The tool description now states that the server keeps replying after the session ends and that the reply must not contain private data.
- Input limits on the new tools: masked `description` 256 characters, `url` 2048, `for_domain` 255; vacation `subject` 998 characters, `text_body` and `html_body` 64 KiB each.

### Security
- The HTTP client for the new tools and for `spam_train` no longer follows redirects, so a 307 or 308 cannot re-post a JMAP request with its credentials to another host. It is built once per account instead of on every call.
- JMAP responses read by the new tools and `spam_train` are capped at 8 MB.
- The Authorization header copied from jmap-client is marked sensitive, and the raw JMAP and spam-filter clients print no headers in their `Debug` output.

### Changed
- The `mail_search` description notes that Stalwart indexes full text asynchronously, so very recent mail may not be found yet.

### Fixed
- `mail_draft` and `mail_send` now return the server's message id instead of a placeholder creation id.
- Rejected updates, moves and deletes are reported as errors, and the bulk tools return the number of messages the server actually changed.

## [1.0.3-1] - 2026-11-20

Versioning change: releases are now numbered `<stalwart version>-<mcp revision>`. The first three numbers are the Stalwart Mail Server release this build was tested against, and the number after the hyphen counts MCP-only releases on that Stalwart version (`1.0.3-1`, `1.0.3-2`, then `1.0.4-1` when Stalwart's API changes). This replaces the planned 0.3.0. Earlier releases (0.1.x and 0.2.0) keep their numbers.

### Changed
- The MCP server now reports this crate's name and version to clients; previously it reported rmcp's.
- `stalwart-mcp --version` prints the Cargo package version.
- **BREAKING:** `spam_train` now calls Stalwart v0.16's JMAP `SpamTrainingSample/set` method instead of the removed `/api/spam-filter/upload/*` REST endpoints. Training runs under the user's own account credentials.
- Removed `[admin_api]` config section and the `STALWART_ADMIN_PASSWORD` environment variable; no longer needed.
- `spam_train` no longer downloads raw email bodies locally; the server fetches each email's existing JMAP blob directly.
- HTTP mode refuses to start when `server.allowed_hosts` is set without `auth.secret`. This does not detect proxies: without a secret, a same-host reverse proxy that forwards a loopback Host is still trusted, so set `auth.secret` behind any proxy.
- Updated compatible dependencies, added `rust-version`, sorted the manifest, fixed the repository URL, and CI now builds with `--locked` and runs the tests.
- Upgraded `jsonwebtoken` to 12 (still on the `aws_lc_rs` backend); existing tokens stay valid, and `token create` now errors on an empty `auth.secret` instead of signing with an empty key.
- Upgraded `rmcp` to 3.11 and `axum` to 0.8; tool, prompt and resource definitions are unchanged, and the 2 MB request body cap now also applies inside the MCP transport.

### Compatibility
- Requires Stalwart v0.16.x or later for `spam_train`.
- All other tools remain compatible with v0.15.x and v0.16.x.

## [0.2.0] - 2026-04-15

### Added
- `mail_bulk_read` tool for bulk marking emails as read in a single JMAP request
- `mail_bulk_delete` tool for permanently deleting multiple emails in one JMAP request
- Rate limiter entries for all bulk operations and spam training

### Fixed
- Missing rate limiters for `mail_bulk_junk`, `mail_bulk_delete`, `mail_bulk_read`, and `spam_train`

## [0.1.0] - 2026-04-13

### Added
- JMAP mail client with multi-account support
- Read tools: `mail_list_folders`, `mail_list_recent`, `mail_search`, `mail_get`
- Write tools: `mail_flag`, `mail_move`, `mail_draft`, `mail_send`
- `mail_bulk_junk` tool for bulk marking emails as junk/notjunk
- `spam_train` tool for training Stalwart's Bayes classifier via admin API
- MCP Prompts: `triage_inbox`, `draft_reply`, `search_and_summarize`, `train_spam_filter`
- MCP Resources: accounts list, folder list, message content
- Real-time notifications via JMAP EventSource (SSE)
- Per-tool rate limiting with token bucket algorithm
- JWT authentication for remote HTTP connections
- Dual transport: stdio (local) and Streamable HTTP (remote)
- Structured audit logging with tracing
- Pagination support with offset parameter

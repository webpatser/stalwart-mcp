# Changelog

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

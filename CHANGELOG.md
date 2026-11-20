# Changelog

## [0.3.0] - 2026-04-21

### Changed
- **BREAKING:** `spam_train` now calls Stalwart v0.16's JMAP `SpamTrainingSample/set` method instead of the removed `/api/spam-filter/upload/*` REST endpoints. Training runs under the user's own account credentials.
- Removed `[admin_api]` config section and the `STALWART_ADMIN_PASSWORD` environment variable; no longer needed.
- `spam_train` no longer downloads raw email bodies locally; the server fetches each email's existing JMAP blob directly.
- HTTP mode refuses to start when `server.allowed_hosts` is set without `auth.secret`, so a same-host reverse proxy cannot bypass JWT auth.

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

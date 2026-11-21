# Changelog

## [1.1.1-5] - 2026-11-21

### Added
- Per-account `password_command`: an argv array run without a shell whose stdout is the password (stdin closed, at most 4 KiB, one trailing newline stripped, killed after 60 s). A failure names the account and carries the exit status plus at most the first stderr line, never the output. Use it or `password_env`, not both; with neither, `STALWART_PASSWORD` is read as before.
- The config is validated at load: duplicate account names, an empty `name`, `url` or `username`, an empty `password_command`, and a `default_account` that names no configured account are errors.
- `stalwart-mcp account add | list | edit <name> | remove <name> | test [name]` create and maintain the config file; they run without an existing config and honour `--config`. Password sources `env` (`--password-env`), `command` (`--password-command`, one flag per argument, program resolved to an absolute path at add time), `1password` and `keychain` (below). Missing values are prompted for on a terminal, otherwise the error names the flag; `--yes` skips confirmations. `add` checks the credentials in memory with a JMAP session fetch (`--no-verify` skips), writes the config (comments kept, atomic, 0600), then reads the password from the stored source once more; a failing check writes nothing. The first account becomes `default_account`, `--default` sets it, `edit --rename` keeps it pointing at the account, `remove` reports where it moved. `list` (and stable `list --json`) shows name, URL, username, password source (`env VAR`, `command <program>`, `1password`, `keychain`) and the default marker, never a secret or a command's arguments. `test` prints `ok` or the error per account and exits non-zero when any failed. New and renamed account names must match `[A-Za-z0-9_-]{1,64}`.
- Password source `1password` for `account add` and `edit`: detected when an `op` executable is on `PATH` or in `/opt/homebrew/bin` or `/usr/local/bin` and `op account list` shows an account. Reference an existing item with `--op-reference op://vault/item/field`, pick one interactively from the Login items whose URL host or title matches the mail host, or create a new Login item `stalwart-mcp <name>` in `--op-vault` from a typed password (`--password-stdin` reads it from stdin; the item template goes to `op` on stdin). The config stores `password_command = ["<absolute op path>", "read", "-n", "--account", "<account id>", "op://<vault id>/<item id>/password"]`, by ids so it survives renames and works from a client with a minimal `PATH`. Not yet tested against a real `op`.
- Password source `keychain` (macOS): the typed password is stored with `/usr/bin/security -i` (the command goes on stdin, never on a command line; no `-A`) under service `stalwart-mcp` and the account name, and the config stores `password_command = ["/usr/bin/security", "find-generic-password", "-s", "stalwart-mcp", "-a", "<name>", "-w"]`. An existing item is refused unless `--force`; passwords with a line break are refused.
- When the source is asked for on a terminal, the suggested default is 1Password when detected, else the Keychain on macOS, else `env`; without a terminal `--password-source` is required.
- A failure after a secret was stored (writing the config, the final read-back) deletes the 1Password item or Keychain item this run created again, and names it when that fails. An item overwritten with `--force` is not deleted.
- `account remove --delete-secret` deletes the Keychain item, located from the stored `password_command` (only when it has exactly the shape above), after the account is removed from the config; without the flag an interactive run asks. An item that another remaining account also reads is never deleted: `--delete-secret` is refused and the prompt is skipped. 1Password items are never deleted by `remove`. The printed hint for deleting an item by hand single-quotes the service and account for the shell.
- `account add` and `account edit` print a warning naming the path when the program of a written `password_command`, or its directory, belongs to another user (other than root) or is writable by group or others (Unix; a warning, not a refusal).
- `account edit --rename` of an account whose source is its own Keychain item moves the item to the new name (store, write, check, then delete the old item), so the item keeps matching the account.

### Changed
- All accounts connect concurrently at startup, so a slow password command does not delay the others. A failing account is still skipped with a warning. Without a usable `default_account` the first connected account in config order is the default.
- README: new "Connecting a client" section replaces the scattered client snippets (Claude Code, Claude Desktop, other stdio clients, HTTP with tokens); the examples no longer put the password in a client config file. It now starts from `stalwart-mcp account add` with a 1Password or Keychain source, so the client runs the binary directly; the wrapper script with an env file is the fallback.

### Security
- `accounts` can no longer be set or replaced through `STALWART_MCP_*` environment variables; they come from the config file bytes alone, whatever the variable's spelling (also with a space or tab after the prefix, mixed case or a nested key). The environment may only set keys under `server`, `capabilities`, `notifications` and `auth`; the README lists the overrides that work, and that keys with an underscore of their own (`default_account`, `server.allowed_hosts`, `capabilities.spam_training`, `capabilities.masked_email`, `notifications.ping_interval`) cannot be set from the environment, as before.
- On Unix a config containing a `password_command` is refused unless the file is owned by the current user and neither the file nor its directory is writable by group or others; the error names the fix (`chmod 600`). The check runs on the handle the file was read from, and a `password_command` without a config file is refused. Not checked on Windows.
- A password command, and every `op` or `security` call, runs in its own process group on Unix; on a timeout the whole group is killed, so a background process holding the output pipe cannot outlive it.
- A failing `security -i` (Keychain store) or `op item create`, both of which receive the password on stdin, is reported with its exit status only, without any stderr text.
- Passwords are held in a type whose `Debug` output is redacted.

## [1.1.1-4] - 2026-11-21

### Added
- Sieve filter tools (JMAP `SieveScript`, RFC 9661): `sieve_list`, `sieve_get` (source downloaded from the script's blob) and `sieve_validate` (server-side compile, no script stored; the source is uploaded as a temporary blob the server expires, so the tool is rate-limited), scope `mail:read`.
- `sieve_put` creates a script or replaces one by `id`, scope `mail:send` because a script can redirect mail. Behind the new `capabilities.sieve` (default false), checked before any request reaches the mail server, as are the 64 KiB script size cap and the name rules. The script is always validated first, is stored inactive unless `activate: true`, and the reserved name `vacation` is refused. Activation has never been run live; the live test stores its script inactive only.
- `contacts_search` (JMAP `ContactCard/query`, `ContactCard/get` and `AddressBook/get`, RFC 9610), scope `mail:read`, read-only: searches the account's contacts by text (the server matches whole words in name, email, organisation and other card fields) and returns per contact only the name, email addresses, organisations and address book names. Only `id`, `name`, `emails`, `organizations` and `addressBookIds` are requested from the server. Default 20 results, at most 50. Fails with a clear error when the session lacks `urn:ietf:params:jmap:contacts`.
- `mail_get_thread` (JMAP `Thread/get`, RFC 8621), scope `mail:read`: returns the conversation of a message as message summaries in the server's thread order, oldest first. Default 20 messages, at most 50; a longer thread returns the most recent ones plus an `omitted` count. An unknown message id is a not-found error.
- `mail_search` takes an optional `snippets` argument (default false). When true, `SearchSnippet/get` runs for the returned results and each gets a `snippet` with highlighted `subject` and `preview`; the server's `<mark>` tags are kept as returned. Without it the output is unchanged.
- Blob upload and download for the raw JMAP client; the session URLs must stay on the API URL's origin and redirects are not followed.
- Live tests for `spam_train` and `mail_bulk_junk` (`test_spam_training`, new `test_bulk_junk`), both opt-in with `STALWART_TEST_SPAM_TRAIN=1`. Each works on its own draft and destroys exactly the training samples it caused, found as new samples whose subject carries the run's unique token, then checks the sample count is back. `test_bulk_junk` needs this because Stalwart 1.1.1 stores a training sample on every move into Junk (spam) and out of it (ham). Destroying a sample does not undo training the classifier has already done.

### Fixed
- `spam_train` called `SpamTrainingSample/set`, which Stalwart 1.1.1 does not dispatch: its registry objects are only reachable under the `x:` prefix (`jmap-proto/src/request/method.rs` at `v1.1.1`). It now calls `x:SpamTrainingSample/set` with `urn:stalwart:jmap` in `using`.
- A method-level refusal of `spam_train` now reaches the MCP client with the server's reason instead of "Upstream request failed". On `forbidden` it adds that the account needs Stalwart's permission to create spam training samples (`sysSpamTrainingSampleCreate`), which a plain user account on Stalwart 1.1.1 does not have: the live run of `test_spam_training` was refused with exactly that error. A successful `spam_train` remains unproven live.

### Security
- `sieve_put` with an `id` now reads the target script before uploading anything: an unknown id is not found, the server-managed `vacation` script is refused (use `mail_vacation_set`), and replacing the active script, which changes live filtering immediately, is refused unless `activate: true`.
- Script names for `sieve_put` are at most 128 bytes and may not be `.` or `..` or contain `/` or control characters. Script downloads use the fixed name `script.sieve` instead of the server-provided one, and a session URL template value made only of dots is refused.
- Session upload and download URLs that carry a username or password are refused, in addition to the same-origin rule.

## [1.1.1-3] - 2026-11-21

### Security
- **Behaviour change:** JWT scopes and the `--account` restriction are now enforced (#3). Before, the claims were validated and then ignored, so any valid token could modify, send and reach every account. Every tool call and resource read is now checked at one point before it runs: read tools need `mail:read`; `mail_flag`, `mail_move`, `mail_draft`, `mail_bulk_read`, `mail_bulk_junk`, `mail_bulk_delete`, `mail_masked_create`, `mail_masked_disable` and `spam_train` need `mail:modify`; `mail_send` and `mail_vacation_set` need `mail:send`. Tokens created with the default `mail:read` lose write access; re-issue them with the scopes they need.
- A token restricted to an account may only name that account; a call without `account` runs against it, and `mail://accounts` lists only that account. Unknown tool names are refused.
- An HTTP request that reaches the MCP handler without an authorization context is refused (fail closed). The rule follows the transport the server instance was built for, not the shape of a request: a stdio server is unrestricted, and every instance the HTTP service creates requires an authorization context, so an HTTP request without one (or without its HTTP request data) is denied. Secret-less loopback HTTP stays unrestricted through the context the middleware inserts.
- `token create` rejects unknown scope strings; accepted are `mail:read`, `mail:modify`, `mail:send` and `*`.
- **Behaviour change:** `mail_bulk_delete` no longer destroys mail by default (#4). It now moves the emails to the Trash mailbox (resolved by its `trash` role, else a folder named "Trash") and reports how many the server actually moved; without a Trash mailbox it fails and deletes nothing. Permanent destruction needs the new `permanent: true` argument and the new `capabilities.delete = true` (default false); the capability is checked before any request reaches the mail server.
- Without `auth.secret`, a loopback HTTP request that carries any of `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Via`, `CF-Connecting-IP`, `True-Client-IP` or `X-Client-IP` (any value, any casing) is now rejected with 401 and a warning naming `auth.secret`: a request a reverse proxy forwarded is not a local client. A proxy that adds none of those headers is still trusted, so set `auth.secret` behind any proxy.
- `scripts/e2e.py` follows a redirect on its direct JMAP calls only to the same scheme, host and port as the configured server, so the Basic credential is never sent to another origin; any other redirect fails the run.

### Fixed
- Resource update notifications now name `mail://{account}/folders`, the declared resource, instead of `stalwart://inbox/{account}`, which matched nothing a client could subscribe to.
- The non-localhost warning at HTTP startup now also fires for an empty `auth.secret`.

### Changed
- Removed axum's `DefaultBodyLimit` layer, which never applied because no axum extractor reads the body. The 2 MB request limit is enforced by the MCP transport itself (413), now covered by a test.
- New `scripts/e2e.py`: an end-to-end MCP client for an installed binary against a live Stalwart. It sends no mail unless `--send` is given, cleans up what it creates, and reads all credentials from the environment.

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

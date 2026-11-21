//! Password stores the `account` CLI can write to: the 1Password CLI (`op`)
//! and the macOS Keychain (`/usr/bin/security`).
//!
//! Both are external programs whose paths are injectable, so tests run fake
//! scripts in their place. A password reaches a child only through stdin: the
//! `op item create` JSON template (built with `serde_json`) and the
//! `security -i` command line (built with [`quote_for_security`]). Every child
//! has a timeout and is killed when it is dropped. Errors carry the exit
//! status plus at most the first stderr line (200 characters, control
//! characters removed, dropped when it contains the password), never stdout.

use crate::secret::{MAX_PASSWORD_OUTPUT, Secret};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Keychain service under which `account add` stores passwords.
pub const KEYCHAIN_SERVICE: &str = "stalwart-mcp";

/// The macOS `security` tool; the stored `password_command` names this path.
pub const SECURITY_PROGRAM: &str = "/usr/bin/security";

/// Directories searched for `op` after the absolute `PATH` entries.
const OP_DIRS: [&str; 2] = ["/opt/homebrew/bin", "/usr/local/bin"];

/// `op account list` during detection; short, so a prompt cannot hang the CLI.
const DETECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Other `op` calls, which may wait for Touch ID or the app's unlock.
const OP_TIMEOUT: Duration = Duration::from_secs(120);

/// `security` calls, which may wait for a Keychain unlock dialog.
const SECURITY_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest stdout read from a store program (`op item list` can be long).
const MAX_STDOUT: usize = 4 * 1024 * 1024;

/// Bytes of stderr read; only the first line is used.
const MAX_STDERR_READ: u64 = 4096;

/// Characters of the first stderr line kept in an error message.
const MAX_STDERR_CHARS: usize = 200;

/// `security` exit status for errSecItemNotFound (-25300).
const SECURITY_ITEM_NOT_FOUND: i32 = 44;

/// Why a store operation failed. Never carries a password or stdout bytes.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("could not start {program}: {source}")]
    Spawn { program: String, source: io::Error },
    #[error("could not talk to {program}: {source}")]
    Io { program: String, source: io::Error },
    #[error("{program} did not finish within {} s and was killed", .timeout.as_secs())]
    Timeout { program: String, timeout: Duration },
    #[error(
        "{action} failed with {status}{}",
        .stderr.as_deref().map(|s| format!(": {s}")).unwrap_or_default()
    )]
    Failed {
        action: String,
        status: String,
        stderr: Option<String>,
    },
    /// The program answered in a way this code does not understand.
    #[error("{0}")]
    Unexpected(String),
    /// The input is not acceptable (a password with a line break, a bad reference).
    #[error("{0}")]
    Refused(String),
}

/// The stores available on this system, with injectable program paths.
#[derive(Debug, Clone, Default)]
pub struct SecretStores {
    /// The `op` executable, when one was found. Whether it has a usable
    /// account is checked only when needed ([`OnePassword::accounts`]).
    pub op: Option<OnePassword>,
    /// The Keychain; `None` outside macOS.
    pub keychain: Option<Keychain>,
}

impl SecretStores {
    /// `op` from `PATH` or the usual Homebrew directories, and the Keychain on
    /// macOS.
    pub fn system() -> Self {
        Self {
            op: OnePassword::find(std::env::var_os("PATH").as_deref()),
            keychain: Keychain::system(),
        }
    }
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

/// A buffer that may hold a secret (an `op` JSON answer includes field
/// values). Overwritten when dropped; `Debug` shows only its length.
struct Sensitive(Vec<u8>);

impl Drop for Sensitive {
    fn drop(&mut self) {
        wipe(std::mem::take(&mut self.0));
    }
}

impl fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sensitive({} bytes)", self.0.len())
    }
}

/// Overwrite a buffer, including its spare capacity, before freeing it.
fn wipe(mut bytes: Vec<u8>) {
    let capacity = bytes.capacity();
    bytes.clear();
    bytes.resize(capacity, 0);
    std::hint::black_box(&bytes);
}

#[derive(Debug)]
struct ToolOutput {
    status: ExitStatus,
    stdout: Sensitive,
    stderr: Option<String>,
}

impl ToolOutput {
    /// stdout on success, otherwise an error built from status and stderr.
    fn success(self, action: &str, redact: Option<&str>) -> Result<Sensitive, StoreError> {
        if self.status.success() {
            Ok(self.stdout)
        } else {
            Err(self.failure(action, redact))
        }
    }

    /// The error for a failed run; a stderr line containing `redact` is dropped.
    fn failure(&self, action: &str, redact: Option<&str>) -> StoreError {
        let stderr = self
            .stderr
            .clone()
            .filter(|line| !redact.is_some_and(|s| !s.is_empty() && line.contains(s)));
        StoreError::Failed {
            action: action.to_string(),
            status: self.status.to_string(),
            stderr,
        }
    }
}

/// Run `program args...` without a shell. `stdin` is written to the child and
/// then closed (null when `None`). The child is killed after `timeout`.
async fn run_tool(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<ToolOutput, StoreError> {
    let name = || program.to_string();
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| StoreError::Spawn {
            program: name(),
            source,
        })?;
    let io_err = |source: io::Error| StoreError::Io {
        program: name(),
        source,
    };
    let input = child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io_err(io::Error::other("no stdout pipe")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io_err(io::Error::other("no stderr pipe")))?;

    // `child` moves into the future, so a timeout drops (and kills) it.
    let run = async move {
        let write = async {
            let (Some(mut pipe), Some(bytes)) = (input, stdin) else {
                return Ok(());
            };
            let written = pipe.write_all(bytes).await;
            drop(pipe);
            match written {
                Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e),
                _ => Ok(()),
            }
        };
        let (written, out, err) = tokio::join!(
            write,
            read_capped(stdout, MAX_STDOUT as u64 + 1),
            read_capped(stderr, MAX_STDERR_READ)
        );
        let out = Sensitive(out.map_err(io_err)?);
        written.map_err(io_err)?;
        if out.0.len() > MAX_STDOUT {
            return Err(StoreError::Unexpected(format!(
                "{program} printed more than {MAX_STDOUT} bytes"
            )));
        }
        let status = child.wait().await.map_err(io_err)?;
        Ok(ToolOutput {
            status,
            stdout: out,
            stderr: first_stderr_line(&err.unwrap_or_default()),
        })
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| StoreError::Timeout {
            program: name(),
            timeout,
        })?
}

async fn read_capped(reader: impl AsyncRead + Unpin, limit: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.take(limit).read_to_end(&mut buf).await?;
    Ok(buf)
}

/// The first stderr line with control characters removed, trimmed and capped
/// at [`MAX_STDERR_CHARS`] characters; `None` when nothing is left.
fn first_stderr_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().next()?;
    let cleaned: String = line.chars().filter(|c| !c.is_control()).collect();
    let cleaned: String = cleaned.trim().chars().take(MAX_STDERR_CHARS).collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn parse_json<T: DeserializeOwned>(out: &Sensitive, action: &str) -> Result<T, StoreError> {
    // The serde error is not shown: its context could quote output bytes.
    serde_json::from_slice(&out.0).map_err(|_| {
        StoreError::Unexpected(format!(
            "could not read the JSON output of `{action}` (an op version this tool does not know?)"
        ))
    })
}

/// True for an existing regular file with an execute bit (any file on
/// non-Unix systems).
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// A password read from stdin (`--password-stdin`): one trailing `\n` or
/// `\r\n` is stripped; empty, over [`MAX_PASSWORD_OUTPUT`] bytes or not UTF-8
/// is refused. `bytes` is wiped on every error path.
pub fn password_from_stdin(mut bytes: Vec<u8>) -> Result<Secret, StoreError> {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
    if bytes.is_empty() {
        return Err(StoreError::Refused("no password on stdin".into()));
    }
    if bytes.len() > MAX_PASSWORD_OUTPUT {
        wipe(bytes);
        return Err(StoreError::Refused(format!(
            "the password on stdin is longer than {MAX_PASSWORD_OUTPUT} bytes"
        )));
    }
    String::from_utf8(bytes).map(Secret::new).map_err(|e| {
        wipe(e.into_bytes());
        StoreError::Refused("the password on stdin is not valid UTF-8".into())
    })
}

// ---------------------------------------------------------------------------
// macOS Keychain
// ---------------------------------------------------------------------------

/// The macOS Keychain through the `security` tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keychain {
    program: String,
    service: String,
}

impl Keychain {
    pub fn new(program: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            service: service.into(),
        }
    }

    /// `/usr/bin/security` with service [`KEYCHAIN_SERVICE`] on macOS.
    pub fn system() -> Option<Self> {
        cfg!(target_os = "macos").then(|| Self::new(SECURITY_PROGRAM, KEYCHAIN_SERVICE))
    }

    /// The same Keychain under another service name (tests, live check).
    pub fn with_service(self, service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            ..self
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    /// The `password_command` that reads the item of `account`.
    pub fn password_command(&self, account: &str) -> Vec<String> {
        [
            self.program.as_str(),
            "find-generic-password",
            "-s",
            &self.service,
            "-a",
            account,
            "-w",
        ]
        .map(String::from)
        .to_vec()
    }

    /// The Keychain account named by `argv` when it is exactly a
    /// [`Self::password_command`] of this program and service; `None` for any
    /// other shape. This is what `account remove --delete-secret` relies on.
    pub fn item_of<'a>(&self, argv: &'a [String]) -> Option<&'a str> {
        match argv {
            [program, find, s, service, a, account, w]
                if *program == self.program
                    && find == "find-generic-password"
                    && s == "-s"
                    && *service == self.service
                    && a == "-a"
                    && w == "-w"
                    && !account.is_empty()
                    && !account.chars().any(char::is_control) =>
            {
                Some(account.as_str())
            }
            _ => None,
        }
    }

    /// Whether an item for `account` exists (`find-generic-password` without
    /// `-w`, which reads attributes only).
    pub async fn exists(&self, account: &str) -> Result<bool, StoreError> {
        let out = run_tool(
            &self.program,
            &["find-generic-password", "-s", &self.service, "-a", account],
            None,
            SECURITY_TIMEOUT,
        )
        .await?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(SECURITY_ITEM_NOT_FOUND) => Ok(false),
            _ => Err(out.failure("security find-generic-password", None)),
        }
    }

    /// Store `password` for `account`. The command goes to `security -i` on
    /// stdin, so the password is never on a command line. `overwrite` adds
    /// `-U`; without it an existing item makes `security` fail. Never `-A`.
    /// Success is confirmed by [`Self::exists`].
    pub async fn store(
        &self,
        account: &str,
        password: &Secret,
        overwrite: bool,
    ) -> Result<(), StoreError> {
        check_keychain_password(password)?;
        let mut line = String::from("add-generic-password -s ");
        line.push_str(&quote_for_security(&self.service)?);
        line.push_str(" -a ");
        line.push_str(&quote_for_security(account)?);
        if overwrite {
            line.push_str(" -U");
        }
        line.push_str(" -w ");
        line.push_str(&quote_for_security(password.expose())?);
        line.push('\n');
        let line = Secret::new(line);
        // `security -i` exits with the status of a failed inner command (44
        // for a failed lookup, checked on macOS 27); the item is checked
        // afterwards all the same.
        let out = run_tool(
            &self.program,
            &["-i"],
            Some(line.expose().as_bytes()),
            SECURITY_TIMEOUT,
        )
        .await?;
        drop(line);
        out.success("security add-generic-password", Some(password.expose()))?;
        if self.exists(account).await? {
            Ok(())
        } else {
            Err(StoreError::Unexpected(format!(
                "the Keychain item (service '{}', account '{account}') was not found after \
                 storing it",
                self.service
            )))
        }
    }

    /// Delete the item of `account` and confirm it is gone.
    pub async fn delete(&self, account: &str) -> Result<(), StoreError> {
        run_tool(
            &self.program,
            &[
                "delete-generic-password",
                "-s",
                &self.service,
                "-a",
                account,
            ],
            None,
            SECURITY_TIMEOUT,
        )
        .await?
        .success("security delete-generic-password", None)?;
        if self.exists(account).await? {
            return Err(StoreError::Unexpected(format!(
                "the Keychain item (service '{}', account '{account}') still exists after \
                 deleting it",
                self.service
            )));
        }
        Ok(())
    }

    /// The shell command a user can run to delete the item by hand.
    pub fn delete_hint(&self, account: &str) -> String {
        format!(
            "security delete-generic-password -s {} -a {account}",
            self.service
        )
    }
}

/// Refuse passwords the `security -i` command line cannot carry: a CR or LF
/// would end the command, a NUL would cut it.
pub fn check_keychain_password(password: &Secret) -> Result<(), StoreError> {
    if password.expose().contains(['\r', '\n', '\0']) {
        return Err(StoreError::Refused(
            "the password contains a line break (or NUL), which the Keychain source cannot \
             store; use another password source"
                .into(),
        ));
    }
    Ok(())
}

/// One argument for a `security -i` command line: wrapped in double quotes,
/// with `"` and `\` escaped by a backslash. Everything else, including `'`,
/// `$`, spaces and `op://` text, is literal inside the quotes. CR, LF and NUL
/// are refused.
pub fn quote_for_security(value: &str) -> Result<String, StoreError> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(StoreError::Refused(
            "a value for the Keychain contains a line break or NUL".into(),
        ));
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    Ok(quoted)
}

// ---------------------------------------------------------------------------
// 1Password
// ---------------------------------------------------------------------------
//
// Unverified until `op` is installed and run (it was not on the development
// machine; built from the 1Password CLI docs):
// - `op account list --format json` neither prompts nor needs an unlock, and
//   prints `[{"url", "email", "user_uuid", "account_uuid"}]`;
// - `op item list --categories Login --format json` prints
//   `[{"id", "title", "vault": {"id", "name"}, "urls": [{"href"}]}]`;
// - `op item get --format json` prints `fields[]` with `id`, `label` and an
//   optional `section: {"id", "label"}`;
// - `op item create ... --url <url> --format json -` reads the JSON template
//   from stdin and prints the new item with `id` and `vault.id`;
// - `op read -n` from a client without a terminal waits for Touch ID or fails.

/// The 1Password CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnePassword {
    program: String,
}

/// One 1Password account known to `op`.
#[derive(Debug, Clone, Deserialize)]
pub struct OpAccount {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    user_uuid: Option<String>,
    #[serde(default)]
    account_uuid: Option<String>,
}

impl OpAccount {
    /// The id passed to `--account`: the account UUID, else the user UUID;
    /// `None` when neither looks like an id.
    pub fn id(&self) -> Option<&str> {
        [&self.account_uuid, &self.user_uuid]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .find(|id| is_op_id(id))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpVault {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpUrl {
    #[serde(default)]
    pub href: String,
}

/// A Login item from `op item list`. Holds no field values.
#[derive(Debug, Clone, Deserialize)]
pub struct OpItemSummary {
    pub id: String,
    #[serde(default)]
    pub title: String,
    pub vault: OpVault,
    #[serde(default)]
    pub urls: Vec<OpUrl>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpSection {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: String,
}

/// A field of `op item get`; its `value` is deliberately not deserialized.
#[derive(Debug, Clone, Deserialize)]
struct OpField {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    section: Option<OpSection>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpItem {
    id: String,
    vault: OpVault,
    #[serde(default)]
    fields: Vec<OpField>,
}

/// The ids of an item `op item create` made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedItem {
    pub vault_id: String,
    pub item_id: String,
}

/// A new Login item for [`OnePassword::item_create`].
#[derive(Debug)]
pub struct NewLogin<'a> {
    pub title: &'a str,
    pub username: &'a str,
    pub url: &'a str,
    pub password: &'a Secret,
}

#[derive(Serialize)]
struct LoginTemplate<'a> {
    title: &'a str,
    category: &'static str,
    fields: [TemplateField<'a>; 2],
}

impl fmt::Debug for LoginTemplate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginTemplate")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct TemplateField<'a> {
    id: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    purpose: &'static str,
    label: &'static str,
    value: &'a str,
}

impl fmt::Debug for TemplateField<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateField")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A parsed `op://vault/item[/section]/field` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpReference {
    pub vault: String,
    pub item: String,
    pub section: Option<String>,
    pub field: String,
}

impl OpReference {
    /// The password field of an item, by ids.
    pub fn password_of(vault_id: &str, item_id: &str) -> Self {
        Self {
            vault: vault_id.into(),
            item: item_id.into(),
            section: None,
            field: "password".into(),
        }
    }

    /// Parse `op://vault/item/field` or `op://vault/item/section/field`.
    /// Parts may be names (with spaces) or ids; query parameters, empty parts,
    /// parts starting with `-` and control characters are refused.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        let bad = |why: &str| {
            StoreError::Refused(format!(
                "invalid 1Password reference ({why}); expected op://vault/item/field"
            ))
        };
        let rest = text
            .strip_prefix("op://")
            .ok_or_else(|| bad("it does not start with op://"))?;
        if rest.contains('?') {
            return Err(bad("query parameters are not supported"));
        }
        if rest.chars().any(char::is_control) {
            return Err(bad("it contains control characters"));
        }
        let parts: Vec<&str> = rest.split('/').collect();
        if parts
            .iter()
            .any(|p| p.trim().is_empty() || p.starts_with('-'))
        {
            return Err(bad("a part is empty or starts with '-'"));
        }
        let owned = |s: &str| s.to_string();
        match parts[..] {
            [vault, item, field] => Ok(Self {
                vault: owned(vault),
                item: owned(item),
                section: None,
                field: owned(field),
            }),
            [vault, item, section, field] => Ok(Self {
                vault: owned(vault),
                item: owned(item),
                section: Some(owned(section)),
                field: owned(field),
            }),
            _ => Err(bad("it needs 3 or 4 parts")),
        }
    }

    pub fn to_uri(&self) -> String {
        match &self.section {
            Some(section) => format!("op://{}/{}/{section}/{}", self.vault, self.item, self.field),
            None => format!("op://{}/{}/{}", self.vault, self.item, self.field),
        }
    }

    fn all_ids(&self) -> bool {
        is_op_id(&self.vault)
            && is_op_id(&self.item)
            && is_op_id(&self.field)
            && self.section.as_deref().is_none_or(is_op_id)
    }
}

/// An id as `op` prints them: letters, digits, `-` and `_`, not starting
/// with `-`. Only such ids are written into a `password_command`.
fn is_op_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A value passed as an `op` argument: not empty, not an option, no control
/// characters.
fn check_op_arg(value: &str, what: &str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.starts_with('-') || value.chars().any(char::is_control) {
        return Err(StoreError::Refused(format!(
            "invalid {what}: it is empty, starts with '-' or contains control characters"
        )));
    }
    Ok(())
}

/// The Login items whose URL host is the mail host (or a parent domain of
/// it), or whose title contains the mail host; in list order.
pub fn matching_items<'a>(items: &'a [OpItemSummary], mail_host: &str) -> Vec<&'a OpItemSummary> {
    let host = mail_host.to_ascii_lowercase();
    if host.is_empty() {
        return Vec::new();
    }
    let host_matches = |href: &str| {
        url::Url::parse(href)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .is_some_and(|h| h == host || host.ends_with(&format!(".{h}")))
    };
    items
        .iter()
        .filter(|item| {
            item.urls.iter().any(|u| host_matches(&u.href))
                || item.title.to_ascii_lowercase().contains(&host)
        })
        .collect()
}

impl OnePassword {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// The first executable `op` in the absolute entries of `path_var`, then
    /// in `/opt/homebrew/bin` and `/usr/local/bin`. The path is kept as found
    /// (a Homebrew symlink survives upgrades).
    pub fn find(path_var: Option<&OsStr>) -> Option<Self> {
        path_var
            .into_iter()
            .flat_map(std::env::split_paths)
            .filter(|dir| dir.is_absolute())
            .chain(OP_DIRS.iter().map(PathBuf::from))
            .map(|dir| dir.join("op"))
            .find(|candidate| is_executable_file(candidate))
            .and_then(|p| p.into_os_string().into_string().ok())
            .map(Self::new)
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    async fn run(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
        action: &str,
        redact: Option<&str>,
    ) -> Result<Sensitive, StoreError> {
        run_tool(&self.program, args, stdin, timeout)
            .await?
            .success(action, redact)
    }

    /// The accounts `op` knows (`op account list --format json`), which is
    /// also the detection: it lists the accounts set up on this device and,
    /// per the 1Password docs, needs no unlock (unverified, see above).
    pub async fn accounts(&self) -> Result<Vec<OpAccount>, StoreError> {
        let action = "op account list";
        let out = self
            .run(
                &["account", "list", "--format", "json"],
                None,
                DETECT_TIMEOUT,
                action,
                None,
            )
            .await?;
        // An empty answer means no accounts.
        if out.0.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        parse_json(&out, action)
    }

    /// The Login items of `account` (`op item list --categories Login`).
    pub async fn item_list(&self, account: &str) -> Result<Vec<OpItemSummary>, StoreError> {
        let action = "op item list";
        let out = self
            .run(
                &[
                    "item",
                    "list",
                    "--categories",
                    "Login",
                    "--account",
                    account,
                    "--format",
                    "json",
                ],
                None,
                OP_TIMEOUT,
                action,
                None,
            )
            .await?;
        if out.0.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        let items: Vec<OpItemSummary> = parse_json(&out, action)?;
        Ok(items
            .into_iter()
            .filter(|i| is_op_id(&i.id) && is_op_id(&i.vault.id))
            .collect())
    }

    /// Resolve a reference by names or ids to one by ids, so it survives
    /// renames (`op item get --format json`). Field values are not read.
    pub async fn resolve(
        &self,
        account: &str,
        reference: &OpReference,
    ) -> Result<OpReference, StoreError> {
        check_op_arg(&reference.vault, "1Password vault")?;
        check_op_arg(&reference.item, "1Password item")?;
        let action = "op item get";
        let out = self
            .run(
                &[
                    "item",
                    "get",
                    &reference.item,
                    "--vault",
                    &reference.vault,
                    "--account",
                    account,
                    "--format",
                    "json",
                ],
                None,
                OP_TIMEOUT,
                action,
                None,
            )
            .await?;
        let item: OpItem = parse_json(&out, action)?;
        drop(out);
        let section_matches = |field: &OpField| match &reference.section {
            None => true,
            Some(wanted) => field
                .section
                .as_ref()
                .is_some_and(|s| s.id == *wanted || s.label.eq_ignore_ascii_case(wanted)),
        };
        let field = item
            .fields
            .iter()
            .find(|f| {
                (f.id == reference.field || f.label.eq_ignore_ascii_case(&reference.field))
                    && section_matches(f)
            })
            .ok_or_else(|| {
                StoreError::Refused(format!(
                    "the 1Password item has no field '{}'",
                    reference.field
                ))
            })?;
        let resolved = OpReference {
            vault: item.vault.id.clone(),
            item: item.id.clone(),
            section: reference
                .section
                .as_ref()
                .and_then(|_| field.section.as_ref().map(|s| s.id.clone())),
            field: field.id.clone(),
        };
        if !resolved.all_ids() {
            return Err(StoreError::Unexpected(
                "op returned ids this tool does not accept (letters, digits, '-' and '_' only)"
                    .into(),
            ));
        }
        Ok(resolved)
    }

    /// Create a Login item in `vault`. The JSON template, with the password,
    /// goes on stdin; title, username and URL are not secret.
    pub async fn item_create(
        &self,
        account: &str,
        vault: &str,
        login: &NewLogin<'_>,
    ) -> Result<CreatedItem, StoreError> {
        check_op_arg(vault, "1Password vault")?;
        let template = LoginTemplate {
            title: login.title,
            category: "LOGIN",
            fields: [
                TemplateField {
                    id: "username",
                    kind: "STRING",
                    purpose: "USERNAME",
                    label: "username",
                    value: login.username,
                },
                TemplateField {
                    id: "password",
                    kind: "CONCEALED",
                    purpose: "PASSWORD",
                    label: "password",
                    value: login.password.expose(),
                },
            ],
        };
        let json = Sensitive(serde_json::to_vec(&template).map_err(|_| {
            StoreError::Unexpected("could not build the 1Password item template".into())
        })?);
        let action = "op item create";
        let out = self
            .run(
                &[
                    "item",
                    "create",
                    "--vault",
                    vault,
                    "--account",
                    account,
                    "--url",
                    login.url,
                    "--format",
                    "json",
                    "-",
                ],
                Some(json.0.as_slice()),
                OP_TIMEOUT,
                action,
                Some(login.password.expose()),
            )
            .await?;
        drop(json);
        let item: OpItem = parse_json(&out, action)?;
        if !is_op_id(&item.id) || !is_op_id(&item.vault.id) {
            return Err(StoreError::Unexpected(
                "op returned item ids this tool does not accept".into(),
            ));
        }
        Ok(CreatedItem {
            vault_id: item.vault.id,
            item_id: item.id,
        })
    }

    /// Delete an item this run created (rollback only).
    pub async fn item_delete(&self, account: &str, item: &CreatedItem) -> Result<(), StoreError> {
        self.run(
            &[
                "item",
                "delete",
                &item.item_id,
                "--vault",
                &item.vault_id,
                "--account",
                account,
            ],
            None,
            OP_TIMEOUT,
            "op item delete",
            None,
        )
        .await
        .map(drop)
    }

    /// The `password_command` that reads `reference` (which must hold ids):
    /// absolute `op` path and `--account`, because a client started from the
    /// GUI has a minimal `PATH` and no `OP_ACCOUNT`.
    pub fn read_command(&self, account: &str, reference: &OpReference) -> Vec<String> {
        vec![
            self.program.clone(),
            "read".into(),
            "-n".into(),
            "--account".into(),
            account.into(),
            reference.to_uri(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE: &str = "not-a-real-password";

    #[test]
    fn quoting_keeps_every_character_literal_inside_double_quotes() {
        let q = |s: &str| quote_for_security(s).expect("quotable");
        assert_eq!(q("plain"), r#""plain""#);
        assert_eq!(q(r#"a"b"#), r#""a\"b""#);
        assert_eq!(q(r"a\b"), r#""a\\b""#);
        assert_eq!(q(r#"\""#), r#""\\\"""#);
        assert_eq!(q("it's"), r#""it's""#);
        assert_eq!(q("with space"), r#""with space""#);
        assert_eq!(q("$HOME $(id) `id`"), r#""$HOME $(id) `id`""#);
        assert_eq!(
            q("op://Private/Mail/password"),
            r#""op://Private/Mail/password""#
        );
        assert_eq!(q(""), r#""""#);
        // A trailing backslash cannot escape the closing quote.
        assert_eq!(q(r"x\"), r#""x\\""#);
        for bad in ["a\nb", "a\rb", "a\0b", "\n"] {
            assert!(quote_for_security(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn keychain_password_with_line_break_is_refused() {
        for bad in ["a\nb", "a\r", "\0"] {
            let err = check_keychain_password(&Secret::new(bad.into())).expect_err("refused");
            assert!(err.to_string().contains("line break"), "{err}");
        }
        check_keychain_password(&Secret::new(r#"q"\ $x 'y' op://a/b/c"#.into())).expect("ok");
    }

    #[test]
    fn keychain_command_shape_and_item_of() {
        let keychain = Keychain::new(SECURITY_PROGRAM, KEYCHAIN_SERVICE);
        let argv = keychain.password_command("work");
        assert_eq!(
            argv,
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "stalwart-mcp",
                "-a",
                "work",
                "-w"
            ]
        );
        assert_eq!(keychain.item_of(&argv), Some("work"));
        let other = Keychain::new(SECURITY_PROGRAM, "something-else");
        assert_eq!(other.item_of(&argv), None);
        let strings = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for bad in [
            strings(&["/usr/bin/security", "find-generic-password", "-w"]),
            strings(&[
                "/usr/local/bin/security",
                "find-generic-password",
                "-s",
                "stalwart-mcp",
                "-a",
                "work",
                "-w",
            ]),
            strings(&[
                "/usr/bin/security",
                "find-generic-password",
                "-a",
                "work",
                "-s",
                "stalwart-mcp",
                "-w",
            ]),
            strings(&[
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "stalwart-mcp",
                "-a",
                "",
                "-w",
            ]),
            strings(&[
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "stalwart-mcp",
                "-a",
                "work",
                "-w",
                "extra",
            ]),
        ] {
            assert_eq!(keychain.item_of(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn references_parse_and_render() {
        let r = OpReference::parse("op://Private/Mail work/password").expect("3 parts");
        assert_eq!(
            (r.vault.as_str(), r.item.as_str(), r.section.as_deref()),
            ("Private", "Mail work", None)
        );
        assert_eq!(r.to_uri(), "op://Private/Mail work/password");
        let r = OpReference::parse("op://v/i/s/f").expect("4 parts");
        assert_eq!(r.section.as_deref(), Some("s"));
        assert_eq!(r.to_uri(), "op://v/i/s/f");
        for bad in [
            "Private/Mail/password",
            "op://v/i",
            "op://v/i/s/f/x",
            "op://v//f",
            "op://v/i/f?attribute=otp",
            "op://-v/i/f",
            "op://v/i/f\n",
        ] {
            assert!(OpReference::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            OpReference::password_of("vid", "iid").to_uri(),
            "op://vid/iid/password"
        );
        assert!(OpReference::password_of("vid", "iid").all_ids());
        assert!(
            !OpReference::parse("op://Private/Mail work/password")
                .expect("ok")
                .all_ids()
        );
    }

    #[test]
    fn op_ids_and_accounts() {
        assert!(is_op_id("abcDEF123_-x"));
        for bad in ["", "-x", "a b", "a/b", "a?b"] {
            assert!(!is_op_id(bad), "{bad}");
        }
        let accounts: Vec<OpAccount> = serde_json::from_str(
            r#"[{"url":"my.1password.com","email":"me@example.com","user_uuid":"USER1","account_uuid":"ACC1"},
                {"url":"x","user_uuid":"USER2"},
                {"url":"y","account_uuid":"bad id"}]"#,
        )
        .expect("json");
        let ids: Vec<_> = accounts.iter().map(OpAccount::id).collect();
        assert_eq!(ids, [Some("ACC1"), Some("USER2"), None]);
    }

    #[test]
    fn items_match_by_url_host_or_title() {
        let items: Vec<OpItemSummary> = serde_json::from_str(
            r#"[{"id":"a","title":"Other","vault":{"id":"v"},"urls":[{"href":"https://other.org"}]},
                {"id":"b","title":"Mail","vault":{"id":"v"},"urls":[{"href":"https://example.com/login"}]},
                {"id":"c","title":"MAIL.example.com account","vault":{"id":"v"}},
                {"id":"d","title":"exact","vault":{"id":"v"},"urls":[{"href":"not a url"},{"href":"https://mail.example.com"}]},
                {"id":"e","title":"suffix trick","vault":{"id":"v"},"urls":[{"href":"https://ample.com"}]}]"#,
        )
        .expect("json");
        let ids: Vec<_> = matching_items(&items, "Mail.Example.com")
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        assert_eq!(ids, ["b", "c", "d"]);
        assert!(matching_items(&items, "").is_empty());
    }

    #[test]
    fn stdin_password_strips_one_newline_and_refuses_bad_input() {
        let p = password_from_stdin(format!("{FAKE}\n").into_bytes()).expect("ok");
        assert_eq!(p.expose(), FAKE);
        let p = password_from_stdin(format!("{FAKE}\r\n").into_bytes()).expect("ok");
        assert_eq!(p.expose(), FAKE);
        let p = password_from_stdin(format!("{FAKE}\n\n").into_bytes()).expect("ok");
        assert_eq!(p.expose(), format!("{FAKE}\n"));
        for bad in [
            Vec::new(),
            b"\n".to_vec(),
            vec![0xff, 0xfe],
            vec![b'a'; 4097],
        ] {
            let err = password_from_stdin(bad).expect_err("refused").to_string();
            assert!(!err.contains(FAKE), "{err}");
        }
    }

    #[test]
    fn template_and_debug_never_show_the_password() {
        let secret = Secret::new(FAKE.into());
        let login = NewLogin {
            title: "stalwart-mcp work",
            username: "u@example.com",
            url: "https://mail.example.com",
            password: &secret,
        };
        assert!(!format!("{login:?}").contains(FAKE));
        let field = TemplateField {
            id: "password",
            kind: "CONCEALED",
            purpose: "PASSWORD",
            label: "password",
            value: FAKE,
        };
        assert!(!format!("{field:?}").contains(FAKE));
        let out = Sensitive(FAKE.as_bytes().to_vec());
        assert!(!format!("{out:?}").contains(FAKE));
    }

    #[cfg(unix)]
    mod processes {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;

        const FAKE: &str = "not-a-real-password";

        /// A script run through `/bin/sh` (never exec'd itself, so no
        /// "text file busy" race on Linux).
        fn script(dir: &Path, body: &str) -> String {
            let path = dir.join("tool.sh");
            std::fs::write(&path, body).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            path.to_string_lossy().into_owned()
        }

        #[tokio::test]
        async fn stdin_reaches_the_child_and_errors_hold_no_stdout() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = script(
                dir.path(),
                "cat > \"$(dirname \"$0\")/in\"\nprintf 'secret-stdout'\necho 'first line' >&2\necho second >&2\nexit 3\n",
            );
            let out = run_tool(
                "/bin/sh",
                &[path.as_str()],
                Some(FAKE.as_bytes()),
                Duration::from_secs(10),
            )
            .await
            .expect("ran");
            assert_eq!(
                std::fs::read_to_string(dir.path().join("in")).expect("in"),
                FAKE
            );
            let err = out.success("tool", None).expect_err("exit 3").to_string();
            assert!(err.contains("first line") && err.contains('3'), "{err}");
            assert!(
                !err.contains("second") && !err.contains("secret-stdout"),
                "{err}"
            );
        }

        #[tokio::test]
        async fn a_stderr_line_with_the_password_is_dropped() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = script(dir.path(), &format!("echo 'bad: {FAKE}' >&2\nexit 1\n"));
            let out = run_tool("/bin/sh", &[path.as_str()], None, Duration::from_secs(10))
                .await
                .expect("ran");
            let err = out
                .success("tool", Some(FAKE))
                .expect_err("fails")
                .to_string();
            assert!(!err.contains(FAKE), "{err}");
            assert!(err.contains("failed with"), "{err}");
        }

        #[tokio::test]
        async fn a_hanging_child_is_killed_at_the_timeout() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = script(dir.path(), "exec sleep 30\n");
            let started = std::time::Instant::now();
            let err = run_tool(
                "/bin/sh",
                &[path.as_str()],
                None,
                Duration::from_millis(300),
            )
            .await
            .expect_err("timeout");
            assert!(matches!(err, StoreError::Timeout { .. }), "{err}");
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn op_is_found_on_path_absolute_entries_only() {
            let dir = tempfile::tempdir().expect("tempdir");
            let op = dir.path().join("op");
            std::fs::write(&op, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let path_var = std::ffi::OsString::from(format!("relative:{}", dir.path().display()));
            let found = OnePassword::find(Some(&path_var)).expect("found");
            assert_eq!(found.program(), op.to_str().expect("utf8"));
            std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o644)).expect("chmod");
            let found = OnePassword::find(Some(&path_var));
            assert!(found.is_none_or(|f| f.program() != op.to_str().expect("utf8")));
        }
    }
}

//! Secrets: the redacted [`Secret`] type, the `password_command` runner and the
//! permission check for config files that contain a command.

use crate::error::AppError;
use std::fmt;
use std::io;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// How long a `password_command` may run before it is killed.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest password output accepted from a `password_command`, in bytes.
pub const MAX_PASSWORD_OUTPUT: usize = 4096;

/// Bytes of stderr read from a failing command; only the first line is used.
const MAX_STDERR_READ: u64 = 4096;

/// Characters of the first stderr line kept in an error message.
const MAX_STDERR_CHARS: usize = 200;

/// A password held in memory. `Debug` never prints it, there is no `Display`,
/// and the buffer is overwritten (best effort) when it is dropped.
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The secret value. Pass it straight to the consumer; never log or format it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(std::mem::take(&mut self.0).into_bytes());
    }
}

/// Overwrite a buffer, including its spare capacity, before freeing it.
fn wipe(mut bytes: Vec<u8>) {
    let capacity = bytes.capacity();
    bytes.clear();
    bytes.resize(capacity, 0);
    std::hint::black_box(&bytes);
}

/// Why a `password_command` produced no password. The messages never contain
/// stdout bytes; a failing command contributes its exit status and at most the
/// first stderr line (control characters removed, capped at 200 characters).
#[derive(Debug, Error)]
pub enum PasswordCommandError {
    #[error("password_command is empty")]
    EmptyArgv,
    #[error("could not start the command: {0}")]
    Spawn(io::Error),
    #[error("could not read the command's output: {0}")]
    Read(io::Error),
    #[error("the command did not finish within {0:?} and was killed")]
    Timeout(Duration),
    #[error("the command printed more than {} bytes", MAX_PASSWORD_OUTPUT)]
    TooLarge,
    #[error("the command printed nothing")]
    EmptyOutput,
    #[error("the command's output is not valid UTF-8")]
    NotUtf8,
    #[error(
        "the command failed with {status}{}",
        .stderr.as_deref().map(|s| format!(": {s}")).unwrap_or_default()
    )]
    Failed {
        status: String,
        stderr: Option<String>,
    },
}

/// Run `argv` without a shell and return its stdout as the password.
///
/// stdin is null; stdout is capped at [`MAX_PASSWORD_OUTPUT`] bytes and one
/// trailing `\n` or `\r\n` is stripped. The child is killed when `timeout`
/// passes (and whenever the returned future is dropped).
pub async fn run_password_command(
    argv: &[String],
    timeout: Duration,
) -> Result<Secret, PasswordCommandError> {
    let (program, args) = argv.split_first().ok_or(PasswordCommandError::EmptyArgv)?;
    if program.is_empty() {
        return Err(PasswordCommandError::EmptyArgv);
    }

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(PasswordCommandError::Spawn)?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PasswordCommandError::Read(io::Error::other("no stdout pipe")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PasswordCommandError::Read(io::Error::other("no stderr pipe")))?;

    // `child` moves into the future, so a timeout drops (and kills) it.
    let run = async move {
        let (out, err) = tokio::join!(
            read_capped(stdout, MAX_PASSWORD_OUTPUT as u64 + 1),
            read_capped(stderr, MAX_STDERR_READ)
        );
        let out = out.map_err(PasswordCommandError::Read)?;
        if out.len() > MAX_PASSWORD_OUTPUT {
            wipe(out);
            return Err(PasswordCommandError::TooLarge);
        }
        let status = child.wait().await.map_err(PasswordCommandError::Read)?;
        if !status.success() {
            wipe(out);
            return Err(PasswordCommandError::Failed {
                status: status.to_string(),
                stderr: first_stderr_line(&err.unwrap_or_default()),
            });
        }
        to_secret(out)
    };

    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| PasswordCommandError::Timeout(timeout))?
}

async fn read_capped(reader: impl AsyncRead + Unpin, limit: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.take(limit).read_to_end(&mut buf).await?;
    Ok(buf)
}

fn to_secret(mut out: Vec<u8>) -> Result<Secret, PasswordCommandError> {
    if out.ends_with(b"\r\n") {
        out.truncate(out.len() - 2);
    } else if out.ends_with(b"\n") {
        out.truncate(out.len() - 1);
    }
    if out.is_empty() {
        return Err(PasswordCommandError::EmptyOutput);
    }
    String::from_utf8(out).map(Secret::new).map_err(|e| {
        wipe(e.into_bytes());
        PasswordCommandError::NotUtf8
    })
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

/// Refuse a config file containing a `password_command` that someone other
/// than the current user could change.
///
/// `file` is the handle the config was read from, so the file checked is the
/// file parsed. The file must be a regular file owned by the current user and
/// not writable by group or others; its directory (both the literal parent of
/// `path` and, for a symlinked config, the parent of the resolved file) must not
/// be writable by group or others and must be owned by the current user or root.
#[cfg(unix)]
pub fn check_config_permissions(file: &std::fs::File, path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let shown = path.display();

    let meta = file
        .metadata()
        .map_err(|e| AppError::Config(format!("Cannot check permissions of {shown}: {e}")))?;
    if !meta.is_file() {
        return Err(AppError::Config(format!("{shown} is not a regular file")));
    }
    if meta.uid() != uid {
        return Err(AppError::Config(format!(
            "{shown} contains a password_command but is not owned by the current user; \
             fix it with `chown $(id -u) {shown}` and `chmod 600 {shown}`"
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(AppError::Config(format!(
            "{shown} contains a password_command but is writable by group or others; \
             fix it with `chmod 600 {shown}`"
        )));
    }

    for dir in parent_dirs(path)? {
        let shown = dir.display();
        let meta = std::fs::metadata(&dir)
            .map_err(|e| AppError::Config(format!("Cannot check permissions of {shown}: {e}")))?;
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(AppError::Config(format!(
                "the config directory {shown} is not owned by the current user, so a \
                 password_command in it is refused; move the config into a directory you own \
                 (and `chmod 700` it)"
            )));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(AppError::Config(format!(
                "the config directory {shown} is writable by group or others, so a \
                 password_command in it is refused; fix it with `chmod 700 {shown}` and \
                 `chmod 600` on the config file"
            )));
        }
    }
    Ok(())
}

/// Permission checks are not implemented on this platform.
#[cfg(not(unix))]
pub fn check_config_permissions(_file: &std::fs::File, _path: &Path) -> Result<(), AppError> {
    Ok(())
}

#[cfg(unix)]
fn parent_dirs(path: &Path) -> Result<Vec<std::path::PathBuf>, AppError> {
    let canon = |p: &Path| {
        std::fs::canonicalize(p)
            .map_err(|e| AppError::Config(format!("Cannot resolve {}: {e}", p.display())))
    };
    let literal = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let mut dirs = vec![canon(&literal)?];
    if let Some(resolved) = canon(path)?.parent()
        && !dirs.iter().any(|d| d == resolved)
    {
        dirs.push(resolved.to_path_buf());
    }
    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const FAKE: &str = "not-a-real-password";

    /// Runs `body` with `/bin/sh <script>`, so the script itself is never exec'd
    /// (avoids "text file busy" races on Linux).
    async fn run_script(body: &str, timeout: Duration) -> Result<Secret, PasswordCommandError> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cmd.sh");
        std::fs::write(&path, body).expect("write script");
        let argv = vec!["/bin/sh".to_string(), path.to_string_lossy().into_owned()];
        run_password_command(&argv, timeout).await
    }

    async fn run(body: &str) -> Result<Secret, PasswordCommandError> {
        run_script(body, Duration::from_secs(10)).await
    }

    #[tokio::test]
    async fn prints_a_password() {
        let secret = run(&format!("printf '%s' '{FAKE}'\n")).await.expect("ok");
        assert_eq!(secret.expose(), FAKE);
    }

    #[tokio::test]
    async fn strips_one_trailing_newline() {
        let secret = run(&format!("printf '%s\\n' '{FAKE}'\n"))
            .await
            .expect("ok");
        assert_eq!(secret.expose(), FAKE);
        let secret = run(&format!("printf '%s\\r\\n' '{FAKE}'\n"))
            .await
            .expect("ok");
        assert_eq!(secret.expose(), FAKE);
        let secret = run(&format!("printf '%s\\n\\n' '{FAKE}'\n"))
            .await
            .expect("ok");
        assert_eq!(secret.expose(), format!("{FAKE}\n"));
    }

    #[tokio::test]
    async fn non_zero_exit_reports_status_and_first_stderr_line_only() {
        let err = run(&format!(
            "printf '%s' '{FAKE}'\nprintf 'item not found\\nsecond line\\n' >&2\nexit 3\n"
        ))
        .await
        .expect_err("fails");
        let msg = err.to_string();
        assert!(matches!(err, PasswordCommandError::Failed { .. }), "{msg}");
        assert!(msg.contains('3'), "{msg}");
        assert!(msg.contains("item not found"), "{msg}");
        assert!(!msg.contains("second line"), "{msg}");
        assert!(!msg.contains(FAKE), "{msg}");
    }

    #[tokio::test]
    async fn stderr_is_cleaned_and_capped() {
        let err = run("printf '\\033[31mred\\tx\\n' >&2\nexit 1\n")
            .await
            .expect_err("fails");
        let PasswordCommandError::Failed { stderr, .. } = &err else {
            panic!("unexpected {err}");
        };
        let stderr = stderr.as_deref().expect("stderr");
        assert!(!stderr.chars().any(char::is_control), "{stderr:?}");
        assert!(stderr.contains("red"), "{stderr:?}");

        let err = run("head -c 500 /dev/zero | tr '\\000' x >&2\nexit 1\n")
            .await
            .expect_err("fails");
        let PasswordCommandError::Failed { stderr, .. } = &err else {
            panic!("unexpected {err}");
        };
        assert_eq!(stderr.as_deref().map(|s| s.chars().count()), Some(200));

        let err = run("exit 2\n").await.expect_err("fails");
        assert!(
            matches!(err, PasswordCommandError::Failed { stderr: None, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn refuses_huge_output() {
        let err = run("head -c 1048576 /dev/zero | tr '\\000' a\n")
            .await
            .expect_err("too large");
        assert!(matches!(err, PasswordCommandError::TooLarge), "{err}");
    }

    #[tokio::test]
    async fn kills_a_command_past_the_timeout() {
        let started = Instant::now();
        let err = run_script("exec sleep 30\n", Duration::from_millis(300))
            .await
            .expect_err("timeout");
        assert!(matches!(err, PasswordCommandError::Timeout(_)), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn refuses_empty_output() {
        let err = run("exit 0\n").await.expect_err("empty");
        assert!(matches!(err, PasswordCommandError::EmptyOutput), "{err}");
        let err = run("printf '\\n'\n").await.expect_err("empty");
        assert!(matches!(err, PasswordCommandError::EmptyOutput), "{err}");
    }

    #[tokio::test]
    async fn refuses_empty_argv_and_missing_program() {
        let err = run_password_command(&[], DEFAULT_COMMAND_TIMEOUT)
            .await
            .expect_err("empty");
        assert!(matches!(err, PasswordCommandError::EmptyArgv));
        let err = run_password_command(&[String::new()], DEFAULT_COMMAND_TIMEOUT)
            .await
            .expect_err("empty");
        assert!(matches!(err, PasswordCommandError::EmptyArgv));
        let err = run_password_command(
            &["/nonexistent/stalwart-mcp-test-program".to_string()],
            DEFAULT_COMMAND_TIMEOUT,
        )
        .await
        .expect_err("missing");
        assert!(matches!(err, PasswordCommandError::Spawn(_)), "{err}");
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new(FAKE.to_string());
        let debug = format!("{secret:?} {:?}", Some(&secret));
        assert!(!debug.contains(FAKE), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    #[test]
    fn first_stderr_line_handles_crlf_and_blank() {
        assert_eq!(first_stderr_line(b"oops\r\nmore"), Some("oops".to_string()));
        assert_eq!(first_stderr_line(b"   \n"), None);
        assert_eq!(first_stderr_line(b""), None);
    }

    #[cfg(unix)]
    mod permissions {
        use super::super::check_config_permissions;
        use std::fs::{File, Permissions};
        use std::os::unix::fs::PermissionsExt;

        fn setup(dir_mode: u32, file_mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("config.toml");
            std::fs::write(&path, "").expect("write");
            std::fs::set_permissions(&path, Permissions::from_mode(file_mode)).expect("chmod");
            std::fs::set_permissions(dir.path(), Permissions::from_mode(dir_mode))
                .expect("chmod dir");
            (dir, path)
        }

        #[test]
        fn accepts_owner_only_file_in_owner_only_dir() {
            let (_dir, path) = setup(0o700, 0o600);
            let file = File::open(&path).expect("open");
            check_config_permissions(&file, &path).expect("accepted");
        }

        #[test]
        fn refuses_group_writable_file() {
            let (_dir, path) = setup(0o700, 0o620);
            let file = File::open(&path).expect("open");
            let err = check_config_permissions(&file, &path)
                .expect_err("refused")
                .to_string();
            assert!(err.contains("chmod 600"), "{err}");
        }

        #[test]
        fn refuses_group_writable_dir() {
            let (dir, path) = setup(0o770, 0o600);
            let file = File::open(&path).expect("open");
            let err = check_config_permissions(&file, &path)
                .expect_err("refused")
                .to_string();
            std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).expect("chmod");
            assert!(err.contains("chmod 700"), "{err}");
        }
    }
}

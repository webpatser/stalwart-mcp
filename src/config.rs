use crate::error::AppError;
use crate::secret::{DEFAULT_COMMAND_TIMEOUT, Secret, run_password_command};
use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable holding the password when an account sets neither
/// `password_env` nor `password_command`.
pub const DEFAULT_PASSWORD_ENV: &str = "STALWART_PASSWORD";

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    /// Only ever read from the config file; the environment cannot set it.
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
    pub default_account: Option<String>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccountConfig {
    pub name: String,
    pub url: String,
    pub username: String,
    /// Read the password from this environment variable. When neither this nor
    /// `password_command` is set, [`DEFAULT_PASSWORD_ENV`] is used.
    #[serde(default)]
    pub password_env: Option<String>,
    /// Run this argv (no shell) and use its stdout as the password. Honoured
    /// only from a config file the current user alone can write.
    #[serde(default)]
    pub password_command: Option<Vec<String>>,
}

/// Where an account's password comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSource<'a> {
    /// The named environment variable.
    Env(&'a str),
    /// The stdout of this argv.
    Command(&'a [String]),
}

impl AccountConfig {
    /// The password source; an error when both `password_env` and
    /// `password_command` are set.
    pub fn password_source(&self) -> Result<PasswordSource<'_>, AppError> {
        match (&self.password_env, &self.password_command) {
            (Some(_), Some(_)) => Err(AppError::Config(format!(
                "Account '{}' sets both password_env and password_command; keep only one",
                self.name
            ))),
            (_, Some(argv)) => Ok(PasswordSource::Command(argv)),
            (Some(var), None) => Ok(PasswordSource::Env(var)),
            (None, None) => Ok(PasswordSource::Env(DEFAULT_PASSWORD_ENV)),
        }
    }

    /// Resolve the password, running a `password_command` with the default
    /// timeout ([`DEFAULT_COMMAND_TIMEOUT`]).
    pub async fn resolve_password(&self) -> Result<Secret, AppError> {
        self.resolve_password_with_timeout(DEFAULT_COMMAND_TIMEOUT)
            .await
    }

    /// Resolve the password, killing a `password_command` after `timeout`.
    pub async fn resolve_password_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Secret, AppError> {
        match self.password_source()? {
            PasswordSource::Env(var) => std::env::var(var)
                .map(Secret::new)
                .map_err(|_| AppError::Config(format!("Environment variable '{var}' not set"))),
            PasswordSource::Command(argv) => {
                tracing::warn!(
                    account = %self.name,
                    program = %argv.first().map(String::as_str).unwrap_or_default(),
                    "Running password_command"
                );
                run_password_command(argv, timeout).await.map_err(|e| {
                    AppError::Config(format!(
                        "Account '{}': password_command failed: {e}",
                        self.name
                    ))
                })
            }
        }
    }

    /// Field checks done at load time.
    pub fn validate(&self) -> Result<(), AppError> {
        let name = &self.name;
        if name.trim().is_empty() {
            return Err(AppError::Config("An account has an empty name".into()));
        }
        if self.url.trim().is_empty() {
            return Err(AppError::Config(format!(
                "Account '{name}' has an empty url"
            )));
        }
        if self.username.trim().is_empty() {
            return Err(AppError::Config(format!(
                "Account '{name}' has an empty username"
            )));
        }
        if let PasswordSource::Command(argv) = self.password_source()?
            && argv.first().is_none_or(|p| p.is_empty())
        {
            return Err(AppError::Config(format!(
                "Account '{name}' has an empty password_command"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Allowed HTTP Host values. Empty retains rmcp's loopback-only defaults.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

fn default_bind() -> String {
    "127.0.0.1:3000".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Capabilities {
    /// Allow sending emails via mail_send tool. Default: false (must explicitly enable).
    #[serde(default)]
    pub send: bool,
    /// Allow spam training via the JMAP `SpamTrainingSample/set` method (Stalwart v0.16+).
    /// Default: false (must explicitly enable).
    #[serde(default)]
    pub spam_training: bool,
    /// Allow creating and disabling Stalwart masked addresses (`x:MaskedEmail/set`,
    /// Stalwart 1.1+). Listing them is always allowed. Default: false.
    #[serde(default)]
    pub masked_email: bool,
    /// Allow changing the vacation response. An enabled response makes the
    /// server auto-reply to every sender, also after the session ends, until
    /// its `to_date` (required, at most 90 days ahead). Reading it is always
    /// allowed. Default: false.
    #[serde(default)]
    pub vacation: bool,
    /// Allow `mail_bulk_delete` with `permanent: true`, which destroys emails
    /// beyond recovery. Moving them to Trash (the default) is always allowed.
    /// Default: false.
    #[serde(default)]
    pub delete: bool,
    /// Allow `sieve_put` to create or replace Sieve filter scripts. A wrong
    /// script can discard or redirect incoming mail. Listing, reading and
    /// validating scripts is always allowed. Default: false.
    #[serde(default)]
    pub sieve: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NotificationsConfig {
    /// Enable JMAP EventSource listener for real-time notifications. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Seconds between SSE keepalive pings. Default: 30.
    #[serde(default = "default_ping_interval")]
    pub ping_interval: u32,
}

fn default_true() -> bool {
    true
}

fn default_ping_interval() -> u32 {
    30
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            ping_interval: default_ping_interval(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthConfig {
    /// Secret for signing/validating JWT tokens. Auto-generated on first `token create` if not set.
    pub secret: Option<String>,
}

impl AuthConfig {
    /// True when a non-empty secret is configured. Matches the auth middleware,
    /// which treats a missing secret and `""` the same way (loopback bypass).
    pub fn has_secret(&self) -> bool {
        self.secret.as_deref().is_some_and(|s| !s.is_empty())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            allowed_hosts: Vec::new(),
        }
    }
}

/// The config file used when `--config` is not given.
pub fn default_config_path() -> PathBuf {
    dirs_config_path()
}

/// `config_path` or, when `None`, [`default_config_path`].
pub fn resolve_config_path(config_path: Option<&PathBuf>) -> PathBuf {
    config_path.cloned().unwrap_or_else(default_config_path)
}

/// Top-level sections that `STALWART_MCP_*` variables may set. Because of
/// the `split("_")`, only keys without an underscore of their own work:
/// `server.bind`, `capabilities.{send,vacation,delete,sieve}`,
/// `notifications.enabled` and `auth.secret`.
const ENV_SECTIONS: [&str; 4] = ["server", "capabilities", "notifications", "auth"];

/// True when an env key (after the prefix and the `_` split) names one of
/// [`ENV_SECTIONS`]. figment trims the key only after this filter ran, so the
/// check trims and lowercases itself: ` ACCOUNTS` or `\tAccounts` is refused.
fn env_key_allowed(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();
    let section = key.split('.').next().unwrap_or_default().trim();
    ENV_SECTIONS.contains(&section)
}

/// `STALWART_MCP_*` overrides, limited to [`ENV_SECTIONS`]. `accounts` is not
/// among them; [`AppConfig::load_from`] also takes the accounts from the file
/// alone, so neither accounts nor a `password_command` can be injected
/// through the environment, whatever shape the variable name has.
fn env_provider() -> Env {
    Env::prefixed("STALWART_MCP_")
        .split("_")
        .filter(|key| env_key_allowed(key.as_str()))
}

/// The part of the config that only the file may set.
#[derive(Debug, Deserialize)]
struct FileOnly {
    #[serde(default)]
    accounts: Vec<AccountConfig>,
}

impl AppConfig {
    /// Load and validate the config; at least one account is required (for
    /// `serve` and `token`).
    pub fn load(config_path: Option<&PathBuf>) -> Result<Self, AppError> {
        let path = resolve_config_path(config_path);
        let config = Self::load_from(&path)?;
        if config.accounts.is_empty() {
            return Err(AppError::Config(format!(
                "No accounts configured in {}",
                path.display()
            )));
        }
        Ok(config)
    }

    /// Like [`Self::load`], but a missing file or an empty `accounts` list is
    /// accepted (for the `account` subcommands, which create and edit accounts).
    pub fn load_allow_empty(config_path: Option<&PathBuf>) -> Result<Self, AppError> {
        Self::load_from(&resolve_config_path(config_path))
    }

    /// Read `path` once through a single handle, parse those bytes, merge the
    /// environment overrides and validate. When any account has a
    /// `password_command`, the same handle (and the directory) must pass
    /// [`crate::secret::check_config_permissions`].
    fn load_from(path: &Path) -> Result<Self, AppError> {
        let (file, content) = match std::fs::File::open(path) {
            Ok(mut file) => {
                let mut content = String::new();
                file.read_to_string(&mut content).map_err(|e| {
                    AppError::Config(format!("Cannot read {}: {e}", path.display()))
                })?;
                (Some(file), content)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, String::new()),
            Err(e) => {
                return Err(AppError::Config(format!(
                    "Cannot open {}: {e}",
                    path.display()
                )));
            }
        };

        let mut config: AppConfig = Figment::new()
            .merge(Toml::string(&content))
            .merge(env_provider())
            .extract()
            .map_err(|e| AppError::Config(e.to_string()))?;
        // Accounts come from the file bytes alone, never from the merge.
        let file_only: FileOnly = Figment::from(Toml::string(&content))
            .extract()
            .map_err(|e| AppError::Config(e.to_string()))?;
        config.accounts = file_only.accounts;

        config.validate_accounts()?;

        if config.accounts.iter().any(|a| a.password_command.is_some()) {
            match &file {
                Some(file) => crate::secret::check_config_permissions(file, path)?,
                None => {
                    return Err(AppError::Config(
                        "a password_command is only honoured from a config file".into(),
                    ));
                }
            }
        }

        Ok(config)
    }

    /// Account checks done at load time: per-account fields, unique names and
    /// a `default_account` that names a configured account.
    pub fn validate_accounts(&self) -> Result<(), AppError> {
        let mut seen = HashSet::new();
        for account in &self.accounts {
            account.validate()?;
            if !seen.insert(account.name.as_str()) {
                return Err(AppError::Config(format!(
                    "Duplicate account name '{}'",
                    account.name
                )));
            }
        }
        if let Some(default) = &self.default_account
            && !seen.contains(default.as_str())
        {
            return Err(AppError::Config(format!(
                "default_account '{default}' does not name a configured account"
            )));
        }
        Ok(())
    }

    /// Validate the merged config before serving. `http` is true for the HTTP transport.
    ///
    /// Refuses HTTP mode with `server.allowed_hosts` set and no `auth.secret`: a reverse
    /// proxy on the same host makes every request look like loopback, which the auth
    /// middleware lets through without a token when no secret is configured.
    pub fn validate(&self, http: bool) -> Result<(), crate::error::AppError> {
        if http && !self.server.allowed_hosts.is_empty() && !self.auth.has_secret() {
            return Err(crate::error::AppError::Config(
                "server.allowed_hosts is set but auth.secret is empty; behind a reverse proxy \
                 every request would look like loopback and skip authentication. Set auth.secret \
                 (run `stalwart-mcp token create` to generate one) or remove server.allowed_hosts"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(allowed_hosts: Vec<String>, secret: Option<&str>) -> AppConfig {
        AppConfig {
            accounts: Vec::new(),
            default_account: None,
            server: ServerConfig {
                allowed_hosts,
                ..Default::default()
            },
            capabilities: Capabilities::default(),
            notifications: NotificationsConfig::default(),
            auth: AuthConfig {
                secret: secret.map(str::to_string),
            },
        }
    }

    #[test]
    fn validate_refuses_allowed_hosts_without_secret() {
        for secret in [None, Some("")] {
            let err = config(vec!["mcp.example.com".into()], secret)
                .validate(true)
                .unwrap_err()
                .to_string();
            assert!(err.contains("server.allowed_hosts"), "{err}");
            assert!(err.contains("auth.secret"), "{err}");
        }
    }

    #[test]
    fn validate_passes_allowed_hosts_with_secret() {
        assert!(
            config(vec!["mcp.example.com".into()], Some("s3cret"))
                .validate(true)
                .is_ok()
        );
    }

    #[test]
    fn validate_passes_empty_allowed_hosts_without_secret() {
        assert!(config(Vec::new(), None).validate(true).is_ok());
        assert!(config(Vec::new(), Some("")).validate(true).is_ok());
    }

    #[test]
    fn write_capabilities_default_to_off() {
        let caps: Capabilities = serde_json::from_str("{}").expect("capabilities");
        assert!(
            !caps.send
                && !caps.spam_training
                && !caps.masked_email
                && !caps.vacation
                && !caps.delete
                && !caps.sieve
        );
        let caps: Capabilities = serde_json::from_str(
            r#"{"masked_email": true, "vacation": true, "delete": true, "sieve": true}"#,
        )
        .expect("caps");
        assert!(caps.masked_email && caps.vacation && caps.delete && caps.sieve);
    }

    #[test]
    fn validate_ignores_allowed_hosts_for_stdio() {
        assert!(
            config(vec!["mcp.example.com".into()], None)
                .validate(false)
                .is_ok()
        );
    }

    const FAKE: &str = "not-a-real-password";

    /// Serializes the tests that change the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Removes the variables it set, also when the test panics.
    struct EnvGuard(Vec<&'static str>);

    impl EnvGuard {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            for (key, value) in vars {
                // SAFETY: every test that changes the environment holds ENV_LOCK,
                // and no other test in this crate reads these variables.
                unsafe { std::env::set_var(key, value) };
            }
            Self(vars.iter().map(|(k, _)| *k).collect())
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in &self.0 {
                // SAFETY: see EnvGuard::set.
                unsafe { std::env::remove_var(key) };
            }
        }
    }

    /// A config file with mode 0600 in a fresh 0700 directory.
    fn write_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, content).expect("write config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod file");
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod dir");
        }
        (dir, path)
    }

    fn load_str(content: &str) -> Result<AppConfig, AppError> {
        let (_dir, path) = write_config(content);
        AppConfig::load(Some(&path))
    }

    fn load_err(content: &str) -> String {
        load_str(content).expect_err("load fails").to_string()
    }

    const ACCOUNT: &str = "[[accounts]]\nname = \"a\"\nurl = \"https://mail.example.com\"\nusername = \"user@example.com\"\n";

    #[test]
    fn load_password_env_only() {
        let config = load_str(&format!("{ACCOUNT}password_env = \"MY_PASSWORD\"\n")).expect("ok");
        assert_eq!(
            config.accounts[0].password_source().expect("source"),
            PasswordSource::Env("MY_PASSWORD")
        );
    }

    #[test]
    fn load_neither_defaults_to_stalwart_password() {
        let config = load_str(ACCOUNT).expect("ok");
        assert_eq!(
            config.accounts[0].password_source().expect("source"),
            PasswordSource::Env(DEFAULT_PASSWORD_ENV)
        );
        assert_eq!(DEFAULT_PASSWORD_ENV, "STALWART_PASSWORD");
    }

    #[test]
    fn load_password_command_only() {
        let config = load_str(&format!(
            "{ACCOUNT}password_command = [\"/usr/bin/printf\", \"%s\", \"x y\"]\n"
        ))
        .expect("ok");
        let argv = ["/usr/bin/printf", "%s", "x y"].map(String::from);
        assert_eq!(
            config.accounts[0].password_source().expect("source"),
            PasswordSource::Command(&argv)
        );
    }

    #[test]
    fn load_refuses_both_sources() {
        let err = load_err(&format!(
            "{ACCOUNT}password_env = \"X\"\npassword_command = [\"/bin/echo\"]\n"
        ));
        assert!(
            err.contains("password_env") && err.contains("password_command"),
            "{err}"
        );
    }

    #[test]
    fn load_refuses_empty_password_command() {
        let err = load_err(&format!("{ACCOUNT}password_command = []\n"));
        assert!(err.contains("empty password_command"), "{err}");
    }

    #[test]
    fn load_refuses_duplicate_names() {
        let err = load_err(&format!("{ACCOUNT}{ACCOUNT}"));
        assert!(err.contains("Duplicate account name 'a'"), "{err}");
    }

    #[test]
    fn load_refuses_unknown_default_account() {
        let err = load_err(&format!("default_account = \"b\"\n{ACCOUNT}"));
        assert!(err.contains("default_account 'b'"), "{err}");
        assert!(load_str(&format!("default_account = \"a\"\n{ACCOUNT}")).is_ok());
    }

    #[test]
    fn load_refuses_empty_fields() {
        for (field, toml) in [
            ("name", "name = \"\"\nurl = \"u\"\nusername = \"x\"\n"),
            ("url", "name = \"a\"\nurl = \" \"\nusername = \"x\"\n"),
            ("username", "name = \"a\"\nurl = \"u\"\nusername = \"\"\n"),
        ] {
            let err = load_err(&format!("[[accounts]]\n{toml}"));
            assert!(err.contains(&format!("empty {field}")), "{err}");
        }
    }

    #[test]
    fn load_requires_accounts_but_load_allow_empty_does_not() {
        let (_dir, path) = write_config("[server]\nbind = \"127.0.0.1:3001\"\n");
        let err = AppConfig::load(Some(&path))
            .expect_err("no accounts")
            .to_string();
        assert!(err.contains("No accounts configured"), "{err}");
        let config = AppConfig::load_allow_empty(Some(&path)).expect("ok");
        assert!(config.accounts.is_empty());

        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.toml");
        assert!(AppConfig::load(Some(&missing)).is_err());
        let config = AppConfig::load_allow_empty(Some(&missing)).expect("missing ok");
        assert!(config.accounts.is_empty());
    }

    const EVIL: &str = "[{name=\"evil\",url=\"https://evil.example\",username=\"e\",password_command=[\"/bin/sh\"]}]";

    #[test]
    fn env_key_filter_refuses_accounts_in_any_shape() {
        for key in [
            "accounts",
            " accounts",
            "\taccounts",
            "AcCoUnTs",
            "accounts.0.name",
            " accounts.0.password_command",
            "default.account",
            "unknown",
            "",
        ] {
            assert!(!env_key_allowed(key), "{key:?}");
        }
        for key in [
            "server.bind",
            "SERVER.BIND",
            "capabilities.send",
            "auth.secret",
        ] {
            assert!(env_key_allowed(key), "{key:?}");
        }
    }

    #[test]
    fn environment_cannot_set_accounts() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set(&[
            ("STALWART_MCP_ACCOUNTS", EVIL),
            ("STALWART_MCP_ ACCOUNTS", EVIL),
            ("STALWART_MCP_\tACCOUNTS", EVIL),
            ("STALWART_MCP_AcCoUnTs", EVIL),
            ("STALWART_MCP_ACCOUNTS_0_NAME", "evil"),
            ("STALWART_MCP_ ACCOUNTS_0_PASSWORD_COMMAND", "[\"/bin/sh\"]"),
            ("STALWART_MCP_SERVER_BIND", "127.0.0.1:3999"),
        ]);
        // Nothing below `accounts` gets past the provider at all.
        assert!(
            env_provider()
                .iter()
                .all(|(key, _)| !key.as_str().contains("accounts")),
            "an accounts key passed the env filter"
        );

        let config = load_str(ACCOUNT).expect("ok");
        assert_eq!(config.accounts.len(), 1);
        assert_eq!(config.accounts[0].name, "a");
        assert!(config.accounts[0].password_command.is_none());
        // Other overrides still apply.
        assert_eq!(config.server.bind, "127.0.0.1:3999");

        // Without a file there are no accounts, and none from the environment.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = AppConfig::load_allow_empty(Some(&dir.path().join("missing.toml")))
            .expect("missing ok");
        assert!(config.accounts.is_empty());
        assert_eq!(config.server.bind, "127.0.0.1:3999");
    }

    /// Exactly these `STALWART_MCP_*` overrides work (the README lists them);
    /// keys with an underscore of their own cannot be reached because of the
    /// `split("_")`.
    #[test]
    fn which_environment_overrides_work() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set(&[
            ("STALWART_MCP_SERVER_BIND", "127.0.0.1:3998"),
            ("STALWART_MCP_CAPABILITIES_SEND", "true"),
            ("STALWART_MCP_CAPABILITIES_VACATION", "true"),
            ("STALWART_MCP_CAPABILITIES_DELETE", "true"),
            ("STALWART_MCP_CAPABILITIES_SIEVE", "true"),
            ("STALWART_MCP_NOTIFICATIONS_ENABLED", "false"),
            ("STALWART_MCP_AUTH_SECRET", "env-secret-value"),
            // These do not work:
            ("STALWART_MCP_DEFAULT_ACCOUNT", "b"),
            ("STALWART_MCP_SERVER_ALLOWED_HOSTS", "[\"mcp.example.com\"]"),
            ("STALWART_MCP_CAPABILITIES_SPAM_TRAINING", "true"),
            ("STALWART_MCP_CAPABILITIES_MASKED_EMAIL", "true"),
            ("STALWART_MCP_NOTIFICATIONS_PING_INTERVAL", "5"),
        ]);
        let config = load_str(ACCOUNT).expect("ok");
        assert_eq!(config.server.bind, "127.0.0.1:3998");
        let caps = &config.capabilities;
        assert!(caps.send && caps.vacation && caps.delete && caps.sieve);
        assert!(!config.notifications.enabled);
        assert_eq!(config.auth.secret.as_deref(), Some("env-secret-value"));

        assert_eq!(config.default_account, None);
        assert!(config.server.allowed_hosts.is_empty());
        assert!(!caps.spam_training && !caps.masked_email);
        assert_eq!(config.notifications.ping_interval, 30);
    }

    #[cfg(unix)]
    #[test]
    fn password_command_needs_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let with_command = format!("{ACCOUNT}password_command = [\"/bin/echo\"]\n");

        let (_dir, path) = write_config(&with_command);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).expect("chmod");
        let err = AppConfig::load(Some(&path))
            .expect_err("refused")
            .to_string();
        assert!(err.contains("chmod 600"), "{err}");

        let (dir, path) = write_config(&with_command);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))
            .expect("chmod");
        let err = AppConfig::load(Some(&path))
            .expect_err("refused")
            .to_string();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        assert!(err.contains("chmod 700"), "{err}");

        // Without a password_command the permissions are not checked (as before).
        let (_dir, path) = write_config(ACCOUNT);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(AppConfig::load(Some(&path)).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resolve_password_runs_the_command_and_debug_stays_clean() {
        let (dir, _path) = write_config("");
        let script = dir.path().join("pw.sh");
        std::fs::write(&script, format!("printf '%s\\n' '{FAKE}'\n")).expect("script");
        let account = AccountConfig {
            name: "a".into(),
            url: "https://mail.example.com".into(),
            username: "user@example.com".into(),
            password_env: None,
            password_command: Some(vec![
                "/bin/sh".into(),
                script.to_string_lossy().into_owned(),
            ]),
        };
        let secret = account.resolve_password().await.expect("password");
        assert_eq!(secret.expose(), FAKE);
        let debug = format!("{account:?} {secret:?}");
        assert!(!debug.contains(FAKE), "{debug}");
    }

    #[tokio::test]
    async fn resolve_password_errors_name_the_account_not_the_output() {
        let account = AccountConfig {
            name: "work".into(),
            url: "https://mail.example.com".into(),
            username: "user@example.com".into(),
            password_env: None,
            password_command: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("printf '%s' '{FAKE}'; echo denied >&2; exit 1"),
            ]),
        };
        let err = account
            .resolve_password_with_timeout(Duration::from_secs(10))
            .await
            .expect_err("fails")
            .to_string();
        assert!(err.contains("'work'") && err.contains("denied"), "{err}");
        assert!(!err.contains(FAKE), "{err}");

        let account = AccountConfig {
            password_env: Some("STALWART_MCP_TEST_UNSET_VARIABLE".into()),
            password_command: None,
            ..account
        };
        let err = account
            .resolve_password()
            .await
            .expect_err("unset")
            .to_string();
        assert!(
            err.contains("Environment variable 'STALWART_MCP_TEST_UNSET_VARIABLE' not set"),
            "{err}"
        );
    }
}

fn dirs_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("stalwart-mcp")
        .join("config.toml")
}

/// Platform-aware config directory
mod dirs {
    use std::path::PathBuf;

    pub fn config_dir() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        }
        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var("HOME")
                        .ok()
                        .map(|h| PathBuf::from(h).join(".config"))
                })
        }
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA").ok().map(PathBuf::from)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }
}

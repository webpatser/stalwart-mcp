use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
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
    /// Read password from this environment variable
    #[serde(default = "default_password_env")]
    pub password_env: String,
}

fn default_password_env() -> String {
    "STALWART_PASSWORD".to_string()
}

impl AccountConfig {
    pub fn password(&self) -> Result<String, crate::error::AppError> {
        std::env::var(&self.password_env).map_err(|_| {
            crate::error::AppError::Config(format!(
                "Environment variable '{}' not set",
                self.password_env
            ))
        })
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
    /// Allow changing the vacation response, which makes the server send
    /// auto-replies when enabled. Reading it is always allowed. Default: false.
    #[serde(default)]
    pub vacation: bool,
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

impl AppConfig {
    pub fn load(config_path: Option<&PathBuf>) -> Result<Self, crate::error::AppError> {
        let default_path = dirs_config_path();

        let path = config_path
            .map(|p| p.as_path())
            .unwrap_or_else(|| default_path.as_path());

        let config: AppConfig = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("STALWART_MCP_").split("_"))
            .extract()
            .map_err(|e| crate::error::AppError::Config(e.to_string()))?;

        Ok(config)
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
        assert!(!caps.send && !caps.spam_training && !caps.masked_email && !caps.vacation);
        let caps: Capabilities =
            serde_json::from_str(r#"{"masked_email": true, "vacation": true}"#).expect("caps");
        assert!(caps.masked_email && caps.vacation);
    }

    #[test]
    fn validate_ignores_allowed_hosts_for_stdio() {
        assert!(
            config(vec!["mcp.example.com".into()], None)
                .validate(false)
                .is_ok()
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

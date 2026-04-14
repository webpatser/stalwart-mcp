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
    #[serde(default)]
    pub admin_api: AdminApiConfig,
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
}

fn default_bind() -> String {
    "127.0.0.1:3000".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Capabilities {
    /// Allow sending emails via mail_send tool. Default: false (must explicitly enable).
    #[serde(default)]
    pub send: bool,
    /// Allow spam training via admin API. Default: false (must explicitly enable).
    #[serde(default)]
    pub spam_training: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminApiConfig {
    /// Admin username. Default: "admin".
    #[serde(default = "default_admin_username")]
    pub username: String,
    /// Admin password directly in config. Takes precedence over password_env.
    pub password: Option<String>,
    /// Environment variable name for admin password. Default: "STALWART_ADMIN_PASSWORD".
    #[serde(default = "default_admin_password_env")]
    pub password_env: String,
}

fn default_admin_username() -> String {
    "admin".to_string()
}

fn default_admin_password_env() -> String {
    "STALWART_ADMIN_PASSWORD".to_string()
}

impl Default for AdminApiConfig {
    fn default() -> Self {
        Self {
            username: default_admin_username(),
            password: None,
            password_env: default_admin_password_env(),
        }
    }
}

impl AdminApiConfig {
    pub fn password(&self) -> Result<String, crate::error::AppError> {
        if let Some(ref pw) = self.password {
            return Ok(pw.clone());
        }
        std::env::var(&self.password_env).map_err(|_| {
            crate::error::AppError::Config(format!(
                "Set 'admin_api.password' in config or environment variable '{}'",
                self.password_env
            ))
        })
    }
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
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

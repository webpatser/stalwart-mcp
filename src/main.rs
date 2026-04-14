use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use stalwart_mcp::config::AppConfig;
use stalwart_mcp::jmap::AccountManager;
use stalwart_mcp::mcp::StalwartMcp;

#[derive(Parser)]
#[command(name = "stalwart-mcp", about = "MCP server for Stalwart Mail Server")]
struct Cli {
    /// Path to config file (default: ~/.config/stalwart-mcp/config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server
    Serve {
        /// Use stdio transport (for Claude Desktop / Cursor)
        #[arg(long, default_value_t = true, conflicts_with = "bind")]
        stdio: bool,

        /// Bind address for HTTP transport (e.g. 127.0.0.1:3000)
        #[arg(long)]
        bind: Option<String>,
    },

    /// Manage JWT tokens for HTTP authentication
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Create a new JWT token
    Create {
        /// Account name to authorize (or "*" for all accounts)
        #[arg(long, default_value = "*")]
        account: String,

        /// Comma-separated scopes: mail:read, mail:modify, mail:send, or * for all
        #[arg(long, default_value = "mail:read")]
        scopes: String,

        /// Token expiry in days
        #[arg(long, default_value = "365")]
        expires: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Init tracing — stderr only (stdout reserved for MCP stdio transport)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let config = AppConfig::load(cli.config.as_ref())?;

    match cli.command {
        Commands::Serve { stdio: _, bind } => {
            // Connect all accounts to Stalwart via JMAP
            let manager =
                AccountManager::connect_all(&config.accounts, config.default_account.as_deref())
                    .await?;
            let server = StalwartMcp::new(manager, config.capabilities, config.notifications);

            if let Some(addr) = bind {
                serve_http(server, &addr, &config.auth).await?;
            } else {
                serve_stdio(server).await?;
            }
        }
        Commands::Token { action } => match action {
            TokenAction::Create {
                account,
                scopes,
                expires,
            } => {
                let secret = get_or_create_secret(&config)?;
                let scopes: Vec<String> = scopes.split(',').map(|s| s.trim().to_string()).collect();

                let token = stalwart_mcp::auth::create_token(&secret, &account, &scopes, expires)?;

                eprintln!(
                    "Token created for account '{}' with scopes: {:?}",
                    account, scopes
                );
                eprintln!("Expires in {} days", expires);
                eprintln!();
                // Print token to stdout so it can be piped/copied
                println!("{token}");
            }
        },
    }

    Ok(())
}

/// Get the JWT secret from config, or generate and print instructions
fn get_or_create_secret(config: &AppConfig) -> anyhow::Result<String> {
    if let Some(ref secret) = config.auth.secret {
        Ok(secret.clone())
    } else {
        let secret = stalwart_mcp::auth::generate_secret();
        eprintln!("No auth.secret configured. Add this to your config.toml:");
        eprintln!();
        eprintln!("[auth]");
        eprintln!("secret = \"{}\"", secret);
        eprintln!();
        Ok(secret)
    }
}

async fn serve_stdio(server: StalwartMcp) -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    use rmcp::transport::io::stdio;

    tracing::info!("Starting MCP server on stdio");

    let notifications_enabled = server.notifications_config().enabled;
    let ping_interval = server.notifications_config().ping_interval;
    let accounts = server.accounts().clone();

    let service = server.serve(stdio()).await?;

    if notifications_enabled {
        let peer = service.peer().clone();
        tokio::spawn(stalwart_mcp::notifications::listen(
            accounts,
            peer,
            ping_interval,
        ));
    }

    service.waiting().await?;

    Ok(())
}

async fn serve_http(
    server: StalwartMcp,
    addr: &str,
    auth_config: &stalwart_mcp::config::AuthConfig,
) -> anyhow::Result<()> {
    use axum::Router;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpService, session::local::LocalSessionManager,
    };
    use stalwart_mcp::auth::AuthSecret;
    use std::sync::Arc;

    let is_localhost = addr.starts_with("127.0.0.1") || addr.starts_with("localhost");

    if !is_localhost && auth_config.secret.is_none() {
        tracing::warn!(
            addr = %addr,
            "HTTP mode bound to non-localhost WITHOUT auth.secret configured. Remote requests will be rejected!"
        );
    }

    if !is_localhost {
        tracing::info!(addr = %addr, "Starting MCP server on HTTP (JWT required for remote)");
    } else {
        tracing::info!(addr = %addr, "Starting MCP server on HTTP (localhost, no auth required)");
    }

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );

    let secret = auth_config.secret.clone().unwrap_or_default();

    let router = Router::new()
        .nest_service("/mcp", service)
        .layer(axum::Extension(AuthSecret(secret)))
        .layer(axum::middleware::from_fn(
            stalwart_mcp::auth::auth_middleware,
        ));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

use std::net::SocketAddr;

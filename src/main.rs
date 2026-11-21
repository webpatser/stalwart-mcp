use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use stalwart_mcp::config::AppConfig;
use stalwart_mcp::jmap::AccountManager;
use stalwart_mcp::mcp::StalwartMcp;

#[derive(Parser)]
#[command(
    name = "stalwart-mcp",
    version,
    about = "MCP server for Stalwart Mail Server"
)]
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
    // Init tracing: stderr only (stdout reserved for MCP stdio transport)
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
            // Fail fast, before connecting accounts or binding the HTTP listener
            config.validate(bind.is_some())?;

            // Connect all accounts to Stalwart via JMAP
            let manager =
                AccountManager::connect_all(&config.accounts, config.default_account.as_deref())
                    .await?;

            let server = StalwartMcp::new(manager, config.capabilities, config.notifications);

            if let Some(addr) = bind {
                serve_http(server, &addr, &config.auth, &config.server).await?;
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
                stalwart_mcp::mcp::authz::validate_scopes(&scopes)?;

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
    server_config: &stalwart_mcp::config::ServerConfig,
) -> anyhow::Result<()> {
    let is_localhost = addr.starts_with("127.0.0.1") || addr.starts_with("localhost");

    if !is_localhost && auth_config.secret.is_none() {
        tracing::warn!(
            addr = %addr,
            "HTTP mode bound to non-localhost WITHOUT auth.secret configured. Remote requests will be rejected!"
        );
    }

    if auth_config
        .secret
        .as_ref()
        .is_some_and(|secret| !secret.is_empty())
    {
        tracing::info!(addr = %addr, "Starting MCP server on HTTP (JWT required for all requests)");
    } else if !is_localhost {
        tracing::info!(addr = %addr, "Starting MCP server on HTTP (JWT required for remote)");
    } else {
        tracing::info!(addr = %addr, "Starting MCP server on HTTP (localhost, no auth required)");
    }

    let router = http_router(server, auth_config, server_config);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

use std::net::SocketAddr;

fn http_router(
    server: impl rmcp::ServerHandler + Clone,
    auth_config: &stalwart_mcp::config::AuthConfig,
    server_config: &stalwart_mcp::config::ServerConfig,
) -> axum::Router {
    use axum::{Router, extract::DefaultBodyLimit};
    use rmcp::transport::streamable_http_server::{
        StreamableHttpService, session::local::LocalSessionManager,
    };
    use stalwart_mcp::auth::AuthSecret;
    use std::sync::Arc;

    // Request bodies are capped at 2 MB. `DefaultBodyLimit` only governs axum extractors,
    // and the rmcp service reads the body itself, so its own limit is set to match.
    const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

    let mut transport_config =
        rmcp::transport::streamable_http_server::StreamableHttpServerConfig::default()
            .with_max_request_body_bytes(MAX_BODY_BYTES);
    // Empty keeps rmcp's loopback-only Host default; a non-empty list replaces it.
    if !server_config.allowed_hosts.is_empty() {
        transport_config = transport_config.with_allowed_hosts(server_config.allowed_hosts.clone());
    }

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        transport_config,
    );

    let secret = auth_config.secret.clone().unwrap_or_default();

    Router::new()
        .nest_service("/mcp", service)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(
            stalwart_mcp::auth::auth_middleware,
        ))
        .layer(axum::Extension(AuthSecret(secret)))
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock};
    use rmcp::service::RequestContext;
    use rmcp::{ErrorData, RoleServer};
    use stalwart_mcp::config::{AuthConfig, ServerConfig};
    use stalwart_mcp::mcp::authz;
    use tower::ServiceExt;

    const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"regression-test","version":"1"}}}"#;
    const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

    /// Test server with the same authorization choke point as `StalwartMcp::call_tool`.
    /// Any tool name from the scope table "runs" and reports the account it got.
    #[derive(Clone)]
    struct TestServer;
    impl rmcp::ServerHandler for TestServer {
        async fn call_tool(
            &self,
            mut request: CallToolRequestParams,
            context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, ErrorData> {
            authz::resolve(&context)?.authorize_tool_call(&mut request)?;
            let account = request
                .arguments
                .as_ref()
                .and_then(|args| args.get("account"))
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            let text = format!("ran {} on {account}", request.name);
            Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into())
        }
    }

    fn test_router(secret: &str, hosts: Vec<String>) -> axum::Router {
        http_router(
            TestServer,
            &AuthConfig {
                secret: Some(secret.into()),
            },
            &ServerConfig {
                allowed_hosts: hosts,
                ..Default::default()
            },
        )
    }

    /// Send one POST to `/mcp` with optional extra headers and a JSON-RPC body.
    async fn send(
        router: &axum::Router,
        local: bool,
        token: Option<&str>,
        host: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", host)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(Body::from(body.to_string())).unwrap();
        let addr = if local {
            "127.0.0.1:1234"
        } else {
            "192.0.2.1:1234"
        };
        request
            .extensions_mut()
            .insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        router.clone().oneshot(request).await.unwrap()
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            axum::body::to_bytes(response.into_body(), usize::MAX),
        )
        .await
        .expect("response body did not finish")
        .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    async fn request(
        local: bool,
        secret: &str,
        token: Option<&str>,
        host: &str,
        hosts: Vec<String>,
    ) -> StatusCode {
        send(
            &test_router(secret, hosts),
            local,
            token,
            host,
            &[],
            INITIALIZE,
        )
        .await
        .status()
    }

    /// Initialize a session and call one tool; returns the response body text.
    async fn call_tool(
        local: bool,
        secret: &str,
        token: Option<&str>,
        tool: &str,
        args: serde_json::Value,
    ) -> String {
        let router = test_router(secret, vec![]);
        let init = send(&router, local, token, "localhost", &[], INITIALIZE).await;
        assert_eq!(init.status(), StatusCode::OK);
        let session = init
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .expect("session id")
            .to_string();
        body_text(init).await;
        let headers = [
            ("mcp-session-id", session.as_str()),
            ("mcp-protocol-version", "2025-03-26"),
        ];
        let ack = send(&router, local, token, "localhost", &headers, INITIALIZED).await;
        assert!(ack.status().is_success(), "initialized: {}", ack.status());
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args },
        })
        .to_string();
        let response = send(&router, local, token, "localhost", &headers, &call).await;
        assert_eq!(response.status(), StatusCode::OK);
        body_text(response).await
    }

    #[tokio::test]
    async fn scopes_and_account_restriction_over_http() {
        let secret = "test-secret-used-only-in-tests";
        let token = |account: &str, scopes: &[&str]| {
            let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
            stalwart_mcp::auth::create_token(secret, account, &scopes, 1).unwrap()
        };
        let empty = serde_json::json!({});

        let read_only = token("*", &["mail:read"]);
        let body = call_tool(false, secret, Some(&read_only), "mail_get", empty.clone()).await;
        assert!(body.contains("ran mail_get on default"), "{body}");
        let body = call_tool(false, secret, Some(&read_only), "mail_flag", empty.clone()).await;
        assert!(body.contains("Forbidden"), "{body}");
        assert!(!body.contains("ran mail_flag"), "{body}");

        let work = token("work", &["mail:read"]);
        let other = serde_json::json!({ "account": "personal" });
        let body = call_tool(false, secret, Some(&work), "mail_get", other.clone()).await;
        assert!(body.contains("Forbidden"), "{body}");
        let body = call_tool(false, secret, Some(&work), "mail_get", empty.clone()).await;
        assert!(body.contains("ran mail_get on work"), "{body}");

        let all = token("*", &["*"]);
        let body = call_tool(false, secret, Some(&all), "mail_flag", other.clone()).await;
        assert!(body.contains("ran mail_flag on personal"), "{body}");

        let body = call_tool(true, "", None, "mail_send", other).await;
        assert!(body.contains("ran mail_send on personal"), "{body}");
    }

    #[tokio::test]
    async fn authentication_matrix_and_layer_order() {
        let secret = "test-secret-used-only-in-tests";
        let valid = stalwart_mcp::auth::create_token(secret, "*", &["*".into()], 1).unwrap();
        let wrong = stalwart_mcp::auth::create_token("wrong-secret", "*", &[], 1).unwrap();
        assert_eq!(
            request(true, "", None, "localhost", vec![]).await,
            StatusCode::OK
        );
        assert_eq!(
            request(false, "", None, "localhost", vec![]).await,
            StatusCode::UNAUTHORIZED
        );
        for local in [true, false] {
            for token in [None, Some("invalid"), Some(wrong.as_str())] {
                assert_eq!(
                    request(local, secret, token, "localhost", vec![]).await,
                    StatusCode::UNAUTHORIZED
                );
            }
            assert_eq!(
                request(local, secret, Some(&valid), "localhost", vec![]).await,
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn allowed_hosts_keep_defaults_and_support_proxy_hostname() {
        assert_eq!(
            request(true, "", None, "untrusted.example", vec![]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(
                true,
                "",
                None,
                "mcp.example.com",
                vec!["mcp.example.com".into()]
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            request(
                true,
                "",
                None,
                "untrusted.example",
                vec!["mcp.example.com".into()]
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }
}

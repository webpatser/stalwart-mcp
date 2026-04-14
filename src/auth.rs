use axum::{
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Account name or "*" for all accounts
    pub sub: String,
    /// Scopes: "mail:read", "mail:modify", "mail:send"
    pub scopes: Vec<String>,
    /// Expiry (seconds since epoch)
    pub exp: u64,
    /// Issued at (seconds since epoch)
    pub iat: u64,
}

impl Claims {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }
}

/// Create a signed JWT token
pub fn create_token(
    secret: &str,
    account: &str,
    scopes: &[String],
    expires_in_days: u64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = Claims {
        sub: account.to_string(),
        scopes: scopes.to_vec(),
        exp: now + (expires_in_days * 86400),
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Validate a JWT token and return claims
pub fn validate_token(secret: &str, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Generate a random secret for JWT signing
pub fn generate_secret() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..64)
        .map(|_| {
            let idx: u8 = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Axum middleware: require JWT for non-loopback requests
pub async fn auth_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(secret): axum::Extension<AuthSecret>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Local requests skip auth
    if addr.ip().is_loopback() {
        return Ok(next.run(request).await);
    }

    // No secret configured → reject all remote requests
    if secret.0.is_empty() {
        tracing::warn!(addr = %addr, "Remote request rejected: no auth.secret configured");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    match validate_token(&secret.0, token) {
        Ok(_claims) => Ok(next.run(request).await),
        Err(e) => {
            tracing::warn!(error = %e, addr = %addr, "JWT validation failed");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Wrapper to pass the JWT secret through request extensions
#[derive(Clone)]
pub struct AuthSecret(pub String);

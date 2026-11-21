use crate::mcp::authz::AuthContext;
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
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
        &EncodingKey::from_secret(secret.as_bytes())?,
    )
}

/// Validate a JWT token and return claims
pub fn validate_token(secret: &str, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes())?,
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

/// Axum middleware: require JWT when a secret is configured; otherwise allow loopback only
pub async fn auth_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(secret): axum::Extension<AuthSecret>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Every request that passes carries an AuthContext; the MCP handler refuses
    // an HTTP request without one.
    // A configured secret also protects requests from a local reverse proxy.
    if addr.ip().is_loopback() && secret.0.is_empty() {
        // A request a reverse proxy forwarded is not a local client, even though
        // the TCP peer is loopback. A proxy that strips these headers is still
        // trusted, so a secret stays mandatory behind any proxy.
        if is_forwarded(request.headers()) {
            tracing::warn!(
                addr = %addr,
                "Forwarded request rejected: no auth.secret configured; set auth.secret to serve behind a reverse proxy"
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
        request.extensions_mut().insert(AuthContext::unrestricted());
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
        Ok(claims) => {
            request
                .extensions_mut()
                .insert(AuthContext::from_claims(&claims));
            Ok(next.run(request).await)
        }
        Err(e) => {
            tracing::warn!(error = %e, addr = %addr, "JWT validation failed");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Headers a reverse proxy adds to say the request came from somewhere else.
const FORWARDING_HEADERS: [&str; 3] = ["forwarded", "x-forwarded-for", "x-real-ip"];

/// True when the request carries any proxy forwarding header, whatever its
/// value (even empty). `HeaderMap` lookups are case-insensitive.
pub fn is_forwarded(headers: &HeaderMap) -> bool {
    FORWARDING_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
}

/// Wrapper to pass the JWT secret through request extensions
#[derive(Clone)]
pub struct AuthSecret(pub String);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn forwarding_headers_are_detected() {
        assert!(!is_forwarded(&HeaderMap::new()));
        for name in [
            "Forwarded",
            "X-Forwarded-For",
            "x-real-ip",
            "X-REAL-IP",
            "x-forwarded-for",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static(""),
            );
            assert!(is_forwarded(&headers), "{name}");
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", HeaderValue::from_static("a"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(!is_forwarded(&headers));
    }
}

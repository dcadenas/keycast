// ABOUTME: JWT cookie extraction and validation utilities for OAuth authorization server

use axum::http::HeaderMap;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user public key
    pub exp: usize,  // expiration time
}

fn get_jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| {
        eprintln!("WARNING: JWT_SECRET not set in environment, using insecure default");
        "insecure-dev-secret-change-in-production".to_string()
    })
}

/// Extract JWT token from Cookie header
/// Looks for cookies in format: "keycast_session=<token>" or "jwt=<token>"
pub fn extract_jwt_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;

    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(token) = cookie.strip_prefix("keycast_session=") {
            return Some(token.to_string());
        }
        if let Some(token) = cookie.strip_prefix("jwt=") {
            return Some(token.to_string());
        }
    }

    None
}

/// Validate JWT token and extract user public key
pub fn extract_user_from_jwt_cookie(headers: &HeaderMap) -> Option<String> {
    let token = extract_jwt_from_cookie(headers)?;

    let jwt_secret = get_jwt_secret();
    let validation = Validation::default();

    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &validation,
    )
    .ok()?;

    Some(token_data.claims.sub)
}

/// Create JWT cookie string for Set-Cookie header
/// Returns formatted cookie with HttpOnly, Secure, SameSite=Lax attributes
pub fn create_jwt_cookie(token: &str) -> String {
    format!(
        "keycast_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400",
        token
    )
}

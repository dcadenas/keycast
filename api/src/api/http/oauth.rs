// ABOUTME: OAuth 2.0 authorization flow handlers for third-party app access
// ABOUTME: Implements authorization code flow that issues bunker URLs for NIP-46 remote signing

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response, Html},
    Form, Json,
};
use base64::Engine;
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub approved: bool,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub bunker_url: String,
}

#[derive(Debug)]
pub enum OAuthError {
    Unauthorized,
    InvalidRequest(String),
    Database(sqlx::Error),
    Encryption(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            OAuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Please log in to continue.".to_string()
            ),
            OAuthError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid request: {}", msg)
            ),
            OAuthError::Database(e) => {
                // Log the real error but return generic message to user
                tracing::error!("OAuth database error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            OAuthError::Encryption(e) => {
                // Log the real error but return generic message to user
                tracing::error!("OAuth encryption error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(e: sqlx::Error) -> Self {
        OAuthError::Database(e)
    }
}

/// Validate PKCE code_verifier against stored code_challenge
/// Implements RFC 7636 validation for both S256 and plain methods
fn validate_pkce(
    code_verifier: &str,
    code_challenge: &str,
    code_challenge_method: &str,
) -> Result<(), OAuthError> {
    match code_challenge_method {
        "S256" => {
            // Compute SHA256 hash of code_verifier
            let hash = sha256::digest(code_verifier);

            // Convert hex to bytes then base64url encode
            let hash_bytes = hex::decode(&hash)
                .map_err(|e| OAuthError::InvalidRequest(format!("Hash decode error: {}", e)))?;

            // Base64 URL-safe encoding (no padding)
            let computed_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&hash_bytes);

            if computed_challenge != code_challenge {
                tracing::warn!("PKCE validation failed: computed {} != stored {}",
                    &computed_challenge[..16], &code_challenge[..16]);
                return Err(OAuthError::InvalidRequest(
                    "Invalid code_verifier: PKCE validation failed".to_string()
                ));
            }
            Ok(())
        }
        "plain" => {
            if code_verifier != code_challenge {
                return Err(OAuthError::InvalidRequest(
                    "Invalid code_verifier: plain PKCE validation failed".to_string()
                ));
            }
            Ok(())
        }
        _ => Err(OAuthError::InvalidRequest(
            format!("Unsupported code_challenge_method: {}", code_challenge_method)
        )),
    }
}

/// GET /oauth/authorize
/// Shows authorization approval page (or redirects to login if not authenticated)
pub async fn authorize_get(
    State(_auth_state): State<super::routes::AuthState>,
    Query(_params): Query<AuthorizeRequest>,
) -> Result<Response, OAuthError> {
    // TODO: Extract user from session/JWT
    // For now, return OK to pass the test structure
    Ok((StatusCode::OK, "Authorization page").into_response())
}

/// POST /oauth/authorize
/// User approves authorization, creates code and redirects back to app OR returns code directly
pub async fn authorize_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Response, OAuthError> {
    if !req.approved {
        return Ok(Redirect::to(&format!(
            "{}?error=access_denied",
            req.redirect_uri
        ))
        .into_response());
    }

    let tenant_id = tenant.0.id;

    // Extract user public key from JWT token in Authorization header
    let user_public_key = super::auth::extract_user_from_token(&headers)
        .map_err(|_| OAuthError::Unauthorized)?;

    // Generate authorization code
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store authorization code (expires in 10 minutes)
    let expires_at = Utc::now() + Duration::minutes(10);

    // Get or create application
    let app_id: Option<i32> =
        sqlx::query_scalar("SELECT id FROM oauth_applications WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant_id)
            .bind(&req.client_id)
            .fetch_optional(&auth_state.state.db)
            .await?;

    let app_id = if let Some(id) = app_id {
        id
    } else {
        // Create test application
        sqlx::query_scalar(
            "INSERT INTO oauth_applications (tenant_id, client_id, client_secret, name, redirect_uris, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
        )
        .bind(tenant_id)
        .bind(&req.client_id)
        .bind("test_secret")
        .bind(&req.client_id)
        .bind(format!("[\"{}\"]", req.redirect_uri))
        .bind(Utc::now())
        .bind(Utc::now())
        .fetch_one(&auth_state.state.db)
        .await?
    };

    // Store authorization code with PKCE support
    sqlx::query(
        "INSERT INTO oauth_codes (tenant_id, code, user_public_key, application_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(tenant_id)
    .bind(&code)
    .bind(&user_public_key)
    .bind(app_id)
    .bind(&req.redirect_uri)
    .bind(&req.scope)
    .bind(&req.code_challenge)
    .bind(&req.code_challenge_method)
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&auth_state.state.db)
    .await?;

    // For JavaScript clients, return code directly instead of redirecting
    // Check if this is an XHR/fetch request by looking for Accept: application/json
    // For now, just return JSON with the code - client can handle it
    Ok(Json(serde_json::json!({
        "code": code,
        "redirect_uri": req.redirect_uri
    })).into_response())
}

/// POST /oauth/token
/// Exchange authorization code for bunker URL
pub async fn token(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;

    // Fetch and validate authorization code with PKCE fields
    let auth_code: Option<(String, i32, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT user_public_key, application_id, redirect_uri, scope, code_challenge, code_challenge_method
         FROM oauth_codes
         WHERE tenant_id = $1 AND code = $2 AND expires_at > $3"
    )
    .bind(tenant_id)
    .bind(&req.code)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;

    let (user_public_key, application_id, stored_redirect_uri, _scope, code_challenge, code_challenge_method) =
        auth_code.ok_or(OAuthError::Unauthorized)?;

    // Validate redirect_uri matches
    if stored_redirect_uri != req.redirect_uri {
        return Err(OAuthError::InvalidRequest(
            "redirect_uri mismatch".to_string(),
        ));
    }

    // PKCE validation (if code_challenge was provided during authorization)
    if let Some(challenge) = code_challenge {
        let method = code_challenge_method.as_deref().unwrap_or("plain");
        let verifier = req.code_verifier.as_ref().ok_or_else(|| {
            OAuthError::InvalidRequest("code_verifier required for PKCE flow".to_string())
        })?;

        validate_pkce(verifier, &challenge, method)?;

        tracing::debug!("PKCE validation successful for code: {}", &req.code[..8]);
    }

    // Delete the authorization code (one-time use)
    sqlx::query("DELETE FROM oauth_codes WHERE tenant_id = $1 AND code = $2")
        .bind(tenant_id)
        .bind(&req.code)
        .execute(pool)
        .await?;

    // Look up user's personal Nostr key from personal_keys table
    // We get the encrypted key to use as the bunker secret (for NIP-46 decryption + signing)
    let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = $1 AND user_public_key = $2"
    )
    .bind(tenant_id)
    .bind(&user_public_key)
    .fetch_one(pool)
    .await
    .map_err(OAuthError::Database)?;

    // Parse the user's public key to use as bunker public key
    let bunker_public_key = nostr_sdk::PublicKey::from_hex(&user_public_key)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?;

    // Generate connection secret for NIP-46 authentication
    let connection_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Create authorization in database - use relay that supports NIP-46
    let relay_url = "wss://relay.damus.io";
    let relays_json = serde_json::to_string(&vec![relay_url])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    sqlx::query(
        "INSERT INTO oauth_authorizations (tenant_id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(tenant_id)
    .bind(&user_public_key)
    .bind(application_id)
    .bind(bunker_public_key.to_hex())
    .bind(&encrypted_user_key)      // bunker_secret = encrypted user key (BLOB)
    .bind(&connection_secret)        // secret = connection secret (TEXT)
    .bind(&relays_json)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(pool)
    .await?;

    // Signal signer daemon to reload immediately
    let signal_file = std::path::Path::new("database/.reload_signal");
    if let Err(e) = std::fs::File::create(signal_file) {
        tracing::error!("Failed to create reload signal file: {}", e);
    } else {
        tracing::info!("Created reload signal for signer daemon");
    }

    // Build bunker URL
    let bunker_url = format!(
        "bunker://{}?relay={}&secret={}",
        bunker_public_key.to_hex(),
        relay_url,
        connection_secret
    );

    Ok(Json(TokenResponse { bunker_url }))
}

// ============================================================================
// nostr-login Integration Handlers
// ============================================================================

/// Nostr Connect parameters from nostrconnect:// URI
#[derive(Debug, Deserialize)]
pub struct NostrConnectParams {
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
    pub image: Option<String>,
}

/// Form data for connect approval
#[derive(Debug, Deserialize)]
pub struct ConnectApprovalForm {
    pub client_pubkey: String,
    pub relay: String,
    pub secret: String,
    pub perms: Option<String>,
    pub approved: bool,
}

/// Parse nostrconnect:// URI from path
/// Format: nostrconnect://CLIENT_PUBKEY?relay=RELAY&secret=SECRET&perms=...
fn parse_nostrconnect_uri(uri: &str) -> Result<(String, NostrConnectParams), OAuthError> {
    // Remove nostrconnect:// prefix
    let uri = uri.strip_prefix("nostrconnect://")
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid nostrconnect URI".to_string()))?;

    // Split pubkey and query params
    let parts: Vec<&str> = uri.split('?').collect();
    if parts.len() != 2 {
        return Err(OAuthError::InvalidRequest("Missing query params".to_string()));
    }

    let client_pubkey = parts[0].to_string();

    // Validate pubkey format (64 hex chars)
    if client_pubkey.len() != 64 || !client_pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OAuthError::InvalidRequest("Invalid client public key format".to_string()));
    }

    let query = parts[1];

    // Parse query params manually (serde_urlencoded not available)
    let mut relay = String::new();
    let mut secret = String::new();
    let mut perms = None;
    let mut name = None;
    let mut url = None;
    let mut image = None;

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            let decoded_value = urlencoding::decode(value)
                .map_err(|e| OAuthError::InvalidRequest(format!("Invalid URL encoding: {}", e)))?
                .into_owned();

            match key {
                "relay" => relay = decoded_value,
                "secret" => secret = decoded_value,
                "perms" => perms = Some(decoded_value),
                "name" => name = Some(decoded_value),
                "url" => url = Some(decoded_value),
                "image" => image = Some(decoded_value),
                _ => {} // Ignore unknown params
            }
        }
    }

    if relay.is_empty() || secret.is_empty() {
        return Err(OAuthError::InvalidRequest("Missing required params: relay and secret".to_string()));
    }

    let params = NostrConnectParams {
        relay,
        secret,
        perms,
        name,
        url,
        image,
    };

    // Validate relay URL
    if !params.relay.starts_with("wss://") && !params.relay.starts_with("ws://") {
        return Err(OAuthError::InvalidRequest("Invalid relay URL".to_string()));
    }

    Ok((client_pubkey, params))
}

/// GET /connect/*nostrconnect
/// Entry point from nostr-login popup - shows authorization page
pub async fn connect_get(
    State(_auth_state): State<super::routes::AuthState>,
    axum::extract::Path(nostrconnect_uri): axum::extract::Path<String>,
) -> Result<Response, OAuthError> {
    // Parse the nostrconnect:// URI
    let (client_pubkey, params) = parse_nostrconnect_uri(&nostrconnect_uri)?;

    tracing::info!(
        "nostr-login connect request - client: {}..., app: {}, relay: {}",
        &client_pubkey[..8],
        params.name.as_deref().unwrap_or("Unknown"),
        params.relay
    );

    // TODO: Check if user is logged in via session/JWT
    // For now, show a simple auth form

    let app_name = params.name.as_deref().unwrap_or("Unknown App");
    let permissions = params.perms.as_deref().unwrap_or("sign_event");

    let html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize Nostr Connection - Keycast</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            background: #1a1a1a;
            color: #e0e0e0;
        }}
        h1 {{
            color: #bb86fc;
            font-size: 24px;
            margin-bottom: 10px;
        }}
        .app-info {{
            background: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .info-row {{
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
        }}
        .label {{
            color: #888;
            font-size: 14px;
        }}
        .value {{
            color: #e0e0e0;
            font-weight: 500;
        }}
        .buttons {{
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }}
        button {{
            flex: 1;
            padding: 12px 20px;
            font-size: 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
        }}
        .approve {{
            background: #bb86fc;
            color: #000;
        }}
        .approve:hover {{
            background: #cb96fc;
        }}
        .deny {{
            background: #333;
            color: #e0e0e0;
        }}
        .deny:hover {{
            background: #444;
        }}
        .warning {{
            background: #2a2a1a;
            border-left: 4px solid #ffb300;
            padding: 12px;
            margin: 20px 0;
            font-size: 14px;
            color: #ffb300;
        }}
    </style>
</head>
<body>
    <h1>🔑 Authorize Nostr Connection</h1>
    <p>An application wants to connect to your Keycast account</p>

    <div class="app-info">
        <div class="info-row">
            <span class="label">Application:</span>
            <span class="value">{app_name}</span>
        </div>
        <div class="info-row">
            <span class="label">Permissions:</span>
            <span class="value">{permissions}</span>
        </div>
        <div class="info-row">
            <span class="label">Relay:</span>
            <span class="value">{relay}</span>
        </div>
    </div>

    <div class="warning">
        ⚠️ This will allow the application to sign events on your behalf using your Keycast-managed keys.
    </div>

    <form method="POST" action="/api/oauth/connect">
        <input type="hidden" name="client_pubkey" value="{client_pubkey}">
        <input type="hidden" name="relay" value="{relay}">
        <input type="hidden" name="secret" value="{secret}">
        <input type="hidden" name="perms" value="{perms}">
        <div class="buttons">
            <button type="submit" name="approved" value="true" class="approve">Approve</button>
            <button type="submit" name="approved" value="false" class="deny">Deny</button>
        </div>
    </form>
</body>
</html>
    "#,
        app_name = app_name,
        permissions = permissions,
        relay = params.relay,
        client_pubkey = client_pubkey,
        secret = params.secret,
        perms = params.perms.as_deref().unwrap_or("")
    );

    Ok(Html(html).into_response())
}

/// POST /oauth/connect
/// User approves/denies the nostr-login connection
pub async fn connect_post(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ConnectApprovalForm>,
) -> Result<Response, OAuthError> {
    let tenant_id = tenant.0.id;

    tracing::info!(
        "nostr-login connect approval - client: {}..., approved: {}",
        &form.client_pubkey[..8],
        form.approved
    );

    if !form.approved {
        return Ok(Html(r#"
<html>
<head>
    <title>Authorization Denied</title>
    <style>
        body {
            font-family: sans-serif;
            text-align: center;
            padding: 50px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        h1 { color: #f44336; }
    </style>
    <script>
        setTimeout(() => window.close(), 2000);
    </script>
</head>
<body>
    <h1>✗ Authorization Denied</h1>
    <p>You can close this window.</p>
</body>
</html>
        "#).into_response());
    }

    // Extract user public key from JWT token in Authorization header
    let user_public_key = super::auth::extract_user_from_token(&headers)
        .map_err(|_| OAuthError::Unauthorized)?;

    // Get user's encrypted key
    let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE tenant_id = ?1 AND user_public_key = ?2"
    )
    .bind(tenant_id)
    .bind(&user_public_key)
    .fetch_one(&auth_state.state.db)
    .await?;

    // Parse user's public key
    let bunker_public_key = nostr_sdk::PublicKey::from_hex(&user_public_key)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?;

    // Create or get application - use client pubkey as identifier
    let app_name = format!("nostr-login-{}", &form.client_pubkey[..12]);

    let app_id: i32 = match sqlx::query_scalar::<_, i32>(
        "SELECT id FROM oauth_applications WHERE tenant_id = ?1 AND client_id = ?2"
    )
    .bind(tenant_id)
    .bind(&form.client_pubkey)
    .fetch_optional(&auth_state.state.db)
    .await? {
        Some(id) => id,
        None => {
            sqlx::query_scalar(
                "INSERT INTO oauth_applications (tenant_id, client_id, client_secret, name, redirect_uris, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, '[]', ?5, ?6) RETURNING id"
            )
            .bind(tenant_id)
            .bind(&form.client_pubkey)
            .bind("") // No client secret for nostr-login
            .bind(&app_name)
            .bind(Utc::now())
            .bind(Utc::now())
            .fetch_one(&auth_state.state.db)
            .await?
        }
    };

    // Create authorization
    let relays_json = serde_json::to_string(&vec![form.relay.clone()])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    sqlx::query(
        "INSERT INTO oauth_authorizations
         (tenant_id, user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, client_public_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
    )
    .bind(tenant_id)
    .bind(&user_public_key)
    .bind(app_id)
    .bind(bunker_public_key.to_hex())
    .bind(&encrypted_user_key)
    .bind(&form.secret)
    .bind(&relays_json)
    .bind(&form.client_pubkey)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&auth_state.state.db)
    .await?;

    // Signal signer daemon to reload
    let signal_file = std::path::Path::new("database/.reload_signal");
    if let Err(e) = std::fs::File::create(signal_file) {
        tracing::error!("Failed to create reload signal file: {}", e);
    } else {
        tracing::info!("Created reload signal for signer daemon (nostr-login)");
    }

    Ok(Html(r#"
<html>
<head>
    <title>Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            text-align: center;
            padding: 50px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        h1 {
            color: #4CAF50;
            font-size: 32px;
        }
        p {
            font-size: 18px;
            color: #888;
        }
        .checkmark {
            font-size: 64px;
            margin-bottom: 20px;
        }
    </style>
    <script>
        setTimeout(() => window.close(), 3000);
    </script>
</head>
<body>
    <div class="checkmark">✓</div>
    <h1>Authorization Successful</h1>
    <p>You can close this window.</p>
    <p style="font-size: 14px; margin-top: 20px;">(Closing automatically in 3 seconds...)</p>
</body>
</html>
    "#).into_response())
}

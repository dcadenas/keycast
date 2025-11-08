// ABOUTME: Unified binary that runs both API server and Signer daemon in one process
// ABOUTME: Shares AuthorizationHandler state between HTTP endpoints and NIP-46 signer for optimal performance

use axum::{routing::get, Router, http::StatusCode, response::{Html, IntoResponse}};
use dotenv::dotenv;
use keycast_core::database::Database;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_signer::UnifiedSigner;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

async fn landing_page() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Keycast - NIP-46 Remote Signing</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a1a; color: #e0e0e0; }
        h1 { color: #bb86fc; }
        h2 { color: #03dac6; margin-top: 30px; }
        a { color: #03dac6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background: #2a2a2a; padding: 2px 6px; border-radius: 3px; }
        .endpoint { background: #2a2a2a; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .method { color: #bb86fc; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔑 Keycast</h1>
    <p>NIP-46 remote signing with OAuth 2.0 authorization</p>

    <h2>API Endpoints</h2>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/auth/register</code><br>
        Register with email/password (ROPC)
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/auth/login</code><br>
        Login and get JWT token
    </div>
    <div class="endpoint">
        <span class="method">GET</span> <code>/api/user/bunker</code><br>
        Get NIP-46 bunker URL (requires auth)
    </div>

    <h2>OAuth 2.0</h2>
    <div class="endpoint">
        <span class="method">GET/POST</span> <code>/api/oauth/authorize</code><br>
        Authorization flow
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/oauth/token</code><br>
        Exchange code for bunker URL
    </div>

    <p><a href="/examples">View examples</a></p>
</body>
</html>
    "#)
}

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    println!("\n================================================");
    println!("🔑 Keycast Unified Service Starting...");
    println!("   Running API + Signer in single process");
    println!("================================================\n");

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Setup database
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let database_url = env::var("DATABASE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(root_dir)
                .parent()
                .unwrap()
                .join("database/keycast.db")
        });

    let database_migrations = PathBuf::from(root_dir)
        .parent()
        .unwrap()
        .join("database/migrations");

    let database = Database::new(database_url.clone(), database_migrations.clone()).await?;
    tracing::info!("✔︎ Database initialized at {:?}", database_url);

    // Setup key managers (one for signer, one for API - they're cheap to create)
    let use_gcp_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";

    let signer_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
        tracing::info!("Using Google Cloud KMS for encryption");
        Box::new(GcpKeyManager::new().await?)
    } else {
        tracing::info!("Using file-based encryption");
        Box::new(FileKeyManager::new()?)
    };

    let api_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
        Box::new(GcpKeyManager::new().await?)
    } else {
        Box::new(FileKeyManager::new()?)
    };

    // Create signer and load all authorizations into memory
    let mut signer = UnifiedSigner::new(database.pool.clone(), signer_key_manager).await?;
    signer.load_authorizations().await?;
    signer.connect_to_relays().await?;
    tracing::info!("✔︎ Signer daemon initialized and connected to relays");

    // Get shared handlers for API (converted to trait objects)
    let signer_handlers = signer.handlers_as_trait_objects().await;

    // Create API state with shared signer handlers
    let api_state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(api_key_manager),
        signer_handlers: Some(signer_handlers),
    });

    // Set global state for routes that use it
    keycast_api::state::KEYCAST_STATE.set(api_state.clone()).ok();

    // Get API port (default 3000)
    let api_port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);


    // Set up static file directories
    let root_dir = env!("CARGO_MANIFEST_DIR");

    // Use WEB_BUILD_DIR if set, otherwise use web/build for dev
    let web_build_dir = env::var("WEB_BUILD_DIR")
        .unwrap_or_else(|_| {
            PathBuf::from(root_dir)
                .parent()
                .unwrap()
                .join("web/build")
                .to_string_lossy()
                .to_string()
        });

    let examples_path = PathBuf::from(root_dir)
        .parent()
        .unwrap()
        .join("examples");

    tracing::info!("✔︎ Serving web frontend from: {}", web_build_dir);

    // CORS configuration
    use tower_http::cors::AllowOrigin;

    let allowed_origins = env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://peek.verse.app,http://localhost".to_string());

    let auth_cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let origin_str = origin.to_str().unwrap_or("");
            if origin_str.starts_with("http://localhost:") || origin_str == "http://localhost" {
                return true;
            }
            allowed_origins.split(',').map(|s| s.trim()).any(|allowed| origin_str == allowed)
        }))
        .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
        .allow_credentials(false);

    let public_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(false);

    // Get pure API routes (JSON endpoints only)
    let api_routes = keycast_api::api::http::routes::api_routes(database.pool.clone(), api_state.clone(), auth_cors, public_cors);

    // Serve examples directory
    let examples_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("examples");

    let app = Router::new()
        // Health checks at root level (for k8s/Cloud Run)
        .route("/health", get(health_check))
        .route("/healthz/startup", get(health_check))
        .route("/healthz/ready", get(health_check))

        // NIP-05 discovery at root level
        .route("/.well-known/nostr.json", get(keycast_api::api::http::nostr_discovery_public))
        .with_state(database.pool.clone())

        // All API endpoints under /api prefix
        .nest("/api", api_routes)

        // Test examples
        .nest_service("/examples", ServeDir::new(&examples_path))

        // SvelteKit frontend (fallback - catches all other routes)
        // SPA mode: serve index.html for all non-file routes
        .fallback_service(ServeDir::new(&web_build_dir).fallback(
            axum::routing::get(|| async move {
                let index_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("web/build/index.html");
                match tokio::fs::read_to_string(&index_path).await {
                    Ok(content) => Html(content).into_response(),
                    Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
                }
            })
        ));

    let api_addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port));
    tracing::info!("✔︎ API server ready on {}", api_addr);

    // Spawn API server task
    let api_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
        tracing::info!("🌐 API server listening on {}", api_addr);
        axum::serve(listener, app).await.unwrap();
    });

    // Spawn Signer daemon task
    let signer_handle = tokio::spawn(async move {
        tracing::info!("🤙 Signer daemon ready, listening for NIP-46 requests");
        signer.run().await.unwrap();
    });

    println!("✨ Unified service running!");
    println!("   API: http://0.0.0.0:{}", api_port);
    println!("   Signer: NIP-46 relay listener active");
    println!("   Shared state: AuthorizationHandlers cached\n");

    // Wait for either task to complete (they shouldn't unless there's an error)
    tokio::select! {
        result = api_handle => {
            tracing::error!("API server exited: {:?}", result);
        }
        result = signer_handle => {
            tracing::error!("Signer daemon exited: {:?}", result);
        }
    }

    Ok(())
}

use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    routing::{get, post},
    Json, Router,
};
use agent_core::types::Snapshot;
use agent_config::{AuthMethod, ServerConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::fs;
use tracing::{info, warn, error};
use axum_server::tls_rustls::RustlsConfig;

#[derive(Serialize, Deserialize)]
struct IngestResponse {
    status: String,
    message: String,
}

#[derive(Deserialize)]
struct ServerConfigFile {
    server: ServerConfigInner,
}

#[derive(Deserialize)]
struct ServerConfigInner {
    endpoint: String,
    auth_method: AuthMethod,
    api_key_ref: Option<String>,
}

struct AppState {
    auth_method: AuthMethod,
    api_key: Option<String>,
}

async fn health_check() -> &'static str {
    "OK"
}

async fn ingest_snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<Snapshot>,
) -> Result<(StatusCode, Json<IngestResponse>), (StatusCode, Json<IngestResponse>)> {
    info!("Received snapshot from machine: {}", payload.machine_id);

    match &state.auth_method {
        AuthMethod::None => {
            info!("AuthMethod::None configured. Allowing request.");
        }
        AuthMethod::ApiKey { .. } => {
            let auth_header = headers.get("x-api-key")
                .and_then(|v| v.to_str().ok());

            match auth_header {
                Some(key) if Some(key) == state.api_key.as_deref() => {
                    info!("API Key validated successfully.");
                }
                Some(_) => {
                    warn!("Authentication failed for machine {}: Invalid API Key", payload.machine_id);
                    return Err((StatusCode::UNAUTHORIZED, Json(IngestResponse {
                        status: "error".to_string(),
                        message: "Unauthorized: Invalid API Key".to_string(),
                    })));
                }
                None => {
                    warn!("Authentication failed for machine {}: Missing x-api-key header", payload.machine_id);
                    return Err((StatusCode::UNAUTHORIZED, Json(IngestResponse {
                        status: "error".to_string(),
                        message: "Unauthorized: Missing x-api-key header".to_string(),
                    })));
                }
            }
        }
        AuthMethod::OAuth2ClientCredentials { .. } | AuthMethod::MTLS { .. } => {
            warn!("Auth method not yet implemented on server side.");
            return Err((StatusCode::NOT_IMPLEMENTED, Json(IngestResponse {
                status: "error".to_string(),
                message: "This authentication method is not yet implemented on the server".to_string(),
            })));
        }
    }

    info!("Snapshot validated successfully for {}. Timestamp: {}", payload.machine_id, payload.collected_at);

    Ok((StatusCode::OK, Json(IngestResponse {
        status: "success".to_string(),
        message: "Snapshot ingested successfully".to_string(),
    })))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load server configuration
    let config_content = fs::read_to_string("server_config.toml").expect("Failed to read server_config.toml");
    let config: ServerConfigFile = toml::from_str(&config_content).expect("Failed to parse server_config.toml");

    let mut api_key = None;
    if let AuthMethod::ApiKey { ref key_ref } = config.server.auth_method {
        let key = fs::read_to_string(key_ref).expect("Failed to read API key reference file");
        api_key = Some(key.trim().to_string());
    }

    let state = Arc::new(AppState {
        auth_method: config.server.auth_method,
        api_key,
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/ingest", post(ingest_snapshot))
        .with_state(state);

    // TLS Configuration
    let cert_path = "cert.pem";
    let key_path = "key.pem";

    if !std::path::Path::new(cert_path).exists() || !std::path::Path::new(key_path).exists() {
        error!("TLS certificates (cert.pem, key.pem) not found!");
        error!("Please generate them using: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes");
        std::process::exit(1);
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path).await.expect("Failed to load TLS certificates");

    let addr = "0.0.0.0:8443";
    info!("Servidor rodando com TLS (certificado de desenvolvimento — NÃO usar em produção)");
    info!("Listening on {}", addr);

    axum_server::binds::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

mod config;
mod tls;

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
    Router,
};
use clap::Parser;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "server-bin")]
#[command(about = "Monitoring Server", long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,
}

struct AppState {
    config: config::ServerConfig,
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match &state.config.auth {
        config::ServerAuthMethod::ApiKey { expected_key } => {
            let provided_key = req
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok());

            if provided_key == Some(expected_key) {
                next.run(req).await
            } else {
                warn!("Unauthorized request: missing or invalid API key");
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn version_handler() -> impl IntoResponse {
    let manifest = serde_json::json!({
        "version": "0.2.0",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "size": 0,
        "released_at": "2026-09-17T00:00:00Z"
    });

    let manifest_string = serde_json::to_string(&manifest).expect("Failed to serialize manifest");

    Json(serde_json::json!({
        "manifest": manifest_string,
        "signature": ""
    }))
}

async fn ingest_handler(
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    info!("Received snapshot: {}", payload);
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let server_config = if let Some(path) = cli.config_path {
        match config::ServerConfig::load_from_file(PathBuf::from(path)) {
            Ok(c) => c,
            Err(e) => {
                error!("Configuration error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        warn!("No config path provided, using default dev config");
        config::ServerConfig::default_for_dev()
    };
    info!("Server config loaded. Listen addr: {}", server_config.listen_addr);

    let cert = tls::generate_self_signed_cert().expect("failed to generate self-signed cert");
    info!("Self-signed certificate generated for localhost/127.0.0.1");

    if let Ok(path) = tls::salvar_cert_publico(&cert) {
        info!("Public certificate saved for development: {:?}", path);
    } else {
        warn!("Could not save public certificate to disk");
    }

    let rustls_config = tls::build_server_config(&cert).expect("failed to build rustls server config");
    let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

    let state = Arc::new(AppState {
        config: server_config.clone(),
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/version", get(version_handler))
        .route("/api/v1/ingest", post(ingest_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    let addr: SocketAddr = server_config.listen_addr.parse().expect("invalid listen_addr");
    let listener = TcpListener::bind(addr).await.expect("failed to bind listener");
    info!("Starting HTTPS server on {}", addr);

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TLS handshake failed with {}: {}", peer_addr, e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let hyper_service = hyper::service::service_fn(move |req| {
                app.clone().call(req)
            });

            if let Err(e) = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
            {
                error!("Connection error with {}: {}", peer_addr, e);
            }
        });
    }
}

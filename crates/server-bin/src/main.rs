mod config;
mod tls;

use axum::{
    extract::{State},
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::{error, info, warn};
use semver::Version;
use sha2::{Sha256, Digest};
use tokio_util::io::ReaderStream;
use axum::extract::Path as AxumPath;

#[derive(Parser)]
#[command(name = "server-bin")]
#[command(about = "Monitoring Server", long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,
}

struct AppState {
    config: config::ServerConfig,
    ingest_lock: tokio::sync::Mutex<()>,
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

async fn find_latest_release() -> Option<(Version, PathBuf)> {
    let releases_dir = Path::new("releases");
    if !releases_dir.exists() {
        return None;
    }

    let mut entries = fs::read_dir(releases_dir).await.ok()?;
    let mut latest: Option<(Version, PathBuf)> = None;

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let filename = path.file_name()?.to_str()?;

        if filename.starts_with("agent-") && filename.ends_with(".exe") {
            let version_str = &filename[6..filename.len() - 4];
            if let Ok(version) = Version::parse(version_str) {
                if latest.as_ref().map_or(true, |(v, _)| version > *v) {
                    latest = Some((version, path));
                }
            }
        }
    }
    latest
}

async fn version_handler() -> impl IntoResponse {
    let release = find_latest_release().await;

    let (manifest_string, version_str) = if let Some((version, path)) = release {
        let version_str = version.to_string();
        let content = fs::read(&path).await.expect("Failed to read release binary");
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hex::encode(hasher.finalize());
        let size = content.len();
        let download_url = format!("/api/v1/download/{}", version_str);

        let manifest = serde_json::json!({
            "version": version_str,
            "sha256": hash,
            "size": size,
            "download_url": download_url,
            "released_at": "2026-09-18T00:00:00Z"
        });

        (serde_json::to_string(&manifest).expect("Failed to serialize manifest"), version_str)
    } else {
        warn!("nenhum release encontrado em releases/");
        let manifest = serde_json::json!({
            "version": "0.2.0",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "size": 0,
            "released_at": "2026-09-17T00:00:00Z"
        });
        (serde_json::to_string(&manifest).expect("Failed to serialize manifest"), "0.2.0".to_string())
    };

    // Carrega a chave privada da variável de ambiente UPDATE_PRIV_KEY_HEX
    let signature = if let Ok(hex_key) = std::env::var("UPDATE_PRIV_KEY_HEX") {
        if let Ok(key_bytes) = hex::decode(hex_key) {
            if key_bytes.len() == 32 {
                use ed25519_dalek::{SigningKey, Signer};
                use base64::Engine;

                let secret_bytes: [u8; 32] = key_bytes.try_into().expect("Invalid key length");
                let signing_key = SigningKey::from_bytes(&secret_bytes);

                let sig = signing_key.sign(manifest_string.as_bytes());
                Some(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Json(serde_json::json!({
        "manifest": manifest_string,
        "signature": signature.unwrap_or_else(|| "".to_string())
    }))
}

async fn download_handler(
    AxumPath(version): AxumPath<String>,
) -> impl IntoResponse {
    // Validamos a versão chamando a mesma lógica de busca de releases
    // para evitar path traversal e garantir que o arquivo existe.
    let releases_dir = Path::new("releases");
    let mut entries = match fs::read_dir(releases_dir).await {
        Ok(e) => e,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut found_path: Option<PathBuf> = None;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if filename == format!("agent-{}.exe", version) {
            found_path = Some(path);
            break;
        }
    }

    if let Some(path) = found_path {
        let file = match fs::File::open(&path).await {
            Ok(f) => f,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let stream = ReaderStream::new(file);
        Response::builder()
            .header("Content-Type", "application/octet-stream")
            .body(axum::body::Body::from_stream(stream))
            .unwrap()
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn ingest_handler(
    State(state): State<Arc<AppState>>,
    Json(mut payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let now = chrono::Utc::now();
    let date_str = now.format("%Y-%m-%d").to_string();
    let timestamp = now.to_rfc3339();

    if let Some(obj) = payload.as_object_mut() {
        obj.insert("received_at".to_string(), serde_json::Value::String(timestamp));
    }

    let log_line = match serde_json::to_string(&payload) {
        Ok(s) => s + "\n",
        Err(e) => {
            error!("Failed to serialize payload for persistence: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    {
        let _lock = state.ingest_lock.lock().await;
        let data_dir = Path::new("data");
        if let Err(e) = fs::create_dir_all(data_dir).await {
            error!("Failed to create data directory: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }

        let file_path = data_dir.join(format!("ingest-{}.jsonl", date_str));

        use tokio::io::AsyncWriteExt;
        let file_result = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .await;

        match file_result {
            Ok(mut file) => {
                if let Err(e) = file.write_all(log_line.as_bytes()).await {
                    error!("Failed to write ingest data to file {:?}: {}", file_path, e);
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
            Err(e) => {
                error!("Failed to open ingest file {:?}: {}", file_path, e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
    }

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

    let cert = match tls::carregar_cert_existente() {
        Ok(existing_cert) => {
            info!("Loaded existing TLS certificate from disk");
            existing_cert
        }
        Err(e) => {
            warn!("Could not load existing TLS certificate: {}. Generating new one...", e);
            let new_cert = tls::generate_self_signed_cert().expect("failed to generate self-signed cert");
            info!("Self-signed certificate generated for localhost, 127.0.0.1 and 172.20.1.124");
            if let Err(e) = tls::salvar_cert_completo(&new_cert) {
                warn!("Could not save TLS certificate to disk: {}", e);
            } else {
                info!("Public and private certificates saved for development");
            }
            new_cert
        }
    };


    let rustls_config = tls::build_server_config(&cert).expect("failed to build rustls server config");
    let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

    let state = Arc::new(AppState {
        config: server_config.clone(),
        ingest_lock: tokio::sync::Mutex::new(()),
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/version", get(version_handler))
        .route("/api/v1/download/:version", get(download_handler))
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

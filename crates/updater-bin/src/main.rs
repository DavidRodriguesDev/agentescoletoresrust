use agent_config::AgentConfig;
use clap::Parser;
use semver::Version;
use std::fs;
use std::io::{Read as IoRead, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*};
use sha2::{Sha256, Digest};
use hex;
use std::sync::Arc;

const INSTALLED_AGENT_VERSION: &str = "0.1.0";
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(name = "updater-bin")]
#[command(about = "Multi-OS Monitoring Agent Updater", long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,
}

fn create_ureq_agent(config: &AgentConfig) -> ureq::Agent {
    let mut builder = ureq::AgentBuilder::new();

    if let Some(ca_path) = &config.extra_ca_cert_path {
        match fs::read(ca_path) {
            Ok(pem_bytes) => {
                let mut reader = std::io::Cursor::new(pem_bytes);
                let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>();

                if let Ok(certs) = certs {
                    let mut root_store = rustls::RootCertStore::empty();
                    for cert in certs {
                        root_store.add(cert).expect("Failed to add certificate to root store");
                    }

                    let tls_config = rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    builder = builder.tls_config(Arc::new(tls_config));
                    info!("Configured ureq agent to trust CA from: {}", ca_path);
                } else {
                    error!("Failed to parse PEM certificates from {}: {:?}", ca_path, certs.err());
                }
            }
            Err(e) => error!("Failed to read CA cert file {}: {}", ca_path, e),
        }
    }

    builder.build()
}

fn verify_hash(file_path: &Path, expected_hash: &str) -> bool {
    let mut file = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open file for hashing: {}", e);
            return false;
        }
    };

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => {
                error!("Error reading file for hashing: {}", e);
                return false;
            }
        }
    }

    let result = hasher.finalize();
    let actual_hash = hex::encode(result);

    actual_hash.eq_ignore_ascii_case(expected_hash)
}

fn substitute_binary(target_path: &Path, new_binary_path: &Path) -> std::io::Result<()> {
    if !target_path.exists() {
        return fs::rename(new_binary_path, target_path);
    }

    #[cfg(target_os = "windows")]
    {
        let mut old_path = target_path.to_path_buf();
        old_path.set_extension("old");

        if old_path.exists() {
            fs::remove_file(&old_path)?;
        }

        fs::rename(target_path, &old_path)?;
        fs::rename(new_binary_path, target_path)?;
        info!("Binary substituted on Windows (moved current to .old)");
    }

    #[cfg(not(target_os = "windows"))]
    {
        fs::rename(new_binary_path, target_path)?;
        info!("Binary substituted on Unix");
    }

    Ok(())
}

fn download_and_apply_update(agent: &ureq::Agent, _config: &AgentConfig, download_url: &str, expected_hash: &str) -> bool {
    info!("Downloading update from: {}", download_url);

    let temp_path = PathBuf::from("agent_update.tmp");

    let response = match agent.get(download_url).call() {
        Ok(res) => res,
        Err(e) => {
            error!("Failed to download binary: {}", e);
            return false;
        }
    };

    let mut file = match fs::File::create(&temp_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create temp file: {}", e);
            return false;
        }
    };

    let mut reader = response.into_reader();
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = file.write_all(&buffer[..n]) {
                    error!("Failed to write to temp file: {}", e);
                    return false;
                }
            }
            Err(e) => {
                error!("Error reading from download stream: {}", e);
                return false;
            }
        }
    }

    if !verify_hash(&temp_path, expected_hash) {
        error!("Hash verification failed! Downloaded binary is corrupt or tampered with.");
        let _ = fs::remove_file(&temp_path);
        return false;
    }

    let target_bin = if cfg!(target_os = "windows") {
        PathBuf::from("C:\\ProgramData\\agente-monitoramento\\agent.exe")
    } else {
        PathBuf::from("/usr/bin/agent")
    };

    if let Err(e) = substitute_binary(&target_bin, &temp_path) {
        error!("Failed to substitute binary: {}", e);
        let _ = fs::remove_file(&temp_path);
        return false;
    }

    info!("Update successfully applied to {:?}", target_bin);
    true
}

fn check_for_update(agent: &ureq::Agent, config: &AgentConfig) {
    let url = format!("{}/api/v1/version", config.endpoint);

    let mut request = agent.get(&url);

    if let agent_config::AuthMethod::ApiKey { key_file } = &config.auth {
        match fs::read_to_string(key_file) {
            Ok(key) => {
                request = request.set("X-API-Key", key.trim());
            }
            Err(e) => {
                error!("Failed to read API key file {:?}: {}", key_file, e);
                return;
            }
        }
    }

    match request.call() {
        Ok(resp) => {
            let body: serde_json::Value = resp.into_json().expect("Failed to parse JSON");

            if let Some(manifest_str) = body["manifest"].as_str() {
                let manifest: serde_json::Value = match serde_json::from_str(manifest_str) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to parse manifest JSON: {}", e);
                        return;
                    }
                };

                if let Some(latest_ver_str) = manifest["version"].as_str() {
                    let current_ver = Version::parse(INSTALLED_AGENT_VERSION).expect("Invalid local version");
                    match Version::parse(latest_ver_str) {
                        Ok(latest_ver) => {
                            if latest_ver > current_ver {
                                info!("Update available! Current: {}, Latest: {}. Notes: {}",
                                    INSTALLED_AGENT_VERSION, latest_ver_str, body["notes"].as_str().unwrap_or("No notes"));

                                if let Some(_download_url) = manifest["download_url"].as_str() {
                                    if let Some(_hash) = manifest["sha256"].as_str() {
                                        warn!("Atualização disponível mas download/substituição está desabilitado até implementarmos verificação de assinatura");
                                    } else {
                                        warn!("Server did not provide a SHA-256 hash for the update.");
                                    }
                                } else {
                                    warn!("Server did not provide a download URL for the update.");
                                }
                            } else {
                                info!("Agent is up to date. Version: {}", INSTALLED_AGENT_VERSION);
                            }
                        }
                        Err(_) => error!("Server returned invalid version format: {}", latest_ver_str),
                    }
                }
            }

            let _signature = body["signature"].as_str();
        }
        Err(e) => {
            error!("Failed to check for updates: {}", e);
        }
    }
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    let config_path = if let Some(path) = cli.config_path {
        PathBuf::from(path)
    } else if cfg!(target_os = "windows") {
        PathBuf::from("C:\\ProgramData\\agente-monitoramento\\config.toml")
    } else {
        PathBuf::from("/etc/agente-monitoramento/config.toml")
    };

    let config = match AgentConfig::load_from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing_subscriber::fmt::init();
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    info!("Updater started. Monitoring version {}...", INSTALLED_AGENT_VERSION);

    let agent = create_ureq_agent(&config);

    loop {
        check_for_update(&agent, &config);
        thread::sleep(CHECK_INTERVAL);
    }
}

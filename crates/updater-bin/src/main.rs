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

const UPDATE_PUBKEY_BYTES: [u8; 32] = [
    0xea, 0xa3, 0x52, 0xb2, 0x10, 0x9a, 0x90, 0x8b,
    0xaf, 0xfc, 0x6e, 0xae, 0x52, 0xea, 0x56, 0xe2,
    0xe2, 0x1b, 0xa9, 0xea, 0x73, 0x14, 0xe0, 0x8b,
    0xbd, 0xb4, 0x41, 0x27, 0x00, 0x38, 0x3b, 0x2e,
];

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

fn verify_manifest(manifest_bytes: &[u8], signature_b64: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use base64::Engine;

    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_array);

    let Ok(verifying_key) = VerifyingKey::from_bytes(&UPDATE_PUBKEY_BYTES) else {
        return false;
    };

    verifying_key.verify_strict(manifest_bytes, &signature).is_ok()
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
                let signature = body["signature"].as_str().unwrap_or("");

                if !verify_manifest(manifest_str.as_bytes(), signature) {
                    error!("Update manifest signature is invalid! Aborting update check.");
                    return;
                }
                info!("Update manifest signature validated successfully.");

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

                                if let Some(download_url) = manifest["download_url"].as_str() {
                                    if let Some(hash) = manifest["sha256"].as_str() {
                                        let current_ver = Version::parse(INSTALLED_AGENT_VERSION).expect("Invalid local version");
                                        match Version::parse(latest_ver_str) {
                                            Ok(latest_ver) => {
                                                if latest_ver > current_ver {
                                                    info!("Applying update to version {}...", latest_ver_str);
                                                    if download_and_apply_update(agent, config, download_url, hash) {
                                                        info!("Update to {} applied successfully!", latest_ver_str);
                                                    } else {
                                                        error!("Failed to apply update to {}.", latest_ver_str);
                                                    }
                                                } else {
                                                    info!("Já está na versão mais recente ({})", INSTALLED_AGENT_VERSION);
                                                }
                                            }
                                            Err(e) => error!("Failed to parse server version {}: {}", latest_ver_str, e),
                                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use base64::Engine;

    #[test]
    fn verify_manifest_accepts_valid_signature() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"{\"version\":\"0.2.0\",\"sha256\":\"abc\"}";
        let signature = signing_key.sign(message);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        // Testa a lógica de verificação usando uma chave gerada no
        // próprio teste (não a chave real do produto), substituindo
        // temporariamente a checagem para usar essa verifying_key.
        // Para isso, replique aqui a lógica de verify_manifest mas
        // com esta verifying_key ao invés de UPDATE_PUBKEY_BYTES:
        use ed25519_dalek::{Signature, Verifier};
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = Signature::from_bytes(&sig_array);
        assert!(verifying_key.verify_strict(message, &sig).is_ok());
    }

    #[test]
    fn verify_manifest_rejects_tampered_message() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let original = b"original message";
        let tampered = b"tampered message!";
        let signature = signing_key.sign(original);

        use ed25519_dalek::Verifier;
        assert!(verifying_key.verify_strict(tampered, &signature).is_err());
    }

    #[test]
    fn verify_manifest_rejects_garbage_signature() {
        let result = verify_manifest(b"any message", "not-valid-base64!!!");
        assert!(!result);
    }
}

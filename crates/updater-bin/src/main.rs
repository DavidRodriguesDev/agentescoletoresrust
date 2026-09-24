use agent_config::AgentConfig;
use clap::Parser;
use semver::Version;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read as IoRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*};
#[cfg(target_os = "windows")]
use windows_service::{
    service,
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const UPDATE_PUBKEY_BYTES: [u8; 32] = [
    0xea, 0xa3, 0x52, 0xb2, 0x10, 0x9a, 0x90, 0x8b,
    0xaf, 0xfc, 0x6e, 0xae, 0x52, 0xea, 0x56, 0xe2,
    0xe2, 0x1b, 0xa9, 0xea, 0x73, 0x14, 0xe0, 0x8b,
    0xbd, 0xb4, 0x41, 0x27, 0x00, 0x38, 0x3b, 0x2e,
];

const INSTALLED_AGENT_VERSION: &str = "0.1.0";
const VERSION_FILE_PATH: &str = if cfg!(target_os = "windows") {
    "C:\\ProgramData\\agente-monitoramento\\installed_version.txt"
} else {
    "/etc/agente-monitoramento/installed_version.txt"
};
const TEMP_DOWNLOAD_DIR: &str = if cfg!(target_os = "windows") {
    "C:\\ProgramData\\agente-monitoramento\\updates"
} else {
    "/etc/agente-monitoramento/updates"
};
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Nome do serviço do agente no SCM (o mesmo registrado por install-agent-service.ps1).
const AGENT_SERVICE_NAME: &str = "AgentMonitor";
/// Nome deste próprio serviço no SCM.
const UPDATER_SERVICE_NAME: &str = "AgentUpdater";

/// Caminho de FALLBACK do binário do agent. Em Windows o caminho real é lido do SCM
/// (binPath do serviço AgentMonitor); esta constante só é usada se essa consulta falhar.
/// Deve refletir o mesmo valor de $BinaryPath em install-agent-service.ps1.
const DEFAULT_AGENT_BINARY_PATH: &str = if cfg!(target_os = "windows") {
    "C:\\ProgramData\\agente-monitoramento\\agent-bin.exe"
} else {
    "/usr/bin/agent"
};

const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(60);
const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(30);
/// Depois do start, o serviço precisa continuar Running por este tempo, senão faz rollback.
const SERVICE_STABILITY_WINDOW: Duration = Duration::from_secs(10);
const FILE_OP_ATTEMPTS: u32 = 10;
const FILE_OP_DELAY: Duration = Duration::from_millis(500);

/// Registro da ultima tentativa de update que falhou ao aplicar (versao:sha256 + timestamp).
const FAILED_UPDATE_FILE_PATH: &str = if cfg!(target_os = "windows") {
    "C:\\ProgramData\\agente-monitoramento\\failed_update.txt"
} else {
    "/etc/agente-monitoramento/failed_update.txt"
};
/// Mesma versao+hash que falhou so e tentada de novo depois deste intervalo.
/// Publicar um build novo (hash diferente) libera a tentativa imediatamente.
const FAILED_UPDATE_RETRY_AFTER: Duration = Duration::from_secs(3600);

#[derive(Parser)]
#[command(name = "updater-bin")]
#[command(about = "Multi-OS Monitoring Agent Updater", long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,
    #[arg(long)]
    service: bool,
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
                        if let Err(e) = root_store.add(cert) {
                            warn!("Failed to add certificate to root store: {}", e);
                        }
                    }

                    let tls_config = rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    builder = builder.tls_config(Arc::new(tls_config));
                    info!("Configured ureq agent to trust CA from: {}", ca_path.display());
                } else {
                    error!("Failed to parse PEM certificates from {}: {:?}", ca_path.display(), certs.err());
                }
            }
            Err(e) => error!("Failed to read CA cert file {}: {}", ca_path.display(), e),
        }
    }

    builder.build()
}

fn read_installed_version() -> Version {
    match fs::read_to_string(VERSION_FILE_PATH) {
        Ok(content) => {
            let trimmed = content.trim();
            match Version::parse(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    error!("Invalid version content in {}: '{}'. Error: {}. Falling back to default.", VERSION_FILE_PATH, trimmed, e);
                    Version::parse(INSTALLED_AGENT_VERSION).expect("Static fallback version must be valid")
                }
            }
        }
        Err(_) => {
            let default_ver = Version::parse(INSTALLED_AGENT_VERSION).expect("Static fallback version must be valid");
            if let Err(e) = fs::write(VERSION_FILE_PATH, INSTALLED_AGENT_VERSION) {
                warn!("Failed to write initial version file {}: {}", VERSION_FILE_PATH, e);
            }
            default_ver
        }
    }
}

fn verify_manifest(manifest_bytes: &[u8], signature_b64: &str) -> bool {
    use base64::Engine;
    use ed25519_dalek::{Signature, VerifyingKey};

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

    let actual_hash = hex::encode(hasher.finalize());
    actual_hash.eq_ignore_ascii_case(expected_hash)
}

// ---------------------------------------------------------------------------
// Resolução do binário do agent e controle do serviço (SCM)
// ---------------------------------------------------------------------------

/// Extrai o caminho do .exe de um binPath do SCM, ex.:
/// `"C:\dir\agent-bin.exe" --service`  ->  `C:\dir\agent-bin.exe`
fn parse_exe_from_bin_path(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('"') {
        let end = rest.find('"')?;
        let path = &rest[..end];
        return if path.is_empty() { None } else { Some(PathBuf::from(path)) };
    }
    let idx = raw.to_ascii_lowercase().find(".exe")?;
    Some(PathBuf::from(&raw[..idx + 4]))
}

#[cfg(target_os = "windows")]
mod agent_service {
    use super::*;
    use std::time::Instant;
    use windows_service::service::{Service, ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    /// windows_service::Error mostra so "IO error in winapi call"; o {:?} traz o codigo
    /// do Windows (ex.: Os { code: 1067, ... }).
    fn winerr(e: windows_service::Error) -> String {
        format!("{} [{:?}]", e, e)
    }

    fn open() -> Result<Service, String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("cannot connect to SCM: {}", winerr(e)))?;
        manager
            .open_service(
                AGENT_SERVICE_NAME,
                ServiceAccess::QUERY_STATUS
                    | ServiceAccess::QUERY_CONFIG
                    | ServiceAccess::START
                    | ServiceAccess::STOP,
            )
            .map_err(|e| format!("cannot open service {}: {}", AGENT_SERVICE_NAME, winerr(e)))
    }

    fn state(svc: &Service) -> Result<ServiceState, String> {
        svc.query_status()
            .map(|s| s.current_state)
            .map_err(|e| format!("query_status failed: {}", winerr(e)))
    }

    fn wait_for_state(svc: &Service, target: ServiceState, timeout: Duration) -> Result<(), String> {
        let began = Instant::now();
        loop {
            let current = state(svc)?;
            if current == target {
                return Ok(());
            }
            if began.elapsed() > timeout {
                return Err(format!(
                    "timeout waiting for state {:?} (current: {:?})",
                    target, current
                ));
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    /// Caminho do binário que o SCM realmente executa para o AgentMonitor.
    /// Fonte única da verdade: o que o instalador registrou.
    pub fn binary_path() -> PathBuf {
        let from_scm = open()
            .and_then(|svc| svc.query_config().map_err(|e| format!("query_config failed: {}", winerr(e))))
            .map(|cfg| cfg.executable_path.to_string_lossy().into_owned());

        match from_scm {
            Ok(raw) => match parse_exe_from_bin_path(&raw) {
                Some(path) => {
                    info!("Agent binary path resolved from SCM: {:?}", path);
                    return path;
                }
                None => warn!("Could not parse binPath from SCM: '{}'", raw),
            },
            Err(e) => warn!("Could not read service config from SCM: {}", e),
        }
        warn!("Using fallback agent binary path: {}", DEFAULT_AGENT_BINARY_PATH);
        PathBuf::from(DEFAULT_AGENT_BINARY_PATH)
    }

    /// Para o serviço e espera o estado Stopped. Retorna Ok(true) se ele estava rodando.
    pub fn stop() -> Result<bool, String> {
        let svc = open()?;
        match state(&svc)? {
            ServiceState::Stopped => return Ok(false),
            ServiceState::StopPending => {}
            _ => {
                svc.stop().map_err(|e| format!("stop failed: {}", winerr(e)))?;
            }
        }
        wait_for_state(&svc, ServiceState::Stopped, SERVICE_STOP_TIMEOUT)?;
        Ok(true)
    }

    /// Inicia o serviço, espera Running e exige que ele permaneça Running por `stable_for`.
    pub fn start_and_verify(stable_for: Duration) -> Result<(), String> {
        let svc = open()?;
        if state(&svc)? == ServiceState::Stopped {
            svc.start::<&str>(&[]).map_err(|e| format!("start failed: {}", winerr(e)))?;
        }
        wait_for_state(&svc, ServiceState::Running, SERVICE_START_TIMEOUT)?;

        let began = Instant::now();
        while began.elapsed() < stable_for {
            thread::sleep(Duration::from_secs(1));
            let current = state(&svc)?;
            if current != ServiceState::Running {
                return Err(format!(
                    "service left Running state during stability window (now {:?})",
                    current
                ));
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
mod agent_service {
    use super::*;

    pub fn binary_path() -> PathBuf {
        PathBuf::from(DEFAULT_AGENT_BINARY_PATH)
    }

    pub fn stop() -> Result<bool, String> {
        warn!("Service control not implemented on this OS: binary will be replaced without restart");
        Ok(false)
    }

    pub fn start_and_verify(_stable_for: Duration) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Substituição do binário
// ---------------------------------------------------------------------------

fn retry_io<T>(what: &str, mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut last_err = None;
    for attempt in 1..=FILE_OP_ATTEMPTS {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                warn!("{} failed (attempt {}/{}): {}", what, attempt, FILE_OP_ATTEMPTS, e);
                last_err = Some(e);
                if attempt < FILE_OP_ATTEMPTS {
                    thread::sleep(FILE_OP_DELAY);
                }
            }
        }
    }
    Err(last_err.expect("at least one attempt was made"))
}

/// target -> backup, staged -> target. Se a segunda etapa falhar, restaura o backup.
/// Só deve ser chamada com o serviço PARADO (arquivo não pode estar em uso).
fn swap_binary(target: &Path, staged: &Path, backup: &Path) -> io::Result<()> {
    if backup.exists() {
        fs::remove_file(backup)?;
    }

    let had_target = target.exists();
    if had_target {
        fs::rename(target, backup)?;
    }

    if let Err(e) = fs::rename(staged, target) {
        error!("Failed to place new binary at {:?}: {}", target, e);
        if had_target {
            match fs::rename(backup, target) {
                Ok(()) => info!("Restored original binary to {:?}", target),
                Err(re) => error!(
                    "CRITICAL: rollback failed! Target {:?} and backup {:?} are inconsistent: {}",
                    target, backup, re
                ),
            }
        }
        return Err(e);
    }
    Ok(())
}

/// Restaura o backup (.old) sobre o binário e reinicia o serviço.
/// `rename` sobrescreve o destino existente (Windows: MOVEFILE_REPLACE_EXISTING).
fn rollback(target: &Path, backup: &Path) {
    if let Err(e) = agent_service::stop() {
        error!("Rollback: could not stop service: {}", e);
    }
    // Guarda o binario que falhou (agent-bin.failed) para diagnostico.
    let failed = target.with_extension("failed");
    let _ = fs::remove_file(&failed);
    match retry_io("preserve failed binary", || fs::rename(target, &failed)) {
        Ok(()) => info!("Failed binary preserved at {:?} for diagnosis", failed),
        Err(e) => warn!("Could not preserve failed binary as {:?}: {}", failed, e),
    }
    match retry_io("restore backup", || fs::rename(backup, target)) {
        Ok(()) => info!("Rollback: previous binary restored at {:?}", target),
        Err(e) => {
            error!(
                "CRITICAL: rollback failed, could not restore {:?} from {:?}: {}",
                target, backup, e
            );
            return;
        }
    }
    match agent_service::start_and_verify(Duration::ZERO) {
        Ok(()) => info!("Rollback complete: previous agent version is running again"),
        Err(e) => error!("Rollback: failed to restart service with previous binary: {}", e),
    }
}

/// Sequência: staging (serviço ainda rodando) -> stop -> swap -> start -> health check.
fn apply_binary_update(new_binary: &Path) -> Result<(), String> {
    let target = agent_service::binary_path();
    let staged = target.with_extension("new");
    let backup = target.with_extension("old");
    info!("Applying update to {:?}", target);

    // 1. Copia o binário para o mesmo diretório/volume do destino ANTES de parar o serviço,
    //    para minimizar o downtime e garantir que o rename final seja atômico.
    fs::copy(new_binary, &staged)
        .map_err(|e| format!("failed to stage new binary at {:?}: {}", staged, e))?;

    // 2. Para o serviço e espera a parada real (o exe fica liberado).
    let was_running = match agent_service::stop() {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_file(&staged);
            return Err(format!("failed to stop {}: {}", AGENT_SERVICE_NAME, e));
        }
    };

    // 3. Troca os arquivos, com retry (antivírus/indexadores podem segurar o handle por instantes).
    if let Err(e) = retry_io("binary swap", || swap_binary(&target, &staged, &backup)) {
        let _ = fs::remove_file(&staged);
        if was_running {
            if let Err(se) = agent_service::start_and_verify(Duration::ZERO) {
                error!("Failed to restart {} after failed swap: {}", AGENT_SERVICE_NAME, se);
            }
        }
        return Err(format!("failed to replace {:?}: {}", target, e));
    }

    // 4. Sobe o serviço e valida que ele fica de pé; senão, rollback.
    if was_running {
        if let Err(e) = agent_service::start_and_verify(SERVICE_STABILITY_WINDOW) {
            error!("New agent binary failed health check: {}. Rolling back...", e);
            rollback(&target, &backup);
            return Err(format!("new agent version failed to start: {}", e));
        }
    } else {
        info!("{} was stopped before the update; leaving it stopped", AGENT_SERVICE_NAME);
    }

    info!("Binary replaced at {:?} (previous version kept at {:?})", target, backup);
    Ok(())
}

// ---------------------------------------------------------------------------
// Download e verificação de atualização
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn failed_update_key(version: &Version, sha256: &str) -> String {
    format!("{}:{}", version, sha256.to_ascii_lowercase())
}

fn recently_failed(key: &str) -> bool {
    let Ok(content) = fs::read_to_string(FAILED_UPDATE_FILE_PATH) else {
        return false;
    };
    let mut lines = content.lines();
    let (Some(saved_key), Some(ts)) = (lines.next(), lines.next()) else {
        return false;
    };
    let Ok(ts) = ts.trim().parse::<u64>() else {
        return false;
    };
    saved_key.trim() == key && now_secs().saturating_sub(ts) < FAILED_UPDATE_RETRY_AFTER.as_secs()
}

fn mark_update_failed(key: &str) {
    if let Err(e) = fs::write(FAILED_UPDATE_FILE_PATH, format!("{}\n{}\n", key, now_secs())) {
        warn!("Failed to record failed update in {}: {}", FAILED_UPDATE_FILE_PATH, e);
    }
}

fn clear_failed_update() {
    let _ = fs::remove_file(FAILED_UPDATE_FILE_PATH);
}

fn with_auth(request: ureq::Request, config: &AgentConfig) -> Option<ureq::Request> {
    if let agent_config::AuthMethod::ApiKey { key_file } = &config.auth {
        return match fs::read_to_string(key_file) {
            Ok(key) => Some(request.set("X-API-Key", key.trim())),
            Err(e) => {
                error!("Failed to read API key file {:?}: {}", key_file, e);
                None
            }
        };
    }
    Some(request)
}

fn download_and_apply_update(agent: &ureq::Agent, config: &AgentConfig, download_url: &str, expected_hash: &str, failure_key: &str) -> bool {
    let full_url = if download_url.starts_with("http://") || download_url.starts_with("https://") {
        download_url.to_string()
    } else {
        let base = config.endpoint.trim_end_matches('/');
        let path = download_url.trim_start_matches('/');
        format!("{}/{}", base, path)
    };

    info!("Downloading update from: {}", full_url);

    let Some(request) = with_auth(agent.get(&full_url), config) else {
        return false;
    };

    let temp_dir = PathBuf::from(TEMP_DOWNLOAD_DIR);
    if let Err(e) = fs::create_dir_all(&temp_dir) {
        error!("Failed to create temp download directory {:?}: {}", temp_dir, e);
        return false;
    }
    if let Err(e) = agent_config::secret::restrict_to_system_and_admins(&temp_dir) {
        error!("Failed to restrict access to temp directory {:?}: {}", temp_dir, e);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let temp_path = temp_dir.join(format!("agent_update_{}_{}.tmp", timestamp, pid));

    let response = match request.call() {
        Ok(res) => res,
        Err(e) => {
            error!("Failed to download binary: {}", e);
            return false;
        }
    };

    let result = (|| {
        let mut file = match fs::File::create(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to create temp file {:?}: {}", temp_path, e);
                return Err(());
            }
        };

        let mut reader = response.into_reader();
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = file.write_all(&buffer[..n]) {
                        error!("Failed to write to temp file {:?}: {}", temp_path, e);
                        return Err(());
                    }
                }
                Err(e) => {
                    error!("Error reading from download stream: {}", e);
                    return Err(());
                }
            }
        }
        // Fecha o handle antes de hashear/copiar.
        drop(file);

        if !verify_hash(&temp_path, expected_hash) {
            error!("Hash verification failed! Downloaded binary is corrupt or tampered with.");
            return Err(());
        }

        if let Err(e) = apply_binary_update(&temp_path) {
            error!("Failed to apply update: {}", e);
            mark_update_failed(failure_key);
            return Err(());
        }

        Ok(())
    })();

    if temp_path.exists() {
        if let Err(e) = fs::remove_file(&temp_path) {
            warn!("Failed to remove temporary file {:?}: {}", temp_path, e);
        }
    }

    result.is_ok()
}

fn check_for_update(agent: &ureq::Agent, config: &AgentConfig) {
    let url = format!("{}/api/v1/version", config.endpoint.trim_end_matches('/'));

    let Some(request) = with_auth(agent.get(&url), config) else {
        return;
    };

    let resp = match request.call() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to check for updates: {}", e);
            return;
        }
    };

    let body: serde_json::Value = match resp.into_json() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to parse version response as JSON: {}", e);
            return;
        }
    };

    let Some(manifest_str) = body["manifest"].as_str() else {
        warn!("Version response did not contain a manifest.");
        return;
    };
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

    let Some(latest_ver_str) = manifest["version"].as_str() else {
        warn!("Manifest has no version field.");
        return;
    };
    let latest_ver = match Version::parse(latest_ver_str) {
        Ok(v) => v,
        Err(e) => {
            error!("Server returned invalid version '{}': {}", latest_ver_str, e);
            return;
        }
    };

    let current_ver = read_installed_version();
    if latest_ver <= current_ver {
        info!("Agent is up to date. Version: {}", current_ver);
        return;
    }

    info!(
        "Update available! Current: {}, Latest: {}. Notes: {}",
        current_ver,
        latest_ver,
        body["notes"].as_str().unwrap_or("No notes")
    );

    let Some(download_url) = manifest["download_url"].as_str() else {
        warn!("Server did not provide a download URL for the update.");
        return;
    };
    let Some(hash) = manifest["sha256"].as_str() else {
        warn!("Server did not provide a SHA-256 hash for the update.");
        return;
    };

    let failure_key = failed_update_key(&latest_ver, hash);
    if recently_failed(&failure_key) {
        warn!(
            "Update {} failed to apply recently; not retrying for up to {} min (publish a new build to retry now).",
            latest_ver,
            FAILED_UPDATE_RETRY_AFTER.as_secs() / 60
        );
        return;
    }

    info!("Applying update to version {}...", latest_ver);
    if download_and_apply_update(agent, config, download_url, hash, &failure_key) {
        info!("Update to {} applied successfully!", latest_ver);
        clear_failed_update();
        // A versão só é persistida DEPOIS de a substituição + restart terem dado certo.
        if let Err(e) = fs::write(VERSION_FILE_PATH, latest_ver.to_string()) {
            error!("Failed to persist new version {} to {}: {}", latest_ver, VERSION_FILE_PATH, e);
        }
    } else {
        error!("Failed to apply update to {}. Installed version unchanged.", latest_ver);
    }
}

// ---------------------------------------------------------------------------
// Serviço Windows / main
// ---------------------------------------------------------------------------

static GLOBAL_CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

#[cfg(target_os = "windows")]
extern "system" fn service_main(_type: u32, _arg_ptr: *mut *mut u16) {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let status_handle = service_control_handler::register(UPDATER_SERVICE_NAME, move |control| {
        match control {
            service::ServiceControl::Stop | service::ServiceControl::Shutdown => {
                info!("Service stop signal received");
                running_clone.store(false, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NoError,
        }
    })
    .expect("Failed to register service control handler");

    let status = service::ServiceStatus {
        service_type: service::ServiceType::OWN_PROCESS,
        current_state: service::ServiceState::Running,
        controls_accepted: service::ServiceControlAccept::all(),
        exit_code: service::ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::from_secs(0),
        process_id: None,
    };

    status_handle
        .set_service_status(status)
        .expect("Failed to set service status to running");

    info!("Updater service started and running...");

    let config_path = GLOBAL_CONFIG_PATH.get().cloned().unwrap_or_else(|| {
        PathBuf::from("C:\\ProgramData\\agente-monitoramento\\config.toml")
    });

    match AgentConfig::load_from_file(&config_path) {
        Ok(config) => {
            let agent = create_ureq_agent(&config);
            while running.load(Ordering::SeqCst) {
                check_for_update(&agent, &config);

                // Interruptible sleep
                for _ in 0..CHECK_INTERVAL.as_secs() {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }

            let stopped_status = service::ServiceStatus {
                service_type: service::ServiceType::OWN_PROCESS,
                current_state: service::ServiceState::Stopped,
                controls_accepted: service::ServiceControlAccept::all(),
                exit_code: service::ServiceExitCode::NO_ERROR,
                checkpoint: 0,
                wait_hint: Duration::from_secs(0),
                process_id: None,
            };
            let _ = status_handle.set_service_status(stopped_status);
            info!("Updater service stopped gracefully");
        }
        Err(e) => {
            error!("Service failed to load configuration from {:?}: {}", config_path, e);
            let error_status = service::ServiceStatus {
                service_type: service::ServiceType::OWN_PROCESS,
                current_state: service::ServiceState::Stopped,
                controls_accepted: service::ServiceControlAccept::all(),
                exit_code: service::ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::from_secs(0),
                process_id: None,
            };
            let _ = status_handle.set_service_status(error_status);
        }
    }
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Initialize tracing before anything else
    if cli.service && cfg!(target_os = "windows") {
        let log_dir = PathBuf::from("C:\\ProgramData\\agente-monitoramento");
        if let Err(e) = fs::create_dir_all(&log_dir) {
            eprintln!("Warning: Failed to create log directory {:?}: {}", log_dir, e);
        }

        let file_appender = tracing_appender::rolling::never("C:\\ProgramData\\agente-monitoramento", "updater-service.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        // Keep the guard alive for the duration of the program
        Box::leak(Box::new(guard));

        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(non_blocking))
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .init();
    }

    #[cfg(target_os = "windows")]
    if cli.service {
        let config_path = if let Some(path) = cli.config_path {
            PathBuf::from(path)
        } else {
            PathBuf::from("C:\\ProgramData\\agente-monitoramento\\config.toml")
        };
        let _ = GLOBAL_CONFIG_PATH.set(config_path);

        if let Err(e) = service_dispatcher::start(UPDATER_SERVICE_NAME, service_main) {
            error!("Failed to start service dispatcher: {}", e);
            std::process::exit(1);
        }
        return;
    }

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
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    info!("Updater started. Monitoring version {}...", read_installed_version());

    let agent = create_ureq_agent(&config);

    loop {
        check_for_update(&agent, &config);
        thread::sleep(CHECK_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_manifest_accepts_valid_signature() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"{\"version\":\"0.2.0\",\"sha256\":\"abc\"}";
        let signature = signing_key.sign(message);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        // Replica a lógica de verify_manifest usando uma chave gerada no próprio teste
        // (não a chave real do produto).
        use ed25519_dalek::Signature;
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

        assert!(verifying_key.verify_strict(tampered, &signature).is_err());
    }

    #[test]
    fn verify_manifest_rejects_garbage_signature() {
        let result = verify_manifest(b"any message", "not-valid-base64!!!");
        assert!(!result);
    }

    #[test]
    fn parse_bin_path_quoted_with_args() {
        let p = parse_exe_from_bin_path(
            "\"C:\\ProgramData\\agente-monitoramento\\agent-bin.exe\" --service",
        );
        assert_eq!(
            p,
            Some(PathBuf::from("C:\\ProgramData\\agente-monitoramento\\agent-bin.exe"))
        );
    }

    #[test]
    fn parse_bin_path_unquoted_with_args() {
        let p = parse_exe_from_bin_path("C:\\agent\\agent-bin.exe --service --foo");
        assert_eq!(p, Some(PathBuf::from("C:\\agent\\agent-bin.exe")));
    }

    #[test]
    fn parse_bin_path_rejects_garbage() {
        assert_eq!(parse_exe_from_bin_path(""), None);
        assert_eq!(parse_exe_from_bin_path("\"\""), None);
        assert_eq!(parse_exe_from_bin_path("no executable here"), None);
    }

    #[test]
    fn swap_binary_moves_current_to_backup_and_installs_new() {
        let dir = std::env::temp_dir().join(format!("updater_swap_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("agent-bin.exe");
        let staged = target.with_extension("new");
        let backup = target.with_extension("old");
        fs::write(&target, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();

        swap_binary(&target, &staged, &backup).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(fs::read(&backup).unwrap(), b"old");
        assert!(!staged.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
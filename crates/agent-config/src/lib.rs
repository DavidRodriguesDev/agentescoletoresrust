use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use tracing::{info, warn, error};
use thiserror::Error;
use uuid::Uuid;

pub mod secret;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Serialization error (write): {0}")]
    TomlWrite(#[from] toml::ser::Error),
    #[error("Missing required configuration: {0}")]
    MissingRequiredField(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub machine_id: Option<String>,
    pub collection_interval_secs: u64,
    pub log_level: String,
    pub server: ServerConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            machine_id: None,
            collection_interval_secs: 3600,
            log_level: "info".to_string(),
            server: ServerConfig {
                base_url: "PREENCHER".to_string(),
                config_url: None,
                ingest_url: None,
                oauth_token_url: None,
                client_id: "PREENCHER".to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub base_url: String,
    pub config_url: Option<String>,
    pub ingest_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub client_id: String,
}

impl ServerConfig {
    pub fn resolved_config_url(&self) -> String {
        self.config_url.clone().unwrap_or_else(|| format!("{}/v1/config", self.base_url))
    }

    pub fn resolved_ingest_url(&self) -> String {
        self.ingest_url.clone().unwrap_or_else(|| format!("{}/v1/ingest", self.base_url))
    }

    pub fn resolved_oauth_token_url(&self) -> String {
        self.oauth_token_url.clone().unwrap_or_else(|| format!("{}/v1/oauth/token", self.base_url))
    }
}

pub fn get_default_config_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        let mut path = PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()));
        path.push("agente-monitoramento");
        path.push("config.toml");
        path
    } else {
        let mut path = PathBuf::from("/etc/agente-monitoramento");
        path.push("config.toml");
        path
    }
}

pub fn get_reports_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        let mut path = PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()));
        path.push("agente-monitoramento");
        path.push("reports");
        path
    } else {
        let mut path = PathBuf::from("/etc/agente-monitoramento");
        path.push("reports");
        path
    }
}

pub fn load_or_create_config() -> Result<AgentConfig, ConfigError> {
    let path = get_default_config_path();

    if !path.exists() {
        info!("Config file not found at {:?}. Creating default config.", path);
        let default_config = AgentConfig::default();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let toml_string = toml::to_string_pretty(&default_config)?;
        fs::write(&path, toml_string)?;

        warn!("Default config created. Please fill base_url and client_id in {:?}", path);
        return Ok(default_config);
    }

    let content = fs::read_to_string(&path)?;
    let config: AgentConfig = toml::from_str(&content)?;

    Ok(config)
}

pub fn save_config(config: &AgentConfig) -> Result<(), ConfigError> {
    let path = get_default_config_path();
    let toml_string = toml::to_string_pretty(config)?;
    fs::write(path, toml_string)?;
    Ok(())
}

pub fn ensure_machine_id(config: &mut AgentConfig) -> Result<String, ConfigError> {
    if let Some(ref id) = config.machine_id {
        return Ok(id.clone());
    }

    let new_id = Uuid::new_v4().to_string();
    info!("Generating new machine_id: {}", new_id);
    config.machine_id = Some(new_id.clone());
    save_config(config)?;
    Ok(new_id)
}

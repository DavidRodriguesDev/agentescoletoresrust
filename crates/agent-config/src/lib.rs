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
                endpoint: "https://PREENCHER".to_string(),
                auth: AuthMethod::None,
                config_url: None,
                ingest_url: None,
                oauth_token_url: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "api_key")]
    ApiKey {
        key_ref: String,
    },
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials {
        client_id: String,
        client_secret_ref: String,
        token_url: String,
    },
    #[serde(rename = "mtls")]
    MTLS {
        cert_ref: String,
        key_ref: String,
    },
}

impl AuthMethod {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self {
            AuthMethod::None => Ok(()),
            AuthMethod::ApiKey { key_ref } => {
                if key_ref.is_empty() || key_ref == "PREENCHER" {
                    Err(ConfigError::MissingRequiredField("api_key: key_ref is required".to_string()))
                } else {
                    Ok(())
                }
            }
            AuthMethod::OAuth2ClientCredentials { client_id, client_secret_ref, token_url, .. } => {
                if client_id.is_empty() || client_id == "PREENCHER" ||
                   client_secret_ref.is_empty() || client_secret_ref == "PREENCHER" ||
                   token_url.is_empty() || token_url == "PREENCHER" {
                    Err(ConfigError::MissingRequiredField("oauth2: client_id, client_secret_ref, and token_url are required".to_string()))
                } else {
                    Ok(())
                }
            }
            AuthMethod::MTLS { cert_ref, key_ref } => {
                if cert_ref.is_empty() || cert_ref == "PREENCHER" ||
                   key_ref.is_empty() || key_ref == "PREENCHER" {
                    Err(ConfigError::MissingRequiredField("mtls: cert_ref and key_ref are required".to_string()))
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub endpoint: String,
    pub auth: AuthMethod,
    pub config_url: Option<String>,
    pub ingest_url: Option<String>,
    pub oauth_token_url: Option<String>,
}

impl ServerConfig {
    pub fn resolved_config_url(&self) -> String {
        self.config_url.clone().unwrap_or_else(|| format!("{}/v1/config", self.endpoint))
    }

    pub fn resolved_ingest_url(&self) -> String {
        self.ingest_url.clone().unwrap_or_else(|| format!("{}/v1/ingest", self.endpoint))
    }

    pub fn resolved_oauth_token_url(&self) -> String {
        self.oauth_token_url.clone().unwrap_or_else(|| format!("{}/v1/oauth/token", self.endpoint))
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

use std::process::Command;

pub fn restrict_file_to_admins(path: &PathBuf) -> Result<(), ConfigError> {
    if cfg!(target_os = "windows") {
        let status = Command::new("icacls")
            .args([
                path.to_str().unwrap(),
                "/inheritance:r",
                "/grant:r", "SYSTEM:(F)",
                "/grant:r", "Administrators:(F)",
            ])
            .status();

        if let Err(e) = status {
            return Err(ConfigError::Io(e));
        }
    }
    Ok(())
}

/// Loads the agent configuration from the default path.
/// If the file does not exist, a default configuration is created.
///
/// IMPORTANT: This function does NOT validate the configuration content.
/// Callers are responsible for calling `AgentConfig::validate()` after loading,
/// especially if CLI overrides are applied.
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

        // Restrict ACL on creation
        if let Err(e) = restrict_file_to_admins(&path) {
            warn!("Failed to restrict ACLs on config.toml: {}", e);
        }

        warn!("Default config created. Please fill endpoint and auth in {:?}", path);
        return Ok(default_config);
    }

    let content = fs::read_to_string(&path)?;
    let config: AgentConfig = toml::from_str(&content)?;

    Ok(config)
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validation: Endpoint must use HTTPS
        if !self.server.endpoint.starts_with("https://") {
            return Err(ConfigError::MissingRequiredField(
                "Server endpoint must use HTTPS for security".to_string(),
            ));
        }

        // Validation: Auth method fields
        self.server.auth.validate()?;

        Ok(())
    }
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

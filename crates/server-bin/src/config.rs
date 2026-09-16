use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerAuthMethod {
    ApiKey { expected_key: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub auth: ServerAuthMethod,
}

impl ServerConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ServerConfigError> {
        let content = std::fs::read_to_string(path)?;
        let cfg: ServerConfig = toml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn default_for_dev() -> Self {
        Self {
            listen_addr: "127.0.0.1:8443".to_string(),
            auth: ServerAuthMethod::ApiKey { expected_key: "dev-secret-key".to_string() },
        }
    }
}

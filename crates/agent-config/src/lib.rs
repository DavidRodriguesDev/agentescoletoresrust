use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use thiserror::Error;

pub mod secret;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("Insecure endpoint (must start with https://): {0}")]
    InsecureEndpoint(String),
    #[error("Missing auth file for field `{field}`: {path}")]
    MissingAuthFile { field: String, path: PathBuf },
    #[error("Failed to restrict ACL on {path}: {detail}")]
    AclRestrictionFailed { path: PathBuf, detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthMethod {
    None,
    ApiKey { key_file: PathBuf },
    OAuth2ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret_file: PathBuf,
        scope: Option<String>,
    },
    Mtls {
        client_cert_file: PathBuf,
        client_key_file: PathBuf,
        ca_cert_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub endpoint: String,
    pub auth: AuthMethod,
    pub extra_ca_cert_path: Option<String>,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.endpoint.starts_with("https://") {
            return Err(ConfigError::InsecureEndpoint(self.endpoint.clone()));
        }
        match &self.auth {
            AuthMethod::None => Ok(()),
            AuthMethod::ApiKey { key_file } => {
                if !key_file.exists() {
                    return Err(ConfigError::MissingAuthFile {
                        field: "key_file".to_string(),
                        path: key_file.clone(),
                    });
                }
                Ok(())
            }
            AuthMethod::OAuth2ClientCredentials { client_secret_file, .. } => {
                if !client_secret_file.exists() {
                    return Err(ConfigError::MissingAuthFile {
                        field: "client_secret_file".to_string(),
                        path: client_secret_file.clone(),
                    });
                }
                Ok(())
            }
            AuthMethod::Mtls { client_cert_file, client_key_file, ca_cert_file } => {
                if !client_cert_file.exists() {
                    return Err(ConfigError::MissingAuthFile {
                        field: "client_cert_file".to_string(),
                        path: client_cert_file.clone(),
                    });
                }
                if !client_key_file.exists() {
                    return Err(ConfigError::MissingAuthFile {
                        field: "client_key_file".to_string(),
                        path: client_key_file.clone(),
                    });
                }
                if let Some(ca) = ca_cert_file {
                    if !ca.exists() {
                        return Err(ConfigError::MissingAuthFile {
                            field: "ca_cert_file".to_string(),
                            path: ca.clone(),
                        });
                    }
                }
                Ok(())
            }
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let content = if path_ref.extension().and_then(|s| s.to_str()) == Some("enc") {
            let bytes = crate::secret::decrypt_file(path_ref)
                .map_err(|e| ConfigError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
            String::from_utf8(bytes).map_err(|e| ConfigError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?
        } else {
            fs::read_to_string(path_ref)?
        };

        let cfg: AgentConfig = toml::from_str(&content)?;
        cfg.validate()?;

        crate::secret::restrict_to_system_and_admins(path_ref)
            .map_err(|e| ConfigError::AclRestrictionFailed { path: path_ref.to_path_buf(), detail: e.to_string() })?;
        match &cfg.auth {
            AuthMethod::None => {}
            AuthMethod::ApiKey { key_file } => {
                crate::secret::restrict_to_system_and_admins(key_file)
                    .map_err(|e| ConfigError::AclRestrictionFailed { path: key_file.clone(), detail: e.to_string() })?;
            }
            AuthMethod::OAuth2ClientCredentials { client_secret_file, .. } => {
                crate::secret::restrict_to_system_and_admins(client_secret_file)
                    .map_err(|e| ConfigError::AclRestrictionFailed { path: client_secret_file.clone(), detail: e.to_string() })?;
            }
            AuthMethod::Mtls { client_cert_file, client_key_file, ca_cert_file } => {
                crate::secret::restrict_to_system_and_admins(client_cert_file)
                    .map_err(|e| ConfigError::AclRestrictionFailed { path: client_cert_file.clone(), detail: e.to_string() })?;
                crate::secret::restrict_to_system_and_admins(client_key_file)
                    .map_err(|e| ConfigError::AclRestrictionFailed { path: client_key_file.clone(), detail: e.to_string() })?;
                if let Some(ca) = ca_cert_file {
                    crate::secret::restrict_to_system_and_admins(ca)
                        .map_err(|e| ConfigError::AclRestrictionFailed { path: ca.clone(), detail: e.to_string() })?;
                }
            }
        }

        Ok(cfg)
    }
}

// REMOVED: restrict_file_to_admins is now handled by crate::secret::restrict_to_system_and_admins

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use crate::secret;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("temp file");
        write!(file, "{}", content).expect("write");
        file
    }

    #[test]
    fn test_encrypted_config_loading() {
        let toml_content = r#"endpoint = "https://example.com"
auth = { type = "none" }
"#;
        let pure_file = write_toml(toml_content);

        let mut enc_file = NamedTempFile::new().expect("enc file");
        let enc_path = enc_file.path().to_path_buf();

        // We need a path ending in .enc for our logic to trigger
        let final_enc_path = enc_path.with_extension("enc");
        fs::rename(&enc_path, &final_enc_path).expect("rename to .enc");

        secret::encrypt_file(pure_file.path(), &final_enc_path).expect("encryption failed");

        let cfg = AgentConfig::load_from_file(&final_enc_path).expect("should load encrypted config");
        assert_eq!(cfg.endpoint, "https://example.com");

        let _ = fs::remove_file(final_enc_path);
    }

    #[test]
    fn test_insecure_endpoint() {
        let toml = r#"endpoint = "http://example.com"
        auth = { type = "none" }
        "#;
        let file = write_toml(toml);
        let result = AgentConfig::load_from_file(file.path());
        assert!(matches!(result, Err(ConfigError::InsecureEndpoint(_))));
    }

    #[test]
    fn test_api_key_success() {
        let mut key_file = NamedTempFile::new().unwrap();
        writeln!(key_file, "dummy").unwrap();
        let path_str = key_file.path().to_string_lossy().replace("\\", "/");
        let toml = format!(
            r#"endpoint = "https://example.com"
            auth = {{ type = "api_key", key_file = "{}" }}
            "#,
            path_str
        );
        let file = write_toml(&toml);
        let cfg = AgentConfig::load_from_file(file.path()).expect("should load");
        assert_eq!(cfg.endpoint, "https://example.com");
    }

    #[test]
    fn test_api_key_missing_file() {
        let toml = r#"endpoint = "https://example.com"
        auth = { type = "api_key", key_file = "/nonexistent/key.pem" }
        "#;
        let file = write_toml(toml);
        let result = AgentConfig::load_from_file(file.path());
        assert!(matches!(result, Err(ConfigError::MissingAuthFile { field, .. }) if field == "key_file"));
    }
}

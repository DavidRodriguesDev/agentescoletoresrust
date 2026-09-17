use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use thiserror::Error;

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
        let content = fs::read_to_string(&path)?;
        let cfg: AgentConfig = toml::from_str(&content)?;
        cfg.validate()?;

        restrict_file_to_admins(path.as_ref())?;
        match &cfg.auth {
            AuthMethod::None => {}
            AuthMethod::ApiKey { key_file } => {
                restrict_file_to_admins(key_file)?;
            }
            AuthMethod::OAuth2ClientCredentials { client_secret_file, .. } => {
                restrict_file_to_admins(client_secret_file)?;
            }
            AuthMethod::Mtls { client_cert_file, client_key_file, ca_cert_file } => {
                restrict_file_to_admins(client_cert_file)?;
                restrict_file_to_admins(client_key_file)?;
                if let Some(ca) = ca_cert_file {
                    restrict_file_to_admins(ca)?;
                }
            }
        }

        Ok(cfg)
    }
}

pub fn restrict_file_to_admins(path: &Path) -> Result<(), ConfigError> {
    if cfg!(target_os = "windows") {
        let path_str = path.to_string_lossy().to_string();
        let output = std::process::Command::new("icacls")
            .args([
                path_str.as_str(),
                "/inheritance:r",
                "/grant:r", "*S-1-5-18:(F)",
                "/grant:r", "*S-1-5-32-544:(F)",
            ])
            .output()
            .map_err(|e| ConfigError::AclRestrictionFailed {
                path: path.to_path_buf(),
                detail: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ConfigError::AclRestrictionFailed {
                path: path.to_path_buf(),
                detail: stderr,
            });
        }
        Ok(())
    } else {
        // TODO: implementar equivalente via chmod/chown no Linux
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("temp file");
        write!(file, "{}", content).expect("write");
        file
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

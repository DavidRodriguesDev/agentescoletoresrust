use async_trait::async_trait;
use reqwest::{Client, RequestBuilder};
use agent_config::{AgentConfig, AuthMethod};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
}

#[async_trait]
pub trait Transport {
    async fn send_snapshot(&self, snapshot: &crate::types::Snapshot) -> Result<(), TransportError>;
}

pub struct HttpTransport {
    client: Client,
    config: AgentConfig,
    token: tokio::sync::RwLock<Option<String>>,
}

impl HttpTransport {
    pub async fn new(config: AgentConfig) -> Result<Self, TransportError> {
        let mut client_builder = Client::builder();

        if let AuthMethod::Mtls { client_cert_file, client_key_file, ca_cert_file } = &config.auth {
            let mut combined_pem = std::fs::read(client_cert_file)?;
            let key_bytes = std::fs::read(client_key_file)?;
            combined_pem.extend_from_slice(b"\n");
            combined_pem.extend_from_slice(&key_bytes);

            let identity = reqwest::Identity::from_pem(&combined_pem)
                .map_err(|e| TransportError::Auth(format!("Failed to build client identity from cert+key: {}", e)))?;

            client_builder = client_builder.identity(identity);

            if let Some(ca_path) = ca_cert_file {
                let ca_cert = std::fs::read(ca_path)?;
                let root_cert = reqwest::Certificate::from_pem(&ca_cert)
                    .map_err(|e| TransportError::Auth(e.to_string()))?;
                client_builder = client_builder.add_root_certificate(root_cert);
            }
        }

        let client = client_builder.build()?;

        Ok(Self {
            client,
            config,
            token: tokio::sync::RwLock::new(None),
        })
    }

    async fn apply_auth(&self, rb: RequestBuilder) -> Result<RequestBuilder, TransportError> {
        match &self.config.auth {
            AuthMethod::None => Ok(rb),
            AuthMethod::ApiKey { key_file } => {
                let key = std::fs::read_to_string(key_file)?.trim().to_string();
                Ok(rb.header("X-API-Key", key))
            }
            AuthMethod::OAuth2ClientCredentials { .. } => {
                let token = self.get_token().await?;
                Ok(rb.bearer_auth(token))
            }
            AuthMethod::Mtls { .. } => Ok(rb),
        }
    }

    async fn get_token(&self) -> Result<String, TransportError> {
        {
            let token_lock = self.token.read().await;
            if let Some(token) = &*token_lock {
                return Ok(token.clone());
            }
        }

        if let AuthMethod::OAuth2ClientCredentials { token_url, client_id, client_secret_file, scope } = &self.config.auth {
            let secret = std::fs::read_to_string(client_secret_file)?.trim().to_string();

            let mut params = vec![
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", &secret),
            ];
            if let Some(s) = scope {
                params.push(("scope", s));
            }

            let resp = self.client.post(token_url).form(&params).send().await?;

            if !resp.status().is_success() {
                return Err(TransportError::Auth(format!("Token request failed: {}", resp.status())));
            }

            #[derive(serde::Deserialize)]
            struct TokenResponse { access_token: String }
            let token_resp: TokenResponse = resp.json().await?;

            let mut token_lock = self.token.write().await;
            *token_lock = Some(token_resp.access_token.clone());

            Ok(token_resp.access_token)
        } else {
            Err(TransportError::Config("OAuth2 credentials not configured".into()))
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send_snapshot(&self, snapshot: &crate::types::Snapshot) -> Result<(), TransportError> {
        let url = format!("{}/api/v1/ingest", self.config.endpoint);
        let rb = self.client.post(url).json(snapshot);
        let authenticated_rb = self.apply_auth(rb).await?;

        let resp = authenticated_rb.send().await?;
        if !resp.status().is_success() {
            return Err(TransportError::Auth(format!("Ingest failed: {}", resp.status())));
        }

        Ok(())
    }
}

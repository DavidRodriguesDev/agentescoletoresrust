use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use std::path::PathBuf;

pub struct SelfSignedCert {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_self_signed_cert() -> Result<SelfSignedCert, Box<dyn std::error::Error>> {
    // Note: Update the IP below or regenerate the certificate if the server's local IP changes
    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "172.20.1.124".to_string()
    ];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;

    Ok(SelfSignedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

pub fn salvar_cert_completo(cert: &SelfSignedCert) -> std::io::Result<()> {
    let cert_path = PathBuf::from("C:\\ProgramData\\agente-monitoramento\\dev-server-ca.pem");
    let key_path = PathBuf::from("C:\\ProgramData\\agente-monitoramento\\dev-server-ca.key");
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cert_path, &cert.cert_pem)?;
    std::fs::write(&key_path, &cert.key_pem)?;
    Ok(())
}

pub fn carregar_cert_existente() -> Result<SelfSignedCert, Box<dyn std::error::Error>> {
    let cert_path = PathBuf::from("C:\\ProgramData\\agente-monitoramento\\dev-server-ca.pem");
    let key_path = PathBuf::from("C:\\ProgramData\\agente-monitoramento\\dev-server-ca.key");

    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let key_pem = std::fs::read_to_string(&key_path)?;

    Ok(SelfSignedCert { cert_pem, key_pem })
}


pub fn build_server_config(cert: &SelfSignedCert) -> Result<RustlsServerConfig, Box<dyn std::error::Error>> {
    let mut cert_reader = BufReader::new(cert.cert_pem.as_bytes());
    let certs: Vec<CertificateDer> = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let mut key_reader = BufReader::new(cert.key_pem.as_bytes());
    let key: PrivateKeyDer = private_key(&mut key_reader)?
        .ok_or("no private key found in PEM")?;

    let config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}

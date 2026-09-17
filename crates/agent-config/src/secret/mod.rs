use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
};
use windows::Win32::Foundation::LocalFree;

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DPAPI error: {0}")]
    Dpapi(String),
    #[error("Secret not found")]
    NotFound,
    #[error("Invalid secret data")]
    InvalidData,
}

fn get_secret_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        let mut path = PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()));
        path.push("agente-monitoramento");
        path.push("secret.bin");
        path
    } else {
        let mut path = PathBuf::from("/etc/agente-monitoramento");
        path.push("secret.bin");
        path
    }
}

pub fn restrict_to_system_and_admins(path: &Path) -> Result<(), SecretError> {
    let status = Command::new("icacls")
        .args([
            path.to_str().unwrap(),
            "/inheritance:r",
            "/grant:r", "*S-1-5-18:(F)",
            "/grant:r", "*S-1-5-32-544:(F)",
        ])
        .status();

    if let Err(e) = status {
        tracing::warn!("Failed to execute icacls on {:?}: {}", path, e);
    }
    Ok(())
}

pub fn store_secret_bytes(data: &[u8]) -> Result<Vec<u8>, SecretError> {
    if !cfg!(target_os = "windows") {
        return Err(SecretError::Dpapi("DPAPI is only available on Windows".to_string()));
    }

    let data_in = CRYPT_INTEGER_BLOB {
        pbData: data.as_ptr() as *mut u8,
        cbData: data.len() as u32,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        pbData: std::ptr::null_mut(),
        cbData: 0,
    };

    unsafe {
        if CryptProtectData(&data_in, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE, &mut data_out).is_err() {
            return Err(SecretError::Dpapi("CryptProtectData failed".to_string()));
        }

        let encrypted_data = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let result = encrypted_data.to_vec();

        let handle = windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut std::ffi::c_void);
        if let Err(e) = LocalFree(handle) {
            tracing::warn!("DPAPI LocalFree failed in store_secret_bytes: {}", e);
        }

        Ok(result)
    }
}

pub fn load_secret_bytes(encrypted_data: &[u8]) -> Result<Vec<u8>, SecretError> {
    if !cfg!(target_os = "windows") {
        return Err(SecretError::Dpapi("DPAPI is only available on Windows".to_string()));
    }

    let data_in = CRYPT_INTEGER_BLOB {
        pbData: encrypted_data.as_ptr() as *mut u8,
        cbData: encrypted_data.len() as u32,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        pbData: std::ptr::null_mut(),
        cbData: 0,
    };

    unsafe {
        if CryptUnprotectData(&data_in, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE, &mut data_out).is_err() {
            return Err(SecretError::Dpapi("CryptUnprotectData failed".to_string()));
        }

        let decrypted_data = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let result = decrypted_data.to_vec();

        let handle = windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut std::ffi::c_void);
        if let Err(e) = LocalFree(handle) {
            tracing::warn!("DPAPI LocalFree failed in load_secret_bytes: {}", e);
        }

        Ok(result)
    }
}

pub fn store_secret(plaintext: &str) -> Result<(), SecretError> {
    let encrypted = store_secret_bytes(plaintext.as_bytes())?;

    let path = get_secret_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, encrypted)?;

    Ok(())
}

pub fn load_secret() -> Result<String, SecretError> {
    let path = get_secret_path();
    if !path.exists() {
        return Err(SecretError::NotFound);
    }

    let encrypted_data = fs::read(path)?;
    let decrypted_bytes = load_secret_bytes(&encrypted_data)?;

    String::from_utf8(decrypted_bytes).map_err(|_| SecretError::InvalidData)
}

pub fn encrypt_file(src_path: &Path, dst_path: &Path) -> Result<(), SecretError> {
    let plaintext = fs::read(src_path)?;
    let encrypted = store_secret_bytes(&plaintext)?;
    fs::write(dst_path, encrypted)?;

    Ok(())
}

pub fn decrypt_file(path: &Path) -> Result<Vec<u8>, SecretError> {
    let encrypted_data = fs::read(path)?;
    load_secret_bytes(&encrypted_data)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dpapi_memory() {
        let valor = "segredo-de-teste-123";
        let encrypted = store_secret_bytes(valor.as_bytes()).expect("store_secret_bytes falhou");
        let decrypted = load_secret_bytes(&encrypted).expect("load_secret_bytes falhou");
        assert_eq!(valor.as_bytes(), decrypted.as_slice());
    }
}

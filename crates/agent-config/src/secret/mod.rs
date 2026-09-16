use std::fs;
use std::path::PathBuf;
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

pub fn store_secret(plaintext: &str) -> Result<(), SecretError> {
    if !cfg!(target_os = "windows") {
        return Err(SecretError::Dpapi("DPAPI is only available on Windows".to_string()));
    }

    let data_in = CRYPT_INTEGER_BLOB {
        pbData: plaintext.as_bytes().as_ptr() as *mut u8,
        cbData: plaintext.len() as u32,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        pbData: std::ptr::null_mut(),
        cbData: 0,
    };

    unsafe {
        // Use CRYPTPROTECT_LOCAL_MACHINE (0x01) for machine-wide scope
        if CryptProtectData(&data_in, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE, &mut data_out).is_err() {
            return Err(SecretError::Dpapi("CryptProtectData failed".to_string()));
        }

        let encrypted_data = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);

        let path = get_secret_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, encrypted_data)?;

        // Free the buffer allocated by DPAPI
        let handle = windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut std::ffi::c_void);
        let _ = LocalFree(handle);

        // Restrict ACL: only SYSTEM and Administrators
        if let Err(e) = crate::restrict_file_to_admins(&path) {
            tracing::warn!("Failed to set ACLs on secret.bin: {}", e);
        }

    }

    Ok(())
}

pub fn load_secret() -> Result<String, SecretError> {
    if !cfg!(target_os = "windows") {
        return Err(SecretError::Dpapi("DPAPI is only available on Windows".to_string()));
    }

    let path = get_secret_path();
    if !path.exists() {
        return Err(SecretError::NotFound);
    }

    let encrypted_data = fs::read(path)?;

    let data_in = CRYPT_INTEGER_BLOB {
        pbData: encrypted_data.as_ptr() as *mut u8,
        cbData: encrypted_data.len() as u32,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        pbData: std::ptr::null_mut(),
        cbData: 0,
    };

    unsafe {
        // Use CRYPTPROTECT_LOCAL_MACHINE (0x01) to decrypt machine-wide secret
        if CryptUnprotectData(&data_in, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE, &mut data_out).is_err() {
            return Err(SecretError::Dpapi("CryptUnprotectData failed".to_string()));
        }

        let decrypted_data = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let secret = String::from_utf8(decrypted_data.to_vec())
            .map_err(|_| SecretError::InvalidData)?;

        // Free the buffer allocated by DPAPI
        let handle = windows::Win32::Foundation::HLOCAL(data_out.pbData as *mut std::ffi::c_void);
        let _ = LocalFree(handle);

        Ok(secret)
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    // Note: This test writes and reads from C:\ProgramData\agente-monitoramento\secret.bin
    // as it validates the actual machine-wide DPAPI behavior.
    #[test]
    fn roundtrip_store_and_load() {
        let valor = "segredo-de-teste-123";
        store_secret(valor).expect("store_secret falhou");
        let recuperado = load_secret().expect("load_secret falhou");
        assert_eq!(valor, recuperado);
    }
}

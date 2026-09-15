use winreg::enums::*;
use winreg::RegKey;
use agent_core::types::InstalledApplication;
use collector_common::CollectorError;

fn collect_from_key(key: &RegKey, apps: &mut Vec<InstalledApplication>) {
    let subkeys = key.enum_keys();

    for subkey_name in subkeys {
        if let Ok(name) = subkey_name {
            if let Ok(subkey) = key.open_subkey(&name) {
                let app_name = subkey.get_value::<String, _>("DisplayName").ok();

                if let Some(name) = app_name {
                    let version = subkey.get_value::<String, _>("DisplayVersion").ok();
                    let publisher = subkey.get_value::<String, _>("Publisher").ok();
                    let install_date = subkey.get_value::<String, _>("InstallDate").ok();

                    apps.push(InstalledApplication {
                        name,
                        version,
                        publisher,
                        install_date,
                    });
                }
            }
        }
    }
}

pub fn collect_installed_apps() -> Result<Vec<InstalledApplication>, CollectorError> {
    let mut apps = Vec::new();

    // 1. HKEY_LOCAL_MACHINE (64-bit)
    if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") {
        collect_from_key(&key, &mut apps);
    }

    // 2. HKEY_LOCAL_MACHINE (32-bit / WOW6432Node)
    if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") {
        collect_from_key(&key, &mut apps);
    }

    // 3. HKEY_CURRENT_USER
    if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") {
        collect_from_key(&key, &mut apps);
    }

    // Deduplicate by (name, version)
    apps.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    apps.dedup_by(|a, b| a.name == b.name && a.version == b.version);

    Ok(apps)
}

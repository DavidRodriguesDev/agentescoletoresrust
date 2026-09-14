use agent_core::types::UpdateInfo;
use std::process::Command;

pub fn collect_updates() -> Vec<UpdateInfo> {
    tracing::info!("Collecting Linux updates via apt list --upgradable...");

    // We read from the existing local index to avoid requiring sudo/network calls.
    // 2>/dev/null filters out the "Listing... Done" message from stderr.
    let output = Command::new("sh")
        .arg("-c")
        .arg("apt list --upgradable 2>/dev/null")
        .output()
        .map_err(|e| {
            tracing::warn!("Failed to execute apt list: {}", e);
            e
        })
        .ok();

    if let Some(out) = output {
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let mut updates = Vec::new();

        for line in stdout_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Listing...") {
                continue;
            }

            // Format: package/origin version architecture [upgradable from: old_version]
            // Example: google-chrome-stable/stable 128.0.6613.119-1 amd64 [upgradable from: 128.0.6613.85-1]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let package_full = parts[0];
                let version = parts[1];

                // Package name is before the first '/'
                let package_name = package_full.split('/').next().unwrap_or(package_full).to_string();

                updates.push(UpdateInfo {
                    package_name,
                    version_available: version.to_string(),
                    severity: "Normal".to_string(),
                });
            }
        }
        return updates;
    }
    vec![]
}

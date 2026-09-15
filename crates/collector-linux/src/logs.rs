use agent_core::types::LogEntry;
use std::process::Command;
use serde_json::Value;
use chrono::{DateTime, Utc};

pub fn collect_logs() -> Vec<LogEntry> {
    tracing::info!("Collecting Linux system logs via journalctl...");

    // -o json: output in JSON format
    // -n 5: last 5 entries
    let output = Command::new("journalctl")
        .args(["-o", "json", "-n", "5"])
        .output()
        .map_err(|e| {
            tracing::warn!("Failed to execute journalctl: {}", e);
            e
        })
        .ok();

    if let Some(out) = output {
        if !out.status.success() {
            tracing::warn!("journalctl returned non-zero exit code: {}. Some logs may be inaccessible without sudo.", out.status);
        }

        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let mut entries = Vec::new();

        // journalctl -o json produces JSON Lines (one JSON object per line)
        
        for line in stdout_str.lines() {
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(json) = serde_json::from_str::<Value>(line) {
                // journalctl timestamps are in microseconds since epoch, but come as strings in JSON
                let timestamp = json["__REALTIME_TIMESTAMP"].as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(|micros| {
                        let seconds = micros / 1_000_000;
                        let nanos = (micros % 1_000_000) * 1000;
                        DateTime::from_timestamp(seconds, nanos as u32)
                    })
                    .unwrap_or_else(Utc::now);

                let level = json["PRIORITY"].as_str()
                    .and_then(|p| p.parse::<u8>().ok())
                    .map(|p| match p {
                        0..=3 => "Error",
                        4 => "Warning",
                        5..=6 => "Info",
                        _ => "Debug",
                    })
                    .unwrap_or("Info")
                    .to_string();

                entries.push(LogEntry {
                    timestamp,
                    level,
                    message: json["MESSAGE"].as_str().unwrap_or("No message").to_string(),
                    source: json["SYSLOG_IDENTIFIER"].as_str().unwrap_or("Unknown").to_string(),
                });
            } else {
                tracing::debug!("Failed to parse journalctl JSON line: {}", line);
            }
        }
        return entries;
    }
    vec![]
}

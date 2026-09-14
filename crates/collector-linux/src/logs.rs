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
                // journalctl timestamps are in microseconds since epoch
                let timestamp_micros = json["__REALTIME_TIMESTAMP"].as_i64();
                let timestamp = timestamp_micros
                    .map(|ms| {
                        // Convert microseconds to seconds and nanoseconds for DateTime
                        let seconds = ms / 1_000_000;
                        let nanos = (ms % 1_000_000) * 1000;
                        DateTime::from_timestamp(seconds, nanos as u32)
                            .unwrap_or(Utc::now())
                    })
                    .unwrap_or_else(Utc::now);

                entries.push(LogEntry {
                    timestamp,
                    level: "Info".to_string(), // journalctl has priority levels, but we simplify to Info for now
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

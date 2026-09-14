use agent_core::types::{Snapshot};
use collector_common::PlatformCollector;
use collector_windows::WindowsCollector;
use collector_linux::LinuxCollector;
use chrono::Utc;
use tracing_subscriber;

fn main() {
    tracing_subscriber::fmt::init();

    #[cfg(target_os = "windows")]
    {
        println!("--- Windows Monitoring Agent Test ---");
        let mut collector = WindowsCollector::new();
        run_test_pipeline(collector);
    }

    #[cfg(target_os = "linux")]
    {
        println!("--- Linux Monitoring Agent Test ---");
        let mut collector = LinuxCollector::new();
        run_test_pipeline(collector);
    }
}

fn run_test_pipeline<C: PlatformCollector>(mut collector: C) {
    println!("Collecting Hardware...");
    let hardware = match collector.collect_hardware() {
        Ok(h) => h,
        Err(e) => {
            println!("Error collecting hardware: {}", e);
            return;
        }
    };
    println!("Hardware: {:#?}", hardware);

    println!("\nCollecting Security...");
    let security = collector.collect_security().unwrap_or_else(|e| {
        tracing::warn!("Failed to collect security data: {}", e);
        None
    });
    println!("Security: {:#?}", security);

    println!("\nCollecting Access...");
    let access = collector.collect_access().unwrap_or_else(|e| {
        tracing::warn!("Failed to collect access data: {}", e);
        None
    });
    println!("Access: {:#?}", access);

    println!("\nCollecting Logs...");
    let logs = collector.collect_logs();
    println!("Logs: {:#?}", logs);

    println!("\nCollecting Updates...");
    let updates = collector.collect_updates();
    println!("Updates: {:#?}", updates);

    let snapshot = Snapshot {
        machine_id: "test-machine-01".to_string(),
        hostname: "test-host".to_string(),
        os: "detected".to_string(),
        collected_at: Utc::now(),
        hardware,
        logs,
        pending_updates: updates,
        security,
        access,
        observations: vec![],
    };

    println!("\nFinal Snapshot: {:#?}", snapshot);
    println!("\nPress ENTER to exit...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

use agent_core::types::{Snapshot, HardwareSnapshot};
use collector_common::PlatformCollector;
use collector_windows::WindowsCollector;
use collector_linux::LinuxCollector;
use agent_config::AgentConfig;
use agent_core::transport::{HttpTransport, Transport};
use chrono::Utc;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, prelude::*};
use clap::{Parser, Subcommand};
use agent_core::execution_log::{ExecutionLog, StepLog, StepStatus, detect_permission_issue, RelatorioFinal};
use std::time::Instant;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "agent-bin")]
#[command(about = "Multi-OS Monitoring Agent", long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    // No subcommands currently active
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // 1. Determine config path
    let config_path = if let Some(path) = cli.config_path {
        PathBuf::from(path)
    } else if cfg!(target_os = "windows") {
        PathBuf::from("C:\\ProgramData\\agente-monitoramento\\config.toml")
    } else {
        PathBuf::from("/etc/agente-monitoramento/config.toml")
    };

    // 2. Load configuration
    let config = match AgentConfig::load_from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            // Initialize basic tracing to log the error
            tracing_subscriber::fmt::init();
            error!("Configuration error: {}", e);
            println!("\n[!] Error: Could not load configuration from {:?}", config_path);
            std::process::exit(1);
        }
    };

    // 3. Initialize Tracing (Fixed INFO level)
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    // 4. Determine Machine ID from hostname
    let machine_id = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "UNKNOWN-HOST".to_string());
    info!("Machine ID: {}", machine_id);

    // 5. Initialize Transport
    let transport = match HttpTransport::new(config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to initialize transport: {}", e);
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "windows")]
    {
        println!("--- Windows Monitoring Agent Test ---");
        let collector = WindowsCollector::new();
        run_test_pipeline(collector, &machine_id, &transport).await;
    }

    #[cfg(target_os = "linux")]
    {
        println!("--- Linux Monitoring Agent Test ---");
        let collector = LinuxCollector::new();
        run_test_pipeline(collector, &machine_id, &transport).await;
    }
}

fn salvar_relatorio(relatorio: &RelatorioFinal, machine_id: &str) {
    let dir = if cfg!(target_os = "windows") {
        PathBuf::from("C:\\ProgramData\\agente-monitoramento\\reports")
    } else {
        PathBuf::from("/etc/agente-monitoramento/reports")
    };

    if let Err(e) = fs::create_dir_all(&dir) {
        error!("Failed to create reports directory {:?}: {}", dir, e);
        return;
    }

    let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("relatorio_{}_{}.json", machine_id, timestamp);
    let path = dir.join(filename);

    match serde_json::to_string_pretty(relatorio) {
        Ok(json) => {
            if let Err(e) = fs::write(&path, json) {
                error!("Failed to write report to {:?}: {}", path, e);
            } else {
                info!("Final report saved to {:?}", path);
            }
        }
        Err(e) => error!("Failed to serialize final report: {}", e),
    }
}

/// Usa para etapas que podem falhar (retornam Result<T, E>).
fn executar_e_registrar<T, E: std::fmt::Display>(
    log: &mut ExecutionLog,
    nome_etapa: &str,
    func: impl FnOnce() -> Result<T, E>,
) -> Option<T> {
    let started_at = Utc::now();
    let inicio = Instant::now();
    let resultado = func();
    let duracao = inicio.elapsed().as_millis();

    match resultado {
        Ok(valor) => {
            log.steps.push(StepLog {
                step_name: nome_etapa.to_string(),
                started_at,
                duration_ms: duracao,
                status: StepStatus::Success,
                error_message: None,
                permission_issue: None,
                warnings: Vec::new(),
            });
            Some(valor)
        }
        Err(erro) => {
            let msg = erro.to_string();
            let permissao = detect_permission_issue(&msg);
            log.steps.push(StepLog {
                step_name: nome_etapa.to_string(),
                started_at,
                duration_ms: duracao,
                status: StepStatus::Error,
                error_message: Some(msg),
                permission_issue: permissao,
                warnings: Vec::new(),
            });
            None
        }
    }
}

/// Usa para etapas que não retornam Result (sempre "sucesso", só mede duração).
fn executar_e_registrar_infalivel<T>(
    log: &mut ExecutionLog,
    nome_etapa: &str,
    func: impl FnOnce() -> T,
) -> T {
    let started_at = Utc::now();
    let inicio = Instant::now();
    let valor = func();
    let duracao = inicio.elapsed().as_millis();

    log.steps.push(StepLog {
        step_name: nome_etapa.to_string(),
        started_at,
        duration_ms: duracao,
        status: StepStatus::Success,
        error_message: None,
        permission_issue: None,
        warnings: Vec::new(),
    });

    valor
}

fn extrair_avisos_hardware(hardware: &agent_core::types::HardwareSnapshot) -> Vec<String> {
    hardware.collection_warnings.clone()
}

fn extrair_avisos_security(security: &Option<agent_core::types::SecuritySnapshot>) -> Vec<String> {
    security.as_ref().map(|s| s.collection_warnings.clone()).unwrap_or_default()
}

fn extrair_avisos_access(access: &Option<agent_core::types::AccessSnapshot>) -> Vec<String> {
    access.as_ref().map(|a| a.collection_warnings.clone()).unwrap_or_default()
}

async fn run_test_pipeline<C: PlatformCollector>(mut collector: C, machine_id: &str, transport: &dyn Transport) {
    let mut execution_log = ExecutionLog::new();

    println!("Collecting Hardware...");
    let hardware = executar_e_registrar(&mut execution_log, "hardware", || {
        collector.collect_hardware()
    }).unwrap_or_else(|| {
        println!("Error collecting hardware. Using dummy data.");
        HardwareSnapshot {
            cpu_usage: 0.0, ram_total: 0, ram_used: 0, disk_usage: vec![], uptime: 0,
            cpu_model: None, cpu_max_ghz: None, cpu_current_ghz: None, cpu_socket: None,
            ram_slots: vec![], gpus: vec![], battery: None, service_tag: None, serial_number: None,
            collection_warnings: Vec::new(),
        }
    });
    if let Some(step) = execution_log.steps.iter_mut().find(|s| s.step_name == "hardware") {
        step.warnings = extrair_avisos_hardware(&hardware);
    }
    println!("Hardware: {:#?}", hardware);

    println!("\nCollecting Security...");
    let security = executar_e_registrar(&mut execution_log, "security", || {
        collector.collect_security()
    }).flatten();
    if let Some(step) = execution_log.steps.iter_mut().find(|s| s.step_name == "security") {
        step.warnings = extrair_avisos_security(&security);
    }
    println!("Security: {:#?}", security);

    println!("\nCollecting Access...");
    let access = executar_e_registrar(&mut execution_log, "access", || {
        collector.collect_access()
    }).flatten();
    if let Some(step) = execution_log.steps.iter_mut().find(|s| s.step_name == "access") {
        step.warnings = extrair_avisos_access(&access);
    }
    println!("Access: {:#?}", access);

    println!("\nCollecting Logs...");
    let logs = executar_e_registrar_infalivel(&mut execution_log, "logs", || {
        collector.collect_logs()
    });
    println!("Logs: {:#?}", logs);

    println!("\nCollecting Updates...");
    let updates = executar_e_registrar_infalivel(&mut execution_log, "updates", || {
        collector.collect_updates()
    });
    println!("Updates: {:#?}", updates);

    println!("\nCollecting Installed Applications...");
    let apps = executar_e_registrar(&mut execution_log, "installed_applications", || {
        collector.collect_installed_applications()
    }).unwrap_or_default();
    println!("Apps: {:#?}", apps);

    let snapshot = Snapshot {
        machine_id: machine_id.to_string(),
        hostname: machine_id.to_string(),
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

    info!("Sending snapshot to server...");
    match transport.send_snapshot(&snapshot).await {
        Ok(_) => info!("Snapshot sent successfully!"),
        Err(e) => error!("Failed to send snapshot: {}", e),
    }

    execution_log.finish();

    let relatorio = RelatorioFinal {
        snapshot,
        execution_log,
    };

    salvar_relatorio(&relatorio, machine_id);

    println!("\n=== Log de Execução ===");
    println!("{:#?}", relatorio.execution_log);

    println!("\nPress ENTER to exit...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

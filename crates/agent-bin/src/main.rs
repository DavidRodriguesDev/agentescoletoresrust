use agent_core::types::{Snapshot, HardwareSnapshot};
use collector_common::PlatformCollector;
use collector_windows::WindowsCollector;
use agent_config::AgentConfig;
use agent_core::transport::{HttpTransport, Transport};
use chrono::Utc;
use tracing::{info, error, warn};
use tracing_subscriber::{fmt, prelude::*};
use clap::{Parser, Subcommand};
use agent_core::execution_log::{ExecutionLog, StepLog, StepStatus, detect_permission_issue, RelatorioFinal};
use std::time::{Instant, Duration};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use semver::Version;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(target_os = "windows")]
use windows_service::{
    service,
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "agent-bin")]
#[command(about = "Multi-OS Monitoring Agent", long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,

    #[arg(long)]
    service: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    // No subcommands currently active
}

async fn run_agent_loop(
    config: AgentConfig,
    keep_running: Arc<AtomicBool>,
) {
    let machine_id = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "UNKNOWN-HOST".to_string());

    info!("Agent loop started for machine: {}", machine_id);

    let transport = match HttpTransport::new(config.clone()).await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to initialize transport: {}", e);
            return;
        }
    };

    let interval_secs = config.collection_interval_secs.unwrap_or(12 * 3600);
    info!("Collection interval set to {} seconds", interval_secs);

    // Delay initial collection by 5 seconds to avoid immediate EDR/AV flags
    info!("Waiting 5 seconds before first collection to stabilize...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    while keep_running.load(Ordering::SeqCst) {
        info!("Starting snapshot collection cycle...");
        #[cfg(target_os = "windows")]
        {
            let collector = WindowsCollector::new();
            run_test_pipeline(collector, &machine_id, &transport).await;
        }

        info!("Snapshot collection cycle complete. Waiting for next interval ({}s).", interval_secs);

        for _ in 0..interval_secs {
        if !keep_running.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    info!("Agent loop received stop signal. Shutting down...");
}

#[cfg(target_os = "windows")]
extern "system" fn service_main(_type: u32, _arg_ptr: *mut *mut u16) {
    // Crash diagnostic: capture panics to a simple file
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("PANIC occurred: {}\n{}", chrono::Utc::now(), info);
        let _ = std::fs::write("C:\\ProgramData\\agente-monitoramento\\crash.log", msg);
    }));

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let status_handle = service_control_handler::register("AgentMonitor", move |control| {
        // BRUTE FORCE RAW DEBUGGING: Synchronous write to file before anything else
        let debug_path = "C:\\ProgramData\\agente-monitoramento\\raw-debug.txt";
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(debug_path) {
            let now = std::time::SystemTime::now();
            let log_line = format!("{:?} | Control: {:?}\n", now, control);
            let _ = file.write_all(log_line.as_bytes());
            let _ = file.sync_all();
        }

        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        info!("[{}] !!! SERVICE CONTROL RECEIVED: {:?} !!!", timestamp, control);
        match control {
            service::ServiceControl::Stop | service::ServiceControl::Shutdown => {
                info!("Service stop signal received - SETTING STOP SIGNAL TO FALSE");
                running_clone.store(false, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => {
                info!("Received non-stop control signal: {:?}. Ignoring.", control);
                ServiceControlHandlerResult::NoError
            }
        }
    }).expect("Failed to register service control handler");

    // 1. Set status to START_PENDING immediately to tell SCM we are working on it
    let pending_status = service::ServiceStatus {
        service_type: service::ServiceType::OWN_PROCESS,
        current_state: service::ServiceState::StartPending,
        controls_accepted: service::ServiceControlAccept::all(),
        exit_code: service::ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = status_handle.set_service_status(pending_status);

    // 2. Load config
    let config_path = PathBuf::from("C:\\ProgramData\\agente-monitoramento\\config.toml");
    match AgentConfig::load_from_file(&config_path) {
        Ok(config) => {
            // 3. Now report as RUNNING. The SCM is satisfied.
            let running_status = service::ServiceStatus {
                service_type: service::ServiceType::OWN_PROCESS,
                current_state: service::ServiceState::Running,
                controls_accepted: service::ServiceControlAccept::all(),
                exit_code: service::ServiceExitCode::NO_ERROR,
                checkpoint: 0,
                wait_hint: Duration::from_secs(0),
                process_id: None,
            };
            status_handle.set_service_status(running_status)
                .expect("Failed to set service status to running");

            info!("Agent monitor service marked as RUNNING. Spawning worker thread...");

            // 4. SPAWN WORKER THREAD
            let running_for_thread = Arc::clone(&running);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to build tokio runtime in worker thread");

                rt.block_on(run_agent_loop(config, running_for_thread));
            });

            // 5. MAIN THREAD WAIT LOOP
            while running.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(500));
            }

            // 6. Final stop status
            let stopped_status = service::ServiceStatus {
                service_type: service::ServiceType::OWN_PROCESS,
                current_state: service::ServiceState::Stopped,
                controls_accepted: service::ServiceControlAccept::all(),
                exit_code: service::ServiceExitCode::NO_ERROR,
                checkpoint: 0,
                wait_hint: Duration::from_secs(0),
                process_id: None,
            };
            let _ = status_handle.set_service_status(stopped_status);
            info!("Agent monitor service stopped gracefully");
        },
        Err(e) => {
            error!("Service failed to load configuration from {:?}: {}", config_path, e);
            let error_status = service::ServiceStatus {
                service_type: service::ServiceType::OWN_PROCESS,
                current_state: service::ServiceState::Stopped,
                controls_accepted: service::ServiceControlAccept::all(),
                exit_code: service::ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::from_secs(0),
                process_id: None,
            };
            let _ = status_handle.set_service_status(error_status);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.service && cfg!(target_os = "windows") {
        let log_dir = PathBuf::from("C:\\ProgramData\\agente-monitoramento");
        if let Err(e) = fs::create_dir_all(&log_dir) {
            eprintln!("Warning: Failed to create log directory {:?}: {}", log_dir, e);
        }

        let file_appender = tracing_appender::rolling::never("C:\\ProgramData\\agente-monitoramento", "agent-service.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // Keep the guard alive for the duration of the program
        Box::leak(Box::new(_guard));

        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(non_blocking))
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .init();

        if let Err(e) = service_dispatcher::start("AgentMonitor", service_main) {
            error!("Failed to start service dispatcher: {}", e);
            std::process::exit(1);
        }
        return;
    }

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

    info!("Starting Agent v{}", AGENT_VERSION);

    // 4. Initialize Transport
    // Transport is now initialized inside run_agent_loop to avoid duplication and blockages

    // 5. Determine Machine ID from hostname
    let machine_id = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "UNKNOWN-HOST".to_string());
    info!("Machine ID: {}", machine_id);

    let keep_running = Arc::new(AtomicBool::new(true));

    #[cfg(target_os = "windows")]
    {
        println!("--- Windows Monitoring Agent (Loop Mode) ---");
        run_agent_loop(config, keep_running).await;
    }

    #[cfg(target_os = "linux")]
    {
        println!("--- Linux Monitoring Agent (Loop Mode) ---");
        // run_agent_loop(config, stop_signal).await;
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
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("\nCollecting Security...");
    let security = executar_e_registrar(&mut execution_log, "security", || {
        collector.collect_security()
    }).flatten();
    if let Some(step) = execution_log.steps.iter_mut().find(|s| s.step_name == "security") {
        step.warnings = extrair_avisos_security(&security);
    }
    println!("Security: {:#?}", security);
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("\nCollecting Access...");
    let access = executar_e_registrar(&mut execution_log, "access", || {
        collector.collect_access()
    }).flatten();
    if let Some(step) = execution_log.steps.iter_mut().find(|s| s.step_name == "access") {
        step.warnings = extrair_avisos_access(&access);
    }
    println!("Access: {:#?}", access);
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("\nCollecting Logs...");
    let logs = executar_e_registrar_infalivel(&mut execution_log, "logs", || {
        collector.collect_logs()
    });
    println!("Logs: {:#?}", logs);
    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("\nCollecting Updates...");
    let updates = executar_e_registrar_infalivel(&mut execution_log, "updates", || {
        collector.collect_updates()
    });
    println!("Updates: {:#?}", updates);
    tokio::time::sleep(Duration::from_secs(2)).await;

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
}

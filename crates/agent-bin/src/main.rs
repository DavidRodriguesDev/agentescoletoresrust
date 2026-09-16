use agent_core::types::{Snapshot, HardwareSnapshot};
use collector_common::PlatformCollector;
use collector_windows::WindowsCollector;
use collector_linux::LinuxCollector;
use agent_config::{load_or_create_config, save_config, ensure_machine_id, secret};
use chrono::Utc;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, prelude::*};
use clap::{Parser, Subcommand};
use agent_core::execution_log::{ExecutionLog, StepLog, StepStatus, detect_permission_issue, RelatorioFinal};
use std::time::Instant;
use std::fs;
#[derive(Parser)]
#[command(name = "agent-bin")]
#[command(about = "Multi-OS Monitoring Agent", long_about = None)]
struct Cli {
    #[arg(long)]
    base_url: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Set the client secret for API authentication
    SetSecret,
}

fn main() {
    let cli = Cli::parse();

    if let Some(Commands::SetSecret) = cli.command {
        // Init tracing for the set-secret command
        tracing_subscriber::fmt::init();
        handle_set_secret();
        return;
    }

    // 1. Load or create configuration
    let mut config = match load_or_create_config() {
        Ok(c) => c,
        Err(e) => {
            tracing_subscriber::fmt::init();
            error!("Configuration error: {}", e);
            println!("\n[!] Error: Please configure the agent before running.");
            println!("Check: C:\\ProgramData\\agente-monitoramento\\config.toml");
            std::process::exit(1);
        }
    };

    // 2. Override placeholders if flags are provided
    let mut modified = false;
    if let Some(url) = cli.base_url {
        if config.server.endpoint == "https://PREENCHER" {
            config.server.endpoint = url;
            modified = true;
        }
    }

    // client_id is now specific to AuthMethod::OAuth2ClientCredentials.
    // Since the current CLI structure is simple, we remove the generic --client-id
    // logic to avoid silent failure or ambiguity.
    // Validations will now catch missing fields based on the chosen AuthMethod.

    if modified {
        if let Err(e) = save_config(&config) {
            tracing_subscriber::fmt::init();
            error!("Failed to save updated config: {}", e);
        }
    }

    // 3. Final Validation of configuration (HTTPS and Auth Fields)
    if let Err(e) = config.validate() {
        tracing_subscriber::fmt::init();
        error!("Configuration validation failed: {}", e);
        println!("\n[!] Error: Configuration incomplete or insecure.");
        println!("Check: C:\\ProgramData\\agente-monitoramento\\config.toml");
        println!("Ensure endpoint starts with 'https://' and all fields for the chosen auth method are filled.");
        std::process::exit(1);
    }


    // 4. Initialize Tracing based on config
    let level = match config.log_level.to_lowercase().as_str() {
        "trace" => tracing_subscriber::filter::LevelFilter::TRACE,
        "debug" => tracing_subscriber::filter::LevelFilter::DEBUG,
        "info" => tracing_subscriber::filter::LevelFilter::INFO,
        "warn" => tracing_subscriber::filter::LevelFilter::WARN,
        "error" => tracing_subscriber::filter::LevelFilter::ERROR,
        _ => tracing_subscriber::filter::LevelFilter::INFO,
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(tracing_subscriber::filter::EnvFilter::from_default_env().add_directive(level.into())))
        .init();

    // 5. Resolve and log Server URLs
    info!("Server Configuration Resolved:");
    info!("  Endpoint: {}", config.server.endpoint);
    info!("  Config URL: {}", config.server.resolved_config_url());
    info!("  Ingest URL: {}", config.server.resolved_ingest_url());
    info!("  OAuth URL:  {}", config.server.resolved_oauth_token_url());

    // 6. Handle machine_id
    let machine_id = match ensure_machine_id(&mut config) {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to ensure machine_id: {}", e);
            std::process::exit(1);
        }
    };
    info!("Machine ID: {}", machine_id);

    // 7. Try to load secret to verify it's set
    match secret::load_secret() {
        Ok(_) => info!("Client secret loaded successfully."),
        Err(e) => {
            warn!("Client secret not set: {}. Use set-secret to configure.", e);
        }
    }

    #[cfg(target_os = "windows")]
    {
        println!("--- Windows Monitoring Agent Test ---");
        let collector = WindowsCollector::new();
        run_test_pipeline(collector, &machine_id);
    }

    #[cfg(target_os = "linux")]
    {
        println!("--- Linux Monitoring Agent Test ---");
        let collector = LinuxCollector::new();
        run_test_pipeline(collector, &machine_id);
    }
}

fn salvar_relatorio(relatorio: &RelatorioFinal, machine_id: &str) {
    let dir = agent_config::get_reports_dir();
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

fn handle_set_secret() {
    println!("Enter the client secret:");
    let password = rpassword::read_password().expect("Failed to read password");

    match secret::store_secret(&password) {
        Ok(_) => println!("Secret stored successfully!"),
        Err(e) => error!("Failed to store secret: {}", e),
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

fn run_test_pipeline<C: PlatformCollector>(mut collector: C, machine_id: &str) {
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
        hostname: "test-host".to_string(),
        os: "detected".to_string(),
        collected_at: Utc::now(),
        hardware,
        logs,
        pending_updates: updates,
        security,
        access,
        installed_applications: apps,
        observations: vec![],
    };

    println!("\nFinal Snapshot: {:#?}", snapshot);

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

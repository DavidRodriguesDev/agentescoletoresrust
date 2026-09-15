use agent_core::types::{HardwareSnapshot, DiskInfo, SmartStatus, InstalledApplication};
use thiserror::Error;
use sysinfo::{System, Disks};
use std::process::Command;
use serde_json::Value;

#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("Failed to collect hardware data: {0}")]
    HardwareCollectionError(String),
    #[error("System error: {0}")]
    SystemError(String),
}

pub trait PlatformCollector {
    fn collect_hardware(&mut self) -> Result<HardwareSnapshot, CollectorError>;
    fn collect_security(&mut self) -> Result<Option<agent_core::types::SecuritySnapshot>, CollectorError> {
        Ok(None)
    }
    fn collect_access(&mut self) -> Result<Option<agent_core::types::AccessSnapshot>, CollectorError> {
        Ok(None)
    }
    fn collect_logs(&self) -> Vec<agent_core::types::LogEntry> {
        vec![]
    }
    fn collect_updates(&self) -> Vec<agent_core::types::UpdateInfo> {
        vec![]
    }

    fn collect_installed_applications(&mut self) -> Result<Vec<InstalledApplication>, CollectorError> {
        Ok(vec![])
    }
}

pub struct CommonCollector {
    sys: System,
}

impl CommonCollector {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
        }
    }

    fn collect_smart_data(disk_name: &str) -> Option<SmartStatus> {
        // Executa smartctl -j /dev/xxx ou similar.
        // Nota: o nome do disco vindo do sysinfo pode precisar de mapeamento para o device path.
        let output = Command::new("smartctl")
            .args(["-j", "-a", disk_name])
            .output()
            .ok()?;

        let json: Value = serde_json::from_slice(&output.stdout).ok()?;

        let model = json["device"]["model"]["model_name"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let health = json["smart_status"]["passed"]
            .as_bool()
            .map(|passed| if passed { "PASSED" } else { "FAILED" })
            .unwrap_or("Unknown")
            .to_string();

        let temperature = json["temperature"]["current"]
            .as_i64()
            .map(|t| t as i32);

        Some(SmartStatus {
            model,
            health,
            temperature,
        })
    }

    pub fn get_hardware_snapshot(&mut self) -> Result<HardwareSnapshot, CollectorError> {
        self.sys.refresh_all();

        let disks = Disks::new_with_refreshed_list().iter().map(|disk| {
            let name = disk.name().to_string_lossy().into_owned();

            // Tenta coletar SMART para cada disco.
            // Em ambientes reais, o nome do sysinfo pode não ser o path do device (/dev/sda),
            // mas para a Fase 2 seguimos a lógica de integração.
            let smart_status = Self::collect_smart_data(&name);

            DiskInfo {
                name: name.clone(),
                total_space: disk.total_space(),
                available_space: disk.available_space(),
                disk_type: None,
                smart_status,
            }
        }).collect();

        Ok(HardwareSnapshot {
            cpu_usage: self.sys.global_cpu_info().cpu_usage(),
            ram_total: self.sys.total_memory(),
            ram_used: self.sys.used_memory(),
            disk_usage: disks,
            uptime: System::uptime(),
            cpu_model: None,
            cpu_max_ghz: None,
            cpu_current_ghz: None,
            cpu_socket: None,
            ram_slots: vec![],
            gpus: vec![],
            battery: None,
            service_tag: None,
            serial_number: None,
            collection_warnings: vec![],
        })
    }
}

impl PlatformCollector for CommonCollector {
    fn collect_hardware(&mut self) -> Result<HardwareSnapshot, CollectorError> {
        self.get_hardware_snapshot()
    }
}

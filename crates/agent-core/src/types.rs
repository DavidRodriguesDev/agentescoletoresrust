use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApplication {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub machine_id: String,
    pub hostname: String,
    pub os: String,           // "windows" | "linux" | "macos"
    pub collected_at: DateTime<Utc>,
    pub hardware: HardwareSnapshot,
    pub security: Option<SecuritySnapshot>,
    pub access: Option<AccessSnapshot>,
    pub logs: Vec<LogEntry>,
    pub pending_updates: Vec<UpdateInfo>,
    #[serde(default)]
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSnapshot {
    pub cpu_usage: f32,
    pub ram_total: u64,
    pub ram_used: u64,
    pub disk_usage: Vec<DiskInfo>,
    pub uptime: u64,
    // Extended fields
    pub cpu_model: Option<String>,
    pub cpu_max_ghz: Option<f32>,
    pub cpu_current_ghz: Option<f32>,
    pub cpu_socket: Option<String>,
    #[serde(default)]
    pub ram_slots: Vec<RamSlot>,
    #[serde(default)]
    pub gpus: Vec<GpuInfo>,
    pub battery: Option<BatteryInfo>,
    pub service_tag: Option<String>,
    pub serial_number: Option<String>,
    pub collection_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RamSlot {
    pub slot: String,
    pub capacity: u64,
    pub speed: u32,
    #[serde(rename = "type")]
    pub ram_type: String,
    pub part_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub model: String,
    pub vram: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub health_pct: u8,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub total_space: u64,
    pub available_space: u64,
    pub disk_type: Option<String>,
    pub smart_status: Option<SmartStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartStatus {
    pub model: String,
    pub health: String, // "PASSED" | "FAILED" | "Unknown"
    pub temperature: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitlockerVolumeStatus {
    pub mount_point: String,
    pub protection_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySnapshot {
    pub tpm_enabled: Option<bool>,
    pub bitlocker_status: Option<Vec<BitlockerVolumeStatus>>,
    pub antivirus_status: Option<String>,
    pub firewall_enabled: Option<bool>,
    pub collection_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessSnapshot {
    pub local_users: Vec<String>,
    pub local_admins: Vec<String>,
    pub rdp_enabled: Option<bool>,
    pub domain_joined: Option<bool>,
    pub azure_ad_joined: Option<bool>,
    pub domain_name: Option<String>,
    pub collection_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub package_name: String,
    pub version_available: String,
    pub severity: String,
}

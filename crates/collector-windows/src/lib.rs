use agent_core::types::{HardwareSnapshot, LogEntry, UpdateInfo, SmartStatus};
use collector_common::{PlatformCollector, CommonCollector, CollectorError};
use std::process::Command;
use serde_json::Value;
use chrono::{DateTime, Utc};

pub struct WindowsCollector {
    common: CommonCollector,
    extended_cache: std::sync::Mutex<Option<Value>>,
}

impl WindowsCollector {
    pub fn new() -> Self {
        let collector = Self {
            common: CommonCollector::new(),
            extended_cache: std::sync::Mutex::new(None),
        };

        tracing::debug!("Checking for smartctl installation...");
        if Command::new("smartctl").arg("--version").output().is_err() {
            tracing::warn!("smartctl not found on this system. SMART data will be unavailable.");
        }

        collector
    }

    fn map_drive_to_physical_disk(drive_letter: &str) -> Option<String> {
        tracing::debug!("Mapping drive {} to physical disk", drive_letter);

        let letter = if drive_letter == "Windows" {
            "C".to_string()
        } else {
            let found = drive_letter.chars()
                .filter(|c| c.is_ascii_alphabetic())
                .next()
                .map(|c| c.to_uppercase().to_string());

            found.unwrap_or_else(|| "C".to_string())
        };

        let script = format!(
            "Get-Partition -DriveLetter {} | Select-Object -ExpandProperty DiskNumber",
            letter
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute powershell for drive mapping: {}", e);
                e
            })
            .ok()?;

        if !output.status.success() {
            tracing::error!("PowerShell drive mapping failed with status {}. stderr: {}",
                output.status, String::from_utf8_lossy(&output.stderr));
            return None;
        }

        let disk_num = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if disk_num.is_empty() {
            tracing::warn!("Drive mapping returned empty disk number for {}", drive_letter);
            return None;
        }
        Some(format!(r"\\.\PhysicalDrive{}", disk_num))
    }

    pub fn collect_logs(&self) -> Vec<LogEntry> {
        tracing::info!("Collecting Windows system logs...");
        let script = r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; @(Get-WinEvent -LogName System -MaxEvents 5) | Select-Object @{Name='TimeCreated';Expression={(Get-Date $_.TimeCreated).ToString('yyyy-MM-ddTHH:mm:ssZ')}}, Message, ProviderName | ConvertTo-Json"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute powershell for logs: {}", e);
                e
            })
            .ok();

        if let Some(out) = output {
            if !out.status.success() {
                tracing::error!("PowerShell logs collection failed (status {}). stderr: {}",
                    out.status, String::from_utf8_lossy(&out.stderr));
                return vec![];
            }

            let stdout_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(json) = serde_json::from_str::<Value>(&stdout_str) {
                let events = if json.is_array() {
                    json.as_array().cloned().unwrap_or_default()
                } else {
                    vec![json]
                };

                return events.into_iter().map(|ev| {
                    let timestamp = ev["TimeCreated"].as_str()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now);

                    LogEntry {
                        timestamp,
                        level: "Info".to_string(),
                        message: ev["Message"].as_str().unwrap_or("No message").to_string(),
                        source: ev["ProviderName"].as_str().unwrap_or("Unknown").to_string(),
                    }
                }).collect();
            } else {
                tracing::error!("Failed to parse logs JSON. Raw output (first 500 chars): {}",
                    &stdout_str[..stdout_str.len().min(500)]);
            }
        }
        vec![]
    }

    pub fn collect_updates(&self) -> Vec<UpdateInfo> {
        tracing::info!("Collecting Windows updates (this may take a while)...");
        let script = r#"
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            @($searchResult.Updates) | ForEach-Object {
                [PSCustomObject]@{
                    Title = $_.Title;
                    Severity = ($_.Categories | Where-Object { $_.Name -eq 'Severity' }).Name
                }
            } | ConvertTo-Json
        "#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute powershell for updates: {}", e);
                e
            })
            .ok();

        if let Some(out) = output {
            if !out.status.success() {
                tracing::error!("PowerShell updates collection failed (status {}). stderr: {}",
                    out.status, String::from_utf8_lossy(&out.stderr));
                return vec![];
            }

            let stdout_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(json) = serde_json::from_str::<Value>(&stdout_str) {
                let updates = if json.is_array() {
                    json.as_array().cloned().unwrap_or_default()
                } else {
                    vec![json]
                };

                return updates.into_iter().map(|u| {
                    UpdateInfo {
                        package_name: u["Title"].as_str().unwrap_or("Unknown").to_string(),
                        version_available: "Latest".to_string(),
                        severity: u["Severity"].as_str().unwrap_or("Normal").to_string(),
                    }
                }).collect();
            } else {
                tracing::error!("Failed to parse updates JSON. Raw output (first 500 chars): {}",
                    &stdout_str[..stdout_str.len().min(500)]);
            }
        }
        vec![]
    }

    fn fetch_extended_data(&self) -> Option<Value> {
        if let Ok(cache) = self.extended_cache.lock() {
            if let Some(ref data) = *cache {
                return Some(data.clone());
            }
        }

        tracing::info!("Collecting extended system data (BIOS, CPU, RAM, GPU, Security, Access)...");
        let script = r#"
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;

            function Get-MembrosGrupoSeguro {
                param([string[]]$NomesPossiveis)
                foreach ($nome in $NomesPossiveis) {
                    try {
                        $membros = Get-LocalGroupMember -Group $nome -ErrorAction Stop
                        return @($membros.Name)
                    } catch { }
                }
                return @()
            }

            $memTypeMap = @{ 0='Unknown'; 20='DDR'; 21='DDR2'; 24='DDR3'; 26='DDR4'; 30='DDR5' };
            $data = @{
                Hardware = @{
                    cpu_model = (Get-CimInstance Win32_Processor).Name;
                    cpu_max_ghz = (Get-CimInstance Win32_Processor).MaxClockSpeed / 1000;
                    cpu_current_ghz = (Get-CimInstance Win32_Processor).CurrentClockSpeed / 1000;
                    cpu_socket = (Get-CimInstance Win32_Processor).SocketDesignation;
                    service_tag = (Get-CimInstance Win32_Bios).SerialNumber;
                    serial_number = (Get-CimInstance Win32_Bios).SerialNumber;
                    ram_slots = @(Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator, Capacity, Speed, PartNumber, @{Name="type";Expression={$type = $_.SMBIOSMemoryType; if (!$type) { $type = $_.MemoryType }; $memTypeMap[$type]}});
                    gpus = @(Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM);
                    battery = Get-CimInstance Win32_Battery | Select-Object EstimatedChargeRemaining, Status;
                };
                Security = @{
                    tpm_enabled = (Get-Tpm).TpmPresent;
                    bitlocker_status = @(Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus);
                    antivirus_status = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct).displayName;
                    firewall_enabled = (Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object {$_.Enabled -eq 'True'}).Name.Count -gt 0;
                };
                Access = @{
                    local_users = @(Get-LocalUser).Name;
                    local_admins = Get-MembrosGrupoSeguro -NomesPossiveis @("Administrators", "Administradores");
                    rdp_users = Get-MembrosGrupoSeguro -NomesPossiveis @("Remote Desktop Users", "Usuários da Área de Trabalho Remota", "Usuarios da Area de Trabalho Remota");
                    domain_joined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain;
                    azure_ad_joined = (Get-CimInstance -Namespace root\Microsoft\Windows\AzureAD -ClassName MSFT_AzureADJoinedDevice).Joined;
                    domain_name = (Get-CimInstance Win32_ComputerSystem).Domain;
                };
            }
            $data | ConvertTo-Json -Depth 5
        "#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
            .map_err(|e| {
                tracing::error!("Failed to execute powershell for extended data: {}", e);
                e
            })
            .ok();

        if let Some(out) = output {
            if !out.status.success() {
                tracing::error!("PowerShell extended data collection failed (status {}). stderr: {}",
                    out.status, String::from_utf8_lossy(&out.stderr));
                return None;
            }

            let stdout_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(json) = serde_json::from_str::<Value>(&stdout_str) {
                if let Ok(mut cache) = self.extended_cache.lock() {
                    *cache = Some(json.clone());
                }
                return Some(json);
            } else {
                tracing::error!("Failed to parse extended data JSON. Raw output (first 500 chars): {}",
                    &stdout_str[..stdout_str.len().min(500)]);
            }
        }
        None
    }

    fn collect_extended_data(&self, hardware: &mut HardwareSnapshot, security: &mut Option<agent_core::types::SecuritySnapshot>, access: &mut Option<agent_core::types::AccessSnapshot>) {
        if let Some(json) = self.fetch_extended_data() {
            if let Some(hw) = json.get("Hardware") {
                hardware.cpu_model = hw["cpu_model"].as_str().map(|s| s.to_string());
                hardware.cpu_max_ghz = hw["cpu_max_ghz"].as_f64().map(|f| f as f32);
                hardware.cpu_current_ghz = hw["cpu_current_ghz"].as_f64().map(|f| f as f32);
                hardware.cpu_socket = hw["cpu_socket"].as_str().map(|s| s.to_string());
                hardware.service_tag = hw["service_tag"].as_str().map(|s| s.to_string());
                hardware.serial_number = hw["serial_number"].as_str().map(|s| s.to_string());

                if let Some(slots) = hw["ram_slots"].as_array() {
                    hardware.ram_slots = slots.into_iter().filter_map(|s| {
                        Some(agent_core::types::RamSlot {
                            slot: s["DeviceLocator"].as_str().unwrap_or("Unknown").to_string(),
                            capacity: s["Capacity"].as_u64().unwrap_or(0),
                            speed: s["Speed"].as_u64().unwrap_or(0) as u32,
                            ram_type: s["type"].as_str().unwrap_or("Unknown").to_string(),
                            part_number: s["PartNumber"].as_str().unwrap_or("Unknown").to_string(),
                        })
                    }).collect();
                }

                if let Some(gpus) = hw["gpus"].as_array() {
                    hardware.gpus = gpus.into_iter().filter_map(|g| {
                        Some(agent_core::types::GpuInfo {
                            model: g["Name"].as_str().unwrap_or("Unknown").to_string(),
                            vram: g["AdapterRAM"].as_u64().unwrap_or(0),
                        })
                    }).collect();
                }

                if let Some(batt) = hw["battery"].as_object() {
                    hardware.battery = Some(agent_core::types::BatteryInfo {
                        health_pct: batt["EstimatedChargeRemaining"].as_u64().unwrap_or(0) as u8,
                        status: batt["Status"].as_str().unwrap_or("Unknown").to_string(),
                    });
                }
            }

            if let Some(sec) = json.get("Security") {
                *security = Some(agent_core::types::SecuritySnapshot {
                    tpm_enabled: sec["tpm_enabled"].as_bool(),
                    bitlocker_status: sec["bitlocker_status"].as_array().map(|arr| {
                        arr.iter().filter_map(|v| {
                            Some(agent_core::types::BitlockerVolumeStatus {
                                mount_point: v["MountPoint"].as_str()?.to_string(),
                                protection_status: v["ProtectionStatus"].as_str()?.to_string(),
                            })
                        }).collect()
                    }),
                    antivirus_status: Some(sec["antivirus_status"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<String>>().join(", ")).unwrap_or_else(|| sec["antivirus_status"].as_str().map(|s| s.to_string()).unwrap_or_default())),
                    firewall_enabled: sec["firewall_enabled"].as_bool(),
                });
            }

            if let Some(acc) = json.get("Access") {
                *access = Some(agent_core::types::AccessSnapshot {
                    local_users: acc["local_users"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                    local_admins: acc["local_admins"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                    rdp_enabled: acc["rdp_users"].as_array().map(|a| !a.is_empty()),
                    domain_joined: acc["domain_joined"].as_bool(),
                    azure_ad_joined: acc["azure_ad_joined"].as_bool(),
                    domain_name: acc["domain_name"].as_str().map(|s| s.to_string()),
                });
            }
        }
    }

    fn collect_smart_with_mapping(&mut self, hardware: &mut HardwareSnapshot) {
        for disk in &mut hardware.disk_usage {
            if let Some(physical_path) = Self::map_drive_to_physical_disk(&disk.name) {
                let output = Command::new("smartctl")
                    .args(["-j", "-a", &physical_path])
                    .output()
                    .ok();

                if let Some(out) = output {
                    if let Ok(json) = serde_json::from_slice::<Value>(&out.stdout) {
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

                        disk.smart_status = Some(SmartStatus {
                            model,
                            health,
                            temperature,
                        });
                    }
                }
            }
        }
    }
}

impl PlatformCollector for WindowsCollector {
    fn collect_hardware(&mut self) -> Result<HardwareSnapshot, CollectorError> {
        let mut hardware = self.common.get_hardware_snapshot()?;
        let mut dummy_sec = None;
        let mut dummy_acc = None;
        self.collect_extended_data(&mut hardware, &mut dummy_sec, &mut dummy_acc);
        self.collect_smart_with_mapping(&mut hardware);
        Ok(hardware)
    }

    fn collect_security(&mut self) -> Result<Option<agent_core::types::SecuritySnapshot>, CollectorError> {
        let mut hardware = HardwareSnapshot {
            cpu_usage: 0.0, ram_total: 0, ram_used: 0, disk_usage: vec![], uptime: 0,
            cpu_model: None, cpu_max_ghz: None, cpu_current_ghz: None, cpu_socket: None,
            ram_slots: vec![], gpus: vec![], battery: None, service_tag: None, serial_number: None,
        };
        let mut access = None;
        let mut security = None;
        self.collect_extended_data(&mut hardware, &mut security, &mut access);
        Ok(security)
    }

    fn collect_access(&mut self) -> Result<Option<agent_core::types::AccessSnapshot>, CollectorError> {
        let mut hardware = HardwareSnapshot {
            cpu_usage: 0.0, ram_total: 0, ram_used: 0, disk_usage: vec![], uptime: 0,
            cpu_model: None, cpu_max_ghz: None, cpu_current_ghz: None, cpu_socket: None,
            ram_slots: vec![], gpus: vec![], battery: None, service_tag: None, serial_number: None,
        };
        let mut security = None;
        let mut access = None;
        self.collect_extended_data(&mut hardware, &mut security, &mut access);
        Ok(access)
    }
}

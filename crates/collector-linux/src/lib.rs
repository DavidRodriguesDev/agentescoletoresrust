use agent_core::types::HardwareSnapshot;
use collector_common::{PlatformCollector, CommonCollector, CollectorError};

mod logs;
mod updates;

pub struct LinuxCollector {
    common: CommonCollector,
}

impl LinuxCollector {
    pub fn new() -> Self {
        Self {
            common: CommonCollector::new(),
        }
    }
}

impl PlatformCollector for LinuxCollector {
    fn collect_hardware(&mut self) -> Result<HardwareSnapshot, CollectorError> {
        // Linux hardware is fully covered by sysinfo in CommonCollector
        self.common.get_hardware_snapshot()
    }

    fn collect_logs(&self) -> Vec<agent_core::types::LogEntry> {
        logs::collect_logs()
    }

    fn collect_updates(&self) -> Vec<agent_core::types::UpdateInfo> {
        updates::collect_updates()
    }
}

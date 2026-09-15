use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::types::Snapshot;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepStatus {
    Success,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatorioFinal {
    pub snapshot: Snapshot,
    pub execution_log: ExecutionLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepLog {
    pub step_name: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u128,
    pub status: StepStatus,
    pub error_message: Option<String>,
    pub permission_issue: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub agent_started_at: DateTime<Utc>,
    pub agent_finished_at: Option<DateTime<Utc>>,
    pub total_duration_ms: Option<u128>,
    pub steps: Vec<StepLog>,
}

impl ExecutionLog {
    pub fn new() -> Self {
        ExecutionLog {
            agent_started_at: Utc::now(),
            agent_finished_at: None,
            total_duration_ms: None,
            steps: Vec::new(),
        }
    }

    pub fn finish(&mut self) {
        let fim = Utc::now();
        self.agent_finished_at = Some(fim);
        self.total_duration_ms = Some((fim - self.agent_started_at).num_milliseconds().max(0) as u128);
    }
}

impl Default for ExecutionLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifica heuristicamente se uma mensagem de erro indica falta de
/// permissão/privilégio administrativo, com base em termos comuns que
/// aparecem em erros do Windows (COM, WMI, Registro, arquivos protegidos).
pub fn detect_permission_issue(mensagem_erro: &str) -> Option<String> {
    let termos_permissao = [
        "access is denied",
        "acesso negado",
        "permission denied",
        "requires administrator",
        "administrador",
        "elevated",
        "elevation required",
        "unauthorized",
        "acesso não autorizado",
    ];
    let msg_lower = mensagem_erro.to_lowercase();
    for termo in termos_permissao {
        if msg_lower.contains(termo) {
            return Some(format!(
                "Possível falta de permissão/privilégio administrativo: \"{}\"",
                mensagem_erro
            ));
        }
    }
    None
}

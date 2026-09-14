# Plano do Projeto — Sistema de Monitoramento e Relatório de Máquinas

## 1. Visão geral

Sistema composto por 3 serviços independentes, escritos em Rust, rodando em Windows, Linux e macOS:

1. **Coletor (Agent)** — roda em cada máquina monitorada, coleta hardware + logs de sistema/software, envia para o serviço central. *(foco atual)*
2. **Dados/Comunicação (Server)** — recebe, valida e armazena os dados; expõe API para consulta.
3. **Relatório (Report)** — consome os dados armazenados e gera relatórios (PDF/HTML/dashboard).
4. **Atualizador (Updater)** — mantém coletor e servidor atualizados de forma segura.

Escala alvo: 50–70 máquinas. Servidor central ainda não decidido (on-premise ou cloud) — decisão adiada, não bloqueia o trabalho no coletor.

---

## 2. Foco atual: Serviço Coletor

### 2.1 Objetivo
Rodar como serviço/daemon com privilégios elevados em cada máquina, coletando:
- **Hardware**: CPU, RAM, disco, rede, uptime, saúde SMART dos discos.
- **Software/Logs**: eventos de sistema, atualizações pendentes do SO, softwares instalados.

### 2.2 Princípio de design: máximo código compartilhado entre SOs
- Uma **trait comum** (`PlatformCollector`) define o contrato de coleta.
- Cada SO implementa essa trait separadamente, isolado com `#[cfg(target_os = "...")]`.
- O resto do agente (buffer, envio, agendamento, config) é 100% cross-platform e não sabe de qual SO veio o dado.
- Tudo que puder ser feito com uma única lib multiplataforma (ex: `sysinfo`) fica fora dos módulos específicos de SO.

### 2.3 Bibliotecas (todas maduras e amplamente usadas)

| Função | Crate | Por quê |
|---|---|---|
| Hardware multiplataforma | `sysinfo` | Cobre CPU/RAM/disco/rede/uptime nos 3 SOs com uma API só; muito usada e mantida |
| Runtime assíncrono | `tokio` | Padrão de fato para I/O assíncrono em Rust |
| Serialização | `serde` + `serde_json` | Padrão de fato para (de)serialização |
| Config | `toml` | Formato simples e legível para arquivo de configuração |
| Cliente HTTP | `reqwest` | Cliente HTTP maduro, baseado em `tokio`, suporta TLS |
| Buffer local | `rusqlite` (SQLite) | Sem dependência de serviço externo; resiliente a queda de rede |
| Logging interno do agente | `tracing` + `tracing-subscriber` | Padrão moderno para logging estruturado em Rust |
| Datas/horários | `chrono` (ou `time`) | Manipulação de timestamps |
| CLI/flags | `clap` | Parsing de argumentos, útil para modo debug/instalação |
| Erros | `thiserror` (lib) / `anyhow` (bin) | Tratamento de erro idiomático |

Ferramentas externas chamadas via `std::process::Command` (não há crates Rust maduras para isso):
- `smartctl -j` (smartmontools) → saúde SMART dos discos, saída em JSON, mesmo comando nos 3 SOs.
- Windows: `wevtutil` (Event Log), PowerShell `Get-WindowsUpdate` (updates pendentes).
- Linux: `journalctl -o json` (logs), gerenciador de pacotes da distro (updates pendentes).
- macOS: `log show` (logs unificados), `softwareupdate -l` (updates pendentes).

### 2.4 Estrutura do projeto (Cargo workspace)

```
monitoring-agent/
├── Cargo.toml                  # workspace
├── crates/
│   ├── agent-core/             # lógica compartilhada: config, buffer, envio, agendamento
│   │   ├── src/
│   │   │   ├── config.rs
│   │   │   ├── buffer.rs       # SQLite local
│   │   │   ├── sender.rs       # envio HTTP para o server
│   │   │   ├── scheduler.rs
│   │   │   └── types.rs        # structs normalizadas (HardwareSnapshot, LogEntry, UpdateInfo)
│   │   └── Cargo.toml
│   │
│   ├── collector-common/       # trait PlatformCollector + parte via sysinfo (comum aos 3 SOs)
│   │   └── src/lib.rs
│   │
│   ├── collector-windows/      # implementação específica Windows
│   │   └── src/lib.rs
│   ├── collector-linux/        # implementação específica Linux
│   │   └── src/lib.rs
│   ├── collector-macos/        # implementação específica macOS
│   │   └── src/lib.rs
│   │
│   └── agent-bin/              # binário final, junta tudo, roda como serviço
│       └── src/main.rs
```

A escolha de crates separados por SO (em vez de só `#[cfg]` dentro de um único crate) é opcional — para um projeto desse tamanho, também é válido manter tudo em `agent-core` com módulos `#[cfg(target_os)]`. Vale decidir isso quando o esqueleto do projeto estiver rodando; não é uma decisão que trava o início.

### 2.5 Formato dos dados coletados (payload)

Esboço inicial da struct normalizada, igual para os 3 SOs:

```rust
struct Snapshot {
    machine_id: String,
    hostname: String,
    os: String,           // "windows" | "linux" | "macos"
    collected_at: DateTime<Utc>,
    hardware: HardwareSnapshot,
    logs: Vec<LogEntry>,
    pending_updates: Vec<UpdateInfo>,
}
```

Esse formato deve ser estabilizado cedo, porque tanto o buffer local (SQLite) quanto o envio para o servidor central dependem dele.

---

## 3. Roadmap do serviço coletor

### Fase 1 — Esqueleto cross-platform
- [ ] Criar workspace Cargo com a estrutura acima
- [ ] Definir structs normalizadas (`types.rs`)
- [ ] Implementar `PlatformCollector` trait
- [ ] Implementar coleta de hardware via `sysinfo` (já cobre os 3 SOs)
- [ ] Validar compilação cruzada nos 3 SOs (ver seção 4)

### Fase 2 — Coleta específica por SO
- [ ] Integração com `smartctl` (SMART, comum aos 3 SOs via `Command`)
- [ ] Windows: Event Log + updates pendentes
- [ ] Linux: journalctl + updates pendentes (detectar gerenciador de pacotes)
- [ ] macOS: log unificado + updates pendentes

### Fase 3 — Persistência e agendamento local
- [ ] Buffer SQLite local (`rusqlite`)
- [ ] Agendador de coleta (intervalo configurável via TOML)
- [ ] Rotina de limpeza do buffer após confirmação de envio

### Fase 4 — Envio (ainda sem servidor real — mockado)
- [ ] Cliente HTTP com `reqwest`
- [ ] Lógica de retry/backoff em caso de falha de rede
- [ ] Endpoint mock local para testar o envio ponta a ponta

### Fase 5 — Execução como serviço com privilégios
- [ ] Windows: registrar como serviço (`windows-service` crate), rodando como `LocalSystem`
- [ ] Linux: unit `systemd`, rodando como root ou usuário com capabilities específicas
- [ ] macOS: `launchd` daemon
- [ ] Documentar processo de instalação/desinstalação nos 3 SOs

---

## 4. Testando multiplataforma desde já

Mesmo trabalhando sozinho, dá pra validar os 3 SOs cedo:
- Usar `cross` (crate/ferramenta) para compilação cruzada a partir de um único ambiente Linux, para gerar binários Windows/Linux rapidamente.
- macOS normalmente exige uma máquina macOS real (ou CI com runner macOS, ex: GitHub Actions) para compilar/testar de forma confiável — compilação cruzada para macOS a partir de Linux é possível mas frágil.
- Sugestão: configurar CI (GitHub Actions) cedo, com matriz de build nos 3 SOs, mesmo antes de ter lógica de coleta específica por SO — só para garantir que o esqueleto compila nos três desde o início.

---

## 5. Decisões em aberto (não bloqueiam o início)
- Onde o servidor central vai rodar (on-premise vs cloud)
- Protocolo de comunicação final (REST/JSON deve bastar para 50–70 máquinas)
- Se os crates `collector-*` ficam separados por SO ou unificados com `#[cfg]`
- Formato de autenticação do agente junto ao servidor (token vs mTLS)

---

## 6. Próximo passo sugerido
Começar pela **Fase 1**: montar o workspace, as structs normalizadas e a coleta de hardware via `sysinfo` — isso já roda nos 3 SOs sem nenhum código condicional, e dá uma base sólida testável desde o primeiro dia.

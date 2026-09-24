# Agente de Monitoramento Multi-OS

## 🌐 Visão Geral
Este projeto implementa um ecossistema de monitoramento corporativo desenvolvido em Rust, projetado para a coleta e análise de dados de conformidade, segurança e hardware em escala (~160 máquinas) abrangendo Windows, Linux e macOS.

O objetivo central é extrair snapshots detalhados do estado de cada máquina e transmiti-los para um servidor central de forma segura, permitindo a auditoria de vulnerabilidades, inventário de hardware e monitoramento de logs em tempo real.

---

## 🏗️ Arquitetura do Sistema

O ecossistema é composto por quatro componentes principais que operam em conjunto:

### 1. Agent (Coletor)
O binário `agent-bin` é instalado em cada máquina monitorada. Ele executa a coleta de dados localmente e os envia via HTTPS para o Servidor de Dados.
- **Modo de Execução:** Pode ser rodado via CLI ou como um Serviço Windows nativo (`AgentMonitor`).
- **Periodicidade:** Coleta snapshots em intervalos configuráveis (ex: a cada 20 minutos).

### 2. Servidor de Dados (Ingest)
O binário `server-bin` atua como o ponto de recepção dos snapshots.
- **Responsabilidade:** Recebe snapshots via API REST, valida a autenticação (API Key) e persiste os dados em armazenamento (JSONL/Database).
- **Segurança:** Implementa TLS com suporte a CAs customizados para ambientes de desenvolvimento/on-premise.

### 3. Atualizador (AgentUpdater)
O binário `updater-bin` roda como um serviço paralelo ao Agent no Windows.
- **Responsabilidade:** Monitora a versão do agente instalada e verifica a existência de novas versões no servidor.
- **Fluxo:** Download do binário $\rightarrow$ Verificação de Assinatura Digital $\rightarrow$ Substituição do binário do Agent $\rightarrow$ Reinicialização do serviço via SCM.

### 4. Módulo de Relatórios
Componente responsável por processar os snapshots brutos e transformá-los em relatórios de conformidade legíveis para a gestão.

---

## 📦 Estrutura do Workspace (Crates)

| Crate | Responsabilidade |
| :--- | :--- |
| `agent-core` | Definições de tipos comuns, estrutura do `Snapshot` e lógica de transporte HTTPS. |
| `collector-common` | Abstrações (`PlatformCollector` trait) e métricas básicas via `sysinfo`. |
| `collector-windows` | Coleta especializada via PowerShell, WMI e CIM (BitLocker, TPM, Event Logs). |
| `collector-linux` | Coleta via `journalctl`, `apt` e ferramentas nativas de sistema. |
| `collector-macos` | (Em desenvolvimento) Coleta especializada para ecossistema Apple. |
| `agent-bin` | Orquestrador do pipeline de coleta e ponto de entrada do serviço Windows. |
| `updater-bin` | Gerenciador de auto-update e ciclo de vida do binário do agente. |
| `server-bin` | API de recepção de snapshots e gerenciamento de versões de update. |
| `agent-config` | Lógica de carregamento de TOML, validação de endpoints e gestão de segredos. |

---

## 🔄 Fluxo de Coleta e Snapshot

1. **Hardware:** CPU, RAM, Discos (via SMART), GPU, Bateria e Service Tag.
2. **Security:** Status de Antivírus, Firewall, BitLocker, TPM e Secure Boot.
3. **Access:** Grupos de Administradores locais, usuários com RDP habilitado e permissões críticas.
4. **Logs:** Extração de eventos críticos do Event Viewer (Windows) ou Journald (Linux).
5. **Updates:** Lista de atualizações de segurança pendentes (KBs no Windows, pacotes no Linux).
6. **Apps:** Inventário de softwares instalados e versões.

**Formato do Snapshot:** Um objeto JSON contendo metadados da máquina (`machine_id`, `hostname`, `timestamp`), os dados de cada etapa acima e um `ExecutionLog` detalhando o tempo de execução e erros de permissão de cada etapa.

---

## 🔒 Segurança e Transporte

### Transporte HTTPS
A comunicação é feita via HTTPS utilizando a biblioteca `ureq`. O sistema suporta três métodos de autenticação:
- **API Key:** Chave estática enviada no header `X-API-Key`.
- **OAuth2:** Fluxo de Client Credentials para ambientes corporativos.
- **mTLS:** Autenticação mútua via certificados X.509.

**Ponte de Confiança TLS:** Para suportar servidores com certificados autoassinados ou CAs internas, o agente permite a configuração de um `extra_ca_cert_path` no `config.toml`, que é injetado no Root Store do cliente TLS.

### Proteção de Segredos
- **ACLs de Arquivo:** No Windows, o agente aplica permissões restritas aos arquivos de configuração e chaves (`restrict_to_system_and_admins`), garantindo que apenas o usuário `SYSTEM` e Administradores possam lê-los.
- **Criptografia:** Implementação de suporte a arquivos `.enc` utilizando DPAPI no Windows para proteger segredos em repouso.

---

## ⚙️ Instalação e Configuração

### Instalação como Serviço Windows
O agente é instalado via script PowerShell:
```powershell
# Executar como Administrador
.\install-agent-service.ps1
```
O script registra o serviço `AgentMonitor` com o binário em `C:\ProgramData\agente-monitoramento\agent-bin.exe` e o argumento `--service`.

**Gestão via sc.exe:**
```powershell
sc.exe start AgentMonitor
sc.exe stop AgentMonitor
sc.exe query AgentMonitor
```

### Configuração (`config.example.toml`)
O arquivo de configuração deve ser colocado em `C:\ProgramData\agente-monitoramento\config.toml`.

| Campo | Tipo | Descrição | Exemplo |
| :--- | :--- | :--- | :--- |
| `endpoint` | String | URL do servidor de ingestão (obrigatório HTTPS). | `"https://api.monitor.local"` |
| `collection_interval_secs` | Int | Intervalo entre coletas em segundos. | `1200` (20 min) |
| `auth.type` | String | Método de autenticação (`none`, `api_key`, `oauth2`, `mtls`). | `"api_key"` |
| `auth.key_file` | Path | Caminho para o arquivo contendo a API Key. | `"api_key.txt"` |
| `extra_ca_cert_path` | Path | (Opcional) Caminho para o certificado CA do servidor. | `"ca.pem"` |

---

## 🛠️ Build e Requisitos

### Requisitos
- **Rust:** Versão estável (via `rustup`).
- **Dependências:**
  - `smartmontools` (Opcional): Necessário para coleta de saúde de disco (SMART).
  - Windows: PowerShell 5.1+.

### Compilação
```bash
# Build de todo o workspace
cargo build --workspace

# Build específico do agente
cargo build -p agent-bin
```

---

## ⚠️ Troubleshooting e Lições Aprendidas

### Bug de Polaridade do AtomicBool (Histórico)
Durante o desenvolvimento do serviço Windows, foi identificado um bug onde a variável de controle de execução (`stop_signal` vs `keep_running`) possuía semânticas opostas entre a `service_main` e a `run_agent_loop`.
- **Sintoma:** O agente iniciava e desligava imediatamente.
- **Causa:** O loop esperava `false` para rodar, mas o serviço iniciava com `true`.
- **Solução:** Padronização de toda a base de código para a semântica `keep_running` (True = Continuar / False = Parar).

---

## 📈 Status Atual e Próximos Passos
- [x] Implementação completa do Coletor Windows e Linux.
- [x] Implementação do Servidor de Ingestão básico.
- [x] Sistema de Auto-Update funcional.
- [ ] Implementação do Coletor macOS.
- [ ] Definição de infraestrutura final (Cloud vs On-Premise).
- [ ] Implementação de Dashboard de visualização de snapshots.

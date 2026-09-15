# Agente de Monitoramento Multi-OS (Rust)

Este projeto implementa um agente de monitoramento cross-platform desenvolvido em Rust. O objetivo principal é coletar dados normalizados de hardware, segurança, acesso, logs e atualizações pendentes de diferentes sistemas operacionais (Windows, Linux e macOS) e consolidá-los em um snapshot único para envio a um servidor central.

## 🚀 Visão Geral da Arquitetura

O projeto utiliza um **Workspace do Cargo**, dividindo as responsabilidades em crates modulares para garantir manutenibilidade e separação de conceitos:

### 📦 Estrutura de Crates

- **`agent-core`**: Define a "linguagem comum" do projeto. Contém todas as structs de dados (`HardwareSnapshot`, `LogEntry`, `UpdateInfo`, etc.) e a estrutura do `Snapshot` final que será enviada ao servidor.
- **`collector-common`**: Camada de abstração. Define a trait `PlatformCollector`, que obriga todos os coletores de OS a implementarem as mesmas funções de coleta. Inclui a `CommonCollector` que usa a biblioteca `sysinfo` para métricas básicas (CPU, RAM, Disco) comuns a todos os sistemas.
- **`collector-windows`**: Especialista em Windows. Executa scripts complexos de PowerShell e consultas CIM/WMI para extrair:
    - Dados de BIOS, GPU e Bateria.
    - Status de BitLocker, TPM e Antivírus.
    - Grupos de Administradores e usuários RDP.
    - Eventos do Windows Event Log e atualizações do Windows Update.
- **`collector-linux`**: Especialista em Linux. Integra-se com as ferramentas nativas do ecossistema:
    - `journalctl` para extração de logs do sistema via JSON.
    - `apt` para verificação de pacotes pendentes.
    - Métricas de hardware via `sysinfo`.
- **`collector-macos`**: (Em desenvolvimento) Implementação para o ecossistema Apple.
- **`agent-bin`**: O ponto de entrada do aplicativo. Detecta o sistema operacional em tempo de compilação e executa o pipeline de coleta, imprimindo o resultado final no console.

## 🛠️ Como Funciona (Fluxo de Dados)

1. **Detecção de OS**: O `agent-bin` usa atributos de compilação condicional (`#[cfg(target_os = "...")]`) para decidir qual implementação de `PlatformCollector` instanciar.
2. **Coleta em Camadas**: 
   - Primeiro, coleta-se o básico via `CommonCollector` (Cross-platform).
   - Depois, o coletor específico (Windows/Linux) executa comandos de sistema para enriquecer os dados.
3. **Normalização**: Dados brutos (como strings do PowerShell ou JSON do journalctl) são convertidos para tipos fortemente tipados do Rust (`agent-core`).
4. **Snapshot Final**: Todas as informações são agrupadas em um objeto `Snapshot` com metadados da máquina (Hostname, MachineID, Timestamp).
5. **Relatório de Execução**: O agente gera um `RelatorioFinal` que combina o `Snapshot` com um log detalhado da execução (tempo gasto por etapa, status de sucesso/erro e avisos de permissão), salvo automaticamente em JSON em `C:\ProgramData\agente-monitoramento\reports` (no Windows).

## 💻 Guia de Instalação e Execução

### Pré-requisitos Gerais
- **Rust**: Instalado via `rustup` (incluindo `cargo`).
- **smartmontools**: Para coleta de saúde de disco (SMART), instale o `smartctl`:
    - **Windows**: `choco install smartmontools` ou via instalador oficial.
    - **Linux**: `sudo apt install smartmontools`.

---

### 🪟 No Windows

**Requisitos Adicionais**:
- PowerShell 5.1 ou superior (Nativo).
- Privilégios de **Administrador** (necessário para ler BitLocker, TPM e alguns logs de evento).

**Como Compilar e Rodar**:
1. Abra o terminal (PowerShell ou CMD) como **Administrador**.
2. Navegue até a pasta raiz do projeto.
3. Execute:
   ```powershell
   cargo run -p agent-bin
   ```

---

### 🐧 No Linux

**Requisitos Adicionais**:
- `systemd` (para acesso ao `journalctl`).
- `apt` (para verificação de updates em distribuições baseadas em Debian/Ubuntu).
- Privilégios de **Sudo** para ler logs do sistema.

**Como Compilar e Rodar**:
1. Abra o terminal.
2. Navegue até a pasta raiz do projeto.
3. Execute:
   ```bash
   # Para rodar com privilégios de leitura de logs
   sudo cargo run -p agent-bin
   ```
   *Nota: Se o cargo não estiver no path do root, use o caminho completo ou configure o sudoers.*

---

## 📋 Roadmap de Implementação

- [x] **Fase 1**: Estrutura de crates e abstração de Trait.
- [x] **Fase 2**: Implementação dos coletores Windows e Linux (Hardware, Security, Access, Logs, Updates).
- [ ] **Fase 3**: Persistência local (SQLite) para cache de dados offline.
- [ ] **Fase 4**: Módulo de transporte HTTP para envio dos snapshots ao servidor.
- [ ] **Fase 5**: Integração como Serviço/Daemon do Sistema (Windows Service / systemd unit).

## ⚙️ Detalhes Técnicos Relevantes
- **Segurança**: O agente prioriza a estabilidade, usando `Option` e `Result` para garantir que a falha em coletar um dado específico (ex: GPU não encontrada) não derrube a execução total.
- **Performance**: Implementação de cache via `Mutex` no Windows para evitar chamadas repetitivas e lentas ao PowerShell.
- **Interoperabilidade**: Uso de JSON como formato de troca entre o shell do OS e o Rust, garantindo que caracteres especiais e encodings (UTF-8) sejam preservados.

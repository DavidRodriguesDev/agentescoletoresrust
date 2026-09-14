# Agente de Monitoramento Multi-OS (Rust)

Este projeto implementa um agente de monitoramento cross-platform desenvolvido em Rust. O objetivo principal é coletar dados normalizados de hardware, segurança, acesso, logs e atualizações pendentes de diferentes sistemas operacionais (Windows, Linux e macOS) e consolidá-los em um snapshot único para envio a um servidor central.

## 🚀 Visão Geral da Arquitetura

O projeto utiliza um **Workspace do Cargo**, dividindo as responsabilidades em crates modulares para garantir manutenibilidade e separação de conceitos:

### 📦 Estrutura de Crates

- **`agent-core`**: Define os tipos de dados globais (`HardwareSnapshot`, `LogEntry`, `UpdateInfo`, etc.) e a estrutura do `Snapshot` final. É a "linguagem comum" entre todos os módulos.
- **`collector-common`**: Contém a trait `PlatformCollector` que define o contrato que todo coletor de OS deve seguir. Também implementa a `CommonCollector` usando a biblioteca `sysinfo` para métricas de hardware básicas que são similares em todos os sistemas (CPU, RAM, Discos).
- **`collector-windows`**: Implementação específica para Windows. Utiliza PowerShell, CIM/WMI e COM API para extrair dados profundos de segurança, acesso e atualizações do Windows Update. Integra-se ao `smartctl` para saúde de discos.
- **`collector-linux`**: Implementação específica para Linux. Utiliza `journalctl` para logs do sistema e `apt` para verificar atualizações de pacotes pendentes.
- **`collector-macos`**: (Em desenvolvimento) Implementação para o ecossistema Apple.
- **`agent-bin`**: O binário executável do agente. Atualmente funciona como um pipeline de teste que instanciar o coletor correto com base no sistema operacional detectado e imprime o snapshot final no console.

## 🛠️ Como Funciona (Fluxo de Dados)

1. **Detecção de OS**: O `agent-bin` utiliza flags de compilação (`#[cfg(target_os = "...")]`) para instanciar o coletor adequado (`WindowsCollector` ou `LinuxCollector`).
2. **Coleta Normalizada**: O coletor chama a `CommonCollector` para dados básicos e executa scripts/comandos específicos do sistema para dados avançados.
3. **Normalização**: Os dados brutos (JSON do PowerShell, texto do journalctl) são parseados e convertidos nos tipos definidos em `agent-core`.
4. **Consolidação**: Todas as informações são agrupadas em um `Snapshot` contendo:
   - **Hardware**: CPU, RAM, Discos (incluindo SMART), GPU, Bateria, BIOS.
   - **Security**: Status de Firewall, Antivírus, TPM, BitLocker.
   - **Access**: Usuários locais, Administradores, Status de Domínio/Azure AD, RDP.
   - **Logs**: Últimas entradas críticas do sistema.
   - **Updates**: Lista de pacotes/atualizações pendentes.

## 💻 Como Rodar

### Pré-requisitos
- **Rust**: Instalado via `rustup`.
- **Dependências Externas**:
  - **Windows**: PowerShell (nativo).
  - **Linux**: `systemd` (para `journalctl`) e `apt` (para atualizações).
  - **Cross-OS**: `smartmontools` (`smartctl`) instalado no PATH para coleta de saúde de discos.

### Executando o Agente
Para rodar o pipeline de teste e ver a coleta em tempo real:

```bash
cargo run -p agent-bin
```

## 📋 Roadmap de Implementação

- [x] **Fase 1**: Estrutura de crates e abstração de Trait.
- [x] **Fase 2**: Implementação dos coletores Windows e Linux (Hardware, Security, Access, Logs, Updates).
- [ ] **Fase 3**: Persistência local (SQLite) para cache de dados offline.
- [ ] **Fase 4**: Módulo de transporte HTTP para envio dos snapshots ao servidor.
- [ ] **Fase 5**: Integração como Serviço/Daemon do Sistema (Windows Service / systemd unit).

## ⚙️ Detalhes Técnicos Relevantes
- **Segurança**: O agente foi projetado para evitar panics usando `Option` e `Result`.
- **Performance**: No Windows, utilizamos cache com `Mutex` para evitar a execução repetitiva de scripts pesados de PowerShell.
- **Interoperabilidade**: Toda a comunicação entre shells do sistema e Rust é feita via JSON para evitar erros de parsing de strings.

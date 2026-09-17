# Agente de Monitoramento Multi-OS

## Visão Geral
O projeto consiste em um agente de monitoramento escrito em Rust, projetado para ser implantado em múltiplos sistemas operacionais (Windows e Linux). O objetivo é coletar telemetria detalhada do sistema (hardware, segurança, acessos e logs) e enviá-la de forma segura para um servidor central.

### Principais Funcionalidades
- **Coleta de Telemetria**: Captura de dados de CPU, RAM, Disco, GPU, Segurança do Sistema e Logs.
- **Transporte Seguro**: Comunicação via HTTPS com suporte a:
    - API Keys (via Header X-API-Key).
    - OAuth2 Client Credentials.
    - mTLS (Mutual TLS).
- **Segurança de Configuração**: No Windows, o agente utiliza ACLs (`icacls`) para restringir o acesso aos arquivos de configuração e segredos apenas para o sistema (SYSTEM) e administradores.
- **Infraestrutura de Testes**: Servidor HTTPS local com geração automática de certificados autoassinados e ponte de confiança (CA export) para validação end-to-end.

## Estrutura de Pastas

### `crates/`
- **`agent-config`**: Gerencia o carregamento e validação da configuração TOML. Implementa a lógica de restrição de permissões de arquivos no Windows.
- **`agent-core`**: Contém a lógica central do agente, incluindo:
    - `transport.rs`: Implementação do `HttpTransport` usando `reqwest`.
    - `types.rs`: Definições de snapshots de hardware, segurança e acesso.
    - `execution_log.rs`: Sistema de log de execução para rastrear sucessos e falhas de permissão durante a coleta.
- **`agent-bin`**: O binário executável do agente. Orquestra a coleta de dados e o envio via transporte.
- **`server-bin`**: Um servidor de referência para testes. Implementa endpoints de ingestão via HTTPS e middleware de autenticação.
- **`collector-common` / `collector-windows` / `collector-linux`**: Bibliotecas específicas de coleta de dados por plataforma.

## Implementações Recentes (Contexto de Desenvolvimento)
1. **Correção de Dependências**: Resolvido conflito entre Hyper 0.14 e 1.0, migrando para `hyper-util` e `tokio-rustls` para o loop do servidor.
2. **Ponte de Confiança TLS**: Implementada a exportação do certificado público do servidor (`dev-server-ca.pem`) e a capacidade do agente de carregar esse CA extra para evitar erros de `TLS handshake EOF`.
3. **Segurança de Arquivos**: Implementado `restrict_file_to_admins` para garantir que segredos não fiquem expostos a usuários comuns.
4. **Validação E2E**: Validado o fluxo completo: Coleta $\rightarrow$ Snapshot $\rightarrow$ Transport (HTTPS + API Key) $\rightarrow$ Server Ingest.

## Fluxo de Execução
1. O agente carrega o `config.toml`.
2. Valida e aplica ACLs de segurança nos arquivos de segredo.
3. Inicializa o `HttpTransport` com os certificados de CA necessários.
4. Executa a pipeline de coleta (Hardware $\rightarrow$ Segurança $\rightarrow$ Acesso $\rightarrow$ Logs).
5. Envia o `Snapshot` final para o endpoint `/api/v1/ingest` do servidor.

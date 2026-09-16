# Plano de Implementação: Transporte HTTP e Segurança (Fase 4)

Este documento detalha as mudanças e implementações planejadas para a Fase 4 do Agente de Monitoramento Multi-OS, agora isoladas na branch `feature/fase4-transporte-http`.

## 1. Configuração e Autenticação (`agent-config`)
- **Endpoint Versátil**: Substituição de `base_url` por `endpoint` no `config.toml`.
- **Enum `AuthMethod`**: Implementação de tipos fortes para autenticação:
    - `None`: Apenas para desenvolvimento local.
    - `ApiKey`: Validação via header `x-api-key` (referência a arquivo).
    - `OAuth2ClientCredentials`: Fluxo de token renovável (referência a secret).
    - `MTLS`: Autenticação via certificado cliente.
- **Validação Rigorosa**: 
    - Bloqueio obrigatório de qualquer endpoint que não utilize `https://`.
    - Verificação de preenchimento de campos obrigatórios conforme o `AuthMethod` escolhido.

## 2. Segurança de Arquivos (ACLs)
- **Restrição de Acesso**: Implementação de função centralizada `restrict_file_to_admins` utilizando `icacls` no Windows.
- **Aplicação**: Garantir que `config.toml` e `secret.bin` sejam acessíveis apenas por `SYSTEM` e `Administradores`, removendo a herança de permissões.

## 3. Coleta de Inventário (`agent-core` & `collectors`)
- **Aplicações Instaladas**: Garantir que a lista de softwares (Nome, Versão, Publisher, Data) seja coletada via Registro do Windows e serializada no `Snapshot` final do JSON.

## 4. Servidor de Recebimento (`server-bin`)
- **Infraestrutura**: Criação de um crate servidor utilizando `axum`.
- **Transporte Seguro**: Implementação de HTTPS obrigatório (TLS) com suporte a certificados autoassinados para ambiente de dev.
- **Endpoint de Ingestão**: `POST /api/v1/ingest` para recepção e validação de Snapshots.
- **Lógica de Autenticação**: Validação do header de API Key comparando com segredo armazenado no servidor.
- **Configuração**: O servidor deve carregar suas próprias definições (método de auth, chave) de um `server_config.toml`.

## 5. Validação e Testes
- **Postman Collection**: Criação de coleção com variáveis para `base_url` e `api_key`.
- **Testes de Stress de Auth**: 
    - Requisição sem header $\rightarrow$ `401`.
    - Requisição com chave errada $\rightarrow$ `401`.
    - Requisição com chave correta $\rightarrow$ `200`.
    - Tentativa via HTTP puro $\rightarrow$ Falha de conexão.

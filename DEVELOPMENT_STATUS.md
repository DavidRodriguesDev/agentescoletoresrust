# Development Status Report - Multi-OS Monitoring Agent

## 1. Project Overview
The project is a production-ready monitoring agent designed for multiple operating systems. Its primary goal is to collect hardware, security, and access telemetry and transport it securely to a central server.

### Core Architectural Goals:
- **Secure Transport**: Use of TLS with support for custom Root CAs (for dev environments) and mTLS.
- **Configuration Security**: `config.toml` is protected by OS-level ACLs (Windows: SYSTEM and Administrators only).
- **Secret Management**: Sensitive data is encrypted using Windows DPAPI.
- **Decoupled Updates**: A separate `updater-bin` service handles binary updates to avoid locking the main agent.

---

## 2. Current State of Components

### `agent-bin` (Main Agent)
- **Function**: Orchestrates telemetry collection (Hardware, Security, Access, Logs, Updates, Apps).
- **Transport**: Uses `HttpTransport` (built on `reqwest`) to send snapshots.
- **Lifecycle**: Loads config $\rightarrow$ Initializes Tracing $\rightarrow$ Checks for updates $\rightarrow$ Collects data $\rightarrow$ Sends snapshot $\rightarrow$ Saves local report.
- **Status**: Core pipeline is functional. Update check logic is present but primarily serves as a trigger for the `updater-bin`.

### `updater-bin` (Update Service) - *New Crate*
- **Function**: Synchronous background service that monitors the server for new versions.
- **Tech Stack**: Uses `ureq` (minimal overhead) and `rustls` for TLS.
- **TLS Configuration**: Implements a custom `rustls::RootCertStore` to trust development CAs specified in `config.extra_ca_cert_path`.
- **Crypto Provider**: Explicitly configured to use `ring` as the crypto provider to avoid `rustls` panics.
- **Implemented Logic**:
    - Version check against `/api/v1/version`.
    - Binary download and SHA-256 hash verification.
    - Windows-specific binary substitution (renames running `.exe` to `.old` before replacing).
- **Current Safety State**: The download/substitution pipeline is **DISABLED** via code comments and warnings. It will only be re-enabled after Ed25519 signature verification is implemented.

### `agent-config` (Configuration Layer)
- **ACL Management**: Implements `restrict_to_system_and_admins` using Windows SIDs (`S-1-5-18` and `S-1-5-32-544`) to ensure only privileged accounts can access the config.
- **Encryption**: Provides DPAPI-based encryption for secret files.
- **Structure**: Loads `AgentConfig` from TOML, including server endpoints and authentication methods (None, API Key, OAuth2, mTLS).

### `agent-core` (Shared Logic)
- **`HttpTransport`**: Handles the actual HTTP requests. It is configured to trust extra root certificates and manage authentication headers/tokens.
- **Types**: Defines the `Snapshot` and `HardwareSnapshot` structures used across the project.

### `server-bin` (Backend)
- **Function**: Receives telemetry and serves version information.
- **TLS**: Implements self-signed TLS for development.
- **Endpoints**:
    - `/api/v1/ingest`: Receives snapshots.
    - `/api/v1/version`: Returns `latest_version`, `notes`, `download_url`, and `sha256`.

---

## 3. Key Implementation Details for Future Agents

### TLS Trust Bridge
To avoid `UnknownIssuer` errors with self-signed dev certificates:
- **Agent**: `HttpTransport` adds the CA cert to the `reqwest` client.
- **Updater**: `create_ureq_agent` manually builds a `rustls::ClientConfig` with a `RootCertStore` containing the CA cert.

### Binary Substitution on Windows
Since Windows locks running executables:
1. The updater renames `agent.exe` $\rightarrow$ `agent.old`.
2. The updater moves `agent_update.tmp` $\rightarrow$ `agent.exe`.
3. The system (or a service manager) restarts the agent.

---

## 4. Pending Tasks & Next Steps
- [ ] **Digital Signatures**: Implement Ed25519 verification in `updater-bin` to ensure binaries are authentic before substitution.
- [ ] **Key Management**: Establish a secure process for generating and distributing the public key to the agent.
- [ ] **Windows Service**: Register `agent-bin` and `updater-bin` as formal Windows Services via SCM.
- [ ] **Recovery**: Configure service recovery options (auto-restart on failure).

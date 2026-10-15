from pathlib import Path

readme = r'''# SecureLAN
### Zero-Trust LAN Collaboration Suite with Inline TLS Inspection

SecureLAN is a Python-based local-area-network collaboration application that combines real-time communication features with a security layer inspired by Zero Trust network access principles.

It brings together **video conferencing, N-1 audio mixing, screen sharing, group chat, and chunked file transfer** with an inline TLS inspection proxy, role-based access control (RBAC), data loss prevention (DLP), and structured security-event logging.

> **Project note:** SecureLAN is an educational implementation inspired by enterprise security architectures. It should not be treated as production-ready or as a certification of SOC 2 or ISO 27001 compliance without independent security review and validation.

---

## Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Communication Features](#communication-features)
- [Security Components](#security-components)
- [Ports and Protocols](#ports-and-protocols)
- [Requirements](#requirements)
- [Installation and Setup](#installation-and-setup)
- [Run SecureLAN](#run-securelan)
- [Security Demos](#security-demos)
- [Repository Structure](#repository-structure)
- [Known Design Notes](#known-design-notes)

---

## Highlights

| Area | Capabilities |
|---|---|
| **Collaboration** | Group chat, video conferencing, audio conferencing, screen sharing, file transfer |
| **Transport** | TCP-based control and file transfer; UDP-based audio and video |
| **Identity and access** | JWT-based sessions, four roles, permission checks, token revocation |
| **Device context** | Initial device-posture trust score based on client metadata |
| **Content protection** | Pattern-based DLP scanning, text redaction, file-signature checks |
| **Traffic inspection** | Inline TLS/mTLS proxy for inspected control traffic |
| **Observability** | Structured JSONL security events and in-memory event statistics |

## Architecture

Control and chat traffic is designed to pass through the inline TLS inspection proxy before reaching the origin server. The proxy terminates the client-side TLS connection, inspects supported application frames, applies authorization and DLP checks, and forwards permitted traffic upstream.

```mermaid
flowchart TD
    A[Desktop Client / CLI Client] -->|TLS + mTLS| B[Inline Inspection Proxy<br/>TCP 5443]
    B --> C[TLS Termination and Frame Parsing]
    C --> D[Authentication and RBAC]
    D --> E[DLP Inspection and Redaction]
    E --> F[Audit Event Logging]
    E -->|Permitted traffic| G[Origin Application Server]
    G --> H[TCP Command and Chat :5000]
    G --> I[TCP File Transfer :5001]
    G --> J[UDP Audio Mixing :5002]
    G --> K[UDP Video Forwarding :5003]
```

### Request flow

1. The client establishes a TLS connection to the inspection proxy.
2. The proxy parses supported application frames and inspects their content.
3. Authentication, role permissions, and DLP policies are evaluated.
4. Permitted traffic is forwarded to the origin service; blocked or redacted events can be logged.
5. The application server handles chat, file transfer, audio, and video services.

## Communication Features

### Video conferencing
- UDP-based Selective Forwarding Unit (SFU)-style forwarding.
- Webcam capture and JPEG encoding using OpenCV.
- Frames are packetized with a custom 8-byte session header.

### Audio conferencing
- Full-duplex microphone capture using PyAudio.
- N-1 audio mixing with NumPy: each participant receives the mix of other participants, excluding their own audio.

### Screen sharing
- Desktop capture using `mss`.
- JPEG frame compression and delivery to connected peers.

### Group text chat
- TCP-based binary framing with a JSON payload.
- Frame fields include a magic number, protocol version, message type, session ID, payload length, and payload.

### File transfer
- Dedicated TCP file server.
- Chunked uploads and downloads with progress tracking.
- Files are stored in the `uploads/` directory.

## Security Components

The `security/` package contains the project's security-related modules.

| Module | Responsibility |
|---|---|
| `security/cert_generator.py` | Generates a local certificate authority and server, client, and proxy certificates |
| `security/tls_config.py` | Creates TLS contexts and configures mutual TLS |
| `security/auth.py` | JWT authentication, role-based access control, device-context scoring, and token revocation |
| `security/dlp_engine.py` | Detects configured sensitive-data patterns, redacts text, and checks file-signature bytes |
| `security/audit_logger.py` | Writes structured JSONL security events and maintains an in-memory event buffer |
| `security/tls_proxy.py` | Accepts client TLS connections, inspects supported frames, and forwards permitted traffic |

### Roles

| Role | Intended permissions |
|---|---|
| `ADMIN` | Administrative actions, user management, and audit inspection |
| `PRESENTER` | Presenting and collaboration features, including media and file transfer |
| `MEMBER` | Chat, audio/video, and file upload/download |
| `GUEST` | Limited access, intended for read-only chat and audio/video listening |

The exact permissions depend on the policy checks implemented by the application.

### DLP detections

The DLP engine is configured to look for patterns such as:

- Payment-card numbers, with Luhn checksum validation
- US Social Security number formats
- Indian Aadhaar-number patterns
- AWS access-key patterns
- API keys, bearer tokens, and password-like assignments
- Corporate email addresses
- Private-key headers
- Internal IPv4 addresses and CIDR ranges

The engine supports configured actions such as **masking** sensitive text or **blocking** a frame. It also checks file-signature bytes to help identify file-type mismatches, such as an executable presented with a document extension.

> Pattern-based DLP is not a guarantee that every secret or malicious file will be detected. Detection coverage depends on the implemented rules and the content that can be inspected.

### Audit events

Security events are written to `security_audit.jsonl` with structured fields such as event ID, timestamp, category, severity, actor, client IP, action, status, resource, and details. An in-memory circular buffer keeps recent events available for quick queries.

## Ports and Protocols

| Service | Port | Transport | Purpose |
|---|---:|---|---|
| TLS inspection proxy | `5443` | TCP / TLS | Client ingress, inspection, and policy enforcement |
| Command and chat server | `5000` | TCP | Login, messaging, presence, and screen-sharing control |
| File transfer server | `5001` | TCP | Chunked file uploads and downloads |
| Audio conference | `5002` | UDP | Real-time audio and N-1 mixing |
| Video conference | `5003` | UDP | Video forwarding |

**Important:** The project description identifies the audio and video streams as plain UDP. They should not be assumed to be encrypted merely because the control path uses TLS. Review the implementation and deployment configuration before using SecureLAN on an untrusted network.

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Microphone, speakers/headphones, and webcam for the corresponding media features
- The packages listed in `requirements.txt`

## Installation and Setup

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd <repository-directory>
```

Replace the placeholders with your repository URL and directory name.

### 2. Create and activate a virtual environment (recommended)

**Windows PowerShell**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Some audio dependencies, particularly PyAudio, may require platform-specific system packages or installation steps.

### 4. Generate development certificates

For local testing:

```bash
python -m security.cert_generator --server-ip 127.0.0.1
```

Use the appropriate LAN IP if clients on other devices need to connect. Ensure the generated certificates contain the correct subject alternative names for the addresses clients use.

> **Keep private keys private.** Do not commit generated private keys, production certificates, access tokens, or real audit data to a public repository. Check `.gitignore` before generating or adding files.

## Run SecureLAN

Start each component in a separate terminal, from the repository root.

### Terminal 1 — Application server

```bash
python main_server.py
```

This launches the server application and its communication services.

### Terminal 2 — TLS inspection proxy

```bash
python -m security.tls_proxy 5443 5000
```

This starts the proxy on port `5443` and forwards inspected control traffic to the origin command server on port `5000`.

### Terminal 3 — Desktop client

```bash
python client.py
```

### Optional — CLI client

```bash
python cli_client.py
```

The precise startup sequence and available features depend on the current implementation and local configuration. If a component fails to start, check the terminal output, certificate paths, and port availability.

## Security Demos

The following examples are intended for local demonstrations. Use synthetic test data only.

### 1. DLP scanning and redaction

```bash
python -c "from security.dlp_engine import DLPEngine; e = DLPEngine(); res = e.scan_text('Test card 4111-1111-1111-1111 and key AKIAIOSFODNN7EXAMPLE'); print('Action:', res.action); print('Sanitized text:', res.redacted_text)"
```

Shows how the DLP engine responds to configured sensitive-data patterns.

### 2. Authentication and permission checks

```bash
python -c "from security.auth import AuthEngine, Permission; a = AuthEngine(); t = a.authenticate('alice', 'DemoPassword123', device_info={'os_name':'Windows','os_version':'11','hostname':'Demo-PC','ip_address':'192.168.1.50'}); u = a.validate_token(t); print('User:', u.username, '| Role:', u.role.value, '| Trust score:', u.device_context.trust_score); print('Can kick users:', a.check_permission(u, Permission.KICK_USER))"
```

Demonstrates token issuance, token validation, device-context scoring, and a permission check. The authentication example should be adjusted if the API or required configuration changes.

### 3. Audit logger statistics

```bash
python -c "from security.audit_logger import AuditLogger; logger = AuditLogger(); print(logger.get_statistics())"
```

Prints the logger's current statistics. Depending on the implementation, a fresh logger may have no events until actions are recorded.

## Repository Structure

```text
.
├── certs/                     # Generated certificates and keys (keep private keys out of Git)
├── security/
│   ├── __init__.py
│   ├── cert_generator.py      # Local CA and certificate generation
│   ├── tls_config.py          # TLS and mTLS context configuration
│   ├── auth.py                # JWT, RBAC, trust scoring, revocation
│   ├── dlp_engine.py          # Sensitive-data inspection and redaction
│   ├── audit_logger.py        # Structured security-event logging
│   └── tls_proxy.py           # Inline TLS inspection proxy
├── uploads/                   # Transferred files
├── client.py                  # Desktop collaboration client
├── cli_client.py              # CLI client
├── file_server.py             # Chunked file-transfer server
├── main_server.py             # Server launcher / supervisor
├── server.py                  # Core protocol handlers and media services
├── requirements.txt           # Python dependencies
└── README.md
```

## Known Design Notes

- **Development scope:** Treat this as a learning and demonstration project until it has undergone security testing and operational hardening.
- **TLS inspection:** A TLS inspection proxy must be configured carefully. Clients need to trust the appropriate certificate chain, and private keys must be protected.
- **Media traffic:** Confirm whether audio and video payloads are protected before deploying beyond a trusted test network.
- **Device posture:** Metadata-based trust scoring is a demonstration of policy input, not proof that a device is secure.
- **Audit and compliance:** Structured audit logs can support investigation, but they do not by themselves establish SOC 2 or ISO 27001 compliance.
- **File inspection:** Magic-byte checks and pattern-based scanning are useful signals, not substitutes for malware scanning or sandboxing.

---

## Project Summary

SecureLAN brings real-time LAN collaboration and a set of security controls into one Python project. Its main learning areas include network programming, binary protocol framing, media streaming, TLS/mTLS, JWT authentication, RBAC, DLP, and structured security logging.
'''

path = Path("/mnt/data/README_SecureLAN_Improved.md")
path.write_text(readme, encoding="utf-8")
print(f"Created: {path}")
print(f"Size: {path.stat().st_size:,} bytes")

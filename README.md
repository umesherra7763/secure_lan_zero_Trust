<div align="center">

# SecureLAN

### Zero Trust Communication Suite with Inline TLS Inspection Proxy

Real-time video, audio, screen sharing, chat and file transfer, secured by mTLS, JWT/RBAC, inline DLP and audit logging.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Qt](https://img.shields.io/badge/UI-PySide6-41CD52?logo=qt&logoColor=white)
![TLS](https://img.shields.io/badge/TLS-1.2%2B%20%7C%20mTLS-blue)
![Auth](https://img.shields.io/badge/Auth-JWT%20%2B%20RBAC-orange)
![DLP](https://img.shields.io/badge/DLP-9%20detectors-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

[Architecture](#architecture) · [Features](#features) · [Security Modules](#security-modules) · [Quick Start](#quick-start) · [Demos](#demos) · [Structure](#project-structure)

</div>

---

## Overview

SecureLAN is a multi-threaded, asyncio-based LAN collaboration suite. Instead of letting clients talk directly to the origin server, all control and chat traffic passes through an **inline TLS inspection proxy** that decrypts, inspects, enforces policy, redacts sensitive data, and re-encrypts upstream. The design is inspired by the Zero Trust Exchange model used by Zscaler.

## Architecture

```mermaid
flowchart TD
    C["<b>Client Tier</b><br/>PySide6 UI · CLI Client · Media Threads"]
    subgraph P["Inline TLS Inspection Proxy :5443"]
        direction TB
        P1["TLS termination and decryption"] --> P2["DPI and magic-byte inspection"]
        P2 --> P3["Zero Trust IAM and RBAC check"]
        P3 --> P4["Inline DLP redaction"]
        P4 --> P5["SOC 2 / ISO 27001 audit log (JSONL)"]
    end
    O["<b>Origin Application Server</b><br/>:5000 Command · :5001 File<br/>:5002 UDP Audio (N-1 mix) · :5003 UDP Video (SFU)"]
    C -- "TLS handshake 1 (mutual TLS)" --> P
    P -- "TLS handshake 2 (upstream TLS)" --> O
```

## Features

### Baseline collaboration modules

| Module | Port | Transport | Description |
|---|---|---|---|
| Video conferencing | 5003 | UDP | SFU forwarding. OpenCV capture, JPEG encoding, 8-byte session header. |
| Audio conferencing | 5002 | UDP | PyAudio capture with NumPy **N-1 mixing** (each user hears everyone except themselves, no echo cancellation needed). |
| Screen sharing | 5000 | TCP | `mss` desktop capture, JPEG frames broadcast to peers. |
| Group chat | 5000 | TCP | Custom binary framed protocol (see below). |
| File transfer | 5001 | TCP | Chunked streaming upload/download with progress tracking. |

<details>
<summary><b>Binary protocol frame layout</b></summary>

| Field | Size | Value / Purpose |
|---|---|---|
| Magic number | 4 bytes | `0xDEADBEEF` |
| Protocol version | 2 bytes | `0x0100` |
| Message type | 2 bytes | Message type identifier |
| Session ID | 8 bytes | Per-session identifier |
| Payload length | 4 bytes | Length of the JSON payload that follows |

</details>

### Enterprise security layer

The baseline had plaintext traffic, dummy authentication, no RBAC, no content inspection and no audit trail. The `security/` package and automated PKI close each of those gaps:

| Gap | Fix | Module |
|---|---|---|
| Plaintext traffic | TLS 1.2+ with mutual TLS | `tls_config.py`, `cert_generator.py` |
| Dummy authentication | Stateless JWT, device posture scoring, revocation list | `auth.py` |
| No authorization | 4-tier RBAC | `auth.py` |
| No content visibility | Inline DLP and magic-byte inspection | `dlp_engine.py` |
| No audit trail | Immutable JSONL log and live metrics | `audit_logger.py` |
| No traffic enforcement point | Inline TLS inspection proxy | `tls_proxy.py` |

## Security Modules

<details open>
<summary><b>1. PKI and X.509 CA engine</b> · <code>security/cert_generator.py</code></summary>

- Issues a Root CA with 4096-bit RSA keys.
- Signs leaf certificates for the server, client and inspection proxy (RSA-2048, SHA-256).
- Adds Subject Alternative Names (`DNS:localhost`, `IP:127.0.0.1`, `IP:<LAN_IP>`) to avoid hostname mismatch warnings.
- Stores all keys and certificates in `certs/`.

</details>

<details open>
<summary><b>2. Zero Trust identity and access</b> · <code>security/auth.py</code></summary>

- **Stateless JWT (HMAC-SHA256):** claims `sub`, `role`, `sid`, `iat`, `exp`, `trust`, `iss`, valid for 1 hour.
- **Device posture scoring:** OS, OS version, hostname and network IP produce an initial trust score from `0.0` to `1.0`.
- **Session revocation:** in-memory token blacklist for immediate termination on alerts or logout.

| Role | Permissions |
|---|---|
| `ADMIN` | Full control, kick/ban users, audit log inspection |
| `PRESENTER` | Screen share, audio/video, chat, file transfer |
| `MEMBER` | Chat, audio/video, file upload/download |
| `GUEST` | Read-only chat, audio/video listening |

</details>

<details open>
<summary><b>3. Data Loss Prevention engine</b> · <code>security/dlp_engine.py</code></summary>

| # | Detector | Notes |
|---|---|---|
| 1 | Credit cards | Visa, Mastercard, Amex, Discover, validated with the **Luhn** checksum |
| 2 | US SSN | `XXX-XX-XXXX` with area and group checks |
| 3 | Indian Aadhaar | 12-digit space-separated pattern |
| 4 | AWS access keys | `AKIA[0-9A-Z]{16}` |
| 5 | API keys and bearer tokens | High-entropy and secret-key structures |
| 6 | Hardcoded passwords | Inline password assignments |
| 7 | Corporate email leakage | Unauthorized corporate domain addresses |
| 8 | Private keys | `-----BEGIN PRIVATE KEY-----` and RSA headers |
| 9 | Internal IPv4 / CIDR | RFC 1918 subnet leakage |

**Actions**
- `MASK`: redacts in memory before forwarding, e.g. `4111-XXXX-XXXX-1111`.
- `BLOCK`: drops the frame and emits a high-severity audit event.

**Binary inspection:** reads raw file headers (`MZ` for PE/EXE, `%PDF`, `PK` for ZIP/DOCX) to block executables and detect **extension spoofing**, such as malware renamed `report.pdf`.

</details>

<details open>
<summary><b>4. Inline TLS inspection proxy</b> · <code>security/tls_proxy.py</code></summary>

1. **Downstream:** accepts client TLS connections on port `5443`.
2. **DPI:** reads the TCP stream asynchronously, extracts protocol frames and inspects the decrypted JSON.
3. **Enforcement:** runs DLP and authorization checks, rewriting sanitized frames in memory with updated header lengths.
4. **Upstream:** keeps a persistent TLS connection to the origin on port `5000` and forwards permitted frames.

</details>

<details open>
<summary><b>5. Audit logging and compliance</b> · <code>security/audit_logger.py</code></summary>

- Structured events written to `security_audit.jsonl` (`event_id`, `timestamp`, `category`, `severity`, `actor`, `client_ip`, `action`, `status`, `resource`, `details`).
- Thread-safe ring buffer (`deque`) of the last 1,000 events for low-latency queries.
- Designed around SOC 2 and ISO 27001 style logging practices.

</details>

## Network Matrix

| Service | Port | Protocol | Security | Purpose |
|---|---|---|---|---|
| TLS Inspection Proxy | 5443 | TCP | TLS 1.2+ / mTLS | Ingress inspection, DPI and DLP |
| Command and Chat Server | 5000 | TCP | TLS (via proxy) | Login, messaging, presence, screen share |
| File Transfer Server | 5001 | TCP | TLS | Chunked upload/download |
| Audio Conference | 5002 | UDP | Plain UDP | Low-latency voice with N-1 mixing |
| Video Conference | 5003 | UDP | Plain UDP | Low-latency webcam via SFU |

## Quick Start

**Requirements:** Python 3.10+ (tested on 3.11 and 3.13), Windows / Linux / macOS. A microphone and webcam are optional.

```bash
pip install -r requirements.txt
```

<details>
<summary>Dependencies</summary>

`PySide6` (GUI) · `cryptography` (PKI) · `PyJWT` (tokens) · `numpy` (audio mixing) · `pyaudio` (audio capture) · `opencv-python` (video) · `mss` (screen capture) · `Pillow` (imaging)

</details>

**1. Generate certificates (one time)**
```bash
python -m security.cert_generator --server-ip 127.0.0.1
```

**2. Start the origin server** (Terminal 1). Launches the admin GUI and ports 5000-5003.
```bash
python main_server.py
```

**3. Start the inspection proxy** (Terminal 2). Listens on 5443, tunnels to 5000.
```bash
python -m security.tls_proxy 5443 5000
```

**4. Launch a client** (Terminal 3)
```bash
python client.py          # PySide6 GUI
python cli_client.py      # optional headless client
```

## Demos

Run each security subsystem straight from the terminal.

<details>
<summary><b>Demo 1: DLP detection and in-flight redaction</b></summary>

```powershell
python -c "from security.dlp_engine import DLPEngine; e = DLPEngine(); res = e.scan_text('Transfer $500 to card 4111-1111-1111-1111 with key AKIAIOSFODNN7EXAMPLE'); print('Overall Action:', res.action); print('Sanitized Text:', res.redacted_text)"
```
Shows Luhn-verified pattern matching and in-memory redaction.

</details>

<details>
<summary><b>Demo 2: Authentication, device scoring and RBAC</b></summary>

```powershell
python -c "from security.auth import AuthEngine, Permission; a = AuthEngine(); t = a.authenticate('alice', 'SecurePassword123', device_info={'os_name':'Windows','os_version':'11','hostname':'Corp-PC','ip_address':'192.168.1.50'}); u = a.validate_token(t); print('User:', u.username, '| Role:', u.role.value, '| Trust Score:', u.device_context.trust_score); print('Can Kick Users:', a.check_permission(u, Permission.KICK_USER))"
```
Shows trust scoring, JWT issuance and permission enforcement.

</details>

<details>
<summary><b>Demo 3: Audit logger statistics</b></summary>

```powershell
python -c "from security.audit_logger import AuditLogger; logger = AuditLogger(); print('Audit Statistics:', logger.get_statistics())"
```
Shows the in-memory telemetry ring buffer.

</details>

## Project Structure

```text
cn/
├── certs/                  # X.509 CA, server, client and proxy certs/keys
├── security/               # Enterprise security package
│   ├── __init__.py
│   ├── cert_generator.py   # Automated PKI
│   ├── tls_config.py       # TLS 1.2+ / mTLS context factory
│   ├── auth.py             # JWT, RBAC, trust scoring
│   ├── dlp_engine.py       # Regex, Luhn, magic bytes
│   ├── audit_logger.py     # JSONL audit trail and metrics
│   └── tls_proxy.py        # Inline TLS inspection proxy
├── uploads/                # Shared file transfer storage
├── client.py               # PySide6 GUI client
├── cli_client.py           # Headless CLI client
├── file_server.py          # Chunked TCP file server
├── main_server.py          # Server supervisor and Qt GUI launcher
├── server.py               # Protocol handlers and UDP media servers
├── requirements.txt
└── README.md
```

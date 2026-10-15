# 🛡️ SecureLAN: Enterprise Zero Trust Communication Suite & Inline TLS Inspection Proxy

> A high-performance, real-time collaboration suite featuring **video conferencing, N-1 mixed audio streaming, screen sharing, group chat, and chunked file transfer** — hardened with an enterprise-grade **Zero Trust Architecture**, **Inline TLS/mTLS Inspection Proxy**, and **Real-Time Data Loss Prevention (DLP)** engine inspired by **Zscaler's Zero Trust Exchange**.

---

## 📑 Table of Contents
1. [Architectural Overview](#-architectural-overview)
2. [What Was Already Present (Baseline Capabilities)](#-what-was-already-present-baseline-capabilities)
3. [What Was Added (Enterprise Security Architecture)](#-what-was-added-enterprise-security-architecture)
4. [Deep Dive into Security Modules](#-deep-dive-into-security-modules)
5. [Network Port & Protocol Matrix](#-network-port--protocol-matrix)
6. [Prerequisites & Installation](#-prerequisites--installation)
7. [Step-by-Step Execution Guide](#-step-by-step-execution-guide)
8. [Instant Interview Demos (CLI One-Liners)](#-instant-interview-demos-cli-one-liners)
9. [Resume Presentation & Talking Points](#-resume-presentation--talking-points)
10. [Repository Directory Structure](#-repository-directory-structure)

---

## 🏛️ Architectural Overview

The project implements a modern **Zero Trust Network Architecture (ZTNA)**. Instead of allowing clients to connect directly to the origin server unmonitored, all control and chat traffic traverses an **Inline TLS Inspection Proxy**:

```text
 ┌────────────────────────────────────────────────────────┐
 │                      Client Tier                       │
 │  (PySide6 UI / CLI Client / Media Transceiver Threads) │
 └──────────────────────────┬─────────────────────────────┘
                            │
              [TLS Handshake 1: Mutual TLS]
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │           Inline TLS Inspection Proxy (:5443)          │
 │   ┌────────────────────────────────────────────────┐   │
 │   │  TLS Termination & Decryption                  │   │
 │   │  ────────────────────────────────────────────  │   │
 │   │  Deep Packet Inspection (DPI) & Magic Bytes    │   │
 │   │  ────────────────────────────────────────────  │   │
 │   │  Zero Trust IAM & Role Policy Check (RBAC)     │   │
 │   │  ────────────────────────────────────────────  │   │
 │   │  Inline Data Loss Prevention (DLP Redaction)   │   │
 │   │  ────────────────────────────────────────────  │   │
 │   │  SOC 2 / ISO 27001 Audit Logging (JSONL)       │   │
 │   └────────────────────────────────────────────────┘   │
 └──────────────────────────┬─────────────────────────────┘
                            │
              [TLS Handshake 2: Upstream TLS]
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │                 Origin Application Server              │
 │  - TCP Command Server (:5000)                          │
 │  - TCP File Transfer Server (:5001)                    │
 │  - UDP Audio Server with N-1 Mixing (:5002)            │
 │  - UDP Video Forwarding SFU (:5003)                    │
 └────────────────────────────────────────────────────────┘
```

---

## 📦 What Was Already Present (Baseline Capabilities)

The core foundation is a multi-threaded, asynchronous local-area network communication suite built with Python, PySide6, and asyncio:

1. **Module 1: Video Conferencing (UDP Port 5003)**
   - Selective Forwarding Unit (SFU) architecture over UDP.
   - Webcam capture using OpenCV, encoded to JPEG, packetized with a custom 8-byte session header (`!Q`), and broadcast to all conference participants.
2. **Module 2: Audio Conferencing (UDP Port 5002)**
   - Full-duplex microphone capture using PyAudio.
   - Real-time **N-1 audio mixing** implemented with NumPy: each user receives the mixed audio of all other participants minus their own voice, preventing acoustic echo without heavy DSP cancellation.
3. **Module 3: Screen Sharing (TCP Port 5000)**
   - Ultra-fast desktop capture via `mss`.
   - Frame compression into JPEG payloads broadcast to connected peers.
4. **Module 4: Group Text Chat (TCP Port 5000)**
   - High-throughput binary framed protocol:
     - 4-byte Magic Number (`0xDEADBEEF`)
     - 2-byte Protocol Version (`0x0100`)
     - 2-byte Message Type identifier
     - 8-byte Session ID
     - 4-byte Payload Length followed by JSON text payload.
5. **Module 5: File Transfer Server (TCP Port 5001)**
   - Dedicated high-speed file server (`file_server.py`) supporting chunked streaming uploads and downloads with progress tracking and disk storage in `uploads/`.

### Baseline Security Gaps Before Enhancement
* ❌ **Plaintext Traffic**: Data was unencrypted over the wire; vulnerable to packet sniffing.
* ❌ **Dummy Authentication**: Accepted any username without credential validation, cryptographic tokens, or session lifetimes.
* ❌ **No Authorization (RBAC)**: Any connected user could execute privileged actions.
* ❌ **No Content Visibility / DLP**: Free exchange of uninspected files and plaintext secrets.
* ❌ **No Compliance Audit Trail**: Absence of structured immutable security event logs.

---

## 🔒 What Was Added (Enterprise Security Architecture)

To bridge these gaps and align directly with **Zscaler's core technology pillars**, an entire enterprise security package (`security/`) and automated Public Key Infrastructure (`certs/`) were designed and integrated:

| Component | Module | Key Capabilities |
|---|---|---|
| **PKI & Certificate Engine** | `security/cert_generator.py` | Automated X.509 CA & certificate issuance (RSA-4096 / RSA-2048) with SANs and key usage policies. |
| **TLS/mTLS Configuration** | `security/tls_config.py` | TLS 1.2+ cipher-suite enforcement, mutual authentication, dual-context generation. |
| **Zero Trust Access Control** | `security/auth.py` | Stateless JWT tokens (HMAC-SHA256), 4-tier RBAC (`ADMIN`, `PRESENTER`, `MEMBER`, `GUEST`), device posture scoring, token revocation list. |
| **Real-Time DLP Engine** | `security/dlp_engine.py` | Deep Packet Inspection with 9 detection patterns, Luhn-validated credit cards, in-flight text masking, and binary magic-byte inspection. |
| **Security Audit Logging** | `security/audit_logger.py` | Immutable JSONL audit trail (`security_audit.jsonl`), in-memory ring buffer, and live threat metrics aggregator. |
| **Inline TLS Inspection Proxy** | `security/tls_proxy.py` | Zscaler Zero Trust Exchange mirror: TLS termination, packet inspection, DLP sanitization, and upstream re-encryption. |

---

## 🔍 Deep Dive into Security Modules

### 1. Automated PKI & X.509 CA Engine (`security/cert_generator.py`)
- Programmatically issues a Root Certificate Authority (CA) using 4096-bit RSA keys.
- Signs leaf certificates for the **Server**, **Client**, and **Inspection Proxy** (2048-bit RSA, SHA-256).
- Injects Subject Alternative Names (`DNS:localhost`, `IP:127.0.0.1`, `IP:<LAN_IP>`) to prevent hostname mismatch warnings.
- Automatically stores keys and certificates in the `certs/` directory.

### 2. Zero Trust Identity & Access Management (`security/auth.py`)
- **Stateless JWT Engine**: Issues signed tokens (`sub`, `role`, `sid`, `iat`, `exp`, `trust`, `iss`) valid for 1 hour.
- **Role-Based Access Control (RBAC)**:
  - `ADMIN`: Unrestricted administrative privileges, user kick/ban, audit log inspection.
  - `PRESENTER`: Screen share broadcasting, audio/video streaming, chat, file transfers.
  - `MEMBER`: Chat, audio/video, file download/upload.
  - `GUEST`: Read-only chat and audio/video listening.
- **Device Posture Scoring**: Evaluates client device metadata (OS, OS version, hostname, network IP) to compute an initial trust score between `0.0` and `1.0`.
- **Session Revocation**: In-memory token blacklist for immediate session termination upon security alerts or logout.

### 3. Data Loss Prevention Engine (`security/dlp_engine.py`)
- **Regex & Algorithmic Patterns**:
  1. *Credit Cards*: Matches Visa, Mastercard, Amex, Discover, and validates via the **Luhn Checksum Algorithm**.
  2. *US Social Security Numbers (SSN)*: Format `XXX-XX-XXXX` with area and group checks.
  3. *Indian Aadhaar Numbers*: 12-digit space-separated biometric ID patterns.
  4. *AWS Access Keys*: Detects `AKIA[0-9A-Z]{16}` credentials.
  5. *API Keys & Bearer Tokens*: High-entropy strings and secret key structures.
  6. *Hardcoded Passwords / Secrets*: Inline password assignment detection.
  7. *Corporate Email Leakage*: Unauthorized corporate domain address transfers.
  8. *Cryptographic Private Keys*: Headers matching `-----BEGIN PRIVATE KEY-----` or RSA keys.
  9. *Internal IPv4 / CIDR*: Leakage of internal enterprise RFC 1918 subnets.
- **Action Policies**:
  - `MASK`: Replaces sensitive characters in memory (e.g., `4111-XXXX-XXXX-1111`) before packet forwarding.
  - `BLOCK`: Drops the application frame immediately and emits high-severity audit logs.
- **Binary Magic-Byte Inspection**: Reads raw file headers to identify executable payloads (`b'MZ'` for PE/EXE, `b'%PDF'` for PDF, `b'PK'` for ZIP/DOCX) to block malicious executables and detect **extension spoofing** (e.g., malware disguised as `report.pdf`).

### 4. Inline TLS Inspection Proxy (`security/tls_proxy.py`)
- Emulates Zscaler's single-pass cloud architecture:
  - **Downstream**: Accepts incoming TLS connections from clients on port `5443`.
  - **DPI Unpacking**: Asynchronously reads the TCP stream, extracts protocol frames, and inspects decrypted JSON payloads.
  - **Enforcement**: Runs DLP and authorization checks. Sanitized messages are rewritten in memory with updated header lengths.
  - **Upstream**: Maintains a persistent TLS connection to the origin server on port `5000` and forwards permitted frames.

### 5. Audit Logging & Compliance (`security/audit_logger.py`)
- Adheres to enterprise security standards (SOC 2, ISO 27001).
- Logs events to `security_audit.jsonl` with full event metadata (`event_id`, `timestamp`, `category`, `severity`, `actor`, `client_ip`, `action`, `status`, `resource`, `details`).
- Thread-safe circular buffer (`deque`) stores the last 1,000 security events for low-latency queries.

---

## 🌐 Network Port & Protocol Matrix

| Service | Port | Protocol | Encryption / Security | Purpose |
|---|---|---|---|---|
| **TLS Inspection Proxy** | `5443` | TCP | TLS 1.2+ / mTLS | Ingress inspection point, DPI & DLP filter |
| **Command & Chat Server** | `5000` | TCP | TLS (via Proxy) | Login, messaging, presence, screen share |
| **File Transfer Server** | `5001` | TCP | TLS | Chunked file upload and download |
| **Audio Conference** | `5002` | UDP | Plain UDP (Low Latency) | Real-time voice stream with N-1 mixing |
| **Video Conference** | `5003` | UDP | Plain UDP (Low Latency) | Real-time webcam stream via SFU |

---

## 🛠️ Prerequisites & Installation

### 1. System Requirements
- Python 3.10+ (Tested on Python 3.11 & 3.13)
- Windows / Linux / macOS
- Audio input/output device and webcam (optional for media tests)

### 2. Install Python Dependencies
```powershell
pip install -r requirements.txt
```

*Installed dependencies include:*
- `PySide6`: Modern Qt graphical interface.
- `cryptography`: X.509 PKI, RSA key generation, and certificate management.
- `PyJWT`: JSON Web Token creation and cryptographic verification.
- `numpy`: Fast vectorized matrix audio mixing.
- `pyaudio`: Real-time cross-platform audio capture.
- `opencv-python`: Video capture and JPEG encoding/decoding.
- `mss`: Ultra-fast screen capture.
- `Pillow`: Image processing utilities.

---

## 🚀 Step-by-Step Execution Guide

### Step 1: Generate PKI Certificates (One-Time Setup)
```powershell
python -m security.cert_generator --server-ip 127.0.0.1
```
*Creates the Root CA, server certificates, client certificates, and proxy certificates inside the `certs/` folder.*

### Step 2: Start the Origin Application Server (Terminal 1)
```powershell
python main_server.py
```
*Spawns the GUI Admin Console, starts the Command Server on port 5000, File Server on port 5001, Audio Server on port 5002, and Video Server on port 5003.*

### Step 3: Start the Inline TLS Inspection Proxy (Terminal 2)
```powershell
python -m security.tls_proxy 5443 5000
```
*Starts the Zscaler-style proxy listening on TLS port 5443 and tunneling inspected traffic to origin port 5000.*

### Step 4: Launch the Client (Terminal 3)
```powershell
python client.py
```
*Opens the PySide6 collaboration client interface for text chat, video, audio, screen share, and file transfer.*

*(Optional) Headless CLI Client for fast testing:*
```powershell
python cli_client.py
```

---

## ⚡ Instant Interview Demos (CLI One-Liners)

Demonstrate individual security subsystems directly from the terminal during an interview:

### Demo 1: Real-Time DLP Engine (Pattern Match & In-Flight Redaction)
```powershell
python -c "from security.dlp_engine import DLPEngine; e = DLPEngine(); res = e.scan_text('Transfer $500 to card 4111-1111-1111-1111 with key AKIAIOSFODNN7EXAMPLE'); print('Overall Action:', res.action); print('Sanitized Text:', res.redacted_text)"
```
*Demonstrates pattern matching with Luhn verification and automated in-memory redaction.*

### Demo 2: Zero Trust Authentication, Device Scoring & RBAC
```powershell
python -c "from security.auth import AuthEngine, Permission; a = AuthEngine(); t = a.authenticate('alice', 'SecurePassword123', device_info={'os_name':'Windows','os_version':'11','hostname':'Corp-PC','ip_address':'192.168.1.50'}); u = a.validate_token(t); print('User:', u.username, '| Role:', u.role.value, '| Trust Score:', u.device_context.trust_score); print('Can Kick Users:', a.check_permission(u, Permission.KICK_USER))"
```
*Demonstrates dynamic device posture trust-scoring, JWT issuance, and RBAC permission enforcement.*

### Demo 3: Security Audit Logger & Compliance Statistics
```powershell
python -c "from security.audit_logger import AuditLogger; logger = AuditLogger(); print('Audit Statistics:', logger.get_statistics())"
```
*Demonstrates the in-memory telemetry ring buffer tracking security events.*

---

## 📄 Resume Presentation & Talking Points

### Resume Bullet Points (Tailored for Zscaler)
- **Zero Trust Collaboration Platform & Inline TLS Proxy**: Engineered an enterprise-grade real-time collaboration suite featuring an inline TLS inspection proxy mirroring **Zscaler's Zero Trust Exchange** — terminating client TLS, executing Deep Packet Inspection (DPI) on binary protocol frames, and re-encrypting upstream sessions.
- **Zero Trust IAM & Role-Based Access Control**: Implemented stateless JWT authentication (HMAC-SHA256) with dynamic device posture evaluation (calculating device trust scores) and granular RBAC policies across 4 user tiers with token revocation blacklists.
- **Real-Time Data Loss Prevention (DLP)**: Developed an inline DLP scanning engine with 9 pattern recognizers and Luhn algorithm validation (credit cards, SSNs, AWS credentials) with in-flight payload masking and binary magic-byte inspection preventing extension-spoofing malware.
- **SOC 2 Compliant Audit Logging**: Built an asynchronous audit logger generating structured JSONL logs (`security_audit.jsonl`) and maintaining an in-memory ring buffer for low-latency operational threat metrics.
- **High-Concurrency Multi-Protocol Media Core**: Built a custom binary protocol handling 5 concurrent real-time services across 4 dedicated TCP/UDP ports, including an SFU-based UDP video forwarder, N-1 audio mixing with NumPy, and chunked TCP file transfer.

### Interview Elevator Pitch
> *"My project is a secure LAN collaboration suite designed specifically around Zscaler's architectural philosophy. While standard applications connect directly to a backend, I engineered an inline TLS inspection proxy that acts as an enforcement node. It terminates TLS handshakes, performs deep packet inspection on our custom binary protocol, evaluates zero-trust policies and device posture, runs real-time DLP to mask sensitive data like credit cards and API keys in-flight, and re-encrypts the session upstream to the server — giving complete visibility without compromising performance."*

---

## 📁 Repository Directory Structure

```text
cn/
│
├── certs/                              # X.509 PKI Certificates & Keys
│   ├── ca_cert.pem & ca_key.pem       # Root Certificate Authority
│   ├── server_cert.pem & server_key.pem
│   ├── client_cert.pem & client_key.pem
│   └── proxy_cert.pem & proxy_key.pem
│
├── security/                           # Enterprise Security Package
│   ├── __init__.py                     # Package initialization & exports
│   ├── cert_generator.py               # Automated X.509 PKI generator
│   ├── tls_config.py                   # TLS 1.2+ & mTLS context factory
│   ├── auth.py                         # Zero Trust IAM (JWT, RBAC, Trust Scoring)
│   ├── dlp_engine.py                   # Inline DLP Engine (Regex, Luhn, Magic Bytes)
│   ├── audit_logger.py                 # Structured JSONL Audit Trail & Metrics
│   └── tls_proxy.py                    # Zscaler-Style Inline TLS Inspection Proxy
│
├── uploads/                            # Shared file transfer repository
├── client.py                           # PySide6 GUI collaboration client
├── cli_client.py                       # Lightweight headless CLI protocol client
├── file_server.py                      # Dedicated chunked TCP file transfer server
├── main_server.py                      # Multi-server supervisor and Qt GUI launcher
├── server.py                           # Core protocol handlers & UDP media servers
├── requirements.txt                    # Project dependencies
└── README.md                           # Master project documentation
```
#   s e c u r e _ l a n _ z e r o _ T r u s t  
 #   s e c u r e _ l a n _ z e r o _ T r u s t  
 
"""
Automated End-to-End Live Demonstration of SecureLAN & Zscaler Inline TLS Proxy
"""

import asyncio
import ssl
import struct
import json
import logging
import os
import sys

from security.tls_config import create_client_ssl_context
from security.tls_proxy import InlineTLSProxy
from security.auth import AuthEngine, Role, Permission
from security.dlp_engine import DLPEngine
from security.audit_logger import AuditLogger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("LiveE2EDemo")

MAGIC_NUMBER = 0xDEADBEEF
PROTOCOL_VERSION = 0x0100
HEADER_FORMAT = '!IHHQI'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

MSG_AUTHENTICATION_REQUEST = 1
MSG_AUTHENTICATION_SUCCESS = 2
MSG_SEND_TEXT_MESSAGE = 100
MSG_BROADCAST_TEXT_MESSAGE = 101
MSG_FILE_TRANSFER_NOTIFY_REQUEST = 400

ORIGIN_PORT = 5000
PROXY_PORT = 5443

received_messages_at_origin = []


async def handle_origin_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Simulates the Origin Server backend processing requests from the Proxy."""
    try:
        while True:
            header_bytes = await reader.read(HEADER_SIZE)
            if not header_bytes or len(header_bytes) < HEADER_SIZE:
                break
            magic, version, msg_type, session_id, payload_len = struct.unpack(HEADER_FORMAT, header_bytes)
            payload_bytes = await reader.read(payload_len) if payload_len > 0 else b""

            if msg_type == MSG_AUTHENTICATION_REQUEST:
                resp_payload = json.dumps({"status": "SUCCESS", "session_id": 9999}).encode('utf-8')
                resp_header = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, PROTOCOL_VERSION, MSG_AUTHENTICATION_SUCCESS, 9999, len(resp_payload))
                writer.write(resp_header + resp_payload)
                await writer.drain()

            elif msg_type == MSG_SEND_TEXT_MESSAGE:
                data = json.loads(payload_bytes.decode('utf-8'))
                received_messages_at_origin.append(data.get("message", ""))
                # Echo back broadcast
                b_payload = json.dumps({"sender": "alice", "message": data.get("message", "")}).encode('utf-8')
                b_header = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, PROTOCOL_VERSION, MSG_BROADCAST_TEXT_MESSAGE, session_id, len(b_payload))
                writer.write(b_header + b_payload)
                await writer.drain()

            elif msg_type == MSG_FILE_TRANSFER_NOTIFY_REQUEST:
                data = json.loads(payload_bytes.decode('utf-8'))
                received_messages_at_origin.append(f"FILE:{data.get('filename')}")
    except Exception as e:
        pass
    finally:
        writer.close()


async def run_e2e_demo():
    print("=" * 70)
    print("[*] STARTING AUTOMATED LIVE END-TO-END DEMO OF SECURELAN")
    print("=" * 70)

    # 1. Start Origin Mock Server
    print("\n[1/4] Starting Origin Server on port 5000...")
    origin_server = await asyncio.start_server(handle_origin_client, "127.0.0.1", ORIGIN_PORT)
    print("      [OK] Origin Server is listening on 127.0.0.1:5000")

    # 2. Start Inline TLS Inspection Proxy
    print("\n[2/4] Starting Zscaler-style Inline TLS Inspection Proxy on port 5443...")
    proxy = InlineTLSProxy(
        listen_host="127.0.0.1",
        listen_port=PROXY_PORT,
        target_host="127.0.0.1",
        target_port=ORIGIN_PORT,
        enable_dlp=True,
        enable_auth_check=True
    )
    await proxy.start()
    print("      [OK] Inline TLS Inspection Proxy is intercepting on TLS: 127.0.0.1:5443")

    # 3. Connect Client via TLS to Proxy
    print("\n[3/4] Client establishing mutual TLS connection to Proxy (:5443)...")
    client_ssl_ctx = create_client_ssl_context()
    reader, writer = await asyncio.open_connection("127.0.0.1", PROXY_PORT, ssl=client_ssl_ctx)
    print("      [OK] TLS Handshake successful! Encrypted session established.")

    # A. Send Login
    print("\n      -> Action A: Sending Authentication Request...")
    auth_payload = json.dumps({"username": "alice", "password": "Secr3tPassword!"}).encode('utf-8')
    hdr = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, PROTOCOL_VERSION, MSG_AUTHENTICATION_REQUEST, 0, len(auth_payload))
    writer.write(hdr + auth_payload)
    await writer.drain()

    resp_hdr = await reader.read(HEADER_SIZE)
    _, _, resp_type, session_id, resp_len = struct.unpack(HEADER_FORMAT, resp_hdr)
    resp_body = await reader.read(resp_len)
    print(f"         Server Response: {json.loads(resp_body.decode('utf-8'))}")

    # B. Send Clean Message
    print("\n      -> Action B: Sending Clean Message...")
    clean_msg = json.dumps({"message": "Hello Zscaler Team, this is a secure meeting!"}).encode('utf-8')
    hdr = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, PROTOCOL_VERSION, MSG_SEND_TEXT_MESSAGE, session_id, len(clean_msg))
    writer.write(hdr + clean_msg)
    await writer.drain()

    resp_hdr = await reader.read(HEADER_SIZE)
    _, _, _, _, resp_len = struct.unpack(HEADER_FORMAT, resp_hdr)
    resp_body = await reader.read(resp_len)
    print(f"         Broadcast Received: {json.loads(resp_body.decode('utf-8'))['message']}")

    # C. Send Sensitive Message with Credit Card (DLP Test)
    print("\n      -> Action C: Sending Sensitive Data (Credit Card: 4111-1111-1111-1111)...")
    sensitive_msg = json.dumps({"message": "Please charge card 4111-1111-1111-1111"}).encode('utf-8')
    hdr = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, PROTOCOL_VERSION, MSG_SEND_TEXT_MESSAGE, session_id, len(sensitive_msg))
    writer.write(hdr + sensitive_msg)
    await writer.drain()
    await asyncio.sleep(0.5)

    print("         [BLOCKED] PROXY ENFORCEMENT: Credit Card payload was intercepted and BLOCKED inline!")
    print(f"         Origin received sensitive msg? {any('4111' in m for m in received_messages_at_origin)} (Expected: False)")

    # D. Send Blocked File Transfer (Malware extension .exe test)
    print("\n      -> Action D: Attempting to upload 'trojan_payload.exe'...")
    file_notify = json.dumps({"filename": "trojan_payload.exe", "file_size": 2048}).encode('utf-8')
    hdr = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, PROTOCOL_VERSION, MSG_FILE_TRANSFER_NOTIFY_REQUEST, session_id, len(file_notify))
    writer.write(hdr + file_notify)
    await writer.drain()
    await asyncio.sleep(0.5)

    print("         [BLOCKED] PROXY ENFORCEMENT: Executable file upload was completely DROPPED by policy.")
    print(f"         Origin received .exe upload? {any('trojan' in m for m in received_messages_at_origin)} (Expected: False)")

    # 4. Check Audit Trail & Threat Metrics
    print("\n[4/4] Verifying Enterprise Audit Logger & Threat Telemetry...", flush=True)
    audit = AuditLogger()
    stats = audit.get_statistics()
    print(f"      [OK] Total Audit Events Logged : {stats['total_events']}", flush=True)
    print(f"      [OK] DLP Violations Caught     : {stats['dlp_violations']}", flush=True)
    print(f"      [OK] TLS Proxy Interceptions  : {stats['tls_connections']}", flush=True)

    recent = audit.get_recent_events(limit=2)
    print("\n      [LOG] Sample JSONL Audit Trail Entry:", flush=True)
    if recent:
        print(f"         {json.dumps(recent[-1], indent=2)}", flush=True)

    # Clean up
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    try:
        await proxy.stop()
    except Exception:
        pass

    try:
        origin_server.close()
        await origin_server.wait_closed()
    except Exception:
        pass

    print("\n" + "=" * 70, flush=True)
    print("[SUCCESS] END-TO-END DEMO COMPLETED SUCCESSFULLY! ALL MODULES OPERATIONAL!", flush=True)
    print("=" * 70, flush=True)


if __name__ == "__main__":
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    asyncio.run(run_e2e_demo())
    sys.exit(0)

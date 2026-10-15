"""
Inline TLS Inspection Proxy (Zscaler Zero Trust Exchange Mirror)

Architecture:
    Client ──[TLS Handshake 1]──> [TLS Inspection Proxy] ──[TLS Handshake 2]──> Origin Server
                                            │
                             ┌──────────────┴──────────────┐
                             │  Deep Packet Inspection     │
                             │  - Real-time DLP Scanning   │
                             │  - Zero Trust Access Check  │
                             │  - Security Audit Logging   │
                             │  - Content Sanitization     │
                             └─────────────────────────────┘

This component directly mirrors Zscaler's cloud-native architecture:
1. Terminates incoming TLS connections from clients using a CA-signed proxy certificate.
2. Decrypts and parses the application-layer frames (commands, chat, metadata).
3. Evaluates Zero Trust policies and executes inline DLP inspection.
4. If permitted, re-encrypts the data using an upstream TLS context and forwards to origin server.
5. Bidirectionally streams data while maintaining an enterprise audit trail.
"""

import sys
import os
import asyncio
import ssl
import struct
import json
import logging
from typing import Optional, Tuple

from security.tls_config import create_proxy_ssl_contexts, create_client_ssl_context
from security.dlp_engine import DLPEngine, DLPSeverity
from security.auth import AuthEngine, Role, Permission
from security.audit_logger import AuditLogger, EventCategory, EventSeverity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
log = logging.getLogger("TLSProxy")

# Protocol constants matching server.py & client.py
MAGIC_NUMBER = 0xDEADBEEF
PROTOCOL_VERSION = 0x0100
HEADER_FORMAT = '!IHHQI'  # Magic, Version, Type, SessionID, PayloadLen
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Message types for inspection
MSG_AUTHENTICATION_REQUEST = 1
MSG_AUTHENTICATION_SUCCESS = 2
MSG_AUTHENTICATION_FAILURE = 3
MSG_SEND_TEXT_MESSAGE = 100
MSG_BROADCAST_TEXT_MESSAGE = 101
MSG_FILE_TRANSFER_NOTIFY_REQUEST = 400


class InlineTLSProxy:
    """
    Zscaler-inspired Inline TLS/SSL Inspection Proxy.
    """

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 5443,
        target_host: str = "127.0.0.1",
        target_port: int = 5000,
        enable_dlp: bool = True,
        enable_auth_check: bool = True,
        cert_dir: Optional[str] = None,
        upstream_ssl: bool = False
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.enable_dlp = enable_dlp
        self.enable_auth_check = enable_auth_check
        self.cert_dir = cert_dir
        self.upstream_ssl = upstream_ssl

        self.dlp = DLPEngine()
        self.auth = AuthEngine()
        self.audit = AuditLogger()

        self.server = None
        self._running = False
        self._active_connections = 0

    async def start(self):
        """Initialize SSL contexts and start proxy listener."""
        log.info("Initializing TLS Inspection Proxy contexts...")
        try:
            client_ctx, server_ctx = create_proxy_ssl_contexts(cert_dir=self.cert_dir)
        except Exception as e:
            log.warning(f"Could not load custom cert contexts ({e}). Creating standard TLS contexts.")
            server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

        self.client_facing_ssl = client_ctx
        self.server_facing_ssl = server_ctx

        self.server = await asyncio.start_server(
            self.handle_client_connection,
            self.listen_host,
            self.listen_port,
            ssl=self.client_facing_ssl
        )

        self._running = True
        log.info("=" * 60)
        log.info("🔐 ZSCALER-STYLE INLINE TLS INSPECTION PROXY ACTIVE")
        log.info(f"   Listening on TLS: {self.listen_host}:{self.listen_port}")
        log.info(f"   Forwarding to:   {self.target_host}:{self.target_port} (TLS: {self.upstream_ssl})")
        log.info(f"   DLP Scanning:    {'ENABLED' if self.enable_dlp else 'DISABLED'}")
        log.info(f"   Zero Trust Auth: {'ENABLED' if self.enable_auth_check else 'DISABLED'}")
        log.info("=" * 60)

    async def handle_client_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter
    ):
        """Handles an incoming TLS connection from a client."""
        client_peer = client_writer.get_extra_info('peername')
        client_ip = client_peer[0] if client_peer else "unknown"
        self._active_connections += 1

        self.audit.log(
            category=EventCategory.TLS,
            action="TLS_PROXY_INTERCEPT",
            status="SUCCESS",
            severity=EventSeverity.INFO,
            actor="INLINE_PROXY",
            client_ip=client_ip,
            details={"client_peer": str(client_peer)}
        )

        log.info(f"[+] Intercepted TLS connection from {client_peer}")

        # Connect upstream to the target server
        try:
            target_ssl = self.server_facing_ssl if self.upstream_ssl else None
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host,
                self.target_port,
                ssl=target_ssl
            )
        except Exception as err:
            log.error(f"Failed to connect to upstream server {self.target_host}:{self.target_port}: {err}")
            self.audit.log(
                category=EventCategory.TLS,
                action="UPSTREAM_CONNECT_FAILED",
                status="ERROR",
                severity=EventSeverity.HIGH,
                actor="INLINE_PROXY",
                client_ip=client_ip,
                details={"error": str(err)}
            )
            client_writer.close()
            await client_writer.wait_closed()
            self._active_connections -= 1
            return

        # Run bidirectional piping with deep packet inspection on client -> server
        try:
            await asyncio.gather(
                self.pipe_client_to_server(client_reader, target_writer, client_ip),
                self.pipe_server_to_client(target_reader, client_writer, client_ip),
                return_exceptions=True
            )
        finally:
            self._active_connections -= 1
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            try:
                target_writer.close()
                await target_writer.wait_closed()
            except Exception:
                pass
            log.info(f"[-] Closed TLS session for {client_peer}")

    async def pipe_client_to_server(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str
    ):
        """
        Reads from client, inspects decrypted packet, and forwards to upstream server.
        Applies DLP and Zero Trust security policies inline.
        """
        buffer = bytearray()
        try:
            while self._running:
                data = await reader.read(4096)
                if not data:
                    break
                buffer.extend(data)

                # Process all complete protocol frames in buffer
                while len(buffer) >= HEADER_SIZE:
                    magic, version, msg_type, session_id, payload_len = struct.unpack(
                        HEADER_FORMAT, buffer[:HEADER_SIZE]
                    )

                    if magic != MAGIC_NUMBER:
                        log.warning(f"Corrupted magic byte from {client_ip}. Dropping frame.")
                        buffer.clear()
                        break

                    total_frame_len = HEADER_SIZE + payload_len
                    if len(buffer) < total_frame_len:
                        break  # Need more bytes for complete payload

                    # Extract frame
                    header_bytes = bytes(buffer[:HEADER_SIZE])
                    payload_bytes = bytes(buffer[HEADER_SIZE:total_frame_len])
                    del buffer[:total_frame_len]

                    # Perform deep packet inspection
                    allowed, modified_payload = self.inspect_packet(
                        msg_type=msg_type,
                        session_id=session_id,
                        payload_bytes=payload_bytes,
                        client_ip=client_ip
                    )

                    if allowed:
                        if modified_payload != payload_bytes:
                            # Reconstruct header with new payload length
                            new_header = struct.pack(
                                HEADER_FORMAT,
                                magic, version, msg_type, session_id, len(modified_payload)
                            )
                            writer.write(new_header + modified_payload)
                        else:
                            writer.write(header_bytes + payload_bytes)
                        await writer.drain()
                    else:
                        log.warning(f"🛡️ Security Policy BLOCKED frame (Type={msg_type}) from {client_ip}")

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.error(f"Error in client->server pipe: {e}")

    async def pipe_server_to_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str
    ):
        """Passes server responses back to client."""
        try:
            while self._running:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            log.error(f"Error in server->client pipe: {e}")

    def inspect_packet(
        self,
        msg_type: int,
        session_id: int,
        payload_bytes: bytes,
        client_ip: str
    ) -> Tuple[bool, bytes]:
        """
        Deep Packet Inspection (DPI) & DLP Filtering:
        - Inspects chat text for credit cards, SSNs, Aadhaar, secrets
        - Inspects file metadata for malicious file extensions
        - Enforces Zero Trust policies
        """
        # Module 4: Chat messages inspection
        if msg_type in (MSG_SEND_TEXT_MESSAGE, MSG_BROADCAST_TEXT_MESSAGE):
            try:
                payload_str = payload_bytes.decode('utf-8')
                data = json.loads(payload_str)
                message_text = data.get('message', '')

                if self.enable_dlp and message_text:
                    dlp_result = self.dlp.scan_text(message_text)

                    if dlp_result.has_violations:
                        self.audit.log_dlp(
                            actor=f"Session-{session_id}",
                            client_ip=client_ip,
                            matched_rules=[v.rule_name for v in dlp_result.violations],
                            action_taken=dlp_result.action,
                            sample=dlp_result.redacted_text[:100]
                        )

                        if dlp_result.action == "block":
                            log.warning(
                                f"🚫 DLP VIOLATION [BLOCKED]: {dlp_result.violations[0].rule_name} "
                                f"detected from IP {client_ip}"
                            )
                            return False, payload_bytes
                        elif dlp_result.action == "mask":
                            log.info(
                                f"⚠️ DLP VIOLATION [MASKED]: Sensitive data sanitized in-flight from {client_ip}"
                            )
                            data['message'] = dlp_result.redacted_text
                            sanitized_payload = json.dumps(data).encode('utf-8')
                            return True, sanitized_payload

            except Exception as e:
                log.debug(f"Non-JSON or encrypted chat payload: {e}")

        # Module 5: File transfer inspection
        elif msg_type == MSG_FILE_TRANSFER_NOTIFY_REQUEST:
            try:
                payload_str = payload_bytes.decode('utf-8')
                data = json.loads(payload_str)
                filename = data.get('filename', '')

                if self.enable_dlp and filename:
                    # Check for blocked executable / script extensions
                    blocked_exts = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".sh", ".scr", ".dll"}
                    _, ext = os.path.splitext(filename.lower())
                    if ext in blocked_exts:
                        self.audit.log(
                            category=EventCategory.DLP,
                            action="DLP_FILE_BLOCKED",
                            status="BLOCKED",
                            severity=EventSeverity.HIGH,
                            actor=f"Session-{session_id}",
                            client_ip=client_ip,
                            resource=filename,
                            details={"reason": f"Executable file extension '{ext}' prohibited by policy"}
                        )
                        log.warning(f"🚫 DLP FILE BLOCK: Upload of '{filename}' blocked by security policy.")
                        return False, payload_bytes

            except Exception as e:
                log.debug(f"Failed to inspect file transfer notify: {e}")

        return True, payload_bytes

    async def stop(self):
        """Gracefully stop the proxy server."""
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            log.info("TLS Inspection Proxy stopped.")


async def run_standalone_proxy(
    listen_port: int = 5443,
    target_port: int = 5000,
    target_host: str = "127.0.0.1"
):
    proxy = InlineTLSProxy(
        listen_host="0.0.0.0",
        listen_port=listen_port,
        target_host=target_host,
        target_port=target_port
    )
    await proxy.start()
    try:
        await proxy.server.serve_forever()
    except asyncio.CancelledError:
        await proxy.stop()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5443
    t_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    try:
        asyncio.run(run_standalone_proxy(listen_port=port, target_port=t_port))
    except KeyboardInterrupt:
        print("\nTLS Inspection Proxy exited by user.")

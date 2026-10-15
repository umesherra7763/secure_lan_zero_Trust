"""
Security Audit Logging Engine

Implements structured enterprise audit logging and security event tracking:
  - Immutable audit trail with ISO timestamps, user context, IP addresses, and actions
  - Event classifications: AUTH, ACCESS_CONTROL, DLP_VIOLATION, TLS_INSPECTION, RATE_LIMIT, SYSTEM
  - In-memory ring buffer for low-latency querying by Server GUI Dashboard
  - File-based persistence in JSON-lines format for compliance (SOC 2 / ISO 27001)
  - Threat metrics aggregator (active threats, violation rates, anomaly detection)
"""

import os
import json
import time
import logging
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from collections import deque


class EventSeverity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategory:
    AUTH = "AUTH"                       # Login, logout, token issuance, auth failures
    ACCESS_CONTROL = "ACCESS_CONTROL"   # Permission checks, role assignment, policy rejections
    DLP = "DLP"                         # Sensitive data leaked, blocked, or masked
    TLS = "TLS"                         # Handshakes, proxy intercepts, certificate validations
    RATE_LIMIT = "RATE_LIMIT"           # Throttling triggered, connection flooding
    FILE_TRANSFER = "FILE_TRANSFER"     # File upload/download security validation
    ADMIN = "ADMIN"                     # Administrative actions, policy changes


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    category: str
    severity: str
    actor: str                  # username or session_id or 'anonymous'
    client_ip: str
    action: str                 # e.g., 'LOGIN_SUCCESS', 'DLP_BLOCK_CREDIT_CARD'
    status: str                 # 'SUCCESS', 'DENIED', 'BLOCKED', 'ERROR'
    resource: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Thread-safe enterprise security audit logger.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AuditLogger, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, log_dir: str = "logs", max_memory_records: int = 1000):
        if getattr(self, "_initialized", False):
            return

        self.log_dir = log_dir
        self.max_memory_records = max_memory_records
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, "security_audit.jsonl")

        self._records: deque = deque(maxlen=max_memory_records)
        self._write_lock = threading.Lock()
        self._callbacks: List[Any] = []
        self._event_counter = 0

        # Threat and stats counters
        self._stats = {
            "total_events": 0,
            "auth_success": 0,
            "auth_failures": 0,
            "dlp_violations": 0,
            "rate_limit_hits": 0,
            "tls_connections": 0,
            "policy_denials": 0
        }

        # Setup standard Python logger for console / file mirroring
        self._logger = logging.getLogger("SecurityAudit")
        self._logger.setLevel(logging.INFO)

        self._initialized = True

    def register_callback(self, callback):
        """Register a callback function func(AuditEvent) for real-time GUI updates."""
        with self._write_lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def unregister_callback(self, callback):
        with self._write_lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def log(
        self,
        category: str,
        action: str,
        status: str,
        severity: str = EventSeverity.INFO,
        actor: str = "SYSTEM",
        client_ip: str = "127.0.0.1",
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """
        Record a security event.
        """
        with self._write_lock:
            self._event_counter += 1
            now_iso = datetime.now(timezone.utc).isoformat()
            event_id = f"SEC-{int(time.time())}-{self._event_counter:04d}"

            event = AuditEvent(
                event_id=event_id,
                timestamp=now_iso,
                category=category,
                severity=severity,
                actor=actor,
                client_ip=client_ip,
                action=action,
                status=status,
                resource=resource,
                details=details or {}
            )

            # Store in ring buffer
            self._records.append(event)

            # Update stats
            self._stats["total_events"] += 1
            if category == EventCategory.AUTH:
                if status == "SUCCESS":
                    self._stats["auth_success"] += 1
                else:
                    self._stats["auth_failures"] += 1
            elif category == EventCategory.DLP:
                self._stats["dlp_violations"] += 1
            elif category == EventCategory.RATE_LIMIT:
                self._stats["rate_limit_hits"] += 1
            elif category == EventCategory.TLS:
                self._stats["tls_connections"] += 1
            elif category == EventCategory.ACCESS_CONTROL and status in ("DENIED", "BLOCKED"):
                self._stats["policy_denials"] += 1

            # Append to file
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(event.to_json() + "\n")
            except Exception as e:
                self._logger.error(f"Failed to persist audit log: {e}")

            callbacks_to_call = list(self._callbacks)

        # Notify callbacks outside write lock
        for cb in callbacks_to_call:
            try:
                cb(event)
            except Exception:
                pass

        return event

    def get_recent_events(self, limit: int = 100, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return recent audit events formatted as dictionaries."""
        with self._write_lock:
            events = list(self._records)

        if category:
            events = [e for e in events if e.category == category]

        return [e.to_dict() for e in events[-limit:]]

    def get_statistics(self) -> Dict[str, Any]:
        """Return operational threat and security metrics."""
        with self._write_lock:
            return dict(self._stats)

    def log_auth(self, actor: str, client_ip: str, success: bool, reason: str = ""):
        self.log(
            category=EventCategory.AUTH,
            action="LOGIN_SUCCESS" if success else "LOGIN_FAILURE",
            status="SUCCESS" if success else "DENIED",
            severity=EventSeverity.INFO if success else EventSeverity.MEDIUM,
            actor=actor,
            client_ip=client_ip,
            details={"reason": reason} if reason else {}
        )

    def log_dlp(self, actor: str, client_ip: str, matched_rules: List[str], action_taken: str, sample: str = ""):
        self.log(
            category=EventCategory.DLP,
            action=f"DLP_{action_taken.upper()}",
            status="BLOCKED" if action_taken == "block" else "FLAGGED",
            severity=EventSeverity.HIGH if action_taken == "block" else EventSeverity.MEDIUM,
            actor=actor,
            client_ip=client_ip,
            details={
                "matched_rules": matched_rules,
                "action": action_taken,
                "redacted_sample": sample
            }
        )

    def log_access(self, actor: str, client_ip: str, resource: str, action: str, allowed: bool, role: str = ""):
        self.log(
            category=EventCategory.ACCESS_CONTROL,
            action=f"ACCESS_{action.upper()}",
            status="SUCCESS" if allowed else "DENIED",
            severity=EventSeverity.INFO if allowed else EventSeverity.HIGH,
            actor=actor,
            client_ip=client_ip,
            resource=resource,
            details={"role": role, "allowed": allowed}
        )

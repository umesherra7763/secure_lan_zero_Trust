"""
Security Module for LAN Communication Suite

This package implements enterprise-grade security controls inspired by
Zscaler's Zero Trust Exchange architecture:

- TLS/mTLS Encryption (cert_generator, tls_config)
- Zero Trust Access Control with JWT + RBAC (auth)
- Data Loss Prevention Engine (dlp_engine)
- Security Audit Logging (audit_logger)

Architecture:
    Client ──[TLS]──> TLS Inspection Proxy ──[TLS]──> Server
                           │
                      DLP Scanning
                      Audit Logging
                      Policy Enforcement
"""

from security.auth import AuthEngine, Role, Permission
from security.dlp_engine import DLPEngine, DLPSeverity
from security.audit_logger import AuditLogger, AuditEvent
from security.tls_config import create_server_ssl_context, create_client_ssl_context
from security.tls_proxy import InlineTLSProxy

__all__ = [
    'AuthEngine', 'Role', 'Permission',
    'DLPEngine', 'DLPSeverity',
    'AuditLogger', 'AuditEvent',
    'create_server_ssl_context', 'create_client_ssl_context',
    'InlineTLSProxy',
]

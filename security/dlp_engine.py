"""
Data Loss Prevention (DLP) Engine

Real-time content inspection for sensitive data detection, mirroring
Zscaler's inline DLP capabilities that scan traffic for:
  - Credit card numbers (Luhn-validated)
  - Social Security Numbers (SSN)
  - Email addresses
  - Phone numbers (Indian + US formats)
  - API keys and tokens
  - Custom patterns (configurable)

The engine also performs file-level inspection:
  - File type detection via magic bytes (prevent extension spoofing)
  - Executable file blocking
  - File size policy enforcement

Architecture:
  All data flowing through the proxy or server is passed through the
  DLP engine AFTER TLS termination (plaintext inspection), exactly
  like Zscaler's inline DLP pipeline.

Usage:
    engine = DLPEngine()
    results = engine.scan_text("My card is 4111-1111-1111-1111")
    if results:
        for finding in results:
            print(f"[{finding.severity}] {finding.pattern_name}: {finding.matched_text}")
"""

import re
import os
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


class DLPSeverity(Enum):
    """Severity levels for DLP findings, aligned with industry standards."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DLPAction(Enum):
    """Actions the engine can recommend based on findings."""
    ALLOW = "ALLOW"           # No issues found
    LOG = "LOG"               # Allow but log the finding
    WARN = "WARN"             # Allow but warn the user
    BLOCK = "BLOCK"           # Block the content
    QUARANTINE = "QUARANTINE" # Hold for admin review


@dataclass
class DLPFinding:
    """Represents a single DLP detection result."""
    pattern_name: str         # e.g., "Credit Card Number"
    severity: DLPSeverity     # Severity level
    action: DLPAction         # Recommended action
    matched_text: str         # The text that matched (partially redacted)
    context: str              # Surrounding text for context
    description: str          # Human-readable description
    category: str             # Category (PII, Financial, Credential, etc.)

    @property
    def rule_name(self) -> str:
        return self.pattern_name


@dataclass
class DLPScanResult:
    """Complete scan result for a piece of content."""
    content_type: str         # "text", "file", "url"
    findings: list            # List of DLPFinding
    scan_time_ms: float       # Time taken to scan (milliseconds)
    overall_action: DLPAction # Most restrictive action from all findings
    is_clean: bool            # True if no findings
    sanitized_text: str = ""  # Text with matches replaced by redactions

    @property
    def has_violations(self) -> bool:
        return not self.is_clean

    @property
    def violations(self) -> list:
        return self.findings

    @property
    def action(self) -> str:
        if self.overall_action in (DLPAction.BLOCK, DLPAction.QUARANTINE):
            return "block"
        elif self.overall_action in (DLPAction.WARN, DLPAction.LOG):
            return "mask"
        return "allow"

    @property
    def redacted_text(self) -> str:
        return self.sanitized_text if self.sanitized_text else self.summary

    @property
    def summary(self) -> str:
        if self.is_clean:
            return "CLEAN — No sensitive data detected"
        counts = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        parts = [f"{v}x {k}" for k, v in counts.items()]
        return f"DETECTED — {', '.join(parts)} | Action: {self.overall_action.value}"


# --- DLP Pattern Definitions ---

class DLPPattern:
    """Defines a single DLP detection pattern."""
    def __init__(
        self,
        name: str,
        regex: str,
        severity: DLPSeverity,
        action: DLPAction,
        category: str,
        description: str,
        validator=None,
    ):
        self.name = name
        self.regex = re.compile(regex, re.IGNORECASE)
        self.severity = severity
        self.action = action
        self.category = category
        self.description = description
        self.validator = validator  # Optional validation function


def _luhn_check(number_str: str) -> bool:
    """Luhn algorithm to validate credit card numbers."""
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# --- Built-in Pattern Library ---
BUILTIN_PATTERNS = [
    # Financial
    DLPPattern(
        name="Credit Card Number",
        regex=r'\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|'   # Visa
              r'5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|'    # MC
              r'3[47][0-9]{1}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{3}|'     # Amex
              r'6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})' # Discover
              r'\b',
        severity=DLPSeverity.CRITICAL,
        action=DLPAction.BLOCK,
        category="Financial",
        description="Credit/debit card number detected (PCI-DSS violation risk)",
        validator=lambda m: _luhn_check(re.sub(r'[-\s]', '', m)),
    ),

    # PII — Indian
    DLPPattern(
        name="Aadhaar Number",
        regex=r'\b[2-9][0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b',
        severity=DLPSeverity.HIGH,
        action=DLPAction.BLOCK,
        category="PII",
        description="Indian Aadhaar number detected (12-digit identity number)",
    ),
    DLPPattern(
        name="PAN Card Number",
        regex=r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        severity=DLPSeverity.HIGH,
        action=DLPAction.BLOCK,
        category="PII",
        description="Indian PAN card number detected",
    ),

    # PII — US
    DLPPattern(
        name="US Social Security Number",
        regex=r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
        severity=DLPSeverity.CRITICAL,
        action=DLPAction.BLOCK,
        category="PII",
        description="US Social Security Number (SSN) detected",
    ),

    # Contact Information
    DLPPattern(
        name="Email Address",
        regex=r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        severity=DLPSeverity.LOW,
        action=DLPAction.LOG,
        category="Contact",
        description="Email address detected",
    ),
    DLPPattern(
        name="Phone Number (Indian)",
        regex=r'\b(?:\+91[-\s]?)?[6-9]\d{4}[-\s]?\d{5}\b',
        severity=DLPSeverity.MEDIUM,
        action=DLPAction.WARN,
        category="Contact",
        description="Indian phone number detected",
    ),

    # Credentials & Secrets
    DLPPattern(
        name="API Key / Token",
        regex=r'\b(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key|auth[_-]?token)'
              r'\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?\b',
        severity=DLPSeverity.CRITICAL,
        action=DLPAction.BLOCK,
        category="Credential",
        description="API key or authentication token detected",
    ),
    DLPPattern(
        name="Password in Plaintext",
        regex=r'\b(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{4,}["\']?\b',
        severity=DLPSeverity.HIGH,
        action=DLPAction.BLOCK,
        category="Credential",
        description="Plaintext password detected in message",
    ),
    DLPPattern(
        name="Private Key Material",
        regex=r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        severity=DLPSeverity.CRITICAL,
        action=DLPAction.BLOCK,
        category="Credential",
        description="Private key material detected — critical security risk",
    ),
]


# --- File Type Detection (Magic Bytes) ---
# Prevents extension spoofing (e.g., malware.exe renamed to document.pdf)
FILE_SIGNATURES = {
    b'\x4D\x5A':                          ('EXE/DLL', 'Executable'),
    b'\x7F\x45\x4C\x46':                  ('ELF', 'Executable'),
    b'\x50\x4B\x03\x04':                  ('ZIP/DOCX/XLSX', 'Archive'),
    b'\x25\x50\x44\x46':                  ('PDF', 'Document'),
    b'\xFF\xD8\xFF':                       ('JPEG', 'Image'),
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('PNG', 'Image'),
    b'\x47\x49\x46\x38':                  ('GIF', 'Image'),
    b'\xD0\xCF\x11\xE0':                  ('DOC/XLS/PPT', 'Office Legacy'),
    b'\x52\x61\x72\x21':                  ('RAR', 'Archive'),
}

# File types that should be BLOCKED by default
BLOCKED_FILE_TYPES = {'EXE/DLL', 'ELF'}

# Maximum file size (50 MB)
MAX_FILE_SIZE = 50 * 1024 * 1024


class DLPEngine:
    """
    Data Loss Prevention Engine for inline content inspection.

    Scans text content and files for sensitive data patterns,
    credential leaks, and policy violations.
    """

    def __init__(self, custom_patterns: list = None, enable_file_scanning: bool = True):
        self.patterns = list(BUILTIN_PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        self.enable_file_scanning = enable_file_scanning
        self.scan_count = 0
        self.finding_count = 0

        log.info(f"DLP Engine initialized with {len(self.patterns)} patterns")

    def _redact(self, text: str, show_chars: int = 4) -> str:
        """Partially redact sensitive text for logging (show first/last N chars)."""
        if len(text) <= show_chars * 2:
            return '*' * len(text)
        return text[:show_chars] + '*' * (len(text) - show_chars * 2) + text[-show_chars:]

    def _get_context(self, text: str, match: re.Match, context_chars: int = 30) -> str:
        """Extract surrounding context for a match."""
        start = max(0, match.start() - context_chars)
        end = min(len(text), match.end() + context_chars)
        context = text[start:end]
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."
        return context

    def scan_text(self, text: str, content_type: str = "text") -> DLPScanResult:
        """
        Scan text content for sensitive data patterns.

        Args:
            text: The text content to scan
            content_type: Type of content ("text", "chat", "filename")

        Returns:
            DLPScanResult with all findings
        """
        import time
        start_time = time.time()

        findings = []
        sanitized_text = text

        for pattern in self.patterns:
            for match in pattern.regex.finditer(text):
                matched_text = match.group()

                # Run optional validator (e.g., Luhn check for credit cards)
                if pattern.validator and not pattern.validator(matched_text):
                    continue

                redacted = self._redact(matched_text)
                sanitized_text = sanitized_text.replace(matched_text, redacted)

                finding = DLPFinding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    action=pattern.action,
                    matched_text=redacted,
                    context=self._redact(self._get_context(text, match)),
                    description=pattern.description,
                    category=pattern.category,
                )
                findings.append(finding)

        scan_time = (time.time() - start_time) * 1000  # Convert to ms
        self.scan_count += 1
        self.finding_count += len(findings)

        # Determine the most restrictive action
        if not findings:
            overall_action = DLPAction.ALLOW
        else:
            action_priority = {
                DLPAction.ALLOW: 0,
                DLPAction.LOG: 1,
                DLPAction.WARN: 2,
                DLPAction.BLOCK: 3,
                DLPAction.QUARANTINE: 4,
            }
            overall_action = max(
                (f.action for f in findings),
                key=lambda a: action_priority[a],
            )

        result = DLPScanResult(
            content_type=content_type,
            findings=findings,
            scan_time_ms=round(scan_time, 2),
            overall_action=overall_action,
            is_clean=len(findings) == 0,
            sanitized_text=sanitized_text,
        )

        if not result.is_clean:
            log.warning(f"DLP ALERT: {result.summary}")

        return result

    def scan_file_metadata(
        self,
        filename: str,
        file_size: int,
        file_header: bytes = None,
    ) -> DLPScanResult:
        """
        Scan file metadata and magic bytes for policy violations.

        Args:
            filename: The name of the file
            file_size: Size of the file in bytes
            file_header: First 16+ bytes of the file for magic byte detection

        Returns:
            DLPScanResult with file-level findings
        """
        import time
        start_time = time.time()
        findings = []

        # 1. Check file size
        if file_size > MAX_FILE_SIZE:
            findings.append(DLPFinding(
                pattern_name="Oversized File",
                severity=DLPSeverity.MEDIUM,
                action=DLPAction.BLOCK,
                matched_text=f"{file_size / (1024*1024):.1f} MB",
                context=f"File '{filename}' exceeds {MAX_FILE_SIZE / (1024*1024):.0f} MB limit",
                description=f"File exceeds maximum allowed size",
                category="Policy",
            ))

        # 2. Check filename for suspicious patterns
        filename_result = self.scan_text(filename, content_type="filename")
        findings.extend(filename_result.findings)

        # 3. Check file extension
        _, ext = os.path.splitext(filename.lower())
        dangerous_extensions = {'.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
                                '.vbs', '.js', '.wsh', '.ps1', '.sh'}
        if ext in dangerous_extensions:
            findings.append(DLPFinding(
                pattern_name="Dangerous File Extension",
                severity=DLPSeverity.HIGH,
                action=DLPAction.BLOCK,
                matched_text=ext,
                context=f"File '{filename}' has a potentially dangerous extension",
                description=f"Executable file type '{ext}' blocked by policy",
                category="Malware Prevention",
            ))

        # 4. Magic byte analysis (detect extension spoofing)
        if file_header and self.enable_file_scanning:
            detected_type = None
            for magic, (file_type, category) in FILE_SIGNATURES.items():
                if file_header.startswith(magic):
                    detected_type = file_type
                    break

            if detected_type:
                # Check if detected type matches the extension
                if detected_type in BLOCKED_FILE_TYPES:
                    findings.append(DLPFinding(
                        pattern_name="Blocked File Type (Magic Bytes)",
                        severity=DLPSeverity.CRITICAL,
                        action=DLPAction.BLOCK,
                        matched_text=detected_type,
                        context=f"File '{filename}' detected as {detected_type} via magic bytes",
                        description=f"Executable binary detected — blocked regardless of extension",
                        category="Malware Prevention",
                    ))

                # Check for extension spoofing
                extension_type_map = {
                    '.pdf': 'PDF', '.jpg': 'JPEG', '.jpeg': 'JPEG',
                    '.png': 'PNG', '.gif': 'GIF', '.zip': 'ZIP/DOCX/XLSX',
                    '.docx': 'ZIP/DOCX/XLSX', '.xlsx': 'ZIP/DOCX/XLSX',
                    '.doc': 'DOC/XLS/PPT', '.xls': 'DOC/XLS/PPT',
                    '.exe': 'EXE/DLL', '.dll': 'EXE/DLL', '.rar': 'RAR',
                }
                expected_type = extension_type_map.get(ext)
                if expected_type and expected_type != detected_type:
                    findings.append(DLPFinding(
                        pattern_name="Extension Spoofing Detected",
                        severity=DLPSeverity.CRITICAL,
                        action=DLPAction.BLOCK,
                        matched_text=f"Extension: {ext} → Actual: {detected_type}",
                        context=f"File '{filename}' claims to be {ext} but is actually {detected_type}",
                        description="File extension does not match file content — possible malware disguise",
                        category="Malware Prevention",
                    ))

        scan_time = (time.time() - start_time) * 1000
        self.scan_count += 1
        self.finding_count += len(findings)

        if not findings:
            overall_action = DLPAction.ALLOW
        else:
            action_priority = {
                DLPAction.ALLOW: 0, DLPAction.LOG: 1, DLPAction.WARN: 2,
                DLPAction.BLOCK: 3, DLPAction.QUARANTINE: 4,
            }
            overall_action = max(
                (f.action for f in findings),
                key=lambda a: action_priority[a],
            )

        result = DLPScanResult(
            content_type="file",
            findings=findings,
            scan_time_ms=round(scan_time, 2),
            overall_action=overall_action,
            is_clean=len(findings) == 0,
        )

        if not result.is_clean:
            log.warning(f"DLP FILE ALERT [{filename}]: {result.summary}")

        return result

    def get_stats(self) -> dict:
        """Return DLP engine statistics."""
        return {
            'total_scans': self.scan_count,
            'total_findings': self.finding_count,
            'pattern_count': len(self.patterns),
            'file_scanning_enabled': self.enable_file_scanning,
        }

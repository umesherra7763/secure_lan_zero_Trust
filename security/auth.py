"""
Zero Trust Authentication Engine with JWT + RBAC

Implements the "Never Trust, Always Verify" principle:
  - JWT (JSON Web Token) based stateless authentication
  - Role-Based Access Control (RBAC) with granular permissions
  - Per-request token validation (no implicit trust)
  - Session management with token expiry and revocation
  - Device context awareness for trust scoring

This mirrors Zscaler's Zero Trust approach where:
  1. Every request is authenticated (identity verification)
  2. Access is context-aware (device posture, location, role)
  3. Least-privilege access is enforced per-action
  4. Sessions are continuously validated (not just at login)

Roles:
  - ADMIN:     Full control — manage users, view audit logs, configure policies
  - PRESENTER: Can share screen, all MEMBER permissions
  - MEMBER:    Chat, file transfer, audio/video — default role

Usage:
    engine = AuthEngine(secret_key="your-secret")
    token = engine.authenticate("alice", "password123")
    user = engine.validate_token(token)
    engine.check_permission(user, Permission.SCREEN_SHARE)
"""

import time
import hashlib
import hmac
import logging
import platform
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional

import jwt  # PyJWT

log = logging.getLogger(__name__)

# --- Token Configuration ---
TOKEN_EXPIRY_SECONDS = 3600      # 1 hour
TOKEN_REFRESH_WINDOW = 300       # Allow refresh within last 5 minutes
TOKEN_ALGORITHM = "HS256"
MAX_FAILED_ATTEMPTS = 5          # Lock account after 5 failed attempts
LOCKOUT_DURATION = 300           # 5 minute lockout


class Role(Enum):
    """User roles with ascending privilege levels."""
    MEMBER = "member"
    PRESENTER = "presenter"
    ADMIN = "admin"


class Permission(Enum):
    """Granular permissions for Zero Trust per-action enforcement."""
    # Chat
    SEND_MESSAGE = auto()
    # File
    UPLOAD_FILE = auto()
    DOWNLOAD_FILE = auto()
    # Screen
    SCREEN_SHARE = auto()
    VIEW_SCREEN = auto()
    # Media
    AUDIO = auto()
    VIDEO = auto()
    # Admin
    KICK_USER = auto()
    VIEW_AUDIT_LOG = auto()
    MANAGE_POLICIES = auto()


# --- RBAC Policy Matrix ---
# Maps each role to the set of permissions it grants
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.MEMBER: {
        Permission.SEND_MESSAGE,
        Permission.UPLOAD_FILE,
        Permission.DOWNLOAD_FILE,
        Permission.VIEW_SCREEN,
        Permission.AUDIO,
        Permission.VIDEO,
    },
    Role.PRESENTER: {
        Permission.SEND_MESSAGE,
        Permission.UPLOAD_FILE,
        Permission.DOWNLOAD_FILE,
        Permission.SCREEN_SHARE,
        Permission.VIEW_SCREEN,
        Permission.AUDIO,
        Permission.VIDEO,
    },
    Role.ADMIN: {
        Permission.SEND_MESSAGE,
        Permission.UPLOAD_FILE,
        Permission.DOWNLOAD_FILE,
        Permission.SCREEN_SHARE,
        Permission.VIEW_SCREEN,
        Permission.AUDIO,
        Permission.VIDEO,
        Permission.KICK_USER,
        Permission.VIEW_AUDIT_LOG,
        Permission.MANAGE_POLICIES,
    },
}


@dataclass
class DeviceContext:
    """
    Device context information for trust scoring.
    In Zscaler, this would include posture checks, EDR status, etc.
    """
    os_name: str = ""
    os_version: str = ""
    hostname: str = ""
    ip_address: str = ""
    trust_score: float = 0.0     # 0.0 (untrusted) to 1.0 (fully trusted)

    def compute_trust_score(self) -> float:
        """
        Compute a simplified trust score based on device context.
        In production (Zscaler), this would check EDR status, patch level,
        disk encryption, etc.
        """
        score = 0.5  # Base score

        # Known OS gets a boost
        if self.os_name in ("Windows", "Linux", "Darwin"):
            score += 0.2

        # Having a hostname indicates a managed device
        if self.hostname:
            score += 0.1

        # Known internal IP range gets a boost
        if self.ip_address.startswith(("192.168.", "10.", "172.16.")):
            score += 0.2

        self.trust_score = min(score, 1.0)
        return self.trust_score


@dataclass
class AuthenticatedUser:
    """Represents a validated, authenticated user session."""
    username: str
    role: Role
    session_id: int
    token: str
    issued_at: float
    expires_at: float
    device_context: DeviceContext = field(default_factory=DeviceContext)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def permissions(self) -> set[Permission]:
        return ROLE_PERMISSIONS.get(self.role, set())

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions


class AuthEngine:
    """
    Zero Trust Authentication Engine.

    Handles:
      - Password-based authentication with salted hashing
      - JWT token generation and validation
      - RBAC permission checks
      - Brute-force protection (failed attempt lockout)
      - Device context trust scoring
    """

    def __init__(self, secret_key: str = "secureLAN-jwt-secret-key-change-in-prod"):
        self._secret_key = secret_key
        self._users_db: dict[str, dict] = {}    # {username: {password_hash, salt, role}}
        self._failed_attempts: dict[str, list] = {}  # {username: [timestamps]}
        self._revoked_tokens: set[str] = set()  # Blacklisted token IDs
        self._active_sessions: dict[str, AuthenticatedUser] = {}  # {username: user}

        # Pre-populate with default users for demo/testing
        self._setup_default_users()

    def _setup_default_users(self):
        """Create default users with different roles for demonstration."""
        self.register_user("admin", "admin123", Role.ADMIN)
        self.register_user("presenter", "present123", Role.PRESENTER)
        # Any other username gets MEMBER role by default

    def _hash_password(self, password: str, salt: str = None) -> tuple[str, str]:
        """
        Hash a password with a salt using SHA-256.
        Returns (hash, salt).
        """
        if salt is None:
            salt = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        salted = f"{salt}{password}".encode('utf-8')
        password_hash = hashlib.sha256(salted).hexdigest()
        return password_hash, salt

    def register_user(self, username: str, password: str, role: Role = Role.MEMBER):
        """Register a new user in the authentication database."""
        password_hash, salt = self._hash_password(password)
        self._users_db[username.lower()] = {
            'password_hash': password_hash,
            'salt': salt,
            'role': role,
        }
        log.debug(f"Registered user '{username}' with role {role.value}")

    def _is_locked_out(self, username: str) -> bool:
        """Check if a user is locked out due to too many failed attempts."""
        key = username.lower()
        if key not in self._failed_attempts:
            return False

        # Clean up old attempts
        now = time.time()
        self._failed_attempts[key] = [
            ts for ts in self._failed_attempts[key]
            if now - ts < LOCKOUT_DURATION
        ]

        return len(self._failed_attempts[key]) >= MAX_FAILED_ATTEMPTS

    def _record_failed_attempt(self, username: str):
        """Record a failed login attempt for brute-force protection."""
        key = username.lower()
        if key not in self._failed_attempts:
            self._failed_attempts[key] = []
        self._failed_attempts[key].append(time.time())

        remaining = MAX_FAILED_ATTEMPTS - len(self._failed_attempts[key])
        if remaining > 0:
            log.warning(f"Failed login for '{username}'. {remaining} attempts remaining.")
        else:
            log.warning(f"Account '{username}' LOCKED OUT for {LOCKOUT_DURATION}s")

    def authenticate(
        self,
        username: str,
        password: str,
        session_id: int = 0,
        device_info: dict = None,
    ) -> Optional[str]:
        """
        Authenticate a user and return a JWT token.

        This enforces the Zero Trust "verify identity" step.

        Args:
            username: The username to authenticate
            password: The plaintext password
            session_id: The server-assigned session ID
            device_info: Optional device context (os, hostname, ip)

        Returns:
            JWT token string on success, None on failure
        """
        key = username.lower()

        # 1. Check lockout (brute-force protection)
        if self._is_locked_out(key):
            log.warning(f"Authentication BLOCKED — '{username}' is locked out")
            return None

        # 2. Check if user exists in DB
        if key in self._users_db:
            user_record = self._users_db[key]
            password_hash, _ = self._hash_password(password, user_record['salt'])

            if not hmac.compare_digest(password_hash, user_record['password_hash']):
                self._record_failed_attempt(key)
                return None

            role = user_record['role']
        else:
            # Dynamic registration for unknown users (MEMBER role)
            # In production, this would be an IdP/SSO integration
            self.register_user(username, password, Role.MEMBER)
            role = Role.MEMBER
            log.info(f"New user '{username}' dynamically registered as MEMBER")

        # 3. Build device context
        device_ctx = DeviceContext()
        if device_info:
            device_ctx.os_name = device_info.get('os_name', '')
            device_ctx.os_version = device_info.get('os_version', '')
            device_ctx.hostname = device_info.get('hostname', '')
            device_ctx.ip_address = device_info.get('ip_address', '')
            device_ctx.compute_trust_score()

        # 4. Generate JWT token
        now = time.time()
        token_payload = {
            'sub': username,               # Subject (username)
            'role': role.value,            # Role for RBAC
            'sid': session_id,             # Session ID
            'iat': now,                    # Issued At
            'exp': now + TOKEN_EXPIRY_SECONDS,  # Expiry
            'trust': device_ctx.trust_score,    # Device trust score
            'iss': 'SecureLAN-ZeroTrust',       # Issuer
        }

        token = jwt.encode(token_payload, self._secret_key, algorithm=TOKEN_ALGORITHM)

        # 5. Store active session
        auth_user = AuthenticatedUser(
            username=username,
            role=role,
            session_id=session_id,
            token=token,
            issued_at=now,
            expires_at=now + TOKEN_EXPIRY_SECONDS,
            device_context=device_ctx,
        )
        self._active_sessions[key] = auth_user

        # 6. Clear any failed attempts on success
        if key in self._failed_attempts:
            del self._failed_attempts[key]

        log.info(
            f"Authentication SUCCESS: '{username}' | role={role.value} | "
            f"trust_score={device_ctx.trust_score:.1f} | "
            f"expires_in={TOKEN_EXPIRY_SECONDS}s"
        )

        return token

    def validate_token(self, token: str) -> Optional[AuthenticatedUser]:
        """
        Validate a JWT token and return the authenticated user.

        This is the Zero Trust "verify on every request" step.

        Returns:
            AuthenticatedUser on success, None on invalid/expired token
        """
        # 1. Check revocation blacklist
        if token in self._revoked_tokens:
            log.warning("Token validation FAILED — token has been revoked")
            return None

        try:
            # 2. Decode and verify the JWT
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[TOKEN_ALGORITHM],
                options={"require": ["sub", "role", "sid", "exp"]},
            )

            username = payload['sub']
            key = username.lower()

            # 3. Check if session is still active
            if key in self._active_sessions:
                return self._active_sessions[key]

            # 4. Reconstruct user from token (session may have been lost)
            role = Role(payload['role'])
            return AuthenticatedUser(
                username=username,
                role=role,
                session_id=payload['sid'],
                token=token,
                issued_at=payload.get('iat', 0),
                expires_at=payload['exp'],
            )

        except jwt.ExpiredSignatureError:
            log.warning("Token validation FAILED — token has expired")
            return None
        except jwt.InvalidTokenError as e:
            log.warning(f"Token validation FAILED — invalid token: {e}")
            return None

    def check_permission(
        self,
        user: AuthenticatedUser,
        permission: Permission,
    ) -> bool:
        """
        Check if an authenticated user has a specific permission.

        This is the Zero Trust "enforce least privilege" step.

        Args:
            user: The authenticated user (from validate_token)
            permission: The permission to check

        Returns:
            True if the user has the permission, False otherwise
        """
        if isinstance(user, str):
            user = self.validate_token(user)

        if user is None:
            log.warning("Permission check DENIED — no authenticated user")
            return False

        if user.is_expired:
            log.warning(f"Permission check DENIED — token expired for '{user.username}'")
            return False

        has_perm = user.has_permission(permission)

        if not has_perm:
            log.warning(
                f"Permission DENIED: '{user.username}' (role={user.role.value}) "
                f"attempted {permission.name}"
            )
        else:
            log.debug(
                f"Permission GRANTED: '{user.username}' — {permission.name}"
            )

        return has_perm

    def revoke_token(self, token: str):
        """Revoke a token (e.g., on logout or security event)."""
        self._revoked_tokens.add(token)
        try:
            payload = jwt.decode(
                token, self._secret_key,
                algorithms=[TOKEN_ALGORITHM],
                options={"verify_exp": False},
            )
            username = payload.get('sub', 'unknown')
            key = username.lower()
            if key in self._active_sessions:
                del self._active_sessions[key]
            log.info(f"Token revoked for user '{username}'")
        except Exception:
            log.info("Token revoked (unable to decode username)")

    def get_active_sessions(self) -> list[dict]:
        """Get all active sessions (for admin dashboard)."""
        sessions = []
        for username, user in self._active_sessions.items():
            sessions.append({
                'username': user.username,
                'role': user.role.value,
                'session_id': user.session_id,
                'trust_score': user.device_context.trust_score,
                'issued_at': user.issued_at,
                'expires_at': user.expires_at,
                'is_expired': user.is_expired,
            })
        return sessions

    @staticmethod
    def get_local_device_info() -> dict:
        """
        Gather local device information for the device context.
        Called by the client before authentication.
        """
        return {
            'os_name': platform.system(),
            'os_version': platform.version(),
            'hostname': platform.node(),
            'ip_address': '',  # Filled by server from connection info
        }

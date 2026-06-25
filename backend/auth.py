"""NetVision Auth — JWT, API keys, RBAC, and FastAPI dependency injection.

Provides:
- JWT token creation (access + refresh tokens)
- Token verification with optional path-based public access
- API key authentication
- Role-based access control: viewer | operator | admin | superadmin
- get_current_user dependency for route protection
"""

import os
import time
import uuid
import hashlib
from enum import Enum
from typing import Optional, List, Dict, Literal
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import jwt
from loguru import logger
from pydantic import BaseModel, Field

from config import settings

log = logger.bind(component="auth")

# ── Security scheme ──────────────────────────────────────────────────────

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Roles ────────────────────────────────────────────────────────────────


class Role(str, Enum):
    VIEWER = "viewer"           # Read-only: GET endpoints
    OPERATOR = "operator"       # Can scan, capture, probe
    ADMIN = "admin"             # Can manage config, delete data
    SUPERADMIN = "superadmin"   # Can manage users, tokens


# Role hierarchy for permission checks
ROLE_HIERARCHY = {
    Role.VIEWER: 0,
    Role.OPERATOR: 1,
    Role.ADMIN: 2,
    Role.SUPERADMIN: 3,
}

# ── User model ───────────────────────────────────────────────────────────


@dataclass
class User:
    """Authenticated user representation."""
    id: str
    username: str
    role: Role
    api_key_hash: str = ""
    scopes: List[str] = field(default_factory=list)

    def has_role(self, minimum: Role) -> bool:
        """Check if user has at least the specified role level."""
        return ROLE_HIERARCHY.get(self.role, -1) >= ROLE_HIERARCHY.get(minimum, 0)

    def can_access_method(self, method: str) -> bool:
        """Check if user's role allows this HTTP method."""
        if self.role == Role.SUPERADMIN:
            return True
        if method in ("GET", "HEAD", "OPTIONS"):
            return True
        if method in ("POST",):
            return self.has_role(Role.OPERATOR)
        if method in ("PUT", "PATCH", "DELETE"):
            return self.has_role(Role.ADMIN)
        return False


# ── Built-in admin account ───────────────────────────────────────────────

ADMIN_USER = User(
    id="builtin-admin",
    username="admin",
    role=Role.SUPERADMIN,
)

# ── In-memory user store (single-user mode; extend to DB later) ──────────

_active_tokens: Dict[str, User] = {}  # token -> User mapping for API keys
_revoked_tokens: set = set()           # set of revoked JWT jti values


def _load_api_keys() -> None:
    """Load API keys from config into the active token store."""
    _active_tokens.clear()
    for key, username in settings.api_keys.items():
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        _active_tokens[key] = User(
            id=username,
            username=username,
            role=Role.SUPERADMIN,
            api_key_hash=key_hash,
        )
    if _active_tokens:
        log.info("API keys loaded", count=len(_active_tokens))
    else:
        log.info("No API keys configured — default admin credentials will be used")


# Load on module import
_load_api_keys()

# ── JWT ──────────────────────────────────────────────────────────────────

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = settings.jwt_expire_seconds
REFRESH_TOKEN_EXPIRE_SECONDS = settings.jwt_refresh_expire_seconds


def create_access_token(username: str, role: str, extra_claims: dict = None) -> str:
    """Create a JWT access token."""
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
        "jti": str(uuid.uuid4()),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_refresh_token(username: str, role: str) -> str:
    """Create a JWT refresh token (longer-lived)."""
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + REFRESH_TOKEN_EXPIRE_SECONDS,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    """Verify a JWT token. Returns payload dict or None if invalid/expired."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
        jti = payload.get("jti", "")
        if jti in _revoked_tokens:
            log.warning(f"Token revoked: {jti[:8]}...")
            return None
        return payload
    except jwt.InvalidTokenError as e:
        log.debug(f"JWT verification failed: {e}")
        return None


def revoke_token(token: str) -> bool:
    """Revoke a JWT token by adding its jti to the revocation set."""
    payload = verify_token(token)
    if payload and payload.get("jti"):
        _revoked_tokens.add(payload["jti"])
        log.info(f"Token revoked: {payload['jti'][:8]}...")
        return True
    return False


# ── Dependency injection ─────────────────────────────────────────────────


def _resolve_user_from_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> Optional[User]:
    """Try to authenticate via JWT bearer token or API key."""
    # 1. Check API key first
    if api_key:
        user = _active_tokens.get(api_key)
        if user:
            return user

    # 2. Check JWT bearer
    if credentials:
        payload = verify_token(credentials.credentials)
        if payload:
            username = payload.get("sub", "unknown")
            role_str = payload.get("role", "viewer")
            try:
                role = Role(role_str)
            except ValueError:
                role = Role.VIEWER
            return User(
                id=payload.get("jti", ""),
                username=username,
                role=role,
            )

    return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> User:
    """FastAPI dependency: extract authenticated user or raise 401."""
    user = _resolve_user_from_jwt(credentials, api_key)
    if user is None:
        # If credentials were provided but invalid/revoked, always reject
        if credentials or api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Dev mode: no credentials + default JWT secret + no API keys = allow
        if not settings.api_keys and settings.jwt_secret_is_default:
            return ADMIN_USER
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide JWT Bearer token or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(minimum_role: Role):
    """Factory for role-based dependencies.

    Usage:
        @app.get("/admin/only")
        async def admin_route(user: User = Depends(require_role(Role.ADMIN))):
            ...
    """
    async def _role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if not current_user.has_role(minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum_role.value}' or higher. Current: '{current_user.role.value}'",
            )
        return current_user
    return _role_checker


def require_method(method: str):
    """Factory for method-based access control.

    Ensures user's role permits the HTTP method they're using.
    """
    async def _method_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if not current_user.can_access_method(method):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role.value}' cannot perform {method} requests. Needs operator+",
            )
        return current_user
    return _method_checker


# ── Public routes list ───────────────────────────────────────────────────

PUBLIC_PATHS = {
    "/health",
    "/health/live",
    "/health/ready",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/auth/token",
    "/auth/register",
}


def is_path_public(path: str) -> bool:
    """Check if a path should bypass authentication."""
    if path in PUBLIC_PATHS:
        return True
    # Prefix matches
    for public_prefix in ("/docs", "/openapi.json", "/redoc"):
        if path.startswith(public_prefix):
            return True
    return False


# ── Auth endpoints handler ───────────────────────────────────────────────


async def login_for_token(username: str, password: str) -> dict:
    """Authenticate with username/password and return JWT tokens."""
    # In single-user mode, compare against configured credentials
    if (username == settings.auth_username and
            password == settings.auth_password):
        access = create_access_token(username, "superadmin")
        refresh = create_refresh_token(username, "superadmin")
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
    )


async def refresh_access_token(refresh_token: str) -> dict:
    """Exchange a refresh token for a new access token."""
    payload = verify_token(refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not a refresh token",
        )
    username = payload.get("sub", "unknown")
    role_str = payload.get("role", "viewer")
    access = create_access_token(username, role_str)
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
    }


# ── Token introspection endpoint ─────────────────────────────────────────


async def introspect_token(token: str) -> dict:
    """Return token metadata without requiring a user lookup."""
    payload = verify_token(token)
    if payload is None:
        return {"active": False}
    return {
        "active": True,
        "sub": payload.get("sub"),
        "role": payload.get("role"),
        "type": payload.get("type"),
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
        "jti": payload.get("jti"),
    }

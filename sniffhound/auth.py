"""
Simple Token-Based Authentication for SniffHound

Provides easy authentication using 8-character mixed-case random tokens.
Tokens are generated at startup and displayed in terminal.

Usage:
    from sniffhound.auth import get_session_token, verify_token
    
    # Get the session token (displayed at startup)
    token = get_session_token()
    
    # Verify token from request
    is_valid = verify_token(token)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import time
from typing import Any


SESSION_TOKEN_LENGTH = 8
SESSION_TOKEN_ALPHABET = string.ascii_letters + string.digits
JWT_ALGORITHM = "HS256"
JWT_SECRET = os.getenv("SNIFFHOUND_JWT_SECRET", "sniffhound-local-signing-key")
JWT_DEFAULT_TTL_SECONDS = int(os.getenv("SNIFFHOUND_JWT_TTL", "3600"))


def _generate_random_token(length: int = SESSION_TOKEN_LENGTH) -> str:
    """Generate a session token with uppercase, lowercase, and digits."""
    return "".join(secrets.choice(SESSION_TOKEN_ALPHABET) for _ in range(length))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))


def _jwt_sign(signing_input: str) -> str:
    digest = hmac.new(
        JWT_SECRET.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def encode_jwt(payload: dict[str, Any]) -> str:
    """Encode a compact JWT using HS256."""
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature_b64 = _jwt_sign(signing_input)
    return f"{signing_input}.{signature_b64}"


def decode_jwt(token: str | None) -> tuple[bool, dict[str, Any] | None]:
    """Decode and verify a HS256 JWT."""
    if not token:
        return False, None
    try:
        header_b64, payload_b64, signature_b64 = str(token).split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}"
        expected_signature = _jwt_sign(signing_input)
        if not secrets.compare_digest(signature_b64, expected_signature):
            return False, None

        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        if str(header.get("alg") or "") != JWT_ALGORITHM:
            return False, None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        exp = payload.get("exp")
        if exp is not None and int(exp) < int(time.time()):
            return False, None
        return True, payload
    except Exception:
        return False, None


def generate_token(
    *,
    user: str = "operator",
    scope: str = "session",
    expires_in: int = JWT_DEFAULT_TTL_SECONDS,
    extra: dict[str, Any] | None = None,
) -> str:
    """Generate a signed JWT for API-oriented authentication tests and integrations."""
    now = int(time.time())
    payload = {
        "user": str(user or "operator"),
        "scope": str(scope or "session"),
        "iat": now,
        "exp": now + max(1, int(expires_in)),
    }
    if extra:
        payload.update(dict(extra))
    return encode_jwt(payload)


# Session token (generated at startup, displayed in terminal)
_SESSION_TOKEN: str | None = None
REQUIRE_AUTH = os.getenv("SNIFFHOUND_REQUIRE_AUTH", "1").lower() in {"1", "true", "yes", "on"}


def initialize_session_token() -> str:
    """Initialize session token at startup (called once)."""
    global _SESSION_TOKEN
    if _SESSION_TOKEN is None:
        _SESSION_TOKEN = _generate_random_token(SESSION_TOKEN_LENGTH)
    return _SESSION_TOKEN


def get_session_token() -> str:
    """Get the current session token."""
    if _SESSION_TOKEN is None:
        return initialize_session_token()
    return _SESSION_TOKEN


def verify_token(token: str | None) -> bool:
    """
    Verify if token matches session token.

    Args:
        token: Token to verify

    Returns:
        True if valid, False otherwise
    """
    if not token:
        return not REQUIRE_AUTH

    if _SESSION_TOKEN is None:
        initialize_session_token()

    candidate = token.strip()
    if secrets.compare_digest(candidate, _SESSION_TOKEN):
        return True

    jwt_valid, _jwt_payload = decode_jwt(candidate)
    return jwt_valid


def extract_token_from_header(auth_header: str | None) -> str | None:
    """
    Extract token from Authorization header or x-access-token.

    Args:
        auth_header: Authorization header value (e.g., "Bearer <token>")

    Returns:
        Token string or None
    """
    if not auth_header:
        return None
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return auth_header.strip()


def authenticate_request(token: str | None) -> tuple[bool, dict[str, Any] | None]:
    """
    Authenticate a request using session token.

    Args:
        token: Token from request

    Returns:
        Tuple of (is_authenticated, user_info)
    """
    if not token:
        if not REQUIRE_AUTH:
            return True, {"authenticated": True, "auth_type": "anonymous"}
        return False, None

    jwt_valid, jwt_payload = decode_jwt(token)
    if jwt_valid and jwt_payload is not None:
        payload = dict(jwt_payload)
        payload["authenticated"] = True
        payload["auth_type"] = "jwt"
        return True, payload

    if not verify_token(token):
        return False, None

    return True, {
        "authenticated": True,
        "auth_type": "session",
    }

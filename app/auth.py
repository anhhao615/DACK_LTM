import os
import hmac
import hashlib
import uuid
import datetime
from typing import Optional, Dict, Any, Tuple
import jwt

from app.config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_MINUTES,
    PASSWORD_HASH_ITERATIONS
)
from app.database import get_db

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 16-byte cryptographically secure salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt.hex()}${key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash using timing-safe comparison."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_key = bytes.fromhex(parts[3])
        computed_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )
        return hmac.compare_digest(computed_key, expected_key)
    except Exception:
        return False

def create_access_token(user_id: int, username: str, role: str) -> Tuple[str, str, datetime.datetime]:
    """Generate signed JWT token with unique JTI and expiration."""
    jti = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    
    payload = {
        "jti": jti,
        "user_id": user_id,
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp())
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, jti, expires_at

def is_token_revoked(jti: str) -> bool:
    """Check if JWT JTI has been revoked via logout."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
        return cursor.fetchone() is not None

def revoke_token(jti: str, exp_timestamp: int):
    """Add JWT JTI to revoked_tokens table."""
    exp_datetime = datetime.datetime.fromtimestamp(exp_timestamp, tz=datetime.timezone.utc)
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
            (jti, exp_datetime.strftime("%Y-%m-%d %H:%M:%S"))
        )

def verify_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if not jti or is_token_revoked(jti):
            raise jwt.InvalidTokenError("Token has been revoked")
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError:
        raise

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify user credentials and return user record if valid."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash, role, full_name, is_active FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        if not user or not user["is_active"]:
            return None
        if verify_password(password, user["password_hash"]):
            return dict(user)
        return None

def create_user(username: str, password: str, role: str = "USER", full_name: str = "") -> int:
    """Create a new user with hashed password."""
    pwd_hash = hash_password(password)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, is_active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (username, pwd_hash, role.upper(), full_name)
        )
        return cursor.lastrowid

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, full_name, is_active FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, full_name, is_active FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

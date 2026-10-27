import time
import datetime
from collections import defaultdict
from typing import Tuple, Dict, Any, List, Optional
from flask import Request, jsonify

from app.config import (
    FIREWALL_ENABLED,
    FIREWALL_MODE,
    RATE_LIMIT_ENABLED,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    BRUTE_FORCE_MAX_FAILURES,
    BRUTE_FORCE_LOCKOUT_SECONDS,
    MAX_UPLOAD_SIZE_BYTES
)
from app.database import get_db
from app.audit_logger import SecurityAuditLogger

class FirewallState:
    """In-memory tracking for high-performance rate limiting and brute force counters."""
    def __init__(self):
        # ip -> list of request timestamps
        self.rate_limit_history: Dict[str, List[float]] = defaultdict(list)
        # ip -> list of failed login timestamps
        self.login_failures: Dict[str, List[float]] = defaultdict(list)

_state = FirewallState()

class FirewallLayer:
    @staticmethod
    def get_setting(key: str, default: str = "") -> str:
        """Fetch dynamic firewall setting from database with fallback."""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM firewall_settings WHERE key = ?", (key,))
                row = cursor.fetchone()
                return row["value"] if row else default
        except Exception:
            return default

    @staticmethod
    def set_setting(key: str, value: str):
        """Update dynamic firewall setting."""
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO firewall_settings (key, value) VALUES (?, ?)",
                (key, str(value))
            )

    @staticmethod
    def is_ip_blocked(client_ip: str) -> Tuple[bool, str]:
        """
        Check if client IP is blocked either permanently or under temporary lockout.
        Returns (is_blocked, reason).
        """
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check whitelist mode first if enabled
            mode = FirewallLayer.get_setting("firewall_mode", FIREWALL_MODE).lower()
            if mode == "whitelist":
                cursor.execute(
                    """
                    SELECT id FROM firewall_rules 
                    WHERE ip_address = ? AND rule_type = 'WHITELIST' AND is_active = 1
                    """,
                    (client_ip,)
                )
                if not cursor.fetchone():
                    return True, "IP is not present in Firewall Whitelist."
                return False, ""

            # Blacklist check (Permanent or Active Temporary)
            cursor.execute(
                """
                SELECT id, reason, expires_at FROM firewall_rules 
                WHERE ip_address = ? AND rule_type = 'BLACKLIST' AND is_active = 1
                AND (expires_at IS NULL OR expires_at > ?)
                """,
                (client_ip, now_str)
            )
            rule = cursor.fetchone()
            if rule:
                reason = rule["reason"] or "IP Address is blacklisted by Firewall administrator."
                return True, reason

        return False, ""

    @staticmethod
    def check_rate_limit(client_ip: str) -> Tuple[bool, int]:
        """
        Sliding-window rate limiter.
        Returns (is_allowed, current_count).
        """
        enabled = FirewallLayer.get_setting("rate_limit_enabled", str(RATE_LIMIT_ENABLED)).lower() == "true"
        if not enabled:
            return True, 0

        max_req = int(FirewallLayer.get_setting("rate_limit_max", str(RATE_LIMIT_MAX_REQUESTS)))
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS

        timestamps = _state.rate_limit_history[client_ip]
        # Purge timestamps outside sliding window
        _state.rate_limit_history[client_ip] = [ts for ts in timestamps if ts > window_start]
        
        if len(_state.rate_limit_history[client_ip]) >= max_req:
            return False, len(_state.rate_limit_history[client_ip])

        _state.rate_limit_history[client_ip].append(now)
        return True, len(_state.rate_limit_history[client_ip])

    @staticmethod
    def record_login_attempt(client_ip: str, success: bool, request_id: str, username: str) -> Optional[str]:
        """
        Track login attempts for Brute-Force protection.
        If threshold reached, automatically triggers temporary firewall ban.
        """
        if success:
            _state.login_failures.pop(client_ip, None)
            return None

        now = time.time()
        window_start = now - BRUTE_FORCE_LOCKOUT_SECONDS
        failures = [ts for ts in _state.login_failures[client_ip] if ts > window_start]
        failures.append(now)
        _state.login_failures[client_ip] = failures

        if len(failures) >= BRUTE_FORCE_MAX_FAILURES:
            # Auto-ban IP
            exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=BRUTE_FORCE_LOCKOUT_SECONDS)
            exp_str = exp.strftime("%Y-%m-%d %H:%M:%S")
            reason = f"Automated Ban: {len(failures)} consecutive failed login attempts (Brute-Force Attack detected)."
            
            FirewallLayer.add_ip_rule(
                ip_address=client_ip,
                rule_type="BLACKLIST",
                reason=reason,
                expires_at_str=exp_str
            )

            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=username,
                action="BRUTE_FORCE_DEFENSE",
                status="BLOCKED_FIREWALL",
                status_code=403,
                reason=reason
            )
            return reason

        return None

    @staticmethod
    def inspect_packet(request: Request, request_id: str) -> Optional[Tuple[Dict[str, Any], int]]:
        """
        Firewall gatekeeper:
        1. Checks IP Blacklist / Whitelist.
        2. Enforces Rate Limiting.
        3. Enforces Packet/Payload Size Limits.
        """
        client_ip = request.remote_addr or "127.0.0.1"

        # 1. IP Check
        blocked, reason = FirewallLayer.is_ip_blocked(client_ip)
        if blocked:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                action="FIREWALL_PACKET_FILTER",
                status="BLOCKED_FIREWALL",
                status_code=403,
                reason=reason
            )
            return {
                "error": "Forbidden - Blocked by Firewall",
                "message": reason,
                "client_ip": client_ip,
                "request_id": request_id
            }, 403

        # 2. Rate Limit Check
        allowed, count = FirewallLayer.check_rate_limit(client_ip)
        if not allowed:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                action="RATE_LIMIT_CHECK",
                status="BLOCKED_FIREWALL",
                status_code=429,
                reason=f"Rate limit exceeded: {count} requests within window."
            )
            return {
                "error": "Too Many Requests",
                "message": f"Rate limit exceeded. Maximum allowed is {RATE_LIMIT_MAX_REQUESTS} requests per minute.",
                "request_id": request_id
            }, 429

        # 3. Payload inspection
        content_length = request.content_length
        if content_length and content_length > MAX_UPLOAD_SIZE_BYTES:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                action="PAYLOAD_INSPECTION",
                status="BLOCKED_FIREWALL",
                status_code=413,
                reason=f"Payload size {content_length} bytes exceeds maximum limit of {MAX_UPLOAD_SIZE_BYTES} bytes."
            )
            return {
                "error": "Payload Too Large",
                "message": f"Upload size exceeds system firewall limit of {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB.",
                "request_id": request_id
            }, 413

        return None

    @staticmethod
    def add_ip_rule(
        ip_address: str,
        rule_type: str = "BLACKLIST",
        reason: str = "",
        expires_at_str: Optional[str] = None
    ) -> int:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO firewall_rules (ip_address, rule_type, reason, is_active, expires_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (ip_address.strip(), rule_type.upper(), reason, expires_at_str)
            )
            return cursor.lastrowid

    @staticmethod
    def remove_ip_rule(rule_id: int) -> bool:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
            return cursor.rowcount > 0

    @staticmethod
    def list_ip_rules() -> List[Dict[str, Any]]:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM firewall_rules ORDER BY id DESC")
            return [dict(r) for r in cursor.fetchall()]

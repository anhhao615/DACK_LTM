import json
import logging
from datetime import datetime
from typing import Optional, Any
from app.database import get_db

logger = logging.getLogger("security.audit")

class SecurityAuditLogger:
    @staticmethod
    def log(
        request_id: str,
        client_ip: str,
        action: str,
        status: str,
        status_code: int,
        username: Optional[str] = None,
        resource_path: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Any] = None
    ) -> int:
        """
        Record a structured security event into the audit_logs table and Python logger.
        """
        details_str = json.dumps(details, ensure_ascii=False) if isinstance(details, (dict, list)) else (str(details) if details else None)
        
        # Color formatting for terminal console logging
        log_level = logging.INFO
        if status in ("BLOCKED_FIREWALL", "QUARANTINED_AV"):
            log_level = logging.WARNING
        elif status in ("DENIED_AUTHZ", "AUTHN_FAILED"):
            log_level = logging.WARNING

        logger.log(
            log_level,
            f"[{status}] IP={client_ip} User={username or 'ANONYMOUS'} Action={action} "
            f"Path={resource_path or '-'} Code={status_code} Reason={reason or '-'}"
        )

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_logs 
                    (request_id, client_ip, username, action, resource_path, status, status_code, reason, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (request_id, client_ip, username, action, resource_path, status, status_code, reason, details_str)
                )
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to record audit log: {e}", exc_info=True)
            return -1

    @staticmethod
    def get_recent_logs(limit: int = 100, status_filter: Optional[str] = None):
        """Fetch latest audit logs for SOC dashboard."""
        with get_db() as conn:
            cursor = conn.cursor()
            if status_filter and status_filter != "ALL":
                cursor.execute(
                    """
                    SELECT * FROM audit_logs 
                    WHERE status = ? 
                    ORDER BY id DESC LIMIT ?
                    """,
                    (status_filter, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM audit_logs 
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,)
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

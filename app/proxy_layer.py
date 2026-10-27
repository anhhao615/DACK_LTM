import re
import os
import urllib.parse
from pathlib import Path
from typing import Tuple, Optional
from flask import Request, Response, jsonify

from app.config import SECURE_STORAGE_DIR
from app.audit_logger import SecurityAuditLogger

# Patterns for Path Traversal attacks (plain, encoded, double encoded)
TRAVERSAL_REGEX = re.compile(
    r"(\.\.[/\\]|"                 # ../ or ..\
    r"%2e%2e[%2f%5c/]|"           # %2e%2e/ or %2e%2e\
    r"%252e%252e|"                # double encoded ..
    r"\.\.%2f|\.\.%5c|"           # ..%2f or ..%5c
    r"%2e\./|\.%2e/|"             # mixed . and %2e
    r"\0)",                       # null byte
    re.IGNORECASE
)

# Forbidden HTTP headers that attackers use for proxy bypass / cache poisoning
DANGEROUS_HEADERS = [
    "x-original-url",
    "x-rewrite-url",
    "x-custom-ip-authorization",
    "x-forwarded-server",
    "x-host"
]

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}

class ProxyLayer:
    """
    Reverse Proxy & Application Gateway Layer:
    - Normalizes & inspects incoming HTTP request
    - Filters dangerous request headers & protocol anomalies
    - Generates and stamps X-Request-ID for distributed tracing
    - Strict Path Traversal defense using lexical and canonical resolution
    """

    @staticmethod
    def inspect_request(request: Request, request_id: str) -> Optional[Response]:
        """
        Validates protocol, method, and headers.
        Returns a Flask Response if blocked, or None if valid.
        """
        # 1. Validate HTTP Method
        if request.method not in ALLOWED_METHODS:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=request.remote_addr or "127.0.0.1",
                action="PROXY_INSPECT",
                status="BLOCKED_PROXY",
                status_code=405,
                reason=f"Invalid HTTP Method: {request.method}"
            )
            return jsonify({
                "error": "Method Not Allowed",
                "message": f"HTTP method {request.method} is disallowed by Proxy Gateway.",
                "request_id": request_id
            }), 405

        # 2. Check for dangerous / attack headers
        for header_name in request.headers.keys():
            lower_header = header_name.lower()
            if lower_header in DANGEROUS_HEADERS:
                SecurityAuditLogger.log(
                    request_id=request_id,
                    client_ip=request.remote_addr or "127.0.0.1",
                    action="PROXY_INSPECT",
                    status="BLOCKED_PROXY",
                    status_code=400,
                    reason=f"Dangerous header rejected: {header_name}"
                )
                return jsonify({
                    "error": "Bad Request",
                    "message": f"Disallowed HTTP Header detected: {header_name}",
                    "request_id": request_id
                }), 400

        return None

    @staticmethod
    def validate_safe_path(raw_path: str, request_id: str, client_ip: str, username: Optional[str] = None) -> Tuple[bool, str, Optional[Path]]:
        """
        Strict Path Traversal Verification:
        1. Decodes URL encoding (up to 2 rounds).
        2. Checks lexical traversal patterns (../, %2e%2e/, etc.).
        3. Canonicalizes target path using os.path.realpath.
        4. Enforces that target path is strictly contained inside SECURE_STORAGE_DIR.
        
        Returns (is_safe, error_message, resolved_path).
        """
        if not raw_path:
            return True, "", SECURE_STORAGE_DIR

        # Step A: Decode URL encoding twice to catch double-encoding bypasses
        decoded = raw_path
        try:
            decoded = urllib.parse.unquote(decoded)
            decoded = urllib.parse.unquote(decoded)
        except Exception:
            pass

        # Step B: Check for null bytes or illegal characters
        if "\0" in decoded or "\x00" in raw_path:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=username,
                action="PATH_INSPECTION",
                status="BLOCKED_PROXY",
                status_code=400,
                resource_path=raw_path,
                reason="Null byte injection detected in path."
            )
            return False, "Null byte injection detected in file path.", None

        # Step C: Lexical traversal pattern check
        if TRAVERSAL_REGEX.search(raw_path) or TRAVERSAL_REGEX.search(decoded):
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=username,
                action="PATH_INSPECTION",
                status="BLOCKED_PROXY",
                status_code=403,
                resource_path=raw_path,
                reason="Path traversal signature (../ or encoded equivalent) detected."
            )
            return False, "Path Traversal attack detected. Access denied by Proxy Gateway.", None

        # Step D: Reject Windows drive letters (C:) or UNC network shares (\\)
        if re.match(r"^[a-zA-Z]:", decoded) or decoded.startswith(r"\\"):
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=username,
                action="PATH_INSPECTION",
                status="BLOCKED_PROXY",
                status_code=403,
                resource_path=raw_path,
                reason="Absolute system or network path forbidden."
            )
            return False, "Absolute system paths are strictly forbidden.", None

        # Step E: Canonical containment verification
        # Strip leading slashes to prevent os.path.join from treating it as root
        sanitized_rel = decoded.lstrip("/\\")
        full_candidate = (SECURE_STORAGE_DIR / sanitized_rel).resolve()
        storage_root = SECURE_STORAGE_DIR.resolve()

        try:
            # Check if storage_root is a strict parent or equal
            full_candidate.relative_to(storage_root)
        except ValueError:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=username,
                action="PATH_INSPECTION",
                status="BLOCKED_PROXY",
                status_code=403,
                resource_path=raw_path,
                reason="Resolved path escaped secure storage sandbox."
            )
            return False, "Path resolution escaped secure storage sandbox.", None

        return True, "", full_candidate

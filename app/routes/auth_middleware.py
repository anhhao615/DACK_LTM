from functools import wraps
from flask import request, jsonify, g
import jwt
from app.auth import verify_access_token, get_user_by_id
from app.audit_logger import SecurityAuditLogger

def get_current_user():
    """Extract and validate JWT from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, "Authorization header missing or format invalid. Expected: Bearer <token>"
    
    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = verify_access_token(token)
        user = get_user_by_id(payload["user_id"])
        if not user or not user["is_active"]:
            return None, "User account is disabled or does not exist."
        # Inject jti and exp for logout
        user["jti"] = payload.get("jti")
        user["exp"] = payload.get("exp")
        return user, None
    except jwt.ExpiredSignatureError:
        return None, "401 Unauthorized - Access Token has expired."
    except jwt.InvalidTokenError as e:
        return None, f"401 Unauthorized - Invalid Access Token: {str(e)}"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, err = get_current_user()
        request_id = getattr(g, "request_id", "NO-REQ-ID")
        client_ip = request.remote_addr or "127.0.0.1"

        if not user:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                action="AUTH_VERIFY",
                status="AUTHN_FAILED",
                status_code=401,
                reason=err
            )
            return jsonify({
                "error": "Unauthorized",
                "message": err,
                "request_id": request_id
            }), 401

        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, err = get_current_user()
        request_id = getattr(g, "request_id", "NO-REQ-ID")
        client_ip = request.remote_addr or "127.0.0.1"

        if not user:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                action="ADMIN_AUTH_CHECK",
                status="AUTHN_FAILED",
                status_code=401,
                reason=err
            )
            return jsonify({
                "error": "Unauthorized",
                "message": err,
                "request_id": request_id
            }), 401

        if user.get("role") != "ADMIN":
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=user.get("username"),
                action="ADMIN_AUTH_CHECK",
                status="DENIED_AUTHZ",
                status_code=403,
                reason="User is not authorized for Admin SOC capabilities."
            )
            return jsonify({
                "error": "Forbidden",
                "message": "Access Denied: Requires ADMIN role privilege.",
                "request_id": request_id
            }), 403

        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function

from flask import Blueprint, request, jsonify, g
from app.auth import (
    authenticate_user,
    create_access_token,
    revoke_token
)
from app.firewall_layer import FirewallLayer
from app.audit_logger import SecurityAuditLogger
from app.routes.auth_middleware import login_required

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and issue JWT token.
    Enforces Firewall IP block check and Brute-force lockout monitoring.
    """
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"

    # 1. Firewall IP inspection
    is_blocked, ban_reason = FirewallLayer.is_ip_blocked(client_ip)
    if is_blocked:
        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            action="LOGIN_ATTEMPT",
            status="BLOCKED_FIREWALL",
            status_code=403,
            reason=ban_reason
        )
        return jsonify({
            "error": "Forbidden - Blocked by Firewall",
            "message": ban_reason,
            "request_id": request_id
        }), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Bad Request",
            "message": "Username and password are required.",
            "request_id": request_id
        }), 400

    # 2. Check credentials
    user = authenticate_user(username, password)
    if not user:
        # Record failure for Brute-force tracking
        auto_ban_reason = FirewallLayer.record_login_attempt(client_ip, False, request_id, username)
        if auto_ban_reason:
            return jsonify({
                "error": "Forbidden - IP Locked",
                "message": f"Security Alert: Your IP has been temporarily blacklisted due to repeated failed logins. {auto_ban_reason}",
                "request_id": request_id
            }), 403

        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=username,
            action="LOGIN",
            status="AUTHN_FAILED",
            status_code=401,
            reason="Invalid username or password"
        )
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid username or password.",
            "request_id": request_id
        }), 401

    # 3. Successful authentication: Clear failure count and issue JWT
    FirewallLayer.record_login_attempt(client_ip, True, request_id, username)
    token, jti, expires_at = create_access_token(user["id"], user["username"], user["role"])

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=user["username"],
        action="LOGIN",
        status="ALLOWED",
        status_code=200,
        reason=f"User authenticated successfully as role {user['role']}"
    )

    return jsonify({
        "message": "Login successful",
        "access_token": token,
        "token_type": "Bearer",
        "expires_at": expires_at.isoformat(),
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"]
        },
        "request_id": request_id
    }), 200

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """Revoke JWT token in database blacklist to prevent replay attacks."""
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"

    jti = user.get("jti")
    exp = user.get("exp")
    if jti and exp:
        revoke_token(jti, exp)

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=user.get("username"),
        action="LOGOUT",
        status="ALLOWED",
        status_code=200,
        reason="User logged out and revoked access token"
    )

    return jsonify({
        "message": "Logout successful. Token revoked in blacklist.",
        "request_id": request_id
    }), 200

@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    """Get current user context and role."""
    return jsonify({
        "user": g.current_user,
        "request_id": getattr(g, "request_id", "NO-REQ-ID")
    }), 200

@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account requiring admin approval (PENDING)."""
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip() or username
    role = data.get("role", "USER").upper()
    reason = data.get("reason", "")

    if not username or not password:
        return jsonify({"error": "Bad Request", "message": "Vui lòng nhập tên đăng nhập và mật khẩu."}), 400
    if len(username) < 3:
        return jsonify({"error": "Bad Request", "message": "Tên đăng nhập phải có ít nhất 3 ký tự."}), 400
    if len(password) < 4:
        return jsonify({"error": "Bad Request", "message": "Mật khẩu phải có tối thiểu 4 ký tự."}), 400

    if role not in ["USER", "GUEST"]:
        role = "USER"

    from app.database import get_db
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({"error": "User Exists", "message": f"Tên đăng nhập '{username}' đã tồn tại."}), 400

        from app.auth import hash_password
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, full_name, is_active) VALUES (?, ?, ?, ?, 0)",
            (username, hash_password(password), role, full_name)
        )
        new_id = cursor.lastrowid

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=username,
        action="USER_REGISTER",
        status="PENDING",
        status_code=201,
        reason=f"Đăng ký tài khoản mới ({role}) - Chờ Admin phê duyệt"
    )

    return jsonify({
        "message": "Đăng ký thành công! Tài khoản đang chờ Quản trị viên (Admin) phê duyệt trước khi có thể đăng nhập.",
        "status": "PENDING",
        "user": {"id": new_id, "username": username, "role": role, "full_name": full_name}
    }), 201

@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    """Reset password using emergency recovery key."""
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip().lower()
    recovery_key = data.get("recovery_key", "").strip()
    new_password = data.get("new_password", "").strip()

    if not username or not new_password:
        return jsonify({"error": "Bad Request", "message": "Vui lòng nhập tên đăng nhập và mật khẩu mới."}), 400
    if len(new_password) < 4:
        return jsonify({"error": "Bad Request", "message": "Mật khẩu mới phải có tối thiểu 4 ký tự."}), 400

    if recovery_key not in ["RESET2026", "admin123"]:
        return jsonify({"error": "Invalid Key", "message": "Mã khôi phục không chính xác. Mã mặc định là RESET2026."}), 400

    from app.database import get_db
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Not Found", "message": f"Không tìm thấy tài khoản '{username}'."}), 404

        from app.auth import hash_password
        cursor.execute("UPDATE users SET password_hash = ?, is_active = 1 WHERE username = ?", (hash_password(new_password), username))

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=username,
        action="PASSWORD_RESET_SUCCESS",
        status="ALLOWED",
        status_code=200,
        reason="Khôi phục và đặt lại mật khẩu thành công"
    )

    return jsonify({"message": "Đặt lại mật khẩu thành công! Tài khoản đã được mở khóa. Bạn có thể đăng nhập ngay."}), 200

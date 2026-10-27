import datetime
from flask import Blueprint, request, jsonify, g
from app.routes.auth_middleware import admin_required
from app.audit_logger import SecurityAuditLogger
from app.firewall_layer import FirewallLayer
from app.antivirus_layer import AntivirusLayer
from app.acl_engine import ACLEngine, normalize_path
from app.database import get_db

soc_bp = Blueprint("soc", __name__, url_prefix="/api/soc")

@soc_bp.route("/logs", methods=["GET"])
@admin_required
def get_audit_logs():
    """Retrieve security audit logs with status filtering."""
    status_filter = request.args.get("status", "ALL")
    limit = int(request.args.get("limit", 100))
    logs = SecurityAuditLogger.get_recent_logs(limit=limit, status_filter=status_filter)
    return jsonify({
        "status_filter": status_filter,
        "count": len(logs),
        "logs": logs
    }), 200

@soc_bp.route("/stats", methods=["GET"])
@admin_required
def get_security_stats():
    """Fetch aggregated security metrics for SOC dashboard."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Count by status in audit_logs
        cursor.execute("SELECT status, COUNT(*) as cnt FROM audit_logs GROUP BY status")
        status_counts = {r["status"]: r["cnt"] for r in cursor.fetchall()}
        
        cursor.execute("SELECT COUNT(*) as total FROM audit_logs")
        total_requests = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as cnt FROM firewall_rules WHERE is_active = 1")
        active_firewall_rules = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM quarantine_records")
        quarantine_count = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM file_permissions")
        acl_rules_count = cursor.fetchone()["cnt"]

    return jsonify({
        "total_requests": total_requests,
        "allowed_requests": status_counts.get("ALLOWED", 0),
        "authz_denied": status_counts.get("DENIED_AUTHZ", 0),
        "firewall_blocked": status_counts.get("BLOCKED_FIREWALL", 0),
        "antivirus_quarantined": status_counts.get("QUARANTINED_AV", 0),
        "authn_failed": status_counts.get("AUTHN_FAILED", 0),
        "active_firewall_rules": active_firewall_rules,
        "quarantine_count": quarantine_count,
        "acl_rules_count": acl_rules_count
    }), 200

# =============================================================================
# Firewall Management Endpoints
# =============================================================================
@soc_bp.route("/firewall/rules", methods=["GET"])
@admin_required
def get_firewall_rules():
    rules = FirewallLayer.list_ip_rules()
    return jsonify({"rules": rules}), 200

@soc_bp.route("/firewall/rules", methods=["POST"])
@admin_required
def add_firewall_rule():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip_address", "").strip()
    rule_type = data.get("rule_type", "BLACKLIST").upper()
    reason = data.get("reason", "Admin manual action")
    duration_minutes = data.get("duration_minutes")

    if not ip:
        return jsonify({"error": "Bad Request", "message": "IP address is required."}), 400

    expires_at_str = None
    if duration_minutes:
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=int(duration_minutes))
        expires_at_str = exp.strftime("%Y-%m-%d %H:%M:%S")

    rule_id = FirewallLayer.add_ip_rule(ip, rule_type, reason, expires_at_str)
    
    SecurityAuditLogger.log(
        request_id=getattr(g, "request_id", "SOC-ACTION"),
        client_ip=request.remote_addr or "127.0.0.1",
        username=g.current_user["username"],
        action="FIREWALL_CONFIG",
        status="ALLOWED",
        status_code=201,
        reason=f"Added {rule_type} rule for IP {ip}"
    )

    return jsonify({"message": f"Firewall rule added for IP {ip}", "rule_id": rule_id}), 201

@soc_bp.route("/firewall/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_firewall_rule(rule_id: int):
    ok = FirewallLayer.remove_ip_rule(rule_id)
    if not ok:
        return jsonify({"error": "Not Found", "message": "Rule not found."}), 404
        
    SecurityAuditLogger.log(
        request_id=getattr(g, "request_id", "SOC-ACTION"),
        client_ip=request.remote_addr or "127.0.0.1",
        username=g.current_user["username"],
        action="FIREWALL_CONFIG",
        status="ALLOWED",
        status_code=200,
        reason=f"Deleted firewall rule ID {rule_id}"
    )
    return jsonify({"message": "Firewall rule removed."}), 200

@soc_bp.route("/firewall/settings", methods=["GET"])
@admin_required
def get_firewall_settings():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM firewall_settings")
        settings = {r["key"]: r["value"] for r in cursor.fetchall()}
    return jsonify({"settings": settings}), 200

@soc_bp.route("/firewall/settings", methods=["POST"])
@admin_required
def update_firewall_settings():
    data = request.get_json(silent=True) or {}
    for k, v in data.items():
        FirewallLayer.set_setting(k, str(v))
    return jsonify({"message": "Firewall settings updated successfully."}), 200

# =============================================================================
# Antivirus & Quarantine Endpoints
# =============================================================================
@soc_bp.route("/antivirus/quarantine", methods=["GET"])
@admin_required
def get_quarantine_records():
    records = AntivirusLayer.list_quarantine()
    return jsonify({"records": records}), 200

@soc_bp.route("/antivirus/quarantine/<record_id>", methods=["DELETE"])
@admin_required
def delete_quarantined_item(record_id: str):
    ok = AntivirusLayer.delete_quarantine_record(record_id)
    if not ok:
        return jsonify({"error": "Not Found", "message": "Quarantine record not found."}), 404
    return jsonify({"message": f"Quarantine record {record_id} destroyed."}), 200

# =============================================================================
# ACL & User Management Endpoints
# =============================================================================
@soc_bp.route("/acl/rules", methods=["GET"])
@admin_required
def get_acl_rules():
    rules = ACLEngine.list_all_permissions()
    return jsonify({"rules": rules}), 200

@soc_bp.route("/acl/rules", methods=["POST"])
@admin_required
def set_acl_rule():
    data = request.get_json(silent=True) or {}
    resource_path = data.get("resource_path", "").strip()
    user_id = data.get("user_id")
    role = data.get("role")
    can_read = 1 if data.get("can_read") else 0
    can_write = 1 if data.get("can_write") else 0
    can_delete = 1 if data.get("can_delete") else 0
    is_deny = 1 if data.get("is_deny") else 0

    if not resource_path:
        return jsonify({"error": "Bad Request", "message": "Resource path is required."}), 400

    rule_id = ACLEngine.set_permission(
        resource_path=resource_path,
        user_id=user_id if user_id else None,
        role=role.upper() if role else None,
        can_read=can_read,
        can_write=can_write,
        can_delete=can_delete,
        is_deny=is_deny
    )

    SecurityAuditLogger.log(
        request_id=getattr(g, "request_id", "SOC-ACTION"),
        client_ip=request.remote_addr or "127.0.0.1",
        username=g.current_user["username"],
        action="ACL_CONFIG",
        status="ALLOWED",
        status_code=200,
        resource_path=normalize_path(resource_path),
        reason=f"Updated ACL for user_id={user_id}, role={role}, read={can_read}, write={can_write}"
    )

    return jsonify({"message": "ACL rule configured successfully.", "rule_id": rule_id}), 200

@soc_bp.route("/acl/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_acl_rule(rule_id: int):
    ok = ACLEngine.delete_permission(rule_id)
    if not ok:
        return jsonify({"error": "Not Found", "message": "ACL rule not found."}), 404
    return jsonify({"message": "ACL rule deleted."}), 200

@soc_bp.route("/users", methods=["GET"])
@admin_required
def list_users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, full_name, is_active, created_at FROM users ORDER BY id ASC")
        users = [dict(r) for r in cursor.fetchall()]
    return jsonify({"users": users}), 200

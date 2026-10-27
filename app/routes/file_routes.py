from flask import Blueprint, request, jsonify, g, send_file
from pathlib import Path
from app.routes.auth_middleware import login_required
from app.proxy_layer import ProxyLayer
from app.file_service import FileService
from app.acl_engine import ACLEngine, normalize_path
from app.audit_logger import SecurityAuditLogger

file_bp = Blueprint("files", __name__, url_prefix="/api/files")

@file_bp.route("/list", methods=["GET"])
@login_required
def list_files():
    """
    List files and folders in the target directory.
    Enforces Proxy path traversal checks and AuthZ READ permission.
    """
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"
    raw_path = request.args.get("path", "/")

    # 1. Proxy Path Traversal Defense
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(raw_path, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({
            "error": "Proxy Violation - Path Traversal Blocked",
            "message": err_msg,
            "request_id": request_id
        }), 403

    # 2. File Service & AuthZ
    ok, err_msg, items = FileService.list_directory(user, raw_path)
    if not ok:
        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=user.get("username"),
            action="LIST_DIR",
            status="DENIED_AUTHZ",
            status_code=403,
            resource_path=raw_path,
            reason=err_msg
        )
        return jsonify({
            "error": "Forbidden",
            "message": err_msg,
            "request_id": request_id
        }), 403

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=user.get("username"),
        action="LIST_DIR",
        status="ALLOWED",
        status_code=200,
        resource_path=raw_path,
        reason="Directory listed"
    )

    current_perms = ACLEngine.get_effective_permissions(user, raw_path)

    return jsonify({
        "current_path": normalize_path(raw_path),
        "permissions": current_perms,
        "items": items,
        "request_id": request_id
    }), 200

@file_bp.route("/content", methods=["GET"])
@login_required
def read_file_content():
    """Read textual content of a file."""
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"
    raw_path = request.args.get("path", "")

    if not raw_path:
        return jsonify({"error": "Bad Request", "message": "Missing 'path' parameter.", "request_id": request_id}), 400

    # 1. Proxy Path Traversal Check
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(raw_path, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({
            "error": "Proxy Violation - Path Traversal Blocked",
            "message": err_msg,
            "request_id": request_id
        }), 403

    # 2. Read File via FileService
    ok, code, msg, file_data = FileService.read_file(user, raw_path)
    if not ok:
        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=user.get("username"),
            action="READ_FILE",
            status="DENIED_AUTHZ" if code == 403 else "ERROR",
            status_code=code,
            resource_path=raw_path,
            reason=msg
        )
        return jsonify({
            "error": "Access Denied" if code == 403 else "Not Found",
            "message": msg,
            "request_id": request_id
        }), code

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=user.get("username"),
        action="READ_FILE",
        status="ALLOWED",
        status_code=200,
        resource_path=raw_path,
        reason="File content retrieved"
    )

    return jsonify({
        "file": file_data,
        "request_id": request_id
    }), 200

@file_bp.route("/download", methods=["GET"])
@login_required
def download_file():
    """Stream download file with AuthZ and Proxy verification."""
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"
    raw_path = request.args.get("path", "")

    if not raw_path:
        return jsonify({"error": "Bad Request", "message": "Missing 'path' parameter.", "request_id": request_id}), 400

    # Proxy check
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(raw_path, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({"error": "Path Traversal Blocked", "message": err_msg, "request_id": request_id}), 403

    # AuthZ check
    allowed, reason, _ = ACLEngine.check_permission(user, raw_path, "READ")
    if not allowed:
        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=user.get("username"),
            action="DOWNLOAD_FILE",
            status="DENIED_AUTHZ",
            status_code=403,
            resource_path=raw_path,
            reason=reason
        )
        return jsonify({"error": "Forbidden", "message": f"403 Forbidden - {reason}", "request_id": request_id}), 403

    phys_path = FileService.get_physical_path(raw_path)
    if not phys_path.exists() or not phys_path.is_file():
        return jsonify({"error": "Not Found", "message": "File does not exist.", "request_id": request_id}), 404

    SecurityAuditLogger.log(
        request_id=request_id,
        client_ip=client_ip,
        username=user.get("username"),
        action="DOWNLOAD_FILE",
        status="ALLOWED",
        status_code=200,
        resource_path=raw_path,
        reason="File download streamed"
    )

    return send_file(phys_path, as_attachment=True, download_name=phys_path.name)

@file_bp.route("/write", methods=["POST"])
@login_required
def write_file():
    """
    Create or edit a file via JSON payload.
    Enforces Proxy path validation, AuthZ WRITE check, and Antivirus inspection.
    """
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"

    data = request.get_json(silent=True) or {}
    raw_path = data.get("path", "")
    filename = data.get("filename", "")
    content = data.get("content", "")

    # If updating existing file, path may contain the filename
    if not filename and raw_path:
        path_obj = Path(raw_path)
        filename = path_obj.name
        raw_path = str(path_obj.parent).replace("\\", "/")

    if not filename:
        return jsonify({"error": "Bad Request", "message": "Filename is required.", "request_id": request_id}), 400

    # 1. Proxy Path Traversal Check
    combined = f"{raw_path.rstrip('/')}/{filename}"
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(combined, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({
            "error": "Proxy Violation - Path Traversal Blocked",
            "message": err_msg,
            "request_id": request_id
        }), 403

    content_bytes = content.encode("utf-8")

    # 2. Perform File Write with AuthZ and Antivirus Scan
    ok, code, msg, result_data = FileService.write_file(
        user=user,
        relative_path=raw_path,
        filename=filename,
        content_bytes=content_bytes,
        client_ip=client_ip,
        request_id=request_id
    )

    if not ok:
        return jsonify({
            "error": "Operation Failed",
            "message": msg,
            "details": result_data,
            "request_id": request_id
        }), code

    return jsonify({
        "message": msg,
        "file": result_data,
        "request_id": request_id
    }), code

@file_bp.route("/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Upload a binary or text file using multipart/form-data.
    Enforces Proxy validation, AuthZ WRITE, and Antivirus scan.
    """
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"

    if "file" not in request.files:
        return jsonify({"error": "Bad Request", "message": "No file uploaded.", "request_id": request_id}), 400

    file_obj = request.files["file"]
    if not file_obj.filename:
        return jsonify({"error": "Bad Request", "message": "No selected file.", "request_id": request_id}), 400

    raw_path = request.form.get("path", "/")
    filename = file_obj.filename

    # 1. Proxy Path Traversal Check
    combined = f"{raw_path.rstrip('/')}/{filename}"
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(combined, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({
            "error": "Proxy Violation - Path Traversal Blocked",
            "message": err_msg,
            "request_id": request_id
        }), 403

    content_bytes = file_obj.read()

    # 2. Commit file with Antivirus and AuthZ checks
    ok, code, msg, result_data = FileService.write_file(
        user=user,
        relative_path=raw_path,
        filename=filename,
        content_bytes=content_bytes,
        client_ip=client_ip,
        request_id=request_id
    )

    if not ok:
        return jsonify({
            "error": "Security Alert - File Blocked" if code == 422 else "Access Denied",
            "message": msg,
            "details": result_data,
            "request_id": request_id
        }), code

    return jsonify({
        "message": msg,
        "file": result_data,
        "request_id": request_id
    }), code

@file_bp.route("/mkdir", methods=["POST"])
@login_required
def mkdir():
    """Create a new folder."""
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"

    data = request.get_json(silent=True) or {}
    raw_path = data.get("path", "/")
    dir_name = data.get("dir_name", "").strip()

    if not dir_name:
        return jsonify({"error": "Bad Request", "message": "Directory name is required.", "request_id": request_id}), 400

    # Proxy Traversal Check
    combined = f"{raw_path.rstrip('/')}/{dir_name}"
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(combined, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({"error": "Proxy Violation", "message": err_msg, "request_id": request_id}), 403

    ok, code, msg = FileService.create_directory(user, raw_path, dir_name, client_ip, request_id)
    if not ok:
        return jsonify({"error": "Failed", "message": msg, "request_id": request_id}), code

    return jsonify({"message": msg, "request_id": request_id}), code

@file_bp.route("/delete", methods=["DELETE", "POST"])
@login_required
def delete_file():
    """Delete file or folder."""
    user = g.current_user
    request_id = getattr(g, "request_id", "NO-REQ-ID")
    client_ip = request.remote_addr or "127.0.0.1"

    data = request.get_json(silent=True) or {}
    raw_path = data.get("path") or request.args.get("path", "")

    if not raw_path:
        return jsonify({"error": "Bad Request", "message": "Path is required.", "request_id": request_id}), 400

    # Proxy Traversal Check
    is_safe, err_msg, _ = ProxyLayer.validate_safe_path(raw_path, request_id, client_ip, user.get("username"))
    if not is_safe:
        return jsonify({"error": "Proxy Violation", "message": err_msg, "request_id": request_id}), 403

    ok, code, msg = FileService.delete_resource(user, raw_path, client_ip, request_id)
    if not ok:
        return jsonify({"error": "Forbidden" if code == 403 else "Error", "message": msg, "request_id": request_id}), code

    return jsonify({"message": msg, "request_id": request_id}), code

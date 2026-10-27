import os
import shutil
import datetime
import base64
import mimetypes
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

from app.config import SECURE_STORAGE_DIR
from app.acl_engine import ACLEngine, normalize_path
from app.antivirus_layer import AntivirusLayer
from app.audit_logger import SecurityAuditLogger
from app.proxy_layer import ProxyLayer

class FileService:
    @staticmethod
    def get_physical_path(relative_path: str) -> Path:
        """Resolve clean relative path to absolute secure storage location."""
        norm = normalize_path(relative_path).lstrip("/")
        return (SECURE_STORAGE_DIR / norm).resolve()

    @staticmethod
    def list_directory(user: Dict[str, Any], relative_path: str) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        List items in folder, annotating each item with the user's specific permissions.
        """
        norm_path = normalize_path(relative_path)
        
        # Verify user has read access to this folder
        allowed, reason, _ = ACLEngine.check_permission(user, norm_path, "READ")
        if not allowed:
            return False, reason, []

        target_dir = FileService.get_physical_path(norm_path)
        if not target_dir.exists() or not target_dir.is_dir():
            return False, f"Directory '{norm_path}' not found.", []

        items = []
        for entry in os.scandir(target_dir):
            child_rel = f"{norm_path.rstrip('/')}/{entry.name}"
            # Check effective permission for this specific child
            child_perms = ACLEngine.get_effective_permissions(user, child_rel)
            
            # Non-admin users don't see items with "No Access" if hidden or can see badge
            # In our enterprise file explorer, we display item with "No Access" badge so user sees the ACL in action!
            stat_res = entry.stat()
            mod_time = datetime.datetime.fromtimestamp(stat_res.st_mtime, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            
            items.append({
                "name": entry.name,
                "path": child_rel,
                "is_dir": entry.is_dir(),
                "size": stat_res.st_size if entry.is_file() else 0,
                "modified_at": mod_time,
                "permissions": child_perms
            })

        # Sort: directories first, then alphabetical
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return True, "", items

    @staticmethod
    def read_file(user: Dict[str, Any], relative_path: str) -> Tuple[bool, int, str, Optional[Dict[str, Any]]]:
        """
        Read file contents. Checks AuthZ READ permission.
        Safely supports images (Base64), PDF, UTF-8 text, and binary formats.
        """
        norm_path = normalize_path(relative_path)
        allowed, reason, _ = ACLEngine.check_permission(user, norm_path, "READ")
        if not allowed:
            return False, 403, f"403 Forbidden - {reason}", None

        phys_path = FileService.get_physical_path(norm_path)
        if not phys_path.exists() or not phys_path.is_file():
            return False, 404, f"File '{norm_path}' does not exist.", None

        ext = phys_path.suffix.lower()
        image_exts = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico"}
        is_img = ext in image_exts

        try:
            raw_bytes = phys_path.read_bytes()
            # Check magic bytes for images even if no extension
            if not is_img and len(raw_bytes) >= 4:
                if raw_bytes[:4] == b"\x89PNG" or raw_bytes[:3] == b"\xff\xd8\xff" or raw_bytes[:4] == b"GIF8":
                    is_img = True

            if is_img:
                mime = mimetypes.guess_type(phys_path.name)[0] or "image/png"
                b64 = base64.b64encode(raw_bytes).decode("ascii")
                return True, 200, "", {
                    "path": norm_path,
                    "filename": phys_path.name,
                    "content": f"data:{mime};base64,{b64}",
                    "is_binary": True,
                    "is_image": True,
                    "is_pdf": False,
                    "mime_type": mime,
                    "size": len(raw_bytes)
                }

            if ext == ".pdf" or (len(raw_bytes) >= 4 and raw_bytes[:4] == b"%PDF"):
                return True, 200, "", {
                    "path": norm_path,
                    "filename": phys_path.name,
                    "content": "[Tài liệu PDF - Nhấn 'Tải xuống' để mở và xem]",
                    "is_binary": True,
                    "is_image": False,
                    "is_pdf": True,
                    "mime_type": "application/pdf",
                    "size": len(raw_bytes)
                }

            # Try decoding as text safely
            content = raw_bytes.decode("utf-8", errors="replace")
            if "\x00" in content[:1024]:
                return True, 200, "", {
                    "path": norm_path,
                    "filename": phys_path.name,
                    "content": f"[Tệp tin định dạng nhị phân ({len(raw_bytes)} bytes) - Nhấn 'Tải xuống' để mở]",
                    "is_binary": True,
                    "is_image": False,
                    "is_pdf": False,
                    "mime_type": "application/octet-stream",
                    "size": len(raw_bytes)
                }

            mime = mimetypes.guess_type(phys_path.name)[0] or "text/plain"
            return True, 200, "", {
                "path": norm_path,
                "filename": phys_path.name,
                "content": content,
                "is_binary": False,
                "is_image": False,
                "is_pdf": False,
                "mime_type": mime,
                "size": len(raw_bytes)
            }
        except Exception as e:
            return False, 500, f"Lỗi đọc tệp tin: {str(e)}", None

    @staticmethod
    def write_file(
        user: Dict[str, Any],
        relative_path: str,
        filename: str,
        content_bytes: bytes,
        client_ip: str,
        request_id: str
    ) -> Tuple[bool, int, str, Optional[Dict[str, Any]]]:
        """
        Write / upload / edit file:
        1. Checks AuthZ WRITE permission on destination.
        2. Executes multi-stage Antivirus scan.
        3. If clean, commits file to disk and records audit log.
        """
        norm_dir = normalize_path(relative_path)
        target_path = f"{norm_dir.rstrip('/')}/{filename}"
        
        # 1. Check Authorization (AuthZ)
        allowed, reason, _ = ACLEngine.check_permission(user, target_path, "WRITE")
        if not allowed:
            # Also check if user has write access to the parent folder
            parent_allowed, parent_reason, _ = ACLEngine.check_permission(user, norm_dir, "WRITE")
            if not parent_allowed:
                SecurityAuditLogger.log(
                    request_id=request_id,
                    client_ip=client_ip,
                    username=user.get("username"),
                    action="FILE_WRITE",
                    status="DENIED_AUTHZ",
                    status_code=403,
                    resource_path=target_path,
                    reason=f"Insufficient write permissions: {reason}"
                )
                return False, 403, f"403 Forbidden - Insufficient Write Permission on '{target_path}'.", None

        # 2. Antivirus Inspection
        is_clean, threat_report = AntivirusLayer.scan_payload(
            filename=filename,
            content_bytes=content_bytes,
            uploader_ip=client_ip,
            uploader_username=user.get("username", "ANONYMOUS"),
            target_path=target_path,
            request_id=request_id
        )
        if not is_clean:
            return False, 422, f"Antivirus Alert: Malware detected in '{filename}'. File isolated to quarantine zone.", threat_report

        # 3. Commit file safely
        phys_target = FileService.get_physical_path(target_path)
        phys_target.parent.mkdir(parents=True, exist_ok=True)
        
        with open(phys_target, "wb") as f:
            f.write(content_bytes)

        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=user.get("username"),
            action="FILE_WRITE",
            status="ALLOWED",
            status_code=200,
            resource_path=target_path,
            reason="File successfully scanned, written, and verified."
        )

        return True, 200, "File written successfully.", {
            "path": target_path,
            "filename": filename,
            "size": len(content_bytes),
            "status": "SECURED_AND_COMMITTED"
        }

    @staticmethod
    def create_directory(
        user: Dict[str, Any],
        parent_path: str,
        dir_name: str,
        client_ip: str,
        request_id: str
    ) -> Tuple[bool, int, str]:
        """Create new directory within parent path."""
        norm_parent = normalize_path(parent_path)
        new_path = f"{norm_parent.rstrip('/')}/{dir_name}"
        
        allowed, reason, _ = ACLEngine.check_permission(user, new_path, "WRITE")
        if not allowed:
            allowed, reason, _ = ACLEngine.check_permission(user, norm_parent, "WRITE")
            if not allowed:
                SecurityAuditLogger.log(
                    request_id=request_id,
                    client_ip=client_ip,
                    username=user.get("username"),
                    action="MKDIR",
                    status="DENIED_AUTHZ",
                    status_code=403,
                    resource_path=new_path,
                    reason=reason
                )
                return False, 403, f"403 Forbidden - {reason}"

        phys_dir = FileService.get_physical_path(new_path)
        if phys_dir.exists():
            return False, 400, "Directory already exists."

        phys_dir.mkdir(parents=True, exist_ok=True)
        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=user.get("username"),
            action="MKDIR",
            status="ALLOWED",
            status_code=201,
            resource_path=new_path,
            reason="Directory created."
        )
        return True, 201, "Directory created successfully."

    @staticmethod
    def delete_resource(
        user: Dict[str, Any],
        relative_path: str,
        client_ip: str,
        request_id: str
    ) -> Tuple[bool, int, str]:
        """Delete file or directory."""
        norm_path = normalize_path(relative_path)
        if norm_path == "/":
            return False, 400, "Cannot delete root directory."

        allowed, reason, _ = ACLEngine.check_permission(user, norm_path, "DELETE")
        if not allowed:
            SecurityAuditLogger.log(
                request_id=request_id,
                client_ip=client_ip,
                username=user.get("username"),
                action="DELETE",
                status="DENIED_AUTHZ",
                status_code=403,
                resource_path=norm_path,
                reason=reason
            )
            return False, 403, f"403 Forbidden - {reason}"

        phys_target = FileService.get_physical_path(norm_path)
        if not phys_target.exists():
            return False, 404, "Target resource does not exist."

        if phys_target.is_dir():
            shutil.rmtree(phys_target)
        else:
            phys_target.unlink()

        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=client_ip,
            username=user.get("username"),
            action="DELETE",
            status="ALLOWED",
            status_code=200,
            resource_path=norm_path,
            reason="Resource deleted successfully."
        )
        return True, 200, "Resource deleted successfully."

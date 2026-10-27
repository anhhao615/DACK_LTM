from typing import Optional, Dict, Any, Tuple, List
from pathlib import PurePosixPath
from app.database import get_db

def normalize_path(path_str: str) -> str:
    """Normalize a resource path to standard posix format with leading slash."""
    if not path_str or path_str.strip() == "":
        return "/"
    p = path_str.replace("\\", "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    # Collapse consecutive slashes and resolve . or ..
    pure = PurePosixPath(p)
    parts = []
    for part in pure.parts:
        if part in ("/", ""):
            continue
        elif part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)
    normalized = "/" + "/".join(parts)
    return normalized

def get_ancestor_paths(path_str: str) -> List[str]:
    """
    Generate ancestor paths from closest parent up to root.
    E.g. '/a/b/c' -> ['/a/b', '/a', '/']
    """
    normalized = normalize_path(path_str)
    if normalized == "/":
        return []
    ancestors = []
    curr = PurePosixPath(normalized).parent
    while str(curr) != "/":
        ancestors.append(str(curr))
        curr = curr.parent
    ancestors.append("/")
    return ancestors

class ACLEngine:
    @staticmethod
    def check_permission(
        user: Dict[str, Any],
        resource_path: str,
        action: str
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Evaluate granular permissions for a user on a given path.
        Action must be one of: 'READ', 'WRITE', 'DELETE'.
        Returns (is_allowed, reason, matched_rule).
        
        Evaluation hierarchy:
        1. ADMIN role has global full access.
        2. Explicit Deny on specific resource (User > Role).
        3. Explicit Allow on specific resource (User > Role).
        4. Inherited permissions from parent directories (closest ancestor first).
        5. Default: Deny.
        """
        norm_path = normalize_path(resource_path)
        action_upper = action.upper()
        
        # 1. Superadmin role bypass
        if user.get("role") == "ADMIN":
            return True, "Admin Role has unrestricted access.", {"type": "ADMIN_BYPASS"}
        
        user_id = user.get("id")
        user_role = user.get("role", "GUEST")
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Fetch all rules for exact path and all ancestors in one query
            check_paths = [norm_path] + get_ancestor_paths(norm_path)
            placeholders = ",".join(["?"] * len(check_paths))
            
            cursor.execute(
                f"""
                SELECT * FROM file_permissions 
                WHERE resource_path IN ({placeholders})
                AND (user_id = ? OR (role = ? AND user_id IS NULL))
                """,
                (*check_paths, user_id, user_role)
            )
            rules = [dict(r) for r in cursor.fetchall()]
            
        # Group rules by path and target (user vs role)
        # Prioritize exact path first, then ancestors in order of depth
        for target_path in check_paths:
            path_rules = [r for r in rules if r["resource_path"] == target_path]
            if not path_rules:
                continue
            
            # User-specific rules take precedence over role-specific rules
            user_rule = next((r for r in path_rules if r["user_id"] == user_id), None)
            role_rule = next((r for r in path_rules if r["role"] == user_role and r["user_id"] is None), None)
            
            evaluated_rule = user_rule if user_rule is not None else role_rule
            if evaluated_rule is not None:
                # Check Explicit Deny
                if evaluated_rule["is_deny"]:
                    return False, f"Explicit Deny rule active on '{target_path}'.", evaluated_rule
                
                # Check requested action
                if action_upper == "READ":
                    if evaluated_rule["can_read"]:
                        return True, f"Read allowed via rule on '{target_path}'.", evaluated_rule
                    else:
                        return False, f"Insufficient Read Permission on '{target_path}'.", evaluated_rule
                        
                elif action_upper == "WRITE":
                    if evaluated_rule["can_write"]:
                        return True, f"Write allowed via rule on '{target_path}'.", evaluated_rule
                    else:
                        return False, f"Read-Only Access - Write forbidden on '{target_path}'.", evaluated_rule
                        
                elif action_upper == "DELETE":
                    if evaluated_rule["can_delete"]:
                        return True, f"Delete allowed via rule on '{target_path}'.", evaluated_rule
                    else:
                        return False, f"Delete forbidden on '{target_path}'.", evaluated_rule
        
        # Default Deny if no matching ACL exists
        return False, f"Default Deny: No ACL permits {action_upper} on '{norm_path}'.", None

    @staticmethod
    def get_effective_permissions(user: Dict[str, Any], resource_path: str) -> Dict[str, Any]:
        """Compute the full permission matrix and user-friendly badge for a path."""
        can_read, _, _ = ACLEngine.check_permission(user, resource_path, "READ")
        can_write, _, _ = ACLEngine.check_permission(user, resource_path, "WRITE")
        can_delete, _, _ = ACLEngine.check_permission(user, resource_path, "DELETE")
        
        if user.get("role") == "ADMIN":
            badge = "Admin Full Access"
        elif can_read and can_write:
            badge = "Read & Write"
        elif can_read:
            badge = "Read-Only"
        else:
            badge = "No Access"
            
        return {
            "resource_path": normalize_path(resource_path),
            "can_read": can_read,
            "can_write": can_write,
            "can_delete": can_delete,
            "badge": badge
        }

    @staticmethod
    def set_permission(
        resource_path: str,
        user_id: Optional[int] = None,
        role: Optional[str] = None,
        can_read: int = 0,
        can_write: int = 0,
        can_delete: int = 0,
        is_deny: int = 0
    ) -> int:
        """Create or update an ACL rule."""
        norm_path = normalize_path(resource_path)
        with get_db() as conn:
            cursor = conn.cursor()
            # Check existing rule
            cursor.execute(
                """
                SELECT id FROM file_permissions 
                WHERE resource_path = ? AND 
                      ((user_id = ? AND ? IS NOT NULL) OR (role = ? AND user_id IS NULL AND ? IS NOT NULL))
                """,
                (norm_path, user_id, user_id, role, role)
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    """
                    UPDATE file_permissions
                    SET can_read = ?, can_write = ?, can_delete = ?, is_deny = ?
                    WHERE id = ?
                    """,
                    (can_read, can_write, can_delete, is_deny, existing["id"])
                )
                return existing["id"]
            else:
                cursor.execute(
                    """
                    INSERT INTO file_permissions (resource_path, user_id, role, can_read, can_write, can_delete, is_deny)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (norm_path, user_id, role, can_read, can_write, can_delete, is_deny)
                )
                return cursor.lastrowid

    @staticmethod
    def delete_permission(rule_id: int) -> bool:
        """Remove an ACL rule."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM file_permissions WHERE id = ?", (rule_id,))
            return cursor.rowcount > 0

    @staticmethod
    def list_all_permissions() -> List[Dict[str, Any]]:
        """List all permission rules with user and role metadata."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT p.*, u.username, u.full_name 
                FROM file_permissions p
                LEFT JOIN users u ON p.user_id = u.id
                ORDER BY p.resource_path ASC, p.id ASC
                """
            )
            return [dict(r) for r in cursor.fetchall()]

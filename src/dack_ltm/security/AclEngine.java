package dack_ltm.security;

import java.util.*;
import dack_ltm.database.JsonDataStore;
import dack_ltm.models.FilePermission;
import dack_ltm.models.User;

public class AclEngine {

    public static class AuthZResult {
        public boolean allowed;
        public String reason;
        public String badge;

        public AuthZResult(boolean allowed, String reason, String badge) {
            this.allowed = allowed;
            this.reason = reason;
            this.badge = badge;
        }
    }

    public static String normalizePath(String path) {
        if (path == null || path.trim().isEmpty() || path.equals("/")) {
            return "/";
        }
        String p = path.replace("\\", "/").trim();
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        String[] parts = p.split("/+");
        List<String> validParts = new ArrayList<>();
        for (String part : parts) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (part.equals("..")) {
                if (!validParts.isEmpty()) validParts.remove(validParts.size() - 1);
            } else {
                validParts.add(part);
            }
        }
        return "/" + String.join("/", validParts);
    }

    public static List<String> getAncestorPaths(String path) {
        String norm = normalizePath(path);
        List<String> ancestors = new ArrayList<>();
        if (norm.equals("/")) return ancestors;

        int lastSlash = norm.lastIndexOf('/');
        while (lastSlash > 0) {
            norm = norm.substring(0, lastSlash);
            ancestors.add(norm);
            lastSlash = norm.lastIndexOf('/');
        }
        ancestors.add("/");
        return ancestors;
    }

    public static AuthZResult checkPermission(User user, String resourcePath, String action) {
        if (user == null) {
            return new AuthZResult(false, "Người dùng chưa xác thực (Chưa đăng nhập).", "Không có quyền");
        }

        // 1. Superadmin Bypass
        if ("ADMIN".equalsIgnoreCase(user.getRole())) {
            return new AuthZResult(true, "Vai trò Quản trị viên (Admin) có toàn quyền truy cập.", "Toàn quyền Quản trị");
        }

        String normPath = normalizePath(resourcePath);
        String actionUpper = action.toUpperCase();
        List<String> checkPaths = new ArrayList<>();
        checkPaths.add(normPath);
        checkPaths.addAll(getAncestorPaths(normPath));

        List<FilePermission> allRules = JsonDataStore.getInstance().getAllPermissions();

        for (String targetPath : checkPaths) {
            FilePermission matchedUserRule = null;
            FilePermission matchedRoleRule = null;

            for (FilePermission p : allRules) {
                if (normalizePath(p.getResourcePath()).equals(targetPath)) {
                    if (p.getUserId() != null && p.getUserId() == user.getId()) {
                        matchedUserRule = p;
                    } else if (p.getRole() != null && p.getRole().equalsIgnoreCase(user.getRole())) {
                        matchedRoleRule = p;
                    }
                }
            }

            FilePermission evalRule = (matchedUserRule != null) ? matchedUserRule : matchedRoleRule;
            if (evalRule != null) {
                // Kiểm tra Explicit Deny
                if (evalRule.isDeny()) {
                    return new AuthZResult(false, "Quy tắc Cấm tuyệt đối (Explicit Deny) đang kích hoạt trên '" + targetPath + "'.", "Không có quyền");
                }

                if (actionUpper.equals("READ")) {
                    if (evalRule.isCanRead()) {
                        return new AuthZResult(true, "Cho phép Đọc trên '" + targetPath + "'.", "Chỉ Đọc");
                    } else {
                        return new AuthZResult(false, "Không có quyền Đọc (Xem) trên '" + targetPath + "'.", "Không có quyền");
                    }
                } else if (actionUpper.equals("WRITE")) {
                    if (evalRule.isCanWrite()) {
                        return new AuthZResult(true, "Cho phép Ghi trên '" + targetPath + "'.", "Đọc & Ghi");
                    } else {
                        return new AuthZResult(false, "Chế độ Chỉ Đọc: Thao tác Ghi bị từ chối trên '" + targetPath + "'.", "Chỉ Đọc");
                    }
                } else if (actionUpper.equals("DELETE")) {
                    if (evalRule.isCanDelete()) {
                        return new AuthZResult(true, "Cho phép Xóa trên '" + targetPath + "'.", "Đọc & Ghi");
                    } else {
                        return new AuthZResult(false, "Không có quyền Xóa trên '" + targetPath + "'.", "Chỉ Đọc");
                    }
                }
            }
        }

        return new AuthZResult(false, "Mặc định từ chối: Không có quy tắc ACL nào cho phép thao tác " + actionUpper + " trên '" + normPath + "'.", "Không có quyền");
    }

    public static String getEffectiveBadge(User user, String resourcePath) {
        if (user == null) return "Không có quyền";
        if ("ADMIN".equalsIgnoreCase(user.getRole())) return "Toàn quyền Quản trị";

        boolean canRead = checkPermission(user, resourcePath, "READ").allowed;
        boolean canWrite = checkPermission(user, resourcePath, "WRITE").allowed;

        if (canRead && canWrite) return "Đọc & Ghi";
        if (canRead) return "Chỉ Đọc";
        return "Không có quyền";
    }
}

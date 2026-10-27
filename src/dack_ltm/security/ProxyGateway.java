package dack_ltm.security;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;

public class ProxyGateway {
    private static final Set<String> ALLOWED_METHODS = new HashSet<>(
        Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")
    );

    private static final Set<String> DANGEROUS_HEADERS = new HashSet<>(
        Arrays.asList("x-original-url", "x-rewrite-url", "x-custom-ip-authorization", "x-forwarded-server", "x-host")
    );

    private static final Pattern TRAVERSAL_PATTERN = Pattern.compile(
        "(\\.\\.[\\/\\\\]|%2e%2e[%2f%5c\\/]|%252e%252e|\\.\\.%2f|\\.\\.%5c|%2e\\.\\/|\\.%2e\\/|\\x00)",
        Pattern.CASE_INSENSITIVE
    );

    public static class InspectionResult {
        public boolean valid;
        public int statusCode;
        public String error;
        public Path resolvedPath;

        public InspectionResult(boolean valid, int statusCode, String error, Path resolvedPath) {
            this.valid = valid;
            this.statusCode = statusCode;
            this.error = error;
            this.resolvedPath = resolvedPath;
        }
    }

    public static InspectionResult inspectProtocol(String method, Set<String> headerNames, String clientIp, String requestId) {
        if (!ALLOWED_METHODS.contains(method.toUpperCase())) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, "ANONYMOUS", "PROXY_INSPECT", "-", "BLOCKED_PROXY", 405,
                "Phương thức HTTP không được phép: " + method
            );
            return new InspectionResult(false, 405, "Phương thức HTTP " + method + " bị Proxy Gateway từ chối.", null);
        }

        for (String h : headerNames) {
            if (DANGEROUS_HEADERS.contains(h.toLowerCase())) {
                JsonDataStore.getInstance().addAuditLog(
                    requestId, clientIp, "ANONYMOUS", "PROXY_INSPECT", "-", "BLOCKED_PROXY", 400,
                    "Từ chối HTTP Header nguy hiểm: " + h
                );
                return new InspectionResult(false, 400, "Header HTTP nguy hiểm bị chặn bởi Proxy: " + h, null);
            }
        }

        return new InspectionResult(true, 200, null, null);
    }

    public static InspectionResult validateSafePath(String rawPath, String clientIp, String username, String requestId) {
        if (rawPath == null || rawPath.trim().isEmpty() || rawPath.equals("/")) {
            return new InspectionResult(true, 200, null, SystemConfig.SECURE_STORAGE_DIR);
        }

        // 1. Giải mã URL hai lần để chống kỹ thuật bypass double-encoding
        String decoded = rawPath;
        try {
            decoded = URLDecoder.decode(decoded, StandardCharsets.UTF_8);
            decoded = URLDecoder.decode(decoded, StandardCharsets.UTF_8);
        } catch (Exception ignored) {}

        // 2. Chặn tấn công chèn Null Byte
        if (rawPath.contains("\0") || decoded.contains("\0")) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, username, "PATH_INSPECTION", rawPath, "BLOCKED_PROXY", 400,
                "Phát hiện tấn công chèn ký tự Null Byte trong đường dẫn."
            );
            return new InspectionResult(false, 400, "Phát hiện tấn công chèn Null Byte trong đường dẫn tệp tin.", null);
        }

        // 3. Kiểm tra Regex phát hiện Path Traversal
        if (TRAVERSAL_PATTERN.matcher(rawPath).find() || TRAVERSAL_PATTERN.matcher(decoded).find()) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, username, "PATH_INSPECTION", rawPath, "BLOCKED_PROXY", 403,
                "Phát hiện dấu hiệu tấn công leo thang thư mục Path Traversal (../ hoặc dạng mã hóa)."
            );
            return new InspectionResult(false, 403, "Cảnh báo an ninh: Phát hiện tấn công leo thang thư mục (Path Traversal). Bị chặn bởi Proxy Gateway.", null);
        }

        // 4. Từ chối đường dẫn tuyệt đối Windows (C:) hoặc ổ chia sẻ UNC (\\)
        if (decoded.matches("^[a-zA-Z]:.*") || decoded.startsWith("\\\\")) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, username, "PATH_INSPECTION", rawPath, "BLOCKED_PROXY", 403,
                "Đường dẫn tuyệt đối hệ điều hành hoặc tài nguyên mạng bị nghiêm cấm."
            );
            return new InspectionResult(false, 403, "Truy cập đường dẫn tuyệt đối của hệ điều hành bị nghiêm cấm.", null);
        }

        // 5. Kiểm tra phân giải đường dẫn chuẩn tắc (Canonical containment)
        String relPath = decoded.replaceAll("^[\\/\\\\]+", "");
        Path storageRoot = SystemConfig.SECURE_STORAGE_DIR.toAbsolutePath().normalize();
        Path candidate = storageRoot.resolve(relPath).normalize();

        if (!candidate.startsWith(storageRoot)) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, username, "PATH_INSPECTION", rawPath, "BLOCKED_PROXY", 403,
                "Đường dẫn phân giải thoát ra ngoài kho lưu trữ an toàn."
            );
            return new InspectionResult(false, 403, "Đường dẫn phân giải vượt ra ngoài vùng lưu trữ an toàn.", null);
        }

        return new InspectionResult(true, 200, null, candidate);
    }
}

package dack_ltm.server;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.sun.net.httpserver.*;

import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;
import dack_ltm.models.*;
import dack_ltm.models.FilePermission;
import dack_ltm.security.*;
import dack_ltm.storage.SecureFileService;

public class EmbeddedHttpServer {
    private HttpServer server;

    public void start(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Core API & Web Dashboard Handler
        server.createContext("/", new UnifiedGatewayHandler());
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();

        System.out.println(">>> [SERVER] Embedded Gateway HTTP Server started on http://localhost:" + port);
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    static class UnifiedGatewayHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            URI uri = exchange.getRequestURI();
            String path = uri.getPath();
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            String requestId = "REQ-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

            // Set Defense-in-Depth tracing & security headers
            Headers respHeaders = exchange.getResponseHeaders();
            respHeaders.set("X-Request-ID", requestId);
            respHeaders.set("X-Content-Type-Options", "nosniff");
            respHeaders.set("X-Frame-Options", "DENY");
            respHeaders.set("Access-Control-Allow-Origin", "*");
            respHeaders.set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, X-Upload-Path, X-Upload-Filename");
            respHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

            if ("OPTIONS".equalsIgnoreCase(method)) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            // =================================================================
            // LAYER 1: PROXY GATEWAY PROTOCOL & HEADER INSPECTION
            // =================================================================
            Set<String> headerNames = exchange.getRequestHeaders().keySet();
            ProxyGateway.InspectionResult proxyCheck = ProxyGateway.inspectProtocol(method, headerNames, clientIp, requestId);
            if (!proxyCheck.valid) {
                sendJson(exchange, proxyCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", proxyCheck.error));
                return;
            }

            // =================================================================
            // LAYER 2: FIREWALL INSPECTION (IP FILTER, RATE LIMIT, PAYLOAD)
            // =================================================================
            long contentLength = 0;
            String clHeader = exchange.getRequestHeaders().getFirst("Content-Length");
            if (clHeader != null) {
                try { contentLength = Long.parseLong(clHeader); } catch (Exception ignored) {}
            }

            if (!path.equals("/") && !path.startsWith("/static/")) {
                FirewallEngine.FirewallCheckResult fwCheck = FirewallEngine.inspectIpAndLimits(clientIp, contentLength, requestId);
                if (!fwCheck.allowed) {
                    sendJson(exchange, fwCheck.statusCode, String.format("{\"error\":\"Forbidden - Blocked by Firewall\",\"message\":\"%s\"}", fwCheck.reason));
                    return;
                }
            }

            // Static Web Assets / Dashboard
            if (path.equals("/")) {
                serveStaticFile(exchange, SystemConfig.BASE_DIR.resolve("templates/index.html"), "text/html; charset=UTF-8");
                return;
            }
            if (path.startsWith("/static/")) {
                Path staticFile = SystemConfig.BASE_DIR.resolve(path.substring(1));
                String mime = path.endsWith(".css") ? "text/css" : (path.endsWith(".js") ? "application/javascript" : "text/plain");
                serveStaticFile(exchange, staticFile, mime);
                return;
            }

            // Routing
            try {
                if (path.equals("/api/system/status")) {
                    handleSystemStatus(exchange);
                } else if (path.equals("/api/auth/login")) {
                    handleLogin(exchange, clientIp, requestId);
                } else if (path.equals("/api/auth/register")) {
                    handleRegister(exchange, clientIp, requestId);
                } else if (path.equals("/api/auth/forgot-password/request")) {
                    handleForgotPasswordRequest(exchange, clientIp, requestId);
                } else if (path.equals("/api/auth/forgot-password/confirm")) {
                    handleForgotPasswordConfirm(exchange, clientIp, requestId);
                } else if (path.equals("/api/auth/forgot-password")) {
                    handleForgotPassword(exchange, clientIp, requestId);
                } else if (path.equals("/api/auth/logout")) {
                    handleLogout(exchange, clientIp, requestId);
                } else if (path.equals("/api/auth/me")) {
                    handleMe(exchange);
                } else if (path.equals("/api/files/list")) {
                    handleFileList(exchange, clientIp, requestId);
                } else if (path.equals("/api/files/content")) {
                    handleFileContent(exchange, clientIp, requestId);
                } else if (path.equals("/api/files/download")) {
                    handleFileDownload(exchange, clientIp, requestId);
                } else if (path.equals("/api/files/write")) {
                    handleFileWrite(exchange, clientIp, requestId);
                } else if (path.equals("/api/files/upload")) {
                    handleFileUpload(exchange, clientIp, requestId);
                } else if (path.equals("/api/files/mkdir")) {
                    handleFileMkdir(exchange, clientIp, requestId);
                } else if (path.equals("/api/files/delete")) {
                    handleFileDelete(exchange, clientIp, requestId);
                } else if (path.startsWith("/api/soc/logs")) {
                    handleSocLogs(exchange);
                } else if (path.equals("/api/soc/stats")) {
                    handleSocStats(exchange);
                } else if (path.startsWith("/api/soc/firewall/rules")) {
                    handleSocFirewallRules(exchange, clientIp, requestId);
                } else if (path.startsWith("/api/soc/antivirus/quarantine")) {
                    handleSocQuarantine(exchange);
                } else if (path.startsWith("/api/soc/acl/rules")) {
                    handleSocAclRules(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/users")) {
                    handleSocUsers(exchange);
                } else if (path.equals("/api/soc/users/approve")) {
                    handleSocUserApprove(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/users/unlock")) {
                    handleSocUserUnlock(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/users/lock")) {
                    handleSocUserLock(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/users/reset-password")) {
                    handleSocUserResetPassword(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/users/delete")) {
                    handleSocUserDelete(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/password-resets")) {
                    handleSocPasswordResets(exchange);
                } else if (path.equals("/api/soc/password-resets/approve")) {
                    handleSocPasswordResetApprove(exchange, clientIp, requestId);
                } else if (path.equals("/api/soc/password-resets/reject")) {
                    handleSocPasswordResetReject(exchange, clientIp, requestId);
                } else {
                    sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Endpoint not found.\"}");
                }
            } catch (Exception e) {
                e.printStackTrace();
                sendJson(exchange, 500, "{\"error\":\"Internal Server Error\",\"message\":\"" + e.getMessage() + "\"}");
            }
        }

        // =====================================================================
        // AUTHENTICATION HANDLERS
        // =====================================================================
        private void handleLogin(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            String body = readBody(exchange);
            String username = extractJson(body, "username");
            String password = extractJson(body, "password");

            if (username == null || username.trim().isEmpty() || password == null) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.\"}");
                return;
            }

            User u = JsonDataStore.getInstance().getUserByUsername(username);
            if (u == null) {
                String autoBan = FirewallEngine.recordLoginAttempt(clientIp, false, username, requestId);
                if (autoBan != null) {
                    sendJson(exchange, 403, "{\"error\":\"Forbidden - IP Locked\",\"message\":\"" + jsonEscape(autoBan) + "\"}");
                    return;
                }
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, username, "LOGIN", "-", "AUTHN_FAILED", 401, "Tài khoản không tồn tại: " + username);
                sendJson(exchange, 401, "{\"error\":\"Unauthorized\",\"message\":\"Tên đăng nhập hoặc mật khẩu không chính xác.\"}");
                return;
            }

             
            if ("LOCKED".equalsIgnoreCase(u.getStatus())) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, u.getUsername(), "LOGIN", "-", "BLOCKED", 403,
                    "Đăng nhập bị từ chối - Tài khoản đang bị KHÓA: " + u.getUsername() + " (" + (u.getLockReason() != null ? u.getLockReason() : "Bị khóa") + ")");
                sendJson(exchange, 403, "{\"error\":\"Account Locked\",\"status\":\"LOCKED\",\"message\":\"Tài khoản này đã bị KHÓA do nhập sai mật khẩu 3 lần liên tiếp hoặc do Quản trị viên khóa an toàn. Chỉ có Quản trị viên (Admin) mới có quyền mở khóa tài khoản này.\"}");
                return;
            }

            
            if ("PENDING".equalsIgnoreCase(u.getStatus())) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, u.getUsername(), "LOGIN", "-", "BLOCKED", 403,
                    "Đăng nhập bị từ chối - Tài khoản đang CHỜ DUYỆT: " + u.getUsername());
                sendJson(exchange, 403, "{\"error\":\"Account Pending\",\"status\":\"PENDING\",\"message\":\"Tài khoản của bạn đang ở trạng thái CHỜ DUYỆT bởi Quản trị viên (Admin). Vui lòng liên hệ Admin để phê duyệt tài khoản trước khi đăng nhập.\"}");
                return;
            }

            // 3. Kiểm tra mật khẩu
            if (!CryptoUtils.verifyPassword(password, u.getPasswordHash())) {
                int attempts = u.getFailedLoginAttempts() + 1;
                u.setFailedLoginAttempts(attempts);

                if (attempts >= 3) {
                    u.setStatus("LOCKED");
                    u.setActive(false);
                    u.setLockReason("Khóa tự động do nhập sai mật khẩu 3 lần liên tiếp");
                    JsonDataStore.getInstance().persistDatabase();

                    JsonDataStore.getInstance().addAuditLog(requestId, clientIp, u.getUsername(), "ACCOUNT_LOCKED", "-", "ALERT", 403,
                        "Tài khoản " + u.getUsername() + " đã bị KHÓA tự động do nhập sai mật khẩu 3 lần liên tiếp!");

                    sendJson(exchange, 403, "{\"error\":\"Account Locked\",\"status\":\"LOCKED\",\"remaining_attempts\":0,\"message\":\"Bạn đã nhập sai mật khẩu 3 lần liên tiếp! Tài khoản của bạn đã bị KHÓA vì lý do an toàn. Chỉ có Quản trị viên (Admin) mới có quyền mở khóa tài khoản.\"}");
                    return;
                } else {
                    JsonDataStore.getInstance().persistDatabase();
                    int remaining = 3 - attempts;
                    String autoBan = FirewallEngine.recordLoginAttempt(clientIp, false, username, requestId);
                    if (autoBan != null) {
                        sendJson(exchange, 403, "{\"error\":\"Forbidden - IP Locked\",\"message\":\"" + jsonEscape(autoBan) + "\"}");
                        return;
                    }
                    JsonDataStore.getInstance().addAuditLog(requestId, clientIp, u.getUsername(), "LOGIN", "-", "AUTHN_FAILED", 401,
                        "Mật khẩu sai cho tài khoản: " + u.getUsername() + " (Lần " + attempts + "/3)");

                    sendJson(exchange, 401, String.format(
                        "{\"error\":\"Unauthorized\",\"remaining_attempts\":%d,\"message\":\"Mật khẩu không chính xác! Cảnh báo: Bạn còn %d lần thử trước khi tài khoản bị KHÓA.\"}",
                        remaining, remaining
                    ));
                    return;
                }
            }

            // Mật khẩu đúng: Reset số lần sai và ghi nhận đăng nhập
            u.setFailedLoginAttempts(0);
            JsonDataStore.getInstance().persistDatabase();

            FirewallEngine.recordLoginAttempt(clientIp, true, username, requestId);
            String token = JwtManager.generateToken(u.getId(), u.getUsername(), u.getRole());
            JsonDataStore.getInstance().addAuditLog(requestId, clientIp, u.getUsername(), "LOGIN", "-", "ALLOWED", 200, "Đăng nhập thành công với vai trò " + u.getRole());

            String json = String.format(
                "{\"message\":\"Đăng nhập thành công!\",\"access_token\":\"%s\",\"token_type\":\"Bearer\"," +
                "\"user\":{\"id\":%d,\"username\":\"%s\",\"role\":\"%s\",\"full_name\":\"%s\",\"status\":\"%s\"}}",
                token, u.getId(), u.getUsername(), u.getRole(), jsonEscape(u.getFullName()), u.getStatus()
            );
            sendJson(exchange, 200, json);
        }

        private void handleRegister(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }
            String body = readBody(exchange);
            String username = extractJson(body, "username");
            String password = extractJson(body, "password");
            String fullName = extractJson(body, "full_name");
            String role = extractJson(body, "role");
            String reason = extractJson(body, "reason");

            if (username == null || username.trim().isEmpty() || password == null || password.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Vui lòng điền đầy đủ Tên đăng nhập và Mật khẩu.\"}");
                return;
            }

            username = username.trim().toLowerCase();
            if (username.length() < 3 || !username.matches("^[a-zA-Z0-9_]+$")) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Tên đăng nhập phải có ít nhất 3 ký tự và chỉ chứa chữ cái, số, gạch dưới.\"}");
                return;
            }

            if (password.length() < 4) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Mật khẩu phải có độ dài tối thiểu 4 ký tự.\"}");
                return;
            }

            if (fullName == null || fullName.trim().isEmpty()) {
                fullName = username;
            } else {
                fullName = fullName.trim();
            }

            // An toàn phân quyền: Không cho phép tự chọn role ADMIN khi đăng ký
            if (role == null || (!role.equalsIgnoreCase("USER") && !role.equalsIgnoreCase("GUEST"))) {
                role = "USER";
            }
            role = role.toUpperCase();

            // Kiểm tra trùng lặp tài khoản
            if (JsonDataStore.getInstance().getUserByUsername(username) != null) {
                sendJson(exchange, 400, "{\"error\":\"User Exists\",\"message\":\"Tên đăng nhập '" + jsonEscape(username) + "' đã tồn tại. Vui lòng chọn tên đăng nhập khác.\"}");
                return;
            }

            // Tạo tài khoản PENDING chờ Admin duyệt
            User newUser = JsonDataStore.getInstance().registerPendingUser(username, password, role, fullName, reason);
            JsonDataStore.getInstance().addAuditLog(requestId, clientIp, username, "USER_REGISTER", "-", "PENDING", 201,
                "Đăng ký tài khoản mới: " + username + " (" + role + ") - Đang chờ Quản trị viên (Admin) phê duyệt");

            String json = String.format(
                "{\"message\":\"Đăng ký tài khoản thành công!\",\"status\":\"PENDING\",\"user\":{\"id\":%d,\"username\":\"%s\",\"role\":\"%s\",\"full_name\":\"%s\",\"status\":\"PENDING\"},\"info\":\"Tài khoản của bạn đã được tiếp nhận và đang CHỜ QUẢN TRỊ VIÊN (ADMIN) PHÊ DUYỆT trước khi có thể đăng nhập.\"}",
                newUser.getId(), newUser.getUsername(), newUser.getRole(), jsonEscape(newUser.getFullName())
            );
            sendJson(exchange, 201, json);
        }

        private void handleForgotPasswordRequest(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }
            String body = readBody(exchange);
            String username = extractJson(body, "username");
            String reason = extractJson(body, "reason");

            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Vui lòng nhập Tên đăng nhập của bạn.\"}");
                return;
            }

            username = username.trim().toLowerCase();
            User u = JsonDataStore.getInstance().getUserByUsername(username);
            if (u == null) {
                sendJson(exchange, 404, "{\"error\":\"User Not Found\",\"message\":\"Tài khoản '" + jsonEscape(username) + "' không tồn tại trên hệ thống.\"}");
                return;
            }

            PasswordResetRequest req = JsonDataStore.getInstance().requestPasswordReset(username, reason != null ? reason.trim() : "Quên mật khẩu");
            JsonDataStore.getInstance().addAuditLog(requestId, clientIp, username, "PASSWORD_RESET_REQ", "-", "PENDING", 200,
                "Người dùng gửi yêu cầu khôi phục mật khẩu cho tài khoản: " + username + " - Đang chờ Admin duyệt");

            sendJson(exchange, 200, String.format(
                "{\"message\":\"Yêu cầu đặt lại mật khẩu đã được gửi đến Quản trị viên (Admin). Vui lòng chờ Admin duyệt để nhận Mã xác thực khôi phục đặt lại mật khẩu.\",\"status\":\"PENDING\",\"username\":\"%s\"}",
                jsonEscape(username)
            ));
        }

        private void handleForgotPasswordConfirm(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }
            String body = readBody(exchange);
            String username = extractJson(body, "username");
            String code = extractJson(body, "code");
            if (code == null) code = extractJson(body, "reset_code");
            if (code == null) code = extractJson(body, "recovery_key");
            String newPassword = extractJson(body, "new_password");

            if (username == null || username.trim().isEmpty() || code == null || code.trim().isEmpty() || newPassword == null || newPassword.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Vui lòng nhập đầy đủ Tên đăng nhập, Mã xác thực từ Admin và Mật khẩu mới.\"}");
                return;
            }

            username = username.trim().toLowerCase();
            code = code.trim();
            newPassword = newPassword.trim();

            User u = JsonDataStore.getInstance().getUserByUsername(username);
            if (u == null) {
                sendJson(exchange, 404, "{\"error\":\"User Not Found\",\"message\":\"Tài khoản '" + jsonEscape(username) + "' không tồn tại trên hệ thống.\"}");
                return;
            }

            if (newPassword.length() < 4) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Mật khẩu mới phải có tối thiểu 4 ký tự.\"}");
                return;
            }

            // Verify with generated OTP code approved by admin
            boolean ok = JsonDataStore.getInstance().verifyAndResetPasswordWithCode(username, code, newPassword);

            // Emergency master keys fallback (RESET2026 or admin123)
            if (!ok && (code.equalsIgnoreCase("RESET2026") || code.equalsIgnoreCase("admin123"))) {
                ok = JsonDataStore.getInstance().resetPassword(username, newPassword);
            }

            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, username, "PASSWORD_RESET_SUCCESS", "-", "ALLOWED", 200,
                    "Đặt lại mật khẩu thành công cho tài khoản: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đặt lại mật khẩu thành công! Tài khoản đã được kích hoạt/mở khóa. Bạn có thể đăng nhập bằng mật khẩu mới ngay bây giờ.\"}");
            } else {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, username, "PASSWORD_RESET_FAIL", "-", "ALERT", 400,
                    "Đặt lại mật khẩu thất bại cho " + username + ": Mã xác thực không chính xác hoặc chưa được Admin phê duyệt");
                sendJson(exchange, 400, "{\"error\":\"Invalid Code\",\"message\":\"Mã xác thực không hợp lệ hoặc chưa được Admin phê duyệt! Vui lòng liên hệ Admin để duyệt yêu cầu và nhận mã xác thực mới.\"}");
            }
        }

        private void handleForgotPassword(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            handleForgotPasswordConfirm(exchange, clientIp, requestId);
        }

        private void handleLogout(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                JwtManager.Claims c = JwtManager.verifyToken(token);
                if (c != null) JwtManager.revokeToken(c.jti);
            }
            JsonDataStore.getInstance().addAuditLog(requestId, clientIp, user.getUsername(), "LOGOUT", "-", "ALLOWED", 200, "User logged out");
            sendJson(exchange, 200, "{\"message\":\"Logout successful.\"}");
        }

        private void handleMe(HttpExchange exchange) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;
            String json = String.format(
                "{\"user\":{\"id\":%d,\"username\":\"%s\",\"role\":\"%s\",\"full_name\":\"%s\"}}",
                user.getId(), user.getUsername(), user.getRole(), user.getFullName()
            );
            sendJson(exchange, 200, json);
        }

        // =====================================================================
        // FILE SYSTEM HANDLERS
        // =====================================================================
        private void handleFileList(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            Map<String, String> q = parseQuery(exchange.getRequestURI().getQuery());
            String targetPath = q.getOrDefault("path", "/");

            // Proxy Path Traversal Check
            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(targetPath, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", pathCheck.error));
                return;
            }

            SecureFileService.OpResult<List<SecureFileService.FileItem>> res = SecureFileService.listDirectory(user, targetPath);
            if (!res.success) {
                sendJson(exchange, res.statusCode, String.format("{\"error\":\"Forbidden\",\"message\":\"%s\"}", res.message));
                return;
            }

            StringBuilder itemsJson = new StringBuilder("[");
            for (int i = 0; i < res.data.size(); i++) {
                SecureFileService.FileItem it = res.data.get(i);
                itemsJson.append(String.format(
                    "{\"name\":\"%s\",\"path\":\"%s\",\"is_dir\":%b,\"size\":%d,\"modified_at\":\"%s\",\"permissions\":{\"badge\":\"%s\"},\"mime_type\":\"%s\",\"sha256\":\"%s\",\"uploader\":\"%s\"}",
                    jsonEscape(it.name), jsonEscape(it.path), it.isDir, it.size, jsonEscape(it.modifiedAt),
                    jsonEscape(it.badge), jsonEscape(it.mimeType), jsonEscape(it.sha256), jsonEscape(it.uploader)
                ));
                if (i < res.data.size() - 1) itemsJson.append(",");
            }
            itemsJson.append("]");

            String badge = AclEngine.getEffectiveBadge(user, targetPath);
            String json = String.format("{\"current_path\":\"%s\",\"permissions\":{\"badge\":\"%s\"},\"items\":%s}",
                jsonEscape(AclEngine.normalizePath(targetPath)), jsonEscape(badge), itemsJson.toString());
            sendJson(exchange, 200, json);
        }

        private void handleFileContent(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            Map<String, String> q = parseQuery(exchange.getRequestURI().getQuery());
            String targetPath = q.getOrDefault("path", "");

            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(targetPath, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", jsonEscape(pathCheck.error)));
                return;
            }

            SecureFileService.OpResult<SecureFileService.FileViewData> res = SecureFileService.readFile(user, targetPath);
            if (!res.success) {
                sendJson(exchange, res.statusCode, String.format("{\"error\":\"Error\",\"message\":\"%s\"}", jsonEscape(res.message)));
                return;
            }

            SecureFileService.FileViewData f = res.data;
            String json = String.format(
                "{\"file\":{\"path\":\"%s\",\"filename\":\"%s\",\"size\":%d,\"mime_type\":\"%s\",\"is_binary\":%b,\"is_image\":%b,\"is_pdf\":%b,\"content\":\"%s\",\"sha256\":\"%s\",\"uploader\":\"%s\",\"modified_at\":\"%s\"}}",
                jsonEscape(f.path),
                jsonEscape(f.filename),
                f.size,
                jsonEscape(f.mimeType),
                f.isBinary,
                f.isImage,
                f.isPdf,
                jsonEscape(f.content),
                jsonEscape(f.sha256),
                jsonEscape(f.uploader),
                jsonEscape(f.modifiedAt)
            );
            sendJson(exchange, 200, json);
        }

        private void handleFileDownload(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            Map<String, String> q = parseQuery(exchange.getRequestURI().getQuery());
            String targetPath = q.getOrDefault("path", "");

            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(targetPath, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", pathCheck.error));
                return;
            }

            SecureFileService.OpResult<byte[]> res = SecureFileService.readFileBytes(user, targetPath);
            if (!res.success) {
                sendJson(exchange, res.statusCode, String.format("{\"error\":\"Error\",\"message\":\"%s\"}", res.message));
                return;
            }

            String filename = new File(targetPath).getName();
            Headers respHeaders = exchange.getResponseHeaders();
            respHeaders.set("Content-Type", "application/octet-stream");
            respHeaders.set("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            exchange.sendResponseHeaders(200, res.data.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(res.data);
            }
        }

        private void handleFileWrite(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            String body = readBody(exchange);
            String rawPath = extractJson(body, "path");
            String filename = extractJson(body, "filename");
            String content = extractJson(body, "content");
            if (content == null) content = "";

            String fullPath = (filename != null && !filename.isEmpty()) ? rawPath + "/" + filename : rawPath;

            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(fullPath, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", pathCheck.error));
                return;
            }

            SecureFileService.OpResult<String> res = SecureFileService.writeFile(
                user, fullPath, content.getBytes(StandardCharsets.UTF_8), clientIp, requestId
            );

            if (!res.success) {
                String threat = res.data != null ? res.data : "MALWARE_DETECTED";
                sendJson(exchange, res.statusCode, String.format(
                    "{\"error\":\"Operation Blocked\",\"message\":\"%s\",\"threat_name\":\"%s\",\"details\":{\"threat_name\":\"%s\",\"quarantine_id\":\"QUAR-ISOLATED\"}}",
                    res.message, threat, threat
                ));
                return;
            }

            sendJson(exchange, 200, "{\"message\":\"File written successfully.\"}");
        }

        private void handleFileUpload(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            byte[] body = exchange.getRequestBody().readAllBytes();
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            
            String pathHeader = exchange.getRequestHeaders().getFirst("X-Upload-Path");
            String fileHeader = exchange.getRequestHeaders().getFirst("X-Upload-Filename");
            byte[] fileBytes = body;

            // Multipart form-data handling
            if (contentType != null && contentType.contains("multipart/form-data")) {
                String bodyStr = new String(body, StandardCharsets.ISO_8859_1);

                java.util.regex.Matcher fnMatcher = java.util.regex.Pattern.compile("filename=\"([^\"]+)\"").matcher(bodyStr);
                if (fnMatcher.find()) {
                    fileHeader = fnMatcher.group(1);
                }

                java.util.regex.Matcher pMatcher = java.util.regex.Pattern.compile("name=\"path\"\\r?\\n\\r?\\n([^\\r\\n]+)").matcher(bodyStr);
                if (pMatcher.find()) {
                    pathHeader = pMatcher.group(1).trim();
                }

                int headerIdx = bodyStr.indexOf("filename=\"");
                if (headerIdx != -1) {
                    int contentStart = bodyStr.indexOf("\r\n\r\n", headerIdx);
                    if (contentStart != -1) {
                        contentStart += 4;
                    } else {
                        contentStart = bodyStr.indexOf("\n\n", headerIdx) + 2;
                    }

                    int contentEnd = bodyStr.indexOf("\r\n--", contentStart);
                    if (contentEnd == -1) {
                        contentEnd = bodyStr.indexOf("\n--", contentStart);
                    }
                    if (contentEnd == -1) {
                        contentEnd = body.length;
                    }

                    if (contentStart > 0 && contentEnd > contentStart) {
                        fileBytes = Arrays.copyOfRange(body, contentStart, contentEnd);
                    }
                }
            }

            if (pathHeader == null || fileHeader == null) {
                Map<String, String> q = parseQuery(exchange.getRequestURI().getQuery());
                if (pathHeader == null) pathHeader = q.getOrDefault("path", "/projects");
                if (fileHeader == null) fileHeader = q.getOrDefault("filename", "upload_" + System.currentTimeMillis() + ".txt");
            }

            String fullPath = pathHeader + "/" + fileHeader;
            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(fullPath, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", pathCheck.error));
                return;
            }

            SecureFileService.OpResult<String> res = SecureFileService.writeFile(user, fullPath, fileBytes, clientIp, requestId);
            if (!res.success) {
                String threat = res.data != null ? res.data : "MALWARE_DETECTED";
                sendJson(exchange, res.statusCode, String.format(
                    "{\"error\":\"Upload Blocked\",\"message\":\"%s\",\"threat_name\":\"%s\",\"details\":{\"threat_name\":\"%s\",\"quarantine_id\":\"QUAR-ISOLATED\"}}",
                    res.message, threat, threat
                ));
                return;
            }

            sendJson(exchange, 200, "{\"message\":\"Upload successful.\"}");
        }

        private void handleFileMkdir(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            String body = readBody(exchange);
            String path = extractJson(body, "path");
            String dirName = extractJson(body, "dir_name");
            String fullPath = path + "/" + dirName;

            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(fullPath, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", pathCheck.error));
                return;
            }

            SecureFileService.OpResult<String> res = SecureFileService.createDirectory(user, fullPath, clientIp, requestId);
            sendJson(exchange, res.statusCode, String.format("{\"message\":\"%s\"}", res.message));
        }

        private void handleFileDelete(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return;

            String body = readBody(exchange);
            String path = extractJson(body, "path");
            if (path == null) {
                Map<String, String> q = parseQuery(exchange.getRequestURI().getQuery());
                path = q.get("path");
            }

            ProxyGateway.InspectionResult pathCheck = ProxyGateway.validateSafePath(path, clientIp, user.getUsername(), requestId);
            if (!pathCheck.valid) {
                sendJson(exchange, pathCheck.statusCode, String.format("{\"error\":\"Proxy Violation\",\"message\":\"%s\"}", pathCheck.error));
                return;
            }

            SecureFileService.OpResult<String> res = SecureFileService.deleteResource(user, path, clientIp, requestId);
            sendJson(exchange, res.statusCode, String.format("{\"message\":\"%s\"}", res.message));
        }

        // =====================================================================
        // SOC & MANAGEMENT HANDLERS
        // =====================================================================
        private void handleSocLogs(HttpExchange exchange) throws IOException {
            Map<String, String> q = parseQuery(exchange.getRequestURI().getQuery());
            String filter = q.getOrDefault("status", "ALL");
            List<AuditLog> logs = JsonDataStore.getInstance().getAllAuditLogs(filter);

            StringBuilder sb = new StringBuilder("{\"logs\":[");
            for (int i = 0; i < logs.size(); i++) {
                AuditLog l = logs.get(i);
                sb.append(String.format(
                    "{\"id\":%d,\"formatted_time\":\"%s\",\"client_ip\":\"%s\",\"username\":\"%s\",\"action\":\"%s\",\"resource_path\":\"%s\",\"status\":\"%s\",\"status_code\":%d,\"reason\":\"%s\"}",
                    l.getId(), l.getFormattedTime(), l.getClientIp(), l.getUsername(), l.getAction(), l.getResourcePath(), l.getStatus(), l.getStatusCode(), l.getReason()
                ));
                if (i < logs.size() - 1) sb.append(",");
            }
            sb.append("]}");
            sendJson(exchange, 200, sb.toString());
        }

        private void handleSocStats(HttpExchange exchange) throws IOException {
            List<AuditLog> logs = JsonDataStore.getInstance().getAllAuditLogs("ALL");
            long total = logs.size();
            long allowed = logs.stream().filter(l -> "ALLOWED".equals(l.getStatus())).count();
            long authz = logs.stream().filter(l -> "DENIED_AUTHZ".equals(l.getStatus())).count();
            long fw = logs.stream().filter(l -> "BLOCKED_FIREWALL".equals(l.getStatus()) || "BLOCKED_PROXY".equals(l.getStatus())).count();
            long av = logs.stream().filter(l -> "QUARANTINED_AV".equals(l.getStatus())).count();

            String json = String.format(
                "{\"total_requests\":%d,\"allowed_requests\":%d,\"authz_denied\":%d,\"firewall_blocked\":%d,\"antivirus_quarantined\":%d}",
                total, allowed, authz, fw, av
            );
            sendJson(exchange, 200, json);
        }

        private void handleSocFirewallRules(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            String method = exchange.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                List<FirewallRule> rules = JsonDataStore.getInstance().getAllFirewallRules();
                StringBuilder sb = new StringBuilder("{\"rules\":[");
                for (int i = 0; i < rules.size(); i++) {
                    FirewallRule r = rules.get(i);
                    sb.append(String.format(
                        "{\"id\":%d,\"ip_address\":\"%s\",\"rule_type\":\"%s\",\"reason\":\"%s\",\"active\":%b,\"expires_at\":%s}",
                        r.getId(), r.getIpAddress(), r.getRuleType(), r.getReason(), r.isActive(),
                        r.getExpiresAtMillis() != null ? "\"" + r.getExpiresAtMillis() + "\"" : "null"
                    ));
                    if (i < rules.size() - 1) sb.append(",");
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } else if ("POST".equalsIgnoreCase(method)) {
                String body = readBody(exchange);
                String ip = extractJson(body, "ip_address");
                String type = extractJson(body, "rule_type");
                String reason = extractJson(body, "reason");
                FirewallRule r = JsonDataStore.getInstance().addFirewallRule(ip, type != null ? type : "BLACKLIST", reason, null);
                sendJson(exchange, 201, "{\"message\":\"Rule added\",\"rule_id\":" + r.getId() + "}");
            } else if ("DELETE".equalsIgnoreCase(method)) {
                String uri = exchange.getRequestURI().getPath();
                int id = Integer.parseInt(uri.substring(uri.lastIndexOf('/') + 1));
                JsonDataStore.getInstance().deleteFirewallRule(id);
                sendJson(exchange, 200, "{\"message\":\"Rule removed.\"}");
            }
        }

        private void handleSocQuarantine(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                List<QuarantineRecord> records = JsonDataStore.getInstance().getAllQuarantineRecords();
                StringBuilder sb = new StringBuilder("{\"records\":[");
                for (int i = 0; i < records.size(); i++) {
                    QuarantineRecord r = records.get(i);
                    sb.append(String.format(
                        "{\"id\":\"%s\",\"original_filename\":\"%s\",\"target_path\":\"%s\",\"threat_name\":\"%s\",\"sha256_hash\":\"%s\",\"file_size\":%d,\"detected_by_step\":\"%s\",\"uploader_ip\":\"%s\",\"uploader_username\":\"%s\",\"created_at\":\"%s\"}",
                        r.getId(), r.getOriginalFilename(), r.getTargetPath(), r.getThreatName(), r.getSha256Hash(), r.getFileSize(), r.getDetectedByStep(), r.getUploaderIp(), r.getUploaderUsername(), r.getFormattedTime()
                    ));
                    if (i < records.size() - 1) sb.append(",");
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } else if ("DELETE".equalsIgnoreCase(method)) {
                String uri = exchange.getRequestURI().getPath();
                String id = uri.substring(uri.lastIndexOf('/') + 1);
                JsonDataStore.getInstance().deleteQuarantineRecord(id);
                sendJson(exchange, 200, "{\"message\":\"Quarantine record deleted.\"}");
            }
        }

        private void handleSocAclRules(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            String method = exchange.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                List<FilePermission> perms = JsonDataStore.getInstance().getAllPermissions();
                StringBuilder sb = new StringBuilder("{\"rules\":[");
                for (int i = 0; i < perms.size(); i++) {
                    FilePermission p = perms.get(i);
                    sb.append(String.format(
                        "{\"id\":%d,\"resource_path\":\"%s\",\"user_id\":%s,\"role\":%s,\"can_read\":%d,\"can_write\":%d,\"can_delete\":%d,\"is_deny\":%d}",
                        p.getId(), p.getResourcePath(), p.getUserId() != null ? p.getUserId() : "null",
                        p.getRole() != null ? "\"" + p.getRole() + "\"" : "null",
                        p.isCanRead() ? 1 : 0, p.isCanWrite() ? 1 : 0, p.isCanDelete() ? 1 : 0, p.isDeny() ? 1 : 0
                    ));
                    if (i < perms.size() - 1) sb.append(",");
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } else if ("POST".equalsIgnoreCase(method)) {
                String body = readBody(exchange);
                String path = extractJson(body, "resource_path");
                String role = extractJson(body, "role");
                boolean r = "1".equals(extractJson(body, "can_read")) || "true".equals(extractJson(body, "can_read"));
                boolean w = "1".equals(extractJson(body, "can_write")) || "true".equals(extractJson(body, "can_write"));
                boolean d = "1".equals(extractJson(body, "can_delete")) || "true".equals(extractJson(body, "can_delete"));
                boolean deny = "1".equals(extractJson(body, "is_deny")) || "true".equals(extractJson(body, "is_deny"));

                FilePermission perm = JsonDataStore.getInstance().addPermission(path, null, role, r, w, d, deny);
                sendJson(exchange, 200, "{\"message\":\"ACL rule updated\",\"rule_id\":" + perm.getId() + "}");
            }
        }

        private void handleSocUsers(HttpExchange exchange) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            List<User> list = JsonDataStore.getInstance().getAllUsers();
            StringBuilder sb = new StringBuilder("{\"users\":[");
            for (int i = 0; i < list.size(); i++) {
                User u = list.get(i);
                sb.append(String.format(
                    "{\"id\":%d,\"username\":\"%s\",\"role\":\"%s\",\"full_name\":\"%s\",\"status\":\"%s\",\"failed_attempts\":%d,\"lock_reason\":%s,\"registered_at\":%s}",
                    u.getId(), jsonEscape(u.getUsername()), jsonEscape(u.getRole()), jsonEscape(u.getFullName()),
                    jsonEscape(u.getStatus()), u.getFailedLoginAttempts(),
                    u.getLockReason() != null ? "\"" + jsonEscape(u.getLockReason()) + "\"" : "null",
                    u.getRegisteredAt() != null ? "\"" + jsonEscape(u.getRegisteredAt()) + "\"" : "null"
                ));
                if (i < list.size() - 1) sb.append(",");
            }
            sb.append("]}");
            sendJson(exchange, 200, sb.toString());
        }

        private void handleSocUserApprove(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập cần duyệt.\"}");
                return;
            }

            boolean ok = JsonDataStore.getInstance().approveUser(username.trim());
            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "USER_APPROVE", "-", "ALLOWED", 200,
                    "Admin đã phê duyệt tài khoản: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đã phê duyệt tài khoản '" + jsonEscape(username) + "' thành công! Người dùng hiện đã có thể đăng nhập.\"}");
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private void handleSocUserUnlock(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập cần mở khóa.\"}");
                return;
            }

            boolean ok = JsonDataStore.getInstance().unlockUser(username.trim());
            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "USER_UNLOCK", "-", "ALLOWED", 200,
                    "Admin đã mở khóa tài khoản: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đã mở khóa tài khoản '" + jsonEscape(username) + "' thành công! Số lần nhập sai mật khẩu đã được cài lại về 0.\"}");
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private void handleSocUserLock(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            String reason = extractJson(body, "reason");
            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập cần khóa.\"}");
                return;
            }

            if (username.equalsIgnoreCase("admin") || username.equalsIgnoreCase(admin.getUsername())) {
                sendJson(exchange, 400, "{\"error\":\"Forbidden\",\"message\":\"Không được phép khóa tài khoản Quản trị viên tối cao.\"}");
                return;
            }

            boolean ok = JsonDataStore.getInstance().lockUser(username.trim(), reason != null ? reason : "Khóa chủ động bởi Quản trị viên");
            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "USER_LOCK", "-", "ALLOWED", 200,
                    "Admin đã chủ động khóa tài khoản: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đã khóa tài khoản '" + jsonEscape(username) + "' thành công.\"}");
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private void handleSocUserResetPassword(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            String newPassword = extractJson(body, "new_password");
            if (username == null || newPassword == null || newPassword.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập hoặc mật khẩu mới.\"}");
                return;
            }

            boolean ok = JsonDataStore.getInstance().resetPassword(username.trim(), newPassword.trim());
            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "ADMIN_RESET_PASSWORD", "-", "ALLOWED", 200,
                    "Admin đã đặt lại mật khẩu cho: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đã đặt lại mật khẩu cho tài khoản '" + jsonEscape(username) + "' thành công.\"}");
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private void handleSocUserDelete(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập cần xóa.\"}");
                return;
            }

            if (username.equalsIgnoreCase("admin") || username.equalsIgnoreCase(admin.getUsername())) {
                sendJson(exchange, 400, "{\"error\":\"Forbidden\",\"message\":\"Không được phép xóa tài khoản Quản trị viên tối cao.\"}");
                return;
            }

            boolean ok = JsonDataStore.getInstance().deleteUser(username.trim());
            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "USER_DELETE", "-", "ALLOWED", 200,
                    "Admin đã xóa tài khoản: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đã xóa tài khoản '" + jsonEscape(username) + "' thành công.\"}");
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private void handleSocPasswordResets(HttpExchange exchange) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            List<PasswordResetRequest> list = JsonDataStore.getInstance().getAllPasswordResetRequests();
            StringBuilder sb = new StringBuilder("{\"requests\":[");
            for (int i = 0; i < list.size(); i++) {
                PasswordResetRequest r = list.get(i);
                sb.append(String.format(
                    "{\"id\":%d,\"username\":\"%s\",\"reason\":\"%s\",\"status\":\"%s\",\"reset_code\":%s,\"requested_at\":\"%s\",\"approved_at\":%s}",
                    r.getId(), jsonEscape(r.getUsername()), jsonEscape(r.getReason()),
                    jsonEscape(r.getStatus()),
                    r.getResetCode() != null ? "\"" + jsonEscape(r.getResetCode()) + "\"" : "null",
                    jsonEscape(r.getRequestedAt()),
                    r.getApprovedAt() != null ? "\"" + jsonEscape(r.getApprovedAt()) + "\"" : "null"
                ));
                if (i < list.size() - 1) sb.append(",");
            }
            sb.append("]}");
            sendJson(exchange, 200, sb.toString());
        }

        private void handleSocPasswordResetApprove(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập cần duyệt khôi phục mật khẩu.\"}");
                return;
            }

            String code = JsonDataStore.getInstance().approvePasswordReset(username.trim());
            if (code != null) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "RESET_REQ_APPROVE", "-", "ALLOWED", 200,
                    "Admin đã duyệt yêu cầu khôi phục mật khẩu cho: " + username + " (Cấp mã OTP: " + code + ")");
                sendJson(exchange, 200, String.format(
                    "{\"message\":\"Đã phê duyệt yêu cầu khôi phục mật khẩu!\",\"username\":\"%s\",\"reset_code\":\"%s\"}",
                    jsonEscape(username.trim()), code
                ));
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy yêu cầu khôi phục mật khẩu đang chờ (PENDING) cho tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private void handleSocPasswordResetReject(HttpExchange exchange, String clientIp, String requestId) throws IOException {
            User admin = authenticateAdmin(exchange);
            if (admin == null) return;

            String body = readBody(exchange);
            String username = extractJson(body, "username");
            if (username == null || username.trim().isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Bad Request\",\"message\":\"Thiếu tên đăng nhập cần từ chối.\"}");
                return;
            }

            boolean ok = JsonDataStore.getInstance().rejectPasswordReset(username.trim());
            if (ok) {
                JsonDataStore.getInstance().addAuditLog(requestId, clientIp, admin.getUsername(), "RESET_REQ_REJECT", "-", "ALLOWED", 200,
                    "Admin đã từ chối yêu cầu khôi phục mật khẩu cho: " + username);
                sendJson(exchange, 200, "{\"message\":\"Đã từ chối yêu cầu khôi phục mật khẩu cho tài khoản '" + jsonEscape(username) + "'.\"}");
            } else {
                sendJson(exchange, 404, "{\"error\":\"Not Found\",\"message\":\"Không tìm thấy yêu cầu khôi phục mật khẩu đang chờ (PENDING) cho tài khoản '" + jsonEscape(username) + "'.\"}");
            }
        }

        private String getPublicTunnelUrl() {
            try {
                Path logFile = SystemConfig.BASE_DIR.resolve("cloudflared.log");
                if (Files.exists(logFile)) {
                    List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
                    java.util.regex.Pattern p = java.util.regex.Pattern.compile("https://[a-zA-Z0-9.-]+\\.trycloudflare\\.com");
                    for (int i = lines.size() - 1; i >= 0; i--) {
                        java.util.regex.Matcher m = p.matcher(lines.get(i));
                        if (m.find()) {
                            return m.group(0);
                        }
                    }
                }
            } catch (Exception ignored) {}
            return null;
        }

        private void handleSystemStatus(HttpExchange exchange) throws IOException {
            String lanIp = SystemConfig.getLanIpAddress();
            int fileCount = JsonDataStore.getInstance().getAllFileRecords().size();
            int userCount = JsonDataStore.getInstance().getAllUsers().size();
            int ruleCount = JsonDataStore.getInstance().getAllPermissions().size();
            String publicUrl = getPublicTunnelUrl();

            String json = String.format(
                "{\"status\":\"ONLINE\",\"system_name\":\"HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)\"," +
                "\"lan_ip\":\"%s\",\"port\":%d,\"public_url\":%s," +
                "\"database\":{\"status\":\"CONNECTED\",\"file_count\":%d,\"user_count\":%d,\"rule_count\":%d}," +
                "\"layers\":{\"proxy\":{\"status\":\"ACTIVE\"},\"firewall\":{\"status\":\"ACTIVE\"},\"antivirus\":{\"status\":\"ACTIVE\"}}}",
                lanIp, SystemConfig.HTTP_PORT,
                publicUrl != null ? "\"" + jsonEscape(publicUrl) + "\"" : "null",
                fileCount, userCount, ruleCount
            );
            sendJson(exchange, 200, json);
        }

        // --- Helpers ---
        private User authenticate(HttpExchange exchange) throws IOException {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.startsWith("Bearer ")) {
                sendJson(exchange, 401, "{\"error\":\"Unauthorized\",\"message\":\"Missing or invalid Bearer token.\"}");
                return null;
            }
            String token = auth.substring(7);
            JwtManager.Claims c = JwtManager.verifyToken(token);
            if (c == null) {
                sendJson(exchange, 401, "{\"error\":\"Unauthorized\",\"message\":\"Invalid or expired token.\"}");
                return null;
            }
            return JsonDataStore.getInstance().getUserById(c.userId);
        }

        private User authenticateAdmin(HttpExchange exchange) throws IOException {
            User user = authenticate(exchange);
            if (user == null) return null;
            if (!"ADMIN".equalsIgnoreCase(user.getRole())) {
                sendJson(exchange, 403, "{\"error\":\"Forbidden\",\"message\":\"Từ chối truy cập! Chức năng này yêu cầu đặc quyền Quản trị viên (ADMIN).\"}");
                return null;
            }
            return user;
        }

        private void serveStaticFile(HttpExchange exchange, Path path, String mimeType) throws IOException {
            if (!Files.exists(path)) {
                sendJson(exchange, 404, "{\"error\":\"Not Found\"}");
                return;
            }
            byte[] bytes = Files.readAllBytes(path);
            exchange.getResponseHeaders().set("Content-Type", mimeType);
            exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-store, must-revalidate");
            exchange.getResponseHeaders().set("Pragma", "no-cache");
            exchange.getResponseHeaders().set("Expires", "0");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private void sendJson(HttpExchange exchange, int code, String json) throws IOException {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(code, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private String readBody(HttpExchange exchange) throws IOException {
            return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        }

        private String extractJson(String json, String key) {
            if (json == null) return null;
            // Match quoted string: "key" \s* : \s* "([^"]*)"
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\""
            );
            java.util.regex.Matcher m = p.matcher(json);
            if (m.find()) {
                String val = m.group(1);
                return val.replace("\\\\", "\\").replace("\\\"", "\"").replace("\\n", "\n").replace("\\r", "\r");
            }
            // Match unquoted values: numbers, booleans
            java.util.regex.Pattern p2 = java.util.regex.Pattern.compile(
                "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*([0-9a-zA-Z_.-]+)"
            );
            java.util.regex.Matcher m2 = p2.matcher(json);
            if (m2.find()) {
                return m2.group(1).trim();
            }
            return null;
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> map = new HashMap<>();
            if (query == null) return map;
            for (String pair : query.split("&")) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    try {
                        map.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                                URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
                    } catch (Exception ignored) {}
                }
            }
            return map;
        }

        public static String jsonEscape(String s) {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\b': sb.append("\\b"); break;
                    case '\f': sb.append("\\f"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < ' ') {
                            String hex = "000" + Integer.toHexString(c);
                            sb.append("\\u").append(hex.substring(hex.length() - 4));
                        } else {
                            sb.append(c);
                        }
                        break;
                }
            }
            return sb.toString();
        }
    }
}

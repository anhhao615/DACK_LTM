package dack_ltm.security;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;
import dack_ltm.models.FirewallRule;

public class FirewallEngine {
    private static final Map<String, List<Long>> rateLimitHistory = new ConcurrentHashMap<>();
    private static final Map<String, List<Long>> loginFailures = new ConcurrentHashMap<>();

    public static class FirewallCheckResult {
        public boolean allowed;
        public int statusCode;
        public String reason;

        public FirewallCheckResult(boolean allowed, int statusCode, String reason) {
            this.allowed = allowed;
            this.statusCode = statusCode;
            this.reason = reason;
        }
    }

    public static FirewallCheckResult inspectIpAndLimits(String clientIp, long contentLength, String requestId) {
        long now = System.currentTimeMillis();
        JsonDataStore ds = JsonDataStore.getInstance();

        // 1. Kiểm tra IP Blacklist / Whitelist
        String mode = ds.getFirewallMode();
        List<FirewallRule> rules = ds.getAllFirewallRules();

        if (mode.equalsIgnoreCase("whitelist")) {
            boolean inWhitelist = false;
            for (FirewallRule r : rules) {
                if (r.isActive() && r.getRuleType().equalsIgnoreCase("WHITELIST") && r.getIpAddress().equals(clientIp)) {
                    inWhitelist = true;
                    break;
                }
            }
            if (!inWhitelist) {
                String reason = "Địa chỉ IP " + clientIp + " không nằm trong Whitelist được phép truy cập của Firewall.";
                ds.addAuditLog(requestId, clientIp, "ANONYMOUS", "FIREWALL_FILTER", "-", "BLOCKED_FIREWALL", 403, reason);
                return new FirewallCheckResult(false, 403, reason);
            }
        } else {
            // Chế độ Blacklist
            for (FirewallRule r : rules) {
                if (r.isActive() && r.getRuleType().equalsIgnoreCase("BLACKLIST") && r.getIpAddress().equals(clientIp)) {
                    if (r.getExpiresAtMillis() == null || r.getExpiresAtMillis() > now) {
                        String reason = r.getReason() != null ? r.getReason() : "Địa chỉ IP nằm trong danh sách đen (Blacklist) của Firewall.";
                        ds.addAuditLog(requestId, clientIp, "ANONYMOUS", "FIREWALL_FILTER", "-", "BLOCKED_FIREWALL", 403, reason);
                        return new FirewallCheckResult(false, 403, reason);
                    }
                }
            }
        }

        // 2. Kiểm tra giới hạn tần suất (Rate Limiting)
        if (ds.isRateLimitEnabled()) {
            List<Long> timestamps = rateLimitHistory.computeIfAbsent(clientIp, k -> Collections.synchronizedList(new ArrayList<>()));
            long windowStart = now - (SystemConfig.RATE_LIMIT_WINDOW_SECONDS * 1000L);
            synchronized (timestamps) {
                timestamps.removeIf(ts -> ts < windowStart);
                if (timestamps.size() >= ds.getRateLimitMax()) {
                    String reason = "Vượt quá giới hạn tần suất gửi request (" + timestamps.size() + " req/phút).";
                    ds.addAuditLog(requestId, clientIp, "ANONYMOUS", "RATE_LIMIT", "-", "BLOCKED_FIREWALL", 429, reason);
                    return new FirewallCheckResult(false, 429, reason);
                }
                timestamps.add(now);
            }
        }

        // 3. Kiểm tra kích thước Payload/Packet tải lên
        if (contentLength > SystemConfig.MAX_UPLOAD_SIZE_BYTES) {
            String reason = "Kích thước tệp tin " + contentLength + " bytes vượt quá giới hạn tối đa cho phép của Firewall (" + (SystemConfig.MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)) + " MB).";
            ds.addAuditLog(requestId, clientIp, "ANONYMOUS", "PAYLOAD_INSPECTION", "-", "BLOCKED_FIREWALL", 413, reason);
            return new FirewallCheckResult(false, 413, reason);
        }

        return new FirewallCheckResult(true, 200, "An toàn (Clean)");
    }

    public static String recordLoginAttempt(String clientIp, boolean success, String username, String requestId) {
        if (success) {
            loginFailures.remove(clientIp);
            return null;
        }

        long now = System.currentTimeMillis();
        long windowStart = now - (SystemConfig.BRUTE_FORCE_LOCKOUT_SECONDS * 1000L);
        List<Long> failures = loginFailures.computeIfAbsent(clientIp, k -> Collections.synchronizedList(new ArrayList<>()));

        synchronized (failures) {
            failures.removeIf(ts -> ts < windowStart);
            failures.add(now);

            if (failures.size() >= SystemConfig.BRUTE_FORCE_MAX_FAILURES) {
                long lockUntil = now + (SystemConfig.BRUTE_FORCE_LOCKOUT_SECONDS * 1000L);
                String reason = "Tự động khóa IP: Đăng nhập thất bại " + failures.size() + " lần liên tiếp (Phát hiện tấn công vét cạn Brute-Force).";
                JsonDataStore.getInstance().addFirewallRule(clientIp, "BLACKLIST", reason, lockUntil);
                JsonDataStore.getInstance().addAuditLog(
                    requestId, clientIp, username, "BRUTE_FORCE_DEFENSE", "-", "BLOCKED_FIREWALL", 403, reason
                );
                return reason;
            }
        }

        return null;
    }
}

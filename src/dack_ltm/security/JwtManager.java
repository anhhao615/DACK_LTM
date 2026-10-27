package dack_ltm.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import dack_ltm.config.SystemConfig;

public class JwtManager {
    private static final Set<String> REVOKED_JTIS = Collections.synchronizedSet(new HashSet<>());

    public static class Claims {
        public String jti;
        public int userId;
        public String username;
        public String role;
        public long expMillis;

        public boolean isExpired() {
            return System.currentTimeMillis() > expMillis;
        }
    }

    public static String generateToken(int userId, String username, String role) {
        String jti = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();
        long exp = now + ((long) SystemConfig.JWT_EXPIRATION_MINUTES * 60 * 1000);

        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = String.format(
            "{\"jti\":\"%s\",\"user_id\":%d,\"sub\":\"%s\",\"role\":\"%s\",\"iat\":%d,\"exp\":%d}",
            jti, userId, username, role, now / 1000, exp / 1000
        );

        String headerB64 = CryptoUtils.base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = CryptoUtils.base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        String toSign = headerB64 + "." + payloadB64;
        String signatureB64 = hmacSha256(toSign, SystemConfig.JWT_SECRET);

        return toSign + "." + signatureB64;
    }

    public static Claims verifyToken(String token) {
        if (token == null || !token.contains(".")) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return null;
        }

        String toSign = parts[0] + "." + parts[1];
        String expectedSig = hmacSha256(toSign, SystemConfig.JWT_SECRET);

        if (!MessageDigest.isEqual(parts[2].getBytes(StandardCharsets.UTF_8), expectedSig.getBytes(StandardCharsets.UTF_8))) {
            return null; // Signature mismatch
        }

        try {
            String payloadJson = new String(CryptoUtils.base64UrlDecode(parts[1]), StandardCharsets.UTF_8);
            Claims claims = new Claims();

            // Simple regex/json parser for pure Java without dependencies
            claims.jti = extractJsonString(payloadJson, "jti");
            claims.userId = extractJsonInt(payloadJson, "user_id");
            claims.username = extractJsonString(payloadJson, "sub");
            claims.role = extractJsonString(payloadJson, "role");
            long expSec = extractJsonLong(payloadJson, "exp");
            claims.expMillis = expSec * 1000;

            if (claims.jti == null || REVOKED_JTIS.contains(claims.jti)) {
                return null; // Revoked token
            }

            if (claims.isExpired()) {
                return null; // Expired
            }

            return claims;
        } catch (Exception e) {
            return null;
        }
    }

    public static void revokeToken(String jti) {
        if (jti != null) {
            REVOKED_JTIS.add(jti);
        }
    }

    private static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return CryptoUtils.base64UrlEncode(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    private static String extractJsonString(String json, String key) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\""
        );
        java.util.regex.Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static int extractJsonInt(String json, String key) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*([0-9-]+)"
        );
        java.util.regex.Matcher m = p.matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    private static long extractJsonLong(String json, String key) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\"" + java.util.regex.Pattern.quote(key) + "\"\\s*:\\s*([0-9-]+)"
        );
        java.util.regex.Matcher m = p.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0L;
    }
}

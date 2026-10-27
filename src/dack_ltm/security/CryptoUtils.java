package dack_ltm.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import dack_ltm.config.SystemConfig;

public class CryptoUtils {
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String hashPassword(String password) {
        try {
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);

            PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                SystemConfig.PBKDF2_ITERATIONS,
                SystemConfig.PBKDF2_KEY_LENGTH
            );
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();

            return "pbkdf2_sha256$" + SystemConfig.PBKDF2_ITERATIONS + "$" + bytesToHex(salt) + "$" + bytesToHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 hashing failed", e);
        }
    }

    public static boolean verifyPassword(String password, String storedHash) {
        try {
            String[] parts = storedHash.split("\\$");
            if (parts.length != 4 || !parts[0].equals("pbkdf2_sha256")) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = hexToBytes(parts[2]);
            byte[] expectedHash = hexToBytes(parts[3]);

            PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                expectedHash.length * 8
            );
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] computedHash = skf.generateSecret(spec).getEncoded();

            return MessageDigest.isEqual(computedHash, expectedHash);
        } catch (Exception e) {
            return false;
        }
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm missing", e);
        }
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] base64UrlDecode(String base64) {
        return Base64.getUrlDecoder().decode(base64);
    }
}

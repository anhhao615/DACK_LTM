package dack_ltm.config;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * System Configurations and Security Parameters for Defense-in-Depth.
 */
public class SystemConfig {
    public static final String APP_NAME = "Defense-in-Depth Remote File Access System";
    public static final String VERSION = "2.6";
    public static final int HTTP_PORT = 8080;

    // Base storage paths
    public static final Path BASE_DIR = Paths.get("").toAbsolutePath();
    public static final Path SECURE_STORAGE_DIR = BASE_DIR.resolve("secure_storage");
    public static final Path QUARANTINE_DIR = BASE_DIR.resolve("quarantine_zone");
    public static final Path DATA_DIR = BASE_DIR.resolve("data_store");

    // Crypto & AuthN
    public static final String JWT_SECRET = "netsec_super_secret_jwt_key_2026_dack_ltm_defense_in_depth";
    public static final int JWT_EXPIRATION_MINUTES = 120;
    public static final int PBKDF2_ITERATIONS = 100_000;
    public static final int PBKDF2_KEY_LENGTH = 256;

    // Firewall & Rate Limiting
    public static final int RATE_LIMIT_MAX_REQUESTS = 60;
    public static final int RATE_LIMIT_WINDOW_SECONDS = 60;
    public static final int BRUTE_FORCE_MAX_FAILURES = 5;
    public static final int BRUTE_FORCE_LOCKOUT_SECONDS = 900; // 15 mins
    public static final long MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB

    // Antivirus Dangerous Extensions
    public static final Set<String> DANGEROUS_EXTENSIONS = new HashSet<>(Arrays.asList(
        ".exe", ".bat", ".cmd", ".sh", ".vbs", ".scr", 
        ".ps1", ".msi", ".dll", ".com", ".pif", ".reg",
        ".jar", ".bin", ".apk", ".elf", ".sys"
    ));

    // Antivirus Signatures & Heuristics
    public static final String EICAR_TEST_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    public static final String[] SUSPICIOUS_SCRIPT_PATTERNS = {
        "eval(", "os.system(", "subprocess.", "powershell -enc",
        "powershell -e ", "base64_decode(", "<?php", "<%eval",
        "passthru(", "shell_exec(", "/bin/sh", "/bin/bash",
        "cmd.exe", "Runtime.getRuntime().exec(", "ProcessBuilder"
    };

    static {
        // Ensure directories exist
        new File(SECURE_STORAGE_DIR.toString()).mkdirs();
        new File(QUARANTINE_DIR.toString()).mkdirs();
        new File(DATA_DIR.toString()).mkdirs();
    }

    public static String getLanIpAddress() {
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces = java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                java.util.Enumeration<java.net.InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    java.net.InetAddress addr = addresses.nextElement();
                    if (addr instanceof java.net.Inet4Address && !addr.isLoopbackAddress()) {
                        String ip = addr.getHostAddress();
                        if (!ip.startsWith("169.254")) {
                            return ip;
                        }
                    }
                }
            }
            return java.net.InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }
}

package dack_ltm.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.*;
import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;
import dack_ltm.models.QuarantineRecord;

public class AntivirusScanner {
    private static final byte[] MAGIC_MZ = new byte[] { (byte) 0x4D, (byte) 0x5A }; // "MZ"
    private static final byte[] MAGIC_ELF = new byte[] { (byte) 0x7F, (byte) 0x45, (byte) 0x4C, (byte) 0x46 }; // "\x7fELF"
    private static final byte[] MAGIC_SHEBANG = new byte[] { (byte) 0x23, (byte) 0x21 }; // "#!"

    private static final Map<String, String> KNOWN_HASH_DB = new HashMap<>();

    static {
        // Mẫu mã băm SHA-256 mã độc nhận diện sẵn
        KNOWN_HASH_DB.put("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR.Standard.Antivirus.TestFile");
        KNOWN_HASH_DB.put("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Ransomware.LockBit.Sample");
        KNOWN_HASH_DB.put("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "Backdoor.WebShell.Chopper");
    }

    public static class ScanResult {
        public boolean clean;
        public String threatName;
        public String step;
        public String details;
        public QuarantineRecord quarantineRecord;

        public ScanResult(boolean clean, String threatName, String step, String details, QuarantineRecord rec) {
            this.clean = clean;
            this.threatName = threatName;
            this.step = step;
            this.details = details;
            this.quarantineRecord = rec;
        }
    }

    public static ScanResult scanPayload(String filename, byte[] content, String targetPath, 
                                        String clientIp, String username, String requestId) {
        String ext = "";
        int dotIdx = filename.lastIndexOf('.');
        if (dotIdx != -1) {
            ext = filename.substring(dotIdx).toLowerCase();
        }
        String sha256 = CryptoUtils.sha256Hex(content);

        // =====================================================================
        // BƯỚC 1: Kiểm tra phần mở rộng tệp tin nguy hiểm (Extension Check)
        // =====================================================================
        if (SystemConfig.DANGEROUS_EXTENSIONS.contains(ext)) {
            return quarantine(
                filename, content, targetPath, "Exploit.ExecutableExtension" + ext,
                "Bước 1: Kiểm tra phần mở rộng (Extension Check)",
                "Phần mở rộng '" + ext + "' nằm trong danh sách cấm tuyệt đối đối với kho tệp tin từ xa.",
                sha256, clientIp, username, requestId
            );
        }

        // =====================================================================
        // BƯỚC 2: Kiểm tra chữ ký byte đầu & Giả mạo định dạng (Magic Bytes)
        // =====================================================================
        if (startsWithBytes(content, MAGIC_MZ) || indexOfBytes(content, MAGIC_MZ, 16) != -1) {
            return quarantine(
                filename, content, targetPath, "Malware.Disguised.WindowsPE",
                "Bước 2: Xác minh chữ ký byte đầu (Magic Bytes Verification)",
                "Tệp tin chứa chữ ký thực thi PE Windows 'MZ' (Phát hiện hành vi giả mạo định dạng tệp).",
                sha256, clientIp, username, requestId
            );
        }

        if (startsWithBytes(content, MAGIC_ELF)) {
            return quarantine(
                filename, content, targetPath, "Malware.Disguised.LinuxELF",
                "Bước 2: Xác minh chữ ký byte đầu (Magic Bytes Verification)",
                "Tệp tin chứa chữ ký nhị phân thực thi Linux ELF.",
                sha256, clientIp, username, requestId
            );
        }

        if (startsWithBytes(content, MAGIC_SHEBANG) && (ext.equals(".txt") || ext.equals(".pdf") || ext.equals(".png"))) {
            return quarantine(
                filename, content, targetPath, "Malware.Disguised.ShellScript",
                "Bước 2: Xác minh chữ ký byte đầu (Magic Bytes Verification)",
                "Tệp tin mang đuôi tài liệu '" + ext + "' nhưng bắt đầu bằng chữ ký thực thi script Shebang '#!'.",
                sha256, clientIp, username, requestId
            );
        }

        // =====================================================================
        // BƯỚC 3: So khớp mã băm SHA-256 với cơ sở dữ liệu mẫu độc hại
        // =====================================================================
        if (KNOWN_HASH_DB.containsKey(sha256)) {
            String threat = KNOWN_HASH_DB.get(sha256);
            return quarantine(
                filename, content, targetPath, threat,
                "Bước 3: So khớp mã băm (SHA-256 Hash Matching)",
                "Mã băm SHA-256 của tệp tin trùng khớp với mẫu mã độc trong cơ sở dữ liệu.",
                sha256, clientIp, username, requestId
            );
        }

        // =====================================================================
        // BƯỚC 4: Quét Heuristic nội dung & Mẫu thử virus tiêu chuẩn EICAR
        // =====================================================================
        String textContent = new String(content, StandardCharsets.UTF_8);

        if (textContent.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE") || textContent.contains(SystemConfig.EICAR_TEST_STRING)) {
            return quarantine(
                filename, content, targetPath, "EICAR.Standard.Antivirus.TestFile",
                "Bước 4: Quét Heuristic & Mẫu thử EICAR (Heuristics & EICAR)",
                "Phát hiện chữ ký mẫu thử virus tiêu chuẩn quốc tế EICAR trong nội dung tệp tin.",
                sha256, clientIp, username, requestId
            );
        }

        for (String pattern : SystemConfig.SUSPICIOUS_SCRIPT_PATTERNS) {
            if (textContent.contains(pattern)) {
                return quarantine(
                    filename, content, targetPath, "Heuristic.SuspiciousScriptPattern",
                    "Bước 4: Quét Heuristic & Mẫu thử EICAR (Heuristics & EICAR)",
                    "Phát hiện mẫu lệnh thực thi / backdoor cửa sau nguy hiểm: '" + pattern + "'.",
                    sha256, clientIp, username, requestId
                );
            }
        }

        // Vượt qua toàn bộ 4 bước an toàn
        return new ScanResult(true, null, null, "Tệp tin an toàn (Clean).", null);
    }

    private static ScanResult quarantine(String filename, byte[] content, String targetPath,
                                         String threatName, String step, String details, 
                                         String sha256, String clientIp, String username, String requestId) {
        String timestamp = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
        String quarId = "QUAR-" + timestamp + "-" + UUID.randomUUID().toString().substring(0, 8);

        Path quarFile = SystemConfig.QUARANTINE_DIR.resolve(quarId + ".infected");
        Path metaFile = SystemConfig.QUARANTINE_DIR.resolve(quarId + ".json");

        try {
            Files.write(quarFile, content);
            String metaJson = String.format(
                "{\n  \"quarantine_id\": \"%s\",\n  \"original_filename\": \"%s\",\n  \"target_path\": \"%s\",\n" +
                "  \"threat_name\": \"%s\",\n  \"sha256\": \"%s\",\n  \"file_size\": %d,\n  \"detected_by_step\": \"%s\",\n" +
                "  \"uploader_ip\": \"%s\",\n  \"uploader_username\": \"%s\",\n  \"details\": \"%s\"\n}",
                quarId, filename, targetPath, threatName, sha256, content.length, step, clientIp, username, details
            );
            Files.writeString(metaFile, metaJson, StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }

        QuarantineRecord rec = JsonDataStore.getInstance().addQuarantineRecord(
            quarId, filename, targetPath, threatName, sha256, content.length, step, clientIp, username
        );

        JsonDataStore.getInstance().addAuditLog(
            requestId, clientIp, username, "ANTIVIRUS_QUARANTINE", targetPath, "QUARANTINED_AV", 422,
            "Mã độc bị cách ly [" + threatName + "] tại " + step
        );

        return new ScanResult(false, threatName, step, details, rec);
    }

    private static boolean startsWithBytes(byte[] source, byte[] prefix) {
        if (source.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (source[i] != prefix[i]) return false;
        }
        return true;
    }

    private static int indexOfBytes(byte[] source, byte[] target, int maxLen) {
        if (source.length < target.length) return -1;
        int limit = Math.min(source.length - target.length, maxLen);
        for (int i = 0; i <= limit; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }
}

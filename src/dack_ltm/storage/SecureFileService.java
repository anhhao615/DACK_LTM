package dack_ltm.storage;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.*;

import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;
import dack_ltm.models.FileRecord;
import dack_ltm.models.User;
import dack_ltm.security.AclEngine;
import dack_ltm.security.AntivirusScanner;
import dack_ltm.security.CryptoUtils;

public class SecureFileService {

    public static class FileItem {
        public String name;
        public String path;
        public boolean isDir;
        public long size;
        public String modifiedAt;
        public String badge;
        public String mimeType;
        public String sha256;
        public String uploader;

        public FileItem(String name, String path, boolean isDir, long size, String modifiedAt, 
                        String badge, String mimeType, String sha256, String uploader) {
            this.name = name;
            this.path = path;
            this.isDir = isDir;
            this.size = size;
            this.modifiedAt = modifiedAt;
            this.badge = badge;
            this.mimeType = mimeType;
            this.sha256 = sha256;
            this.uploader = uploader;
        }
    }

    public static class FileViewData {
        public String path;
        public String filename;
        public long size;
        public String mimeType;
        public boolean isBinary;
        public boolean isImage;
        public boolean isPdf;
        public String content; // Text decoded, Base64 data URI for images, or message for binary
        public String sha256;
        public String uploader;
        public String modifiedAt;

        public FileViewData(String path, String filename, long size, String mimeType,
                            boolean isBinary, boolean isImage, boolean isPdf,
                            String content, String sha256, String uploader, String modifiedAt) {
            this.path = path;
            this.filename = filename;
            this.size = size;
            this.mimeType = mimeType;
            this.isBinary = isBinary;
            this.isImage = isImage;
            this.isPdf = isPdf;
            this.content = content;
            this.sha256 = sha256;
            this.uploader = uploader;
            this.modifiedAt = modifiedAt;
        }
    }

    public static class OpResult<T> {
        public boolean success;
        public int statusCode;
        public String message;
        public T data;

        public OpResult(boolean success, int statusCode, String message, T data) {
            this.success = success;
            this.statusCode = statusCode;
            this.message = message;
            this.data = data;
        }
    }

    public static OpResult<List<FileItem>> listDirectory(User user, String relPath) {
        String normPath = AclEngine.normalizePath(relPath);
        AclEngine.AuthZResult authz = AclEngine.checkPermission(user, normPath, "READ");
        if (!authz.allowed) {
            return new OpResult<>(false, 403, "403 Bị từ chối (Forbidden) - " + authz.reason, null);
        }

        Path target = SystemConfig.SECURE_STORAGE_DIR.resolve(normPath.replaceAll("^[\\/\\\\]+", "")).normalize();
        File dir = target.toFile();
        if (!dir.exists() || !dir.isDirectory()) {
            return new OpResult<>(false, 404, "Không tìm thấy thư mục '" + normPath + "'.", null);
        }

        List<FileItem> items = new ArrayList<>();
        File[] files = dir.listFiles();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        if (files != null) {
            for (File f : files) {
                String childRel = normPath.equals("/") ? "/" + f.getName() : normPath + "/" + f.getName();
                String badge = AclEngine.getEffectiveBadge(user, childRel);

                FileRecord rec = JsonDataStore.getInstance().getFileRecord(childRel);
                String mimeType = f.isDirectory() ? "inode/directory" : detectMimeType(f.getName(), null);
                String sha256 = (rec != null) ? rec.getSha256() : "-";
                String uploader = (rec != null) ? rec.getUploader() : "system";

                items.add(new FileItem(
                    f.getName(),
                    childRel,
                    f.isDirectory(),
                    f.isFile() ? f.length() : 0,
                    sdf.format(new Date(f.lastModified())),
                    badge,
                    mimeType,
                    sha256,
                    uploader
                ));
            }
        }

        // Sắp xếp: Thư mục lên trước, sau đó theo bảng chữ cái
        items.sort((a, b) -> {
            if (a.isDir != b.isDir) return a.isDir ? -1 : 1;
            return a.name.compareToIgnoreCase(a.name);
        });

        return new OpResult<>(true, 200, "Thành công", items);
    }

    public static OpResult<FileViewData> readFile(User user, String relPath) {
        String normPath = AclEngine.normalizePath(relPath);
        AclEngine.AuthZResult authz = AclEngine.checkPermission(user, normPath, "READ");
        if (!authz.allowed) {
            return new OpResult<>(false, 403, "403 Bị từ chối (Forbidden) - " + authz.reason, null);
        }

        Path target = SystemConfig.SECURE_STORAGE_DIR.resolve(normPath.replaceAll("^[\\/\\\\]+", "")).normalize();
        File file = target.toFile();
        if (!file.exists() || !file.isFile()) {
            return new OpResult<>(false, 404, "Tệp tin '" + normPath + "' không tồn tại.", null);
        }

        try {
            byte[] bytes = Files.readAllBytes(target);
            String filename = file.getName();
            long size = bytes.length;
            String sha256 = CryptoUtils.sha256Hex(bytes);
            String mimeType = detectMimeType(filename, bytes);
            boolean isImage = mimeType.startsWith("image/");
            boolean isPdf = mimeType.equals("application/pdf");
            boolean isBinary = isImage || isPdf || isBinaryBytes(bytes);

            String content;
            if (isImage) {
                // Base64 data URI for instant, crystal-clear preview in modal
                content = "data:" + mimeType + ";base64," + Base64.getEncoder().encodeToString(bytes);
            } else if (isPdf) {
                content = "[Tài liệu PDF - Nhấn 'Tải xuống' để mở và xem nội dung]";
            } else if (isBinary) {
                content = "[Tệp tin định dạng nhị phân (" + mimeType + ", " + size + " bytes) - Nhấn 'Tải xuống' để mở]";
            } else {
                // Safe text decoding: NEVER throw MalformedInputException: Input length = 1
                try {
                    CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
                    decoder.onMalformedInput(CodingErrorAction.REPLACE);
                    decoder.onUnmappableCharacter(CodingErrorAction.REPLACE);
                    content = decoder.decode(ByteBuffer.wrap(bytes)).toString();
                } catch (Exception ex) {
                    content = new String(bytes, StandardCharsets.ISO_8859_1);
                }
            }

            FileRecord rec = JsonDataStore.getInstance().getFileRecord(normPath);
            String uploader = (rec != null && rec.getUploader() != null) ? rec.getUploader() : "system";
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String modTime = sdf.format(new Date(file.lastModified()));

            FileViewData data = new FileViewData(
                normPath, filename, size, mimeType, isBinary, isImage, isPdf, content, sha256, uploader, modTime
            );

            // Record audit log
            JsonDataStore.getInstance().addAuditLog(
                "REQ-READ-" + System.currentTimeMillis() % 100000,
                "127.0.0.1", user.getUsername(), "READ_FILE", normPath, "ALLOWED", 200,
                "Đọc nội dung tệp tin thành công (" + mimeType + ")"
            );

            return new OpResult<>(true, 200, "Thành công", data);
        } catch (IOException e) {
            return new OpResult<>(false, 500, "Lỗi đọc tệp tin: " + e.getMessage(), null);
        }
    }

    public static OpResult<byte[]> readFileBytes(User user, String relPath) {
        String normPath = AclEngine.normalizePath(relPath);
        AclEngine.AuthZResult authz = AclEngine.checkPermission(user, normPath, "READ");
        if (!authz.allowed) {
            return new OpResult<>(false, 403, "403 Bị từ chối (Forbidden) - " + authz.reason, null);
        }

        Path target = SystemConfig.SECURE_STORAGE_DIR.resolve(normPath.replaceAll("^[\\/\\\\]+", "")).normalize();
        File file = target.toFile();
        if (!file.exists() || !file.isFile()) {
            return new OpResult<>(false, 404, "Tệp tin '" + normPath + "' không tồn tại.", null);
        }

        try {
            byte[] bytes = Files.readAllBytes(target);
            return new OpResult<>(true, 200, "Thành công", bytes);
        } catch (IOException e) {
            return new OpResult<>(false, 500, "Lỗi đọc tệp tin: " + e.getMessage(), null);
        }
    }

    public static OpResult<String> writeFile(User user, String relPath, byte[] content, 
                                             String clientIp, String requestId) {
        String normPath = AclEngine.normalizePath(relPath);
        String filename = new File(normPath).getName();
        String parentDir = new File(normPath).getParent();
        if (parentDir == null) parentDir = "/";
        parentDir = parentDir.replace("\\", "/");

        // 1. Kiểm tra Ủy quyền AuthZ: Quyền Ghi trên tệp và thư mục cha
        AclEngine.AuthZResult authz = AclEngine.checkPermission(user, normPath, "WRITE");
        if (!authz.allowed) {
            AclEngine.AuthZResult parentAuthz = AclEngine.checkPermission(user, parentDir, "WRITE");
            if (!parentAuthz.allowed) {
                JsonDataStore.getInstance().addAuditLog(
                    requestId, clientIp, user.getUsername(), "FILE_WRITE", normPath, "DENIED_AUTHZ", 403,
                    "Không đủ quyền Ghi: " + authz.reason
                );
                return new OpResult<>(false, 403, "403 Bị từ chối - Không đủ quyền Ghi trên '" + normPath + "'.", null);
            }
        }

        // 2. Quét kiểm tra Antivirus đa lớp
        AntivirusScanner.ScanResult avResult = AntivirusScanner.scanPayload(
            filename, content, normPath, clientIp, user.getUsername(), requestId
        );
        if (!avResult.clean) {
            return new OpResult<>(
                false, 422,
                "Cảnh báo Antivirus: Phát hiện mã độc trong '" + filename + "' (" + avResult.threatName + "). Tệp tin đã được cô lập vào khu vực cách ly (Quarantine Vault).",
                avResult.threatName
            );
        }

        // 3. Ghi tệp tin an toàn vào kho lưu trữ vật lý & đồng bộ Database
        try {
            Path target = SystemConfig.SECURE_STORAGE_DIR.resolve(normPath.replaceAll("^[\\/\\\\]+", "")).normalize();
            Files.createDirectories(target.getParent());
            Files.write(target, content);

            // Ghi nhận / Cập nhật vào Database JsonDataStore
            String sha256 = CryptoUtils.sha256Hex(content);
            String mimeType = detectMimeType(filename, content);
            JsonDataStore.getInstance().saveOrUpdateFileRecord(
                normPath, filename, content.length, mimeType, user.getUsername(), sha256, false
            );

            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, user.getUsername(), "FILE_WRITE", normPath, "ALLOWED", 200,
                "Tệp tin đã được quét Antivirus sạch, ghi thành công vào bộ lưu trữ và lưu vào Database."
            );

            return new OpResult<>(true, 200, "Ghi tệp tin thành công.", normPath);
        } catch (IOException e) {
            return new OpResult<>(false, 500, "Lỗi I/O ghi đĩa: " + e.getMessage(), null);
        }
    }

    public static OpResult<String> createDirectory(User user, String relPath, String clientIp, String requestId) {
        String normPath = AclEngine.normalizePath(relPath);
        AclEngine.AuthZResult authz = AclEngine.checkPermission(user, normPath, "WRITE");
        if (!authz.allowed) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, user.getUsername(), "MKDIR", normPath, "DENIED_AUTHZ", 403,
                authz.reason
            );
            return new OpResult<>(false, 403, "403 Bị từ chối - " + authz.reason, null);
        }

        try {
            Path target = SystemConfig.SECURE_STORAGE_DIR.resolve(normPath.replaceAll("^[\\/\\\\]+", "")).normalize();
            if (Files.exists(target)) {
                return new OpResult<>(false, 400, "Thư mục đã tồn tại từ trước.", null);
            }
            Files.createDirectories(target);

            String dirName = new File(normPath).getName();
            JsonDataStore.getInstance().saveOrUpdateFileRecord(
                normPath, dirName, 0, "inode/directory", user.getUsername(), "-", true
            );

            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, user.getUsername(), "MKDIR", normPath, "ALLOWED", 201,
                "Tạo thư mục thành công và đồng bộ vào Database."
            );
            return new OpResult<>(true, 201, "Tạo thư mục thành công.", normPath);
        } catch (IOException e) {
            return new OpResult<>(false, 500, "Lỗi I/O: " + e.getMessage(), null);
        }
    }

    public static OpResult<String> deleteResource(User user, String relPath, String clientIp, String requestId) {
        String normPath = AclEngine.normalizePath(relPath);
        AclEngine.AuthZResult authz = AclEngine.checkPermission(user, normPath, "DELETE");
        if (!authz.allowed) {
            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, user.getUsername(), "DELETE", normPath, "DENIED_AUTHZ", 403,
                authz.reason
            );
            return new OpResult<>(false, 403, "403 Bị từ chối - " + authz.reason, null);
        }

        // Chặn xóa các thư mục bảo vệ hệ thống
        if (normPath.equals("/") || normPath.equals("/projects") || 
            normPath.equals("/company_policies") || normPath.equals("/hr_confidential")) {
            return new OpResult<>(false, 403, "Không được phép xóa các thư mục hệ thống mặc định.", null);
        }

        try {
            Path target = SystemConfig.SECURE_STORAGE_DIR.resolve(normPath.replaceAll("^[\\/\\\\]+", "")).normalize();
            if (!Files.exists(target)) {
                return new OpResult<>(false, 404, "Tài nguyên không tồn tại.", null);
            }

            if (Files.isDirectory(target)) {
                deleteRecursively(target.toFile());
            } else {
                Files.delete(target);
            }

            // Xóa bản ghi trong Database
            JsonDataStore.getInstance().removeFileRecord(normPath);

            JsonDataStore.getInstance().addAuditLog(
                requestId, clientIp, user.getUsername(), "DELETE", normPath, "ALLOWED", 200,
                "Xóa tài nguyên và cập nhật Database thành công."
            );
            return new OpResult<>(true, 200, "Xóa tài nguyên thành công.", normPath);
        } catch (IOException e) {
            return new OpResult<>(false, 500, "Lỗi I/O: " + e.getMessage(), null);
        }
    }

    private static void deleteRecursively(File file) throws IOException {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File f : files) {
                    deleteRecursively(f);
                }
            }
        }
        if (!file.delete()) {
            throw new IOException("Không thể xóa: " + file.getAbsolutePath());
        }
    }

    public static String detectMimeType(String filename, byte[] sample) {
        String lower = filename.toLowerCase();
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".gif")) return "image/gif";
        if (lower.endsWith(".webp")) return "image/webp";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".bmp")) return "image/bmp";
        if (lower.endsWith(".ico")) return "image/x-icon";
        if (lower.endsWith(".pdf")) return "application/pdf";
        if (lower.endsWith(".txt")) return "text/plain";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".csv")) return "text/csv";
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
        if (lower.endsWith(".xml")) return "application/xml";
        if (lower.endsWith(".js")) return "application/javascript";
        if (lower.endsWith(".css")) return "text/css";
        if (lower.endsWith(".py")) return "text/x-python";
        if (lower.endsWith(".java")) return "text/x-java-source";
        if (lower.endsWith(".md")) return "text/markdown";
        if (lower.endsWith(".zip")) return "application/zip";
        if (lower.endsWith(".docx")) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        if (lower.endsWith(".xlsx")) return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

        // Check magic bytes if sample is provided
        if (sample != null && sample.length >= 4) {
            if (sample[0] == (byte) 0x89 && sample[1] == 0x50 && sample[2] == 0x4E && sample[3] == 0x47) return "image/png";
            if (sample[0] == (byte) 0xFF && sample[1] == (byte) 0xD8 && sample[2] == (byte) 0xFF) return "image/jpeg";
            if (sample[0] == 0x47 && sample[1] == 0x49 && sample[2] == 0x46) return "image/gif";
            if (sample[0] == 0x25 && sample[1] == 0x50 && sample[2] == 0x44 && sample[3] == 0x46) return "application/pdf";
            if (sample[0] == 0x50 && sample[1] == 0x4B && sample[2] == 0x03 && sample[3] == 0x04) return "application/zip";
        }

        return "application/octet-stream";
    }

    public static boolean isBinaryBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        int checkLen = Math.min(bytes.length, 1024);
        for (int i = 0; i < checkLen; i++) {
            if (bytes[i] == 0) {
                return true;
            }
        }
        return false;
    }
}

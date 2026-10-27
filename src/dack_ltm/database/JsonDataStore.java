package dack_ltm.database;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import dack_ltm.config.SystemConfig;
import dack_ltm.models.*;
import dack_ltm.security.CryptoUtils;

/**
 * Self-Contained Thread-Safe Enterprise Data Store with Auto-Seeding and Disk Persistence.
 * Manages Users, Permissions (ACL), Firewall Rules, Audit Logs, Quarantine Vault, and File Metadata Records.
 */
public class JsonDataStore {
    private static JsonDataStore instance;

    private final Map<Integer, User> users = new ConcurrentHashMap<>();
    private final Map<String, User> usersByUsername = new ConcurrentHashMap<>();
    private final List<FilePermission> permissions = new CopyOnWriteArrayList<>();
    private final List<FirewallRule> firewallRules = new CopyOnWriteArrayList<>();
    private final List<AuditLog> auditLogs = new CopyOnWriteArrayList<>();
    private final List<QuarantineRecord> quarantineRecords = new CopyOnWriteArrayList<>();
    private final Map<String, FileRecord> fileRecords = new ConcurrentHashMap<>();
    private final List<PasswordResetRequest> passwordResetRequests = new CopyOnWriteArrayList<>();

    private final AtomicInteger userIdSeq = new AtomicInteger(1);
    private final AtomicInteger permIdSeq = new AtomicInteger(1);
    private final AtomicInteger fwIdSeq = new AtomicInteger(1);
    private final AtomicInteger logIdSeq = new AtomicInteger(1);
    private final AtomicInteger fileIdSeq = new AtomicInteger(1);
    private final AtomicInteger resetReqIdSeq = new AtomicInteger(1);

    private String firewallMode = "blacklist"; // "blacklist" or "whitelist"
    private boolean rateLimitEnabled = true;
    private int rateLimitMax = SystemConfig.RATE_LIMIT_MAX_REQUESTS;

    public static synchronized JsonDataStore getInstance() {
        if (instance == null) {
            instance = new JsonDataStore();
            instance.initAndSeed();
        }
        return instance;
    }

    private JsonDataStore() {}

    private void initAndSeed() {
        // Ensure required directories exist
        try {
            Files.createDirectories(SystemConfig.DATA_DIR);
            Files.createDirectories(SystemConfig.SECURE_STORAGE_DIR);
            Files.createDirectories(SystemConfig.QUARANTINE_DIR);
        } catch (IOException e) {
            System.err.println("[JsonDataStore] Failed to initialize storage directories: " + e.getMessage());
        }

        // 1. Seed Accounts (3 Roles with Distinct Duties)
        User admin = createUser("admin", "admin123", "ADMIN", "Administrator - Chief Information Security Officer");
        User alice = createUser("user", "user123", "USER", "Security Engineer - Project Developer");
        User bob = createUser("guest", "guest123", "GUEST", "Security Research Intern / Auditor");

        // Backward-compatible aliases for existing sessions:
        createUser("anhhao", "anhhao123", "ADMIN", "Administrator (Admin)");
        createUser("thaibao", "thaibao123", "USER", "Security Engineer (User)");
        createUser("ducnam", "ducnam123", "GUEST", "Security Auditor (Guest)");
        createUser("staff", "staff123", "USER", "Security Staff (User)");

        // 2. Seed Granular ACL Matrix Rules
        // Role 2 (USER/STAFF):
        // - /projects -> R/W/D (Full Access to projects)
        addPermission("/projects", alice.getId(), "USER", true, true, true, false);
        // - /company_policies -> Read-Only (Cannot edit policies)
        addPermission("/company_policies", alice.getId(), "USER", true, false, false, false);
        // - /hr_confidential -> Explicit Deny (Blocked from salary/HR)
        addPermission("/hr_confidential", alice.getId(), "USER", false, false, false, true);

        // Role 3 (GUEST/INTERN):
        // - /projects -> Read-Only (Can view project docs, cannot modify)
        addPermission("/projects", bob.getId(), "GUEST", true, false, false, false);
        // - /company_policies -> Read-Only
        addPermission("/company_policies", bob.getId(), "GUEST", true, false, false, false);
        // - /hr_confidential -> Explicit Deny (Strictly forbidden)
        addPermission("/hr_confidential", bob.getId(), "GUEST", false, false, false, true);

        // 3. Seed Physical Storage Files
        seedPhysicalFile("projects/architecture.txt",
            "===================================================================\n" +
            "ENTERPRISE SECURE CLOUD ARCHITECTURE SPECIFICATION (2026)\n" +
            "===================================================================\n" +
            "Project: Defense-in-Depth Distributed Remote File Access Management\n" +
            "Author: Security Engineer (Staff)\n" +
            "Status: APPROVED FOR PRODUCTION DEPLOYMENT\n\n" +
            "1. NETWORK TOPOLOGY:\n" +
            "   - External Gateway: Reverse Proxy with Protocol & Path Traversal Neutralization.\n" +
            "   - Firewall Engine: IP Filtering, Sliding Window Rate Limiting, Brute-Force Lockout.\n" +
            "   - Antivirus Scanner: 4-Stage Heuristic & EICAR Quarantine Inspection.\n" +
            "   - Access Control: Granular Matrix ACL + PBKDF2/JWT Authentication.\n"
        );

        seedPhysicalFile("company_policies/security_rules.txt",
            "===================================================================\n" +
            "CORPORATE CYBERSECURITY & REMOTE ACCESS POLICY\n" +
            "===================================================================\n" +
            "Document ID: SEC-POL-2026-v4.2\n" +
            "Audience: All Employees, Contractors, and Interns\n\n" +
            "1. ACCESS CONTROL GUIDELINES:\n" +
            "   - Principle of Least Privilege (PoLP): Minimum required rights.\n" +
            "   - Credentials must never be shared under any circumstances.\n" +
            "   - All uploads pass through real-time Antivirus Quarantine analysis.\n"
        );

        seedPhysicalFile("hr_confidential/salary_2026.txt",
            "===================================================================\n" +
            "STRICTLY CONFIDENTIAL - EXECUTIVE & ENGINEERING SALARY MATRIX 2026\n" +
            "===================================================================\n" +
            "Classification: TOP SECRET // HR & CISO CLEARANCE ONLY\n\n" +
            "[EXECUTIVE LEADERSHIP]\n" +
            "- Chief Information Security Officer (admin) : $280,000 / yr + Equity\n" +
            "- Senior Security Engineer (user)            : $165,000 / yr + Bonus\n" +
            "- Security Research Intern (guest)           : $45,000 / yr\n"
        );

        // 4. Auto-sync physical storage into Database records
        syncStorageFiles();

        // 5. Commit initial state to database file
        persistDatabase();
    }

    private void seedPhysicalFile(String relPath, String content) {
        try {
            Path file = SystemConfig.SECURE_STORAGE_DIR.resolve(relPath);
            Files.createDirectories(file.getParent());
            if (!Files.exists(file)) {
                Files.writeString(file, content, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Scans SECURE_STORAGE_DIR and registers all files and folders into the database.
     */
    public synchronized void syncStorageFiles() {
        try {
            File root = SystemConfig.SECURE_STORAGE_DIR.toFile();
            if (!root.exists()) return;
            scanAndIndexRecursive(root, "");
        } catch (Exception e) {
            System.err.println("[JsonDataStore] syncStorageFiles error: " + e.getMessage());
        }
    }

    private void scanAndIndexRecursive(File currentDir, String relPath) {
        File[] list = currentDir.listFiles();
        if (list == null) return;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        for (File f : list) {
            String childRel = relPath.isEmpty() ? "/" + f.getName() : relPath + "/" + f.getName();
            String normPath = childRel.replace("\\", "/");

            if (!fileRecords.containsKey(normPath)) {
                int id = fileIdSeq.getAndIncrement();
                long size = f.isFile() ? f.length() : 0;
                String modTime = sdf.format(new Date(f.lastModified()));
                String sha256 = "-";
                String mimeType = f.isDirectory() ? "inode/directory" : detectSimpleMime(f.getName());

                if (f.isFile() && f.length() > 0 && f.length() < 20 * 1024 * 1024) {
                    try {
                        byte[] bytes = Files.readAllBytes(f.toPath());
                        sha256 = CryptoUtils.sha256Hex(bytes);
                    } catch (Exception ignored) {}
                }

                FileRecord rec = new FileRecord(
                    id, normPath, f.getName(), size, mimeType, "anhhao", sha256, modTime, modTime, f.isDirectory()
                );
                fileRecords.put(normPath, rec);
            }

            if (f.isDirectory()) {
                scanAndIndexRecursive(f, normPath);
            }
        }
    }

    private String detectSimpleMime(String filename) {
        String lower = filename.toLowerCase();
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".gif")) return "image/gif";
        if (lower.endsWith(".webp")) return "image/webp";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".pdf")) return "application/pdf";
        if (lower.endsWith(".txt")) return "text/plain";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".csv")) return "text/csv";
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
        if (lower.endsWith(".md")) return "text/markdown";
        return "application/octet-stream";
    }

    // --- File Records in Database ---
    public synchronized FileRecord saveOrUpdateFileRecord(String virtualPath, String fileName, long size,
                                                         String mimeType, String uploader, String sha256, boolean isFolder) {
        String normPath = virtualPath.replace("\\", "/").replaceAll("^/+", "/");
        if (!normPath.startsWith("/")) normPath = "/" + normPath;

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String now = sdf.format(new Date());

        FileRecord existing = fileRecords.get(normPath);
        FileRecord rec;
        if (existing != null) {
            existing.setFileSize(size);
            existing.setMimeType(mimeType);
            existing.setSha256(sha256);
            existing.setModifiedAt(now);
            if (uploader != null && !uploader.isEmpty()) existing.setUploader(uploader);
            rec = existing;
        } else {
            int id = fileIdSeq.getAndIncrement();
            rec = new FileRecord(id, normPath, fileName, size, mimeType, uploader != null ? uploader : "anhhao", sha256, now, now, isFolder);
            fileRecords.put(normPath, rec);
        }

        persistDatabase();
        return rec;
    }

    public synchronized void removeFileRecord(String virtualPath) {
        String p = virtualPath.replace("\\", "/").replaceAll("^/+", "/");
        if (!p.startsWith("/")) p = "/" + p;
        final String normPath = p;
        final String prefix = normPath + "/";
        fileRecords.remove(normPath);
        // Also remove child entries if directory
        fileRecords.keySet().removeIf(k -> k.startsWith(prefix));
        persistDatabase();
    }

    public FileRecord getFileRecord(String virtualPath) {
        if (virtualPath == null) return null;
        String normPath = virtualPath.replace("\\", "/").replaceAll("^/+", "/");
        if (!normPath.startsWith("/")) normPath = "/" + normPath;
        return fileRecords.get(normPath);
    }

    public List<FileRecord> getAllFileRecords() {
        return new ArrayList<>(fileRecords.values());
    }

    // --- Users ---
    public User createUser(String username, String password, String role, String fullName) {
        return createUser(username, password, role, fullName, "ACTIVE");
    }

    public User createUser(String username, String password, String role, String fullName, String status) {
        int id = userIdSeq.getAndIncrement();
        String hash = CryptoUtils.hashPassword(password);
        boolean active = "ACTIVE".equalsIgnoreCase(status);
        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        User u = new User(id, username, hash, role.toUpperCase(), fullName, active, status, 0, null, now);
        users.put(id, u);
        usersByUsername.put(username.toLowerCase(), u);
        persistDatabase();
        return u;
    }

    public synchronized User registerPendingUser(String username, String password, String role, String fullName, String reason) {
        int id = userIdSeq.getAndIncrement();
        String hash = CryptoUtils.hashPassword(password);
        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String r = (role != null && role.equalsIgnoreCase("GUEST")) ? "GUEST" : "USER";
        User u = new User(id, username, hash, r, fullName, false, "PENDING", 0, "Chờ Quản trị viên (Admin) phê duyệt", now);
        users.put(id, u);
        usersByUsername.put(username.toLowerCase(), u);

        // Pre-configure ACL rules for this user
        if ("USER".equals(r)) {
            addPermission("/projects", u.getId(), "USER", true, true, true, false);
            addPermission("/company_policies", u.getId(), "USER", true, false, false, false);
            addPermission("/hr_confidential", u.getId(), "USER", false, false, false, true);
        } else {
            addPermission("/projects", u.getId(), "GUEST", true, false, false, false);
            addPermission("/company_policies", u.getId(), "GUEST", true, false, false, false);
            addPermission("/hr_confidential", u.getId(), "GUEST", false, false, false, true);
        }

        persistDatabase();
        return u;
    }

    public synchronized boolean approveUser(String username) {
        User u = getUserByUsername(username);
        if (u == null) return false;
        u.setStatus("ACTIVE");
        u.setActive(true);
        u.setFailedLoginAttempts(0);
        u.setLockReason(null);
        persistDatabase();
        return true;
    }

    public synchronized boolean unlockUser(String username) {
        User u = getUserByUsername(username);
        if (u == null) return false;
        u.setStatus("ACTIVE");
        u.setActive(true);
        u.setFailedLoginAttempts(0);
        u.setLockReason(null);
        persistDatabase();
        return true;
    }

    // --- Password Reset Request Lifecycle (Admin Review & OTP Code) ---
    public synchronized PasswordResetRequest requestPasswordReset(String username, String reason) {
        User u = getUserByUsername(username);
        if (u == null) return null;

        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        for (PasswordResetRequest r : passwordResetRequests) {
            if (r.getUsername().equalsIgnoreCase(username) && "PENDING".equalsIgnoreCase(r.getStatus())) {
                r.setReason(reason);
                r.setRequestedAt(now);
                persistDatabase();
                return r;
            }
        }

        int id = resetReqIdSeq.getAndIncrement();
        PasswordResetRequest req = new PasswordResetRequest(id, u.getUsername(), reason, now);
        passwordResetRequests.add(0, req);
        persistDatabase();
        return req;
    }

    public synchronized String approvePasswordReset(String username) {
        for (PasswordResetRequest r : passwordResetRequests) {
            if (r.getUsername().equalsIgnoreCase(username) && "PENDING".equalsIgnoreCase(r.getStatus())) {
                // Generate a secure 6-digit OTP code (e.g. 748192)
                String code = String.format("%06d", new java.util.Random().nextInt(1000000));
                r.setStatus("APPROVED");
                r.setResetCode(code);
                r.setApprovedAt(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
                persistDatabase();
                return code;
            }
        }
        return null;
    }

    public synchronized boolean rejectPasswordReset(String username) {
        for (PasswordResetRequest r : passwordResetRequests) {
            if (r.getUsername().equalsIgnoreCase(username) && "PENDING".equalsIgnoreCase(r.getStatus())) {
                r.setStatus("REJECTED");
                persistDatabase();
                return true;
            }
        }
        return false;
    }

    public synchronized boolean verifyAndResetPasswordWithCode(String username, String code, String newPassword) {
        if (username == null || code == null || newPassword == null) return false;
        User u = getUserByUsername(username);
        if (u == null) return false;

        for (PasswordResetRequest r : passwordResetRequests) {
            if (r.getUsername().equalsIgnoreCase(username) &&
                "APPROVED".equalsIgnoreCase(r.getStatus()) &&
                r.getResetCode() != null &&
                r.getResetCode().trim().equals(code.trim())) {

                u.setPasswordHash(CryptoUtils.hashPassword(newPassword));
                u.setStatus("ACTIVE");
                u.setActive(true);
                u.setFailedLoginAttempts(0);
                u.setLockReason(null);

                r.setStatus("COMPLETED");
                persistDatabase();
                return true;
            }
        }
        return false;
    }

    public List<PasswordResetRequest> getAllPasswordResetRequests() {
        return new ArrayList<>(passwordResetRequests);
    }

    public PasswordResetRequest getLatestResetRequest(String username) {
        for (PasswordResetRequest r : passwordResetRequests) {
            if (r.getUsername().equalsIgnoreCase(username)) {
                return r;
            }
        }
        return null;
    }

    public synchronized boolean lockUser(String username, String reason) {
        User u = getUserByUsername(username);
        if (u == null) return false;
        u.setStatus("LOCKED");
        u.setActive(false);
        u.setLockReason(reason != null ? reason : "Khóa bởi Quản trị viên");
        persistDatabase();
        return true;
    }

    public synchronized boolean resetPassword(String username, String newPassword) {
        User u = getUserByUsername(username);
        if (u == null) return false;
        u.setPasswordHash(CryptoUtils.hashPassword(newPassword));
        u.setStatus("ACTIVE");
        u.setActive(true);
        u.setFailedLoginAttempts(0);
        u.setLockReason(null);
        persistDatabase();
        return true;
    }

    public synchronized boolean deleteUser(String username) {
        User u = getUserByUsername(username);
        if (u == null) return false;
        users.remove(u.getId());
        usersByUsername.remove(username.toLowerCase());
        permissions.removeIf(p -> p.getUserId() != null && p.getUserId() == u.getId());
        persistDatabase();
        return true;
    }

    public User getUserById(int id) {
        return users.get(id);
    }

    public User getUserByUsername(String username) {
        if (username == null) return null;
        return usersByUsername.get(username.toLowerCase());
    }

    public List<User> getAllUsers() {
        return new ArrayList<>(users.values());
    }

    // --- Permissions ---
    public FilePermission addPermission(String resourcePath, Integer userId, String role, 
                                        boolean canRead, boolean canWrite, boolean canDelete, boolean isDeny) {
        int id = permIdSeq.getAndIncrement();
        FilePermission p = new FilePermission(id, resourcePath, userId, role, canRead, canWrite, canDelete, isDeny);
        permissions.add(p);
        persistDatabase();
        return p;
    }

    public List<FilePermission> getAllPermissions() {
        return new ArrayList<>(permissions);
    }

    public boolean deletePermission(int id) {
        boolean removed = permissions.removeIf(p -> p.getId() == id);
        if (removed) persistDatabase();
        return removed;
    }

    // --- Firewall Rules ---
    public FirewallRule addFirewallRule(String ip, String type, String reason, Long expiresAtMillis) {
        int id = fwIdSeq.getAndIncrement();
        FirewallRule r = new FirewallRule(id, ip, type.toUpperCase(), reason, true, expiresAtMillis);
        firewallRules.add(r);
        return r;
    }

    public List<FirewallRule> getAllFirewallRules() {
        return new ArrayList<>(firewallRules);
    }

    public boolean deleteFirewallRule(int id) {
        return firewallRules.removeIf(r -> r.getId() == id);
    }

    public String getFirewallMode() { return firewallMode; }
    public void setFirewallMode(String mode) { this.firewallMode = mode.toLowerCase(); }

    public boolean isRateLimitEnabled() { return rateLimitEnabled; }
    public void setRateLimitEnabled(boolean val) { this.rateLimitEnabled = val; }

    public int getRateLimitMax() { return rateLimitMax; }
    public void setRateLimitMax(int val) { this.rateLimitMax = val; }

    // --- Audit Logs ---
    public AuditLog addAuditLog(String requestId, String clientIp, String username, 
                                String action, String resourcePath, String status, int statusCode, String reason) {
        int id = logIdSeq.getAndIncrement();
        AuditLog log = new AuditLog(id, requestId, clientIp, username, action, resourcePath, status, statusCode, reason);
        auditLogs.add(0, log); // Newest first
        while (auditLogs.size() > 1000) {
            auditLogs.remove(auditLogs.size() - 1);
        }
        return log;
    }

    public List<AuditLog> getAllAuditLogs(String filterStatus) {
        if (filterStatus == null || filterStatus.equalsIgnoreCase("ALL")) {
            return new ArrayList<>(auditLogs);
        }
        List<AuditLog> filtered = new ArrayList<>();
        for (AuditLog l : auditLogs) {
            if (l.getStatus().equalsIgnoreCase(filterStatus)) {
                filtered.add(l);
            }
        }
        return filtered;
    }

    // --- Quarantine Records ---
    public QuarantineRecord addQuarantineRecord(String id, String origFile, String targetPath, 
                                               String threat, String hash, long size, 
                                               String step, String ip, String user) {
        QuarantineRecord rec = new QuarantineRecord(id, origFile, targetPath, threat, hash, size, step, ip, user);
        quarantineRecords.add(0, rec);
        return rec;
    }

    public List<QuarantineRecord> getAllQuarantineRecords() {
        return new ArrayList<>(quarantineRecords);
    }

    public boolean deleteQuarantineRecord(String id) {
        return quarantineRecords.removeIf(r -> r.getId().equals(id));
    }

    // --- Database Persistence ---
    public synchronized void persistDatabase() {
        try {
            Path dbPath = SystemConfig.DATA_DIR.resolve("database.json");
            Files.createDirectories(dbPath.getParent());

            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"version\": \"2.6\",\n");
            sb.append("  \"status\": \"CONNECTED\",\n");
            sb.append("  \"last_synced\": \"").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\",\n");

            // Users
            sb.append("  \"users\": [\n");
            List<User> userList = getAllUsers();
            for (int i = 0; i < userList.size(); i++) {
                User u = userList.get(i);
                sb.append(String.format("    {\"id\":%d,\"username\":\"%s\",\"role\":\"%s\",\"full_name\":\"%s\",\"status\":\"%s\",\"active\":%b,\"failed_attempts\":%d,\"lock_reason\":%s,\"registered_at\":%s}",
                    u.getId(), escape(u.getUsername()), escape(u.getRole()), escape(u.getFullName()),
                    escape(u.getStatus()), u.isActive(), u.getFailedLoginAttempts(),
                    u.getLockReason() != null ? "\"" + escape(u.getLockReason()) + "\"" : "null",
                    u.getRegisteredAt() != null ? "\"" + escape(u.getRegisteredAt()) + "\"" : "null"));
                if (i < userList.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ],\n");

            // Permissions
            sb.append("  \"permissions\": [\n");
            List<FilePermission> permList = getAllPermissions();
            for (int i = 0; i < permList.size(); i++) {
                FilePermission p = permList.get(i);
                sb.append(String.format("    {\"id\":%d,\"resource_path\":\"%s\",\"user_id\":%s,\"role\":%s,\"can_read\":%b,\"can_write\":%b,\"can_delete\":%b,\"deny\":%b}",
                    p.getId(), escape(p.getResourcePath()),
                    p.getUserId() == null ? "null" : p.getUserId().toString(),
                    p.getRole() == null ? "null" : "\"" + escape(p.getRole()) + "\"",
                    p.isCanRead(), p.isCanWrite(), p.isCanDelete(), p.isDeny()));
                if (i < permList.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ],\n");

            // Files
            sb.append("  \"files\": [\n");
            List<FileRecord> fileList = getAllFileRecords();
            for (int i = 0; i < fileList.size(); i++) {
                FileRecord fr = fileList.get(i);
                sb.append(String.format("    {\"id\":%d,\"virtual_path\":\"%s\",\"file_name\":\"%s\",\"size\":%d,\"mime_type\":\"%s\",\"uploader\":\"%s\",\"sha256\":\"%s\",\"created_at\":\"%s\",\"modified_at\":\"%s\",\"is_folder\":%b}",
                    fr.getId(), escape(fr.getVirtualPath()), escape(fr.getFileName()), fr.getFileSize(),
                    escape(fr.getMimeType()), escape(fr.getUploader()), escape(fr.getSha256()),
                    escape(fr.getCreatedAt()), escape(fr.getModifiedAt()), fr.isFolder()));
                if (i < fileList.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ]\n");
            sb.append("}\n");

            Files.writeString(dbPath, sb.toString(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[JsonDataStore] Failed to persist database: " + e.getMessage());
        }
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}

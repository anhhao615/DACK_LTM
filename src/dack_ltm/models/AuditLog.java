package dack_ltm.models;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class AuditLog {
    private static final DateTimeFormatter FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private int id;
    private String requestId;
    private String clientIp;
    private String username;
    private String action;       // LOGIN, LOGOUT, READ, WRITE, DELETE, MKDIR, etc.
    private String resourcePath;
    private String status;       // ALLOWED, DENIED_AUTHZ, BLOCKED_FIREWALL, BLOCKED_PROXY, QUARANTINED_AV, AUTHN_FAILED
    private int statusCode;
    private String reason;
    private long timestamp;

    public AuditLog() {
        this.timestamp = System.currentTimeMillis();
    }

    public AuditLog(int id, String requestId, String clientIp, String username, String action, 
                    String resourcePath, String status, int statusCode, String reason) {
        this.id = id;
        this.requestId = requestId;
        this.clientIp = clientIp;
        this.username = username != null ? username : "ANONYMOUS";
        this.action = action;
        this.resourcePath = resourcePath != null ? resourcePath : "-";
        this.status = status;
        this.statusCode = statusCode;
        this.reason = reason;
        this.timestamp = System.currentTimeMillis();
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }

    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getResourcePath() { return resourcePath; }
    public void setResourcePath(String resourcePath) { this.resourcePath = resourcePath; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getFormattedTime() {
        return FORMATTER.format(Instant.ofEpochMilli(timestamp));
    }
}

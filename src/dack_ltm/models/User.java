package dack_ltm.models;

import java.io.Serializable;

/**
 * User Account Entity with Enterprise RBAC and Account Lockout Lifecycle.
 * Statuses: ACTIVE (Approved & Normal), PENDING (Awaiting Admin Approval), LOCKED (Locked after 3 failed logins).
 */
public class User implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String username;
    private String passwordHash;
    private String role; // "ADMIN", "USER", "GUEST"
    private String fullName;
    private boolean active;
    private String status; // "ACTIVE", "PENDING", "LOCKED"
    private int failedLoginAttempts;
    private String lockReason;
    private String registeredAt;

    public User() {
        this.status = "ACTIVE";
        this.failedLoginAttempts = 0;
    }

    public User(int id, String username, String passwordHash, String role, String fullName, boolean active) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.fullName = fullName;
        this.active = active;
        this.status = active ? "ACTIVE" : "PENDING";
        this.failedLoginAttempts = 0;
        this.lockReason = null;
        this.registeredAt = null;
    }

    public User(int id, String username, String passwordHash, String role, String fullName,
                boolean active, String status, int failedLoginAttempts, String lockReason, String registeredAt) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.fullName = fullName;
        this.active = active;
        this.status = status;
        this.failedLoginAttempts = failedLoginAttempts;
        this.lockReason = lockReason;
        this.registeredAt = registeredAt;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public String getStatus() { 
        if (status == null) return active ? "ACTIVE" : "PENDING";
        return status; 
    }
    public void setStatus(String status) { 
        this.status = status; 
        if ("LOCKED".equalsIgnoreCase(status) || "PENDING".equalsIgnoreCase(status)) {
            this.active = false;
        } else if ("ACTIVE".equalsIgnoreCase(status)) {
            this.active = true;
        }
    }

    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public void setFailedLoginAttempts(int failedLoginAttempts) { this.failedLoginAttempts = failedLoginAttempts; }

    public String getLockReason() { return lockReason; }
    public void setLockReason(String lockReason) { this.lockReason = lockReason; }

    public String getRegisteredAt() { return registeredAt; }
    public void setRegisteredAt(String registeredAt) { this.registeredAt = registeredAt; }
}

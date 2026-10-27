package dack_ltm.models;

import java.io.Serializable;

/**
 * Model representing a user's password recovery request.
 * Workflow:
 * 1. User submits request (status = PENDING).
 * 2. Admin reviews request in SOC Dashboard and approves it, generating a 6-digit OTP reset code (status = APPROVED).
 * 3. User enters the received reset code + new password to complete password reset & unlock account (status = COMPLETED).
 */
public class PasswordResetRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String username;
    private String status; // "PENDING", "APPROVED", "COMPLETED", "REJECTED"
    private String resetCode;
    private String reason;
    private String requestedAt;
    private String approvedAt;

    public PasswordResetRequest() {
        this.status = "PENDING";
    }

    public PasswordResetRequest(int id, String username, String reason, String requestedAt) {
        this.id = id;
        this.username = username;
        this.reason = reason;
        this.requestedAt = requestedAt;
        this.status = "PENDING";
        this.resetCode = null;
        this.approvedAt = null;
    }

    public PasswordResetRequest(int id, String username, String status, String resetCode, String reason, String requestedAt, String approvedAt) {
        this.id = id;
        this.username = username;
        this.status = status;
        this.resetCode = resetCode;
        this.reason = reason;
        this.requestedAt = requestedAt;
        this.approvedAt = approvedAt;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getResetCode() { return resetCode; }
    public void setResetCode(String resetCode) { this.resetCode = resetCode; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getRequestedAt() { return requestedAt; }
    public void setRequestedAt(String requestedAt) { this.requestedAt = requestedAt; }

    public String getApprovedAt() { return approvedAt; }
    public void setApprovedAt(String approvedAt) { this.approvedAt = approvedAt; }
}

package dack_ltm.models;

public class FirewallRule {
    private int id;
    private String ipAddress;
    private String ruleType; // "BLACKLIST", "WHITELIST"
    private String reason;
    private boolean active;
    private Long expiresAtMillis; // null if permanent

    public FirewallRule() {}

    public FirewallRule(int id, String ipAddress, String ruleType, String reason, boolean active, Long expiresAtMillis) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.ruleType = ruleType;
        this.reason = reason;
        this.active = active;
        this.expiresAtMillis = expiresAtMillis;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getRuleType() { return ruleType; }
    public void setRuleType(String ruleType) { this.ruleType = ruleType; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public Long getExpiresAtMillis() { return expiresAtMillis; }
    public void setExpiresAtMillis(Long expiresAtMillis) { this.expiresAtMillis = expiresAtMillis; }
}

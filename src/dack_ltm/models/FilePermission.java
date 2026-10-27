package dack_ltm.models;

public class FilePermission {
    private int id;
    private String resourcePath;
    private Integer userId; // nullable if assigned to role
    private String role;     // nullable if assigned to user
    private boolean canRead;
    private boolean canWrite;
    private boolean canDelete;
    private boolean deny;    // true for explicit deny

    public FilePermission() {}

    public FilePermission(int id, String resourcePath, Integer userId, String role, 
                          boolean canRead, boolean canWrite, boolean canDelete, boolean deny) {
        this.id = id;
        this.resourcePath = resourcePath;
        this.userId = userId;
        this.role = role;
        this.canRead = canRead;
        this.canWrite = canWrite;
        this.canDelete = canDelete;
        this.deny = deny;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getResourcePath() { return resourcePath; }
    public void setResourcePath(String resourcePath) { this.resourcePath = resourcePath; }

    public Integer getUserId() { return userId; }
    public void setUserId(Integer userId) { this.userId = userId; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public boolean isCanRead() { return canRead; }
    public void setCanRead(boolean canRead) { this.canRead = canRead; }

    public boolean isCanWrite() { return canWrite; }
    public void setCanWrite(boolean canWrite) { this.canWrite = canWrite; }

    public boolean isCanDelete() { return canDelete; }
    public void setCanDelete(boolean canDelete) { this.canDelete = canDelete; }

    public boolean isDeny() { return deny; }
    public void setDeny(boolean deny) { this.deny = deny; }
}

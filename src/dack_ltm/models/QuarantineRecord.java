package dack_ltm.models;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class QuarantineRecord {
    private static final DateTimeFormatter FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private String id;
    private String originalFilename;
    private String targetPath;
    private String threatName;
    private String sha256Hash;
    private long fileSize;
    private String detectedByStep;
    private String uploaderIp;
    private String uploaderUsername;
    private long timestamp;

    public QuarantineRecord() {
        this.timestamp = System.currentTimeMillis();
    }

    public QuarantineRecord(String id, String originalFilename, String targetPath, String threatName, 
                            String sha256Hash, long fileSize, String detectedByStep, 
                            String uploaderIp, String uploaderUsername) {
        this.id = id;
        this.originalFilename = originalFilename;
        this.targetPath = targetPath;
        this.threatName = threatName;
        this.sha256Hash = sha256Hash;
        this.fileSize = fileSize;
        this.detectedByStep = detectedByStep;
        this.uploaderIp = uploaderIp;
        this.uploaderUsername = uploaderUsername;
        this.timestamp = System.currentTimeMillis();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getOriginalFilename() { return originalFilename; }
    public void setOriginalFilename(String originalFilename) { this.originalFilename = originalFilename; }

    public String getTargetPath() { return targetPath; }
    public void setTargetPath(String targetPath) { this.targetPath = targetPath; }

    public String getThreatName() { return threatName; }
    public void setThreatName(String threatName) { this.threatName = threatName; }

    public String getSha256Hash() { return sha256Hash; }
    public void setSha256Hash(String sha256Hash) { this.sha256Hash = sha256Hash; }

    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }

    public String getDetectedByStep() { return detectedByStep; }
    public void setDetectedByStep(String detectedByStep) { this.detectedByStep = detectedByStep; }

    public String getUploaderIp() { return uploaderIp; }
    public void setUploaderIp(String uploaderIp) { this.uploaderIp = uploaderIp; }

    public String getUploaderUsername() { return uploaderUsername; }
    public void setUploaderUsername(String uploaderUsername) { this.uploaderUsername = uploaderUsername; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getFormattedTime() {
        return FORMATTER.format(Instant.ofEpochMilli(timestamp));
    }
}

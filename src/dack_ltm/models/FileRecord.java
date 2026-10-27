package dack_ltm.models;

import java.io.Serializable;

/**
 * File metadata entity stored in JsonDataStore Database.
 * Tracks file attributes, cryptographic SHA-256 integrity hash, uploader, and timestamps.
 */
public class FileRecord implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String virtualPath;   // e.g. "/projects/architecture.txt"
    private String fileName;      // e.g. "architecture.txt"
    private long fileSize;        // bytes
    private String mimeType;      // e.g. "text/plain", "image/png"
    private String uploader;      // username e.g. "anhhao"
    private String sha256;        // sha256 checksum
    private String createdAt;     // yyyy-MM-dd HH:mm:ss
    private String modifiedAt;    // yyyy-MM-dd HH:mm:ss
    private boolean isFolder;

    public FileRecord() {}

    public FileRecord(int id, String virtualPath, String fileName, long fileSize,
                      String mimeType, String uploader, String sha256,
                      String createdAt, String modifiedAt, boolean isFolder) {
        this.id = id;
        this.virtualPath = virtualPath;
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.mimeType = mimeType;
        this.uploader = uploader;
        this.sha256 = sha256;
        this.createdAt = createdAt;
        this.modifiedAt = modifiedAt;
        this.isFolder = isFolder;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getVirtualPath() { return virtualPath; }
    public void setVirtualPath(String virtualPath) { this.virtualPath = virtualPath; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }

    public String getMimeType() { return mimeType; }
    public void setMimeType(String mimeType) { this.mimeType = mimeType; }

    public String getUploader() { return uploader; }
    public void setUploader(String uploader) { this.uploader = uploader; }

    public String getSha256() { return sha256; }
    public void setSha256(String sha256) { this.sha256 = sha256; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    public String getModifiedAt() { return modifiedAt; }
    public void setModifiedAt(String modifiedAt) { this.modifiedAt = modifiedAt; }

    public boolean isFolder() { return isFolder; }
    public void setFolder(boolean folder) { isFolder = folder; }
}

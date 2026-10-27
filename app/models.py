import logging
from app.database import get_db

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
-- Users table for Authentication (AuthN)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    full_name TEXT,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Revoked JWT tokens for secure logout
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

-- Granular File & Folder Access Control List (AuthZ)
CREATE TABLE IF NOT EXISTS file_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_path TEXT NOT NULL,
    user_id INTEGER NULL,
    role TEXT NULL,
    can_read INTEGER DEFAULT 0,
    can_write INTEGER DEFAULT 0,
    can_delete INTEGER DEFAULT 0,
    is_deny INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Firewall IP Blacklist / Whitelist rules
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    rule_type TEXT NOT NULL DEFAULT 'BLACKLIST',
    reason TEXT,
    is_active INTEGER DEFAULT 1,
    expires_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Firewall dynamic settings
CREATE TABLE IF NOT EXISTS firewall_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Antivirus Malware Signatures (SHA-256)
CREATE TABLE IF NOT EXISTS malware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_name TEXT NOT NULL,
    sha256_hash TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Antivirus Quarantine Records
CREATE TABLE IF NOT EXISTS quarantine_records (
    id TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    target_path TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    quarantined_file_path TEXT NOT NULL,
    detected_by_step TEXT NOT NULL,
    uploader_ip TEXT NOT NULL,
    uploader_username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Unified Security Audit Logs for SOC
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    resource_path TEXT,
    status TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    reason TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for lightning fast lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_file_permissions_path ON file_permissions(resource_path);
CREATE INDEX IF NOT EXISTS idx_file_permissions_user ON file_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_file_permissions_role ON file_permissions(role);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_ip ON firewall_rules(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at DESC);
"""

def init_db():
    """Initializes all tables, constraints, and initial firewall settings."""
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
        
        # Default firewall settings if not present
        default_settings = [
            ("firewall_enabled", "true"),
            ("firewall_mode", "blacklist"),
            ("rate_limit_enabled", "true"),
            ("rate_limit_max", "60"),
            ("brute_force_protection", "true"),
            ("av_enabled", "true"),
            ("av_check_extension", "true"),
            ("av_check_magic_bytes", "true"),
            ("av_check_hash", "true"),
            ("av_check_heuristics", "true")
        ]
        for key, val in default_settings:
            conn.execute(
                "INSERT OR IGNORE INTO firewall_settings (key, value) VALUES (?, ?);",
                (key, val)
            )
        
        # Seed known malware sample SHA-256 signatures for testing
        known_signatures = [
            ("Trojan.Script.Generic", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "Standard EICAR Anti-virus Test File"),
            ("Ransomware.LockBit.Sample", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Known Ransomware Binary Hash"),
            ("Backdoor.WebShell.Chopper", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "PHP WebShell Generic Signature")
        ]
        for name, shasum, desc in known_signatures:
            conn.execute(
                "INSERT OR IGNORE INTO malware_signatures (threat_name, sha256_hash, description) VALUES (?, ?, ?);",
                (name, shasum, desc)
            )
        logger.info("Database schema and baseline security signatures initialized successfully.")

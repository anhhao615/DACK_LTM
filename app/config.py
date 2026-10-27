import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
SECURE_STORAGE_DIR = BASE_DIR / "secure_storage"
QUARANTINE_DIR = BASE_DIR / "quarantine_zone"
QUARANTINE_META_DIR = QUARANTINE_DIR / "metadata"
DATABASE_PATH = BASE_DIR / "remote_file_system.db"

# Security & Crypto Configurations
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "netsec_super_secret_jwt_key_2026_dack_ltm_defense_in_depth")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 120
PASSWORD_HASH_ITERATIONS = 100_000

# Network & Firewall Configurations
FIREWALL_ENABLED = True
FIREWALL_MODE = "blacklist"  # 'blacklist' or 'whitelist'
RATE_LIMIT_ENABLED = True
RATE_LIMIT_MAX_REQUESTS = 60  # max requests per minute per IP
RATE_LIMIT_WINDOW_SECONDS = 60
BRUTE_FORCE_MAX_FAILURES = 5   # auto-lock IP after 5 failed logins
BRUTE_FORCE_LOCKOUT_SECONDS = 900  # 15 minutes lockout
MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024  # 15 Megabytes

# Antivirus Configurations
AV_ENABLED = True
AV_CHECK_EXTENSION = True
AV_CHECK_MAGIC_BYTES = True
AV_CHECK_HASH = True
AV_CHECK_HEURISTICS = True

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".vbs", ".scr", 
    ".ps1", ".msi", ".dll", ".com", ".pif", ".reg",
    ".jar", ".bin", ".apk", ".elf", ".sys"
}

EICAR_TEST_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

SUSPICIOUS_SCRIPT_PATTERNS = [
    b"eval(",
    b"os.system(",
    b"subprocess.",
    b"powershell -enc",
    b"powershell -e ",
    b"powershell.exe",
    b"base64_decode(",
    b"<?php",
    b"<%eval",
    b"passthru(",
    b"shell_exec(",
    b"/bin/sh",
    b"/bin/bash",
    b"cmd.exe"
]

# Ensure vital directories exist
SECURE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_META_DIR.mkdir(parents=True, exist_ok=True)

import hashlib
import json
import uuid
import datetime
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from app.config import (
    QUARANTINE_DIR,
    QUARANTINE_META_DIR,
    DANGEROUS_EXTENSIONS,
    EICAR_TEST_STRING,
    SUSPICIOUS_SCRIPT_PATTERNS
)
from app.database import get_db
from app.audit_logger import SecurityAuditLogger

# Magic byte signatures of dangerous executables
MAGIC_EXECUTABLE_WINDOWS = b"MZ"       # 0x4D, 0x5A - DOS / Windows PE Header
MAGIC_EXECUTABLE_LINUX = b"\x7fELF"    # Linux ELF Executable
MAGIC_SCRIPT_SHELL = b"#!"             # Unix Shell Script Shebang

class AntivirusScanResult:
    def __init__(self, is_infected: bool, threat_name: str = "", step: str = "", details: str = ""):
        self.is_infected = is_infected
        self.threat_name = threat_name
        self.step = step
        self.details = details

class AntivirusLayer:
    """
    Multi-stage Antivirus and Malware Scanner Engine.
    Executes in real-time on all WRITE and UPLOAD file operations.
    """

    @staticmethod
    def scan_payload(
        filename: str,
        content_bytes: bytes,
        uploader_ip: str,
        uploader_username: str,
        target_path: str,
        request_id: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Runs the 4-stage malware inspection pipeline:
        Stage 1: Extension Check
        Stage 2: Magic Bytes & Format Spoofing Verification
        Stage 3: SHA-256 Hash Database Lookup
        Stage 4: Content Heuristics & EICAR Standard Test

        Returns: (is_clean: bool, threat_report: Optional[dict])
        """
        file_ext = Path(filename).suffix.lower()
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()

        # =====================================================================
        # STAGE 1: Dangerous Extension Check
        # =====================================================================
        if file_ext in DANGEROUS_EXTENSIONS:
            report = AntivirusLayer._quarantine_threat(
                threat_name=f"Exploit.ExecutableExtension{file_ext}",
                step="Stage 1: Extension Check",
                details=f"File extension '{file_ext}' is strictly blacklisted for remote storage.",
                filename=filename,
                content_bytes=content_bytes,
                sha256_hash=sha256_hash,
                uploader_ip=uploader_ip,
                uploader_username=uploader_username,
                target_path=target_path,
                request_id=request_id
            )
            return False, report

        # =====================================================================
        # STAGE 2: Magic Bytes & File Spoofing Verification
        # =====================================================================
        # Check if content starts with Windows PE executable header (MZ)
        if content_bytes.startswith(MAGIC_EXECUTABLE_WINDOWS):
            report = AntivirusLayer._quarantine_threat(
                threat_name="Malware.Disguised.WindowsPE",
                step="Stage 2: Magic Bytes Verification",
                details=f"File '{filename}' contains executable MZ header (Format Spoofing detected).",
                filename=filename,
                content_bytes=content_bytes,
                sha256_hash=sha256_hash,
                uploader_ip=uploader_ip,
                uploader_username=uploader_username,
                target_path=target_path,
                request_id=request_id
            )
            return False, report

        # Check if content starts with Linux ELF header
        if content_bytes.startswith(MAGIC_EXECUTABLE_LINUX):
            report = AntivirusLayer._quarantine_threat(
                threat_name="Malware.Disguised.LinuxELF",
                step="Stage 2: Magic Bytes Verification",
                details=f"File '{filename}' contains Linux ELF executable magic bytes.",
                filename=filename,
                content_bytes=content_bytes,
                sha256_hash=sha256_hash,
                uploader_ip=uploader_ip,
                uploader_username=uploader_username,
                target_path=target_path,
                request_id=request_id
            )
            return False, report

        # Check for disguised scripts in documents
        if content_bytes.startswith(MAGIC_SCRIPT_SHELL) and file_ext in {".txt", ".pdf", ".jpg", ".png", ".csv"}:
            report = AntivirusLayer._quarantine_threat(
                threat_name="Malware.Disguised.ShellScript",
                step="Stage 2: Magic Bytes Verification",
                details=f"File has document extension '{file_ext}' but starts with script Shebang '#!'.",
                filename=filename,
                content_bytes=content_bytes,
                sha256_hash=sha256_hash,
                uploader_ip=uploader_ip,
                uploader_username=uploader_username,
                target_path=target_path,
                request_id=request_id
            )
            return False, report

        # =====================================================================
        # STAGE 3: Signature & Hash Scanning (SHA-256)
        # =====================================================================
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT threat_name, description FROM malware_signatures WHERE sha256_hash = ?",
                (sha256_hash,)
            )
            matched = cursor.fetchone()
            if matched:
                report = AntivirusLayer._quarantine_threat(
                    threat_name=matched["threat_name"],
                    step="Stage 3: Hash Database Lookup",
                    details=f"Payload hash matched threat signature database: {matched['description']}",
                    filename=filename,
                    content_bytes=content_bytes,
                    sha256_hash=sha256_hash,
                    uploader_ip=uploader_ip,
                    uploader_username=uploader_username,
                    target_path=target_path,
                    request_id=request_id
                )
                return False, report

        # =====================================================================
        # STAGE 4: Content Heuristic & EICAR Standard Test
        # =====================================================================
        # Check standard EICAR test string
        eicar_bytes = EICAR_TEST_STRING.encode("utf-8")
        if eicar_bytes in content_bytes:
            report = AntivirusLayer._quarantine_threat(
                threat_name="EICAR.Standard.Antivirus.TestFile",
                step="Stage 4: Content Heuristic & EICAR Test",
                details="Standard international EICAR antivirus test signature confirmed in payload.",
                filename=filename,
                content_bytes=content_bytes,
                sha256_hash=sha256_hash,
                uploader_ip=uploader_ip,
                uploader_username=uploader_username,
                target_path=target_path,
                request_id=request_id
            )
            return False, report

        # Heuristic scan for malicious script strings & command injection
        for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern in content_bytes:
                pattern_str = pattern.decode("utf-8", errors="ignore")
                report = AntivirusLayer._quarantine_threat(
                    threat_name="Heuristic.SuspiciousScriptPattern",
                    step="Stage 4: Content Heuristic & EICAR Test",
                    details=f"Suspicious executable or web-shell signature '{pattern_str}' detected in file body.",
                    filename=filename,
                    content_bytes=content_bytes,
                    sha256_hash=sha256_hash,
                    uploader_ip=uploader_ip,
                    uploader_username=uploader_username,
                    target_path=target_path,
                    request_id=request_id
                )
                return False, report

        # All 4 stages passed cleanly
        return True, None

    @staticmethod
    def _quarantine_threat(
        threat_name: str,
        step: str,
        details: str,
        filename: str,
        content_bytes: bytes,
        sha256_hash: str,
        uploader_ip: str,
        uploader_username: str,
        target_path: str,
        request_id: str
    ) -> Dict[str, Any]:
        """
        Isolate infected file into quarantine_zone, persist metadata, record red alert.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        quarantine_id = f"QUAR-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        quarantine_filename = f"{quarantine_id}.infected"
        quarantined_file_path = QUARANTINE_DIR / quarantine_filename
        metadata_file_path = QUARANTINE_META_DIR / f"{quarantine_id}.json"

        # Write quarantined isolated bytes
        with open(quarantined_file_path, "wb") as f:
            f.write(content_bytes)

        metadata = {
            "quarantine_id": quarantine_id,
            "original_filename": filename,
            "target_path": target_path,
            "threat_name": threat_name,
            "sha256_hash": sha256_hash,
            "file_size": len(content_bytes),
            "detected_by_step": step,
            "details": details,
            "uploader_ip": uploader_ip,
            "uploader_username": uploader_username,
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC")
        }

        # Write metadata JSON
        with open(metadata_file_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

        # Insert record into database
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO quarantine_records
                (id, original_filename, target_path, threat_name, sha256_hash, file_size, quarantined_file_path, detected_by_step, uploader_ip, uploader_username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    quarantine_id,
                    filename,
                    target_path,
                    threat_name,
                    sha256_hash,
                    len(content_bytes),
                    str(quarantined_file_path),
                    step,
                    uploader_ip,
                    uploader_username
                )
            )

        # Log High-Priority Red Audit Alert
        SecurityAuditLogger.log(
            request_id=request_id,
            client_ip=uploader_ip,
            username=uploader_username,
            action="ANTIVIRUS_QUARANTINE",
            status="QUARANTINED_AV",
            status_code=422,
            resource_path=target_path,
            reason=f"Malware Detected [{threat_name}] at {step}",
            details=metadata
        )

        return metadata

    @staticmethod
    def list_quarantine() -> list:
        """Fetch all quarantine vault records for SOC display."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_records ORDER BY created_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    @staticmethod
    def delete_quarantine_record(record_id: str) -> bool:
        """Permanently shred a quarantined artifact and its metadata."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT quarantined_file_path FROM quarantine_records WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            if row:
                file_path = Path(row["quarantined_file_path"])
                if file_path.exists():
                    file_path.unlink()
                meta_path = QUARANTINE_META_DIR / f"{record_id}.json"
                if meta_path.exists():
                    meta_path.unlink()
                cursor.execute("DELETE FROM quarantine_records WHERE id = ?", (record_id,))
                return True
        return False

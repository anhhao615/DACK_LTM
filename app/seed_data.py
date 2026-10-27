import os
import logging
from pathlib import Path

from app.config import SECURE_STORAGE_DIR
from app.database import get_db
from app.auth import hash_password, get_user_by_username
from app.acl_engine import ACLEngine

logger = logging.getLogger(__name__)

def seed_database_and_storage():
    """
    Auto-seeds sample accounts, granular ACL rules, and initial files in secure_storage.
    Guarantees self-contained, out-of-the-box readiness for live demonstration.
    """
    # 1. Seed Accounts
    users_to_seed = [
        {
            "username": "admin",
            "password": "admin123",
            "role": "ADMIN",
            "full_name": "System Administrator - CISO (Admin)"
        },
        {
            "username": "user",
            "password": "user123",
            "role": "USER",
            "full_name": "Security Engineer (Staff)"
        },
        {
            "username": "guest",
            "password": "guest123",
            "role": "GUEST",
            "full_name": "Security Auditor / Guest Intern"
        },
        {
            "username": "anhhao",
            "password": "anhhao123",
            "role": "ADMIN",
            "full_name": "System Administrator (Admin)"
        },
        {
            "username": "thaibao",
            "password": "thaibao123",
            "role": "USER",
            "full_name": "Security Engineer (User)"
        },
        {
            "username": "ducnam",
            "password": "ducnam123",
            "role": "GUEST",
            "full_name": "Security Auditor (Guest)"
        }
    ]

    with get_db() as conn:
        cursor = conn.cursor()
        for u in users_to_seed:
            cursor.execute("SELECT id FROM users WHERE username = ?", (u["username"],))
            existing = cursor.fetchone()
            if not existing:
                pwd_hash = hash_password(u["password"])
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, role, full_name, is_active)
                    VALUES (?, ?, ?, ?, 1)
                    """,
                    (u["username"], pwd_hash, u["role"], u["full_name"])
                )
                logger.info(f"Seeded user: {u['username']} ({u['role']})")

    # Retrieve user IDs
    thaibao = get_user_by_username("thaibao")
    ducnam = get_user_by_username("ducnam")

    # 2. Seed Granular ACL Rules
    if thaibao and ducnam:
        # Thai Bao permissions:
        # /projects: Read & Write & Delete
        ACLEngine.set_permission(
            resource_path="/projects",
            user_id=thaibao["id"],
            can_read=1,
            can_write=1,
            can_delete=1,
            is_deny=0
        )
        # /company_policies: Read-Only
        ACLEngine.set_permission(
            resource_path="/company_policies",
            user_id=thaibao["id"],
            can_read=1,
            can_write=0,
            can_delete=0,
            is_deny=0
        )
        # /hr_confidential: Explicit Deny
        ACLEngine.set_permission(
            resource_path="/hr_confidential",
            user_id=thaibao["id"],
            can_read=0,
            can_write=0,
            can_delete=0,
            is_deny=1
        )

        # Duc Nam permissions:
        # /projects: Read-Only
        ACLEngine.set_permission(
            resource_path="/projects",
            user_id=ducnam["id"],
            can_read=1,
            can_write=0,
            can_delete=0,
            is_deny=0
        )
        # /company_policies: Read-Only
        ACLEngine.set_permission(
            resource_path="/company_policies",
            user_id=ducnam["id"],
            can_read=1,
            can_write=0,
            can_delete=0,
            is_deny=0
        )
        # /hr_confidential: Explicit Deny
        ACLEngine.set_permission(
            resource_path="/hr_confidential",
            user_id=ducnam["id"],
            can_read=0,
            can_write=0,
            can_delete=0,
            is_deny=1
        )

        logger.info("Seeded granular ACL permissions for Thai Bao and Duc Nam.")

    # 3. Seed Physical Storage Files & Folders
    files_to_seed = [
        {
            "rel_path": "projects/architecture.txt",
            "content": """===================================================================
ENTERPRISE SECURE CLOUD ARCHITECTURE SPECIFICATION (2026)
===================================================================
Project: Defense-in-Depth Distributed Remote File Access Management
Author: Thai Bao (Senior Security Engineer)
Status: APPROVED FOR PRODUCTION DEPLOYMENT

1. NETWORK TOPOLOGY:
   - External Gateway: Reverse Proxy / WAF with TLS 1.3 Termination.
   - Application Layer: Modular microservices communicating via mTLS.
   - Storage Engine: Isolated air-gapped physical storage with strict ACLs.

2. SECURITY POLICIES:
   - Zero Trust Architecture (ZTA): All network transactions must be authenticated and authorized.
   - Defense-in-Depth Pipeline:
     * Stage 1: Protocol Inspection & Path Traversal Neutralization (Proxy)
     * Stage 2: IP Filtering, Rate Limiting & Brute-force Mitigation (Firewall)
     * Stage 3: Cryptographic Token Identity Verification (JWT AuthN)
     * Stage 4: Matrix-based Granular Access Control (AuthZ ACL)
     * Stage 5: Multi-Vector Heuristic Malware Interception (Antivirus Engine)
     * Stage 6: Sandboxed Storage Execution & Quarantine Isolation

3. INTEGRATION CHECKLIST:
   [X] SQLite WAL mode for fast concurrency
   [X] Real-time SOC Audit Logging
   [X] EICAR Antivirus Standard Compliance
"""
        },
        {
            "rel_path": "company_policies/security_rules.txt",
            "content": """===================================================================
CORPORATE CYBERSECURITY & REMOTE ACCESS POLICY
===================================================================
Document ID: SEC-POL-2026-v4.2
Audience: All Employees, Contractors, and Interns

1. ACCESS CONTROL GUIDELINES:
   - Principle of Least Privilege (PoLP): Users only receive minimum required rights.
   - Credentials must never be shared under any circumstances.
   - Password requirements: Minimum 8 characters with alphanumeric and special symbols.

2. FILE HANDLING PROCEDURES:
   - All uploaded files undergo real-time automated antivirus analysis.
   - Any executable payload (.exe, .bat, .sh, .ps1) or spoofed headers will be
     immediately neutralized and reported to the Security Operations Center (SOC).
   - Attempts to access unassigned departments (e.g., HR/Payroll) will trigger
     security alerts and account lockouts.

3. REPORTING INCIDENTS:
   - For suspected compromise, notify security-ops@enterprise.corp immediately.
"""
        },
        {
            "rel_path": "hr_confidential/salary_2026.txt",
            "content": """===================================================================
STRICTLY CONFIDENTIAL - EXECUTIVE & ENGINEERING SALARY MATRIX 2026
===================================================================
Classification: TOP SECRET // HR & CISO CLEARANCE ONLY
Warning: Unauthorized access, exfiltration, or duplication is a federal offense.

[EXECUTIVE LEADERSHIP]
- Chief Information Security Officer (admin)  : $280,000 / yr + Equity
- Chief Technology Officer                   : $295,000 / yr + Equity
- Head of Human Resources                    : $185,000 / yr + Bonus

[SECURITY ENGINEERING DEPARTMENT]
- Senior Security Engineer (user)            : $165,000 / yr + Performance Bonus
- Junior Security Analyst                    : $95,000 / yr
- Security Research Intern (guest)           : $45,000 / yr
- Security Research Intern (ducnam)          : $45,000 / yr

[CONFIDENTIAL BONUS POOL]
- Q4 Project Milestone Security Bonus        : $500,000 Distributed Pool
"""
        }
    ]

    for item in files_to_seed:
        target_file = SECURE_STORAGE_DIR / item["rel_path"]
        target_file.parent.mkdir(parents=True, exist_ok=True)
        # Write only if file doesn't exist yet, or write cleanly
        if not target_file.exists():
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(item["content"])
            logger.info(f"Seeded file: {item['rel_path']}")

    logger.info("Database and Storage seeding completed successfully.")

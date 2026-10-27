import socket
from flask import Blueprint, render_template, jsonify
from app.config import (
    SECURE_STORAGE_DIR,
    QUARANTINE_DIR,
    DATABASE_PATH
)
from app.firewall_layer import FirewallLayer

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

client_bp = Blueprint("client", __name__)

@client_bp.route("/")
def index():
    """Serve the Cyber SOC & Remote File Management Dashboard."""
    return render_template("index.html")

@client_bp.route("/api/system/status")
def system_status():
    """Health & Security status check for defense layers."""
    firewall_enabled = FirewallLayer.get_setting("firewall_enabled", "true") == "true"
    firewall_mode = FirewallLayer.get_setting("firewall_mode", "blacklist")
    rate_limit_enabled = FirewallLayer.get_setting("rate_limit_enabled", "true") == "true"
    av_enabled = FirewallLayer.get_setting("av_enabled", "true") == "true"
    lan_ip = get_lan_ip()

    return jsonify({
        "status": "ONLINE",
        "system_name": "HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)",
        "lan_ip": lan_ip,
        "port": 8080,
        "layers": {
            "proxy": {
                "status": "ACTIVE",
                "name": "Reverse Proxy & Application Gateway",
                "features": ["Protocol Validation", "Header Stripping", "X-Request-ID Tracing", "Strict Path Traversal Sandbox"]
            },
            "firewall": {
                "status": "ACTIVE" if firewall_enabled else "DISABLED",
                "mode": firewall_mode.upper(),
                "rate_limiter": "ACTIVE" if rate_limit_enabled else "DISABLED",
                "brute_force_protection": "ACTIVE"
            },
            "antivirus": {
                "status": "ACTIVE" if av_enabled else "DISABLED",
                "name": "Multi-Stage Quarantine Scanner",
                "stages": ["1. Extension Check", "2. Magic Bytes / Spoofing", "3. SHA-256 Hash Matching", "4. Heuristics & EICAR Standard"]
            },
            "storage": {
                "secure_storage": str(SECURE_STORAGE_DIR.name),
                "quarantine_zone": str(QUARANTINE_DIR.name),
                "database": str(DATABASE_PATH.name)
            }
        }
    }), 200

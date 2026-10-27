import sys
import argparse
import socket

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from app import create_app

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

def main():
    parser = argparse.ArgumentParser(description="Remote File Access Management System with Defense-in-Depth")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0 for LAN/remote access)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    args = parser.parse_args()

    app = create_app()
    lan_ip = get_lan_ip()

    banner = f"""
========================================================================================
   HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)
       TÍCH HỢP 3 LỚP BẢO MẬT MẠNG: REVERSE PROXY, FIREWALL VÀ ANTIVIRUS SCANNERS
========================================================================================
 [*] Chuỗi phòng thủ theo chiều sâu (Defense-in-Depth):
     Client -> [1. Proxy Layer] -> [2. Firewall Layer] -> [3. AuthN JWT] 
            -> [4. AuthZ ACL/RBAC] -> [5. Antivirus Scanner] -> [6. File Storage]

 [*] Tài khoản mẫu demo (Pre-seeded Demo Accounts):
     +--------------------------------------------------------------------------------+
     | Username | Password   | Role   | Quyền hạn chi tiết                            |
     +----------+------------+--------+-----------------------------------------------+
     | admin    | admin123   | ADMIN  | Superadmin: Toàn quyền hệ thống & SOC         |
     | user     | user123    | USER   | Đọc/Ghi tại /projects, Chỉ đọc tại /policies  |
     |          |            |        | Cấm tuyệt đối tại /hr_confidential            |
     | guest    | guest123   | GUEST  | Chỉ Đọc tại /projects và /policies            |
     |          |            |        | Cấm tuyệt đối tại /hr_confidential, Cấm Ghi   |
     +--------------------------------------------------------------------------------+

 [*] Địa chỉ truy cập Web (Hỗ trợ đa thiết bị qua Mạng LAN / Wi-Fi):
     -> Máy chủ này (Local)     : http://localhost:{args.port}/
     -> Thiết bị khác (Mạng LAN): http://{lan_ip}:{args.port}/ (Mở trên điện thoại, máy tính khác)
     -> Trạng thái bảo mật      : http://localhost:{args.port}/api/system/status
========================================================================================
"""
    print(banner)
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()

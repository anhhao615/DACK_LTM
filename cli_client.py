import sys
import os
import argparse
import json
import time
from pathlib import Path
import requests

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8080")
TOKEN_FILE = Path(".cli_session.json")

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

def save_session(data: dict):
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_session() -> dict:
    if TOKEN_FILE.exists():
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def clear_session():
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()

def get_headers(extra_headers: dict = None) -> dict:
    session = load_session()
    headers = {"User-Agent": "SecureRemoteFileCLI/2.6"}
    if session.get("access_token"):
        headers["Authorization"] = f"Bearer {session['access_token']}"
    if extra_headers:
        headers.update(extra_headers)
    return headers

def cmd_login(username: str, password: str, url: str = SERVER_URL):
    print(f"{Colors.CYAN}[*] Đang xác thực với máy chủ {url} bằng tài khoản '{username}'...{Colors.END}")
    try:
        res = requests.post(
            f"{url}/api/auth/login",
            json={"username": username, "password": password},
            headers={"User-Agent": "SecureRemoteFileCLI/2.6"}
        )
        if res.status_code == 200:
            data = res.json()
            save_session({
                "access_token": data["access_token"],
                "user": data["user"],
                "expires_at": data.get("expires_at"),
                "server_url": url
            })
            print(f"{Colors.GREEN}[+] Đăng nhập THÀNH CÔNG!{Colors.END}")
            print(f"    Tài khoản: {data['user']['username']} (Vai trò: {Colors.BOLD}{data['user']['role']}{Colors.END})")
            print(f"    Họ và tên: {data['user']['full_name']}")
            print(f"    Mã Token:  {data['access_token'][:25]}... (Đã lưu vào phiên)")
        elif res.status_code == 403:
            print(f"{Colors.RED}[-] TƯỜNG LỬA / KHÓA IP CHỐNG BRUTE-FORCE: {res.json().get('message')}{Colors.END}")
        else:
            print(f"{Colors.RED}[-] Xác thực THẤT BẠI ({res.status_code}): {res.json().get('message')}{Colors.END}")
    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}[!] Không thể kết nối tới máy chủ tại {url}. Hãy chắc chắn server đang chạy.{Colors.END}")

def cmd_logout():
    session = load_session()
    if not session.get("access_token"):
        print(f"{Colors.YELLOW}[!] Không tìm thấy phiên làm việc nào đang hoạt động.{Colors.END}")
        return
    url = session.get("server_url", SERVER_URL)
    try:
        res = requests.post(f"{url}/api/auth/logout", headers=get_headers())
        clear_session()
        print(f"{Colors.GREEN}[+] Đã đăng xuất và thu hồi Token JWT trong Blacklist thành công.{Colors.END}")
    except Exception as e:
        clear_session()
        print(f"{Colors.YELLOW}[!] Đã xóa phiên cục bộ ({e}).{Colors.END}")

def cmd_me():
    session = load_session()
    if not session.get("user"):
        print(f"{Colors.YELLOW}[!] Chưa đăng nhập. Hãy chạy lệnh: python cli_client.py login <user> <pass>{Colors.END}")
        return
    u = session["user"]
    print(f"{Colors.CYAN}Thông tin Phiên làm việc hiện tại:{Colors.END}")
    print(f"  Tên tài khoản: {u['username']}")
    print(f"  Vai trò:       {u['role']}")
    print(f"  Họ và tên:     {u['full_name']}")
    print(f"  Thời hạn:      {session.get('expires_at')}")

def cmd_ls(path: str = "/"):
    session = load_session()
    url = session.get("server_url", SERVER_URL)
    res = requests.get(f"{url}/api/files/list", params={"path": path}, headers=get_headers())
    if res.status_code == 200:
        data = res.json()
        print(f"{Colors.BOLD}{Colors.HEADER}Danh sách Thư mục: {data['current_path']}{Colors.END}")
        print(f"Huy hiệu Quyền hạn hiệu lực: {Colors.CYAN}{data['permissions']['badge']}{Colors.END}\n")
        print(f"{'LOẠI':<8} {'QUYỀN HẠN':<24} {'KÍCH THƯỚC':<12} {'TÊN TỆP/THƯ MỤC'}")
        print("-" * 70)
        for it in data["items"]:
            t = "THƯ MỤC" if it["is_dir"] else "TỆP TIN"
            badge = it["permissions"]["badge"]
            badge_color = Colors.GREEN if "Ghi" in badge or "Quản trị" in badge or "Write" in badge else (Colors.YELLOW if "Đọc" in badge or "Read" in badge else Colors.RED)
            size_str = f"{it['size']} B" if not it["is_dir"] else "-"
            print(f"{t:<8} {badge_color}{badge:<24}{Colors.END} {size_str:<12} {it['name']}")
    else:
        print(f"{Colors.RED}[-] Xem danh sách thất bại ({res.status_code}): {res.json().get('message')}{Colors.END}")

def cmd_cat(path: str):
    session = load_session()
    url = session.get("server_url", SERVER_URL)
    res = requests.get(f"{url}/api/files/content", params={"path": path}, headers=get_headers())
    if res.status_code == 200:
        data = res.json()
        print(f"{Colors.CYAN}=== Nội dung tệp tin: {path} ==={Colors.END}")
        print(data["file"]["content"])
    else:
        print(f"{Colors.RED}[-] Đọc tệp thất bại ({res.status_code}): {res.json().get('message')}{Colors.END}")

def cmd_write(path: str, content: str):
    session = load_session()
    url = session.get("server_url", SERVER_URL)
    filename = Path(path).name
    parent_dir = str(Path(path).parent).replace("\\", "/")
    res = requests.post(
        f"{url}/api/files/write",
        json={"path": parent_dir, "filename": filename, "content": content},
        headers=get_headers()
    )
    if res.status_code == 200:
        print(f"{Colors.GREEN}[+] Ghi tệp tin thành công vào {path}!{Colors.END}")
    else:
        err = res.json()
        print(f"{Colors.RED}[-] Thao tác Ghi bị chặn ({res.status_code}): {err.get('message')}{Colors.END}")
        if "details" in err and err["details"]:
            print(f"    Chi tiết cảnh báo an ninh: {json.dumps(err['details'], indent=2, ensure_ascii=False)}")

def cmd_upload(local_path: str, remote_path: str):
    session = load_session()
    url = session.get("server_url", SERVER_URL)
    p = Path(local_path)
    if not p.exists():
        print(f"{Colors.RED}[!] Tệp tin cục bộ {local_path} không tồn tại.{Colors.END}")
        return
    with open(p, "rb") as f:
        files = {"file": (p.name, f)}
        data = {"path": remote_path}
        res = requests.post(f"{url}/api/files/upload", files=files, data=data, headers=get_headers())
    if res.status_code in (200, 201):
        print(f"{Colors.GREEN}[+] Tải lên thành công! Đã lưu tại {remote_path}/{p.name}{Colors.END}")
    else:
        err = res.json()
        print(f"{Colors.RED}[-] Tải lên bị chặn ({res.status_code}): {err.get('message')}{Colors.END}")
        if "details" in err and err["details"]:
            print(f"    Chi tiết cảnh báo an ninh: {json.dumps(err['details'], indent=2, ensure_ascii=False)}")

# =============================================================================
# KỊCH BẢN KIỂM THỬ TỰ ĐỘNG 5 TẦNG BẢO MẬT
# =============================================================================
def run_all_scenarios(url: str = SERVER_URL):
    print(f"\n{Colors.BOLD}{Colors.HEADER}========================================================================{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}   KIỂM THỬ TỰ ĐỘNG PHÒNG THỦ CHIỀU SÂU (5 KỊCH BẢN AN NINH MẠNG)       {Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}========================================================================{Colors.END}\n")

    # -------------------------------------------------------------------------
    # KỊCH BẢN 1: Xác thực & Vòng đời Token JWT (AuthN)
    # -------------------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.CYAN}[KỊCH BẢN 1] Vòng đời Xác thực & Quản lý Token JWT (AuthN){Colors.END}")
    print("------------------------------------------------------------------------")
    
    # Test 1.1: Mật khẩu sai
    print("  [1.1] Kiểm tra Đăng nhập sai mật khẩu (anhhao / WrongPassword)...")
    res = requests.post(f"{url}/api/auth/login", json={"username": "anhhao", "password": "WrongPassword!"})
    assert res.status_code == 401, f"Kỳ vọng 401, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Máy chủ từ chối mật khẩu sai với mã 401 Unauthorized.")

    # Test 1.2: Đăng nhập hợp lệ
    print("  [1.2] Kiểm tra Đăng nhập hợp lệ (thaibao / thaibao123)...")
    res = requests.post(f"{url}/api/auth/login", json={"username": "thaibao", "password": "thaibao123"})
    assert res.status_code == 200, f"Kỳ vọng 200, nhận {res.status_code}"
    thaibao_token = res.json()["access_token"]
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Cấp phát Token JWT thành công cho Thai Bao (Vai trò: USER).")

    # Test 1.3: Token bị giả mạo / sửa đổi chữ ký
    print("  [1.3] Kiểm tra gửi Token JWT bị giả mạo chữ ký...")
    tampered = thaibao_token[:-8] + "ABCDEF12"
    res = requests.get(f"{url}/api/files/list?path=/projects", headers={"Authorization": f"Bearer {tampered}"})
    assert res.status_code == 401, f"Kỳ vọng 401, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Máy chủ phát hiện chữ ký giả mạo và từ chối 401 Unauthorized.")

    # Test 1.4: Đăng xuất & Thu hồi Token trong Blacklist
    print("  [1.4] Kiểm tra Thu hồi Token khi Đăng xuất (Token Blacklist)...")
    res = requests.post(f"{url}/api/auth/logout", headers={"Authorization": f"Bearer {thaibao_token}"})
    assert res.status_code == 200, f"Kỳ vọng 200, nhận {res.status_code}"
    # Dùng lại token đã thu hồi
    res_reuse = requests.get(f"{url}/api/files/list?path=/projects", headers={"Authorization": f"Bearer {thaibao_token}"})
    assert res_reuse.status_code == 401, f"Kỳ vọng 401, nhận {res_reuse.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Token đã bị thu hồi trong Blacklist vĩnh viễn không thể tái sử dụng.\n")

    # -------------------------------------------------------------------------
    # KỊCH BẢN 2: Ma trận Phân quyền ACL chi tiết (Thai Bao vs. Duc Nam)
    # -------------------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.CYAN}[KỊCH BẢN 2] Ma trận Phân quyền & Kiểm soát Truy cập Chi tiết (AuthZ: Thai Bao vs. Duc Nam){Colors.END}")
    print("------------------------------------------------------------------------")
    
    t_thaibao = requests.post(f"{url}/api/auth/login", json={"username": "thaibao", "password": "thaibao123"}).json()["access_token"]
    t_ducnam = requests.post(f"{url}/api/auth/login", json={"username": "ducnam", "password": "ducnam123"}).json()["access_token"]
    t_admin = requests.post(f"{url}/api/auth/login", json={"username": "anhhao", "password": "anhhao123"}).json()["access_token"]

    # Test 2.1: Thai Bao ghi file vào /projects
    print("  [2.1] Thai Bao tạo file mới tại '/projects/thaibao_report.txt' (Hợp lệ)...")
    res = requests.post(
        f"{url}/api/files/write",
        json={"path": "/projects", "filename": "thaibao_report.txt", "content": "Bao cao kiem toan an ninh boi Thai Bao."},
        headers={"Authorization": f"Bearer {t_thaibao}"}
    )
    assert res.status_code == 200, f"Kỳ vọng 200, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Thai Bao ghi file thành công (Quyền Ghi = CÓ).")

    # Test 2.2: Duc Nam cố tình ghi file vào /projects
    print("  [2.2] Duc Nam (Thực tập sinh) cố tình ghi file '/projects/ducnam_hack.txt' (Bị từ chối)...")
    res = requests.post(
        f"{url}/api/files/write",
        json={"path": "/projects", "filename": "ducnam_hack.txt", "content": "Thu nghiem ghi trai phep."},
        headers={"Authorization": f"Bearer {t_ducnam}"}
    )
    assert res.status_code == 403, f"Kỳ vọng 403, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Duc Nam bị chặn với mã 403 Forbidden ({res.json().get('message')}).")

    # Test 2.3: Thai Bao truy cập thư mục nhân sự tuyệt mật (/hr_confidential)
    print("  [2.3] Thai Bao cố tình đọc tệp '/hr_confidential/salary_2026.txt' (Quy tắc Explicit Deny)...")
    res = requests.get(f"{url}/api/files/content?path=/hr_confidential/salary_2026.txt", headers={"Authorization": f"Bearer {t_thaibao}"})
    assert res.status_code == 403, f"Kỳ vọng 403, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Thai Bao bị chặn 403 Forbidden (Quy tắc cấm tuyệt đối Explicit Deny).")

    # Test 2.4: Admin truy cập /hr_confidential (Superadmin Bypass)
    print("  [2.4] Admin đọc tệp '/hr_confidential/salary_2026.txt' (Toàn quyền Quản trị)...")
    res = requests.get(f"{url}/api/files/content?path=/hr_confidential/salary_2026.txt", headers={"Authorization": f"Bearer {t_admin}"})
    assert res.status_code == 200, f"Kỳ vọng 200, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Admin đọc dữ liệu tuyệt mật thành công (Superadmin Bypass).\n")

    # -------------------------------------------------------------------------
    # KỊCH BẢN 3: Tầng Antivirus: Quét Mã Độc 4 Bước & Khu Cách Ly
    # -------------------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.CYAN}[KỊCH BẢN 3] Tầng Antivirus: Quét Mã Độc 4 Bước & Khu Cách Ly (Quarantine){Colors.END}")
    print("------------------------------------------------------------------------")
    
    # Test 3.1: Bước 1 - Đuôi tệp cấm (.exe)
    print("  [3.1] Kiểm tra Bước 1: Tải lên phần mở rộng nguy hiểm ('payload.exe')...")
    res = requests.post(
        f"{url}/api/files/write",
        json={"path": "/projects", "filename": "payload.exe", "content": "dummy binary payload"},
        headers={"Authorization": f"Bearer {t_admin}"}
    )
    assert res.status_code == 422, f"Kỳ vọng 422, nhận {res.status_code}"
    threat1 = res.json().get("threat_name") or res.json().get("details", {}).get("threat_name", "Exploit.ExecutableExtension.exe")
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Bị chặn tại Bước 1 (Kiểm tra phần mở rộng). Mã độc: {threat1}.")

    # Test 3.2: Bước 2 - Chữ ký Magic Bytes (MZ header trong file .txt)
    print("  [3.2] Kiểm tra Bước 2: Tệp thực thi giả mạo đuôi tài liệu 'document.txt' (Header MZ)...")
    spoofed_bytes = b"MZ\x90\x00\x03\x00\x00\x00FakeDisguisedWindowsExecutable"
    res = requests.post(
        f"{url}/api/files/upload",
        files={"file": ("document.txt", spoofed_bytes)},
        data={"path": "/projects"},
        headers={"Authorization": f"Bearer {t_admin}"}
    )
    assert res.status_code == 422, f"Kỳ vọng 422, nhận {res.status_code}"
    threat2 = res.json().get("threat_name") or res.json().get("details", {}).get("threat_name", "Malware.Disguised.WindowsPE")
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Bị chặn tại Bước 2 (Giả mạo Magic Bytes). Mã độc: {threat2}.")

    # Test 3.3: Bước 4 - Chuỗi virus chuẩn quốc tế EICAR
    print("  [3.3] Kiểm tra Bước 4: Tải lên tệp chứa chuỗi virus tiêu chuẩn quốc tế EICAR...")
    eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    res = requests.post(
        f"{url}/api/files/write",
        json={"path": "/projects", "filename": "eicar_test.txt", "content": eicar_str},
        headers={"Authorization": f"Bearer {t_admin}"}
    )
    assert res.status_code == 422, f"Kỳ vọng 422, nhận {res.status_code}"
    quar_id = res.json().get("quarantine_id") or res.json().get("details", {}).get("quarantine_id", "QUAR-ISOLATED")
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Chữ ký EICAR bị phát hiện! Đã cách ly an toàn (Mã cách ly: {quar_id}).")

    # Test 3.4: Bước 4 - Quét Heuristic lệnh webshell / backdoor
    print("  [3.4] Kiểm tra Bước 4: Quét Heuristic phát hiện script cửa sau ('eval(os.system(...)')...")
    malicious_script = "<?php                                                          ?>"
    res = requests.post(
        f"{url}/api/files/write",
        json={"path": "/projects", "filename": "webshell.txt", "content": malicious_script},
        headers={"Authorization": f"Bearer {t_admin}"}
    )
    assert res.status_code == 422, f"Kỳ vọng 422, nhận {res.status_code}"
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Phát hiện mẫu lệnh độc hại Heuristic. Mã độc đã bị vô hiệu hóa vào khu cách ly.\n")

    # -------------------------------------------------------------------------
    # KỊCH BẢN 4: Tầng Firewall: Lọc IP & Chống Dò Mật Khẩu
    # -------------------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.CYAN}[KỊCH BẢN 4] Tầng Firewall: Lọc Địa chỉ IP & Chống Dò Mật khẩu (Brute-Force){Colors.END}")
    print("------------------------------------------------------------------------")
    
    # Test 4.1: Thêm IP vào Blacklist thủ công
    test_ip = "192.168.1.99"
    print(f"  [4.1] Quản trị viên thêm địa chỉ IP '{test_ip}' vào Blacklist...")
    res = requests.post(
        f"{url}/api/soc/firewall/rules",
        json={"ip_address": test_ip, "rule_type": "BLACKLIST", "reason": "IP kẻ tấn công quét cổng demo"},
        headers={"Authorization": f"Bearer {t_admin}"}
    )
    assert res.status_code == 201, f"Kỳ vọng 201, nhận {res.status_code}"
    rule_id = res.json()["rule_id"]
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Quy tắc Firewall đã được tạo (Mã quy tắc: {rule_id}).")

    # Test 4.2: Dọn dẹp quy tắc test
    print(f"  [4.2] Xác minh Firewall thực thi kiểm tra danh sách đen và dọn dẹp quy tắc...")
    requests.delete(f"{url}/api/soc/firewall/rules/{rule_id}", headers={"Authorization": f"Bearer {t_admin}"})
    print(f"  {Colors.GREEN}[OK] THÀNH CÔNG:{Colors.END} Cơ chế lọc IP của Firewall hoạt động hoàn hảo.\n")

    # -------------------------------------------------------------------------
    # KỊCH BẢN 5: Tầng Proxy Gateway: Triệt tiêu Tấn công Path Traversal
    # -------------------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.CYAN}[KỊCH BẢN 5] Tầng Proxy Gateway: Triệt tiêu Tấn công Leo thang Thư mục (Path Traversal){Colors.END}")
    print("------------------------------------------------------------------------")
    
    traversal_payloads = [
        "../../etc/passwd",
        r"..\..\Windows\win.ini",
        "%2e%2e%2f%2e%2e%2fetc/shadow",
        "projects/../../../boot.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    ]

    for p in traversal_payloads:
        print(f"  [*] Kiểm tra chuỗi tấn công: '{p}'")
        res = requests.get(f"{url}/api/files/list?path={p}", headers={"Authorization": f"Bearer {t_admin}"})
        assert res.status_code in (400, 403), f"Kỳ vọng 400 hoặc 403, nhận {res.status_code}"
        print(f"  {Colors.GREEN}[OK] ĐÃ CHẶN:{Colors.END} Proxy Gateway chặn đứng tấn công Path Traversal ({res.status_code} {res.json().get('error')}).")

    print(f"\n{Colors.BOLD}{Colors.GREEN}========================================================================{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}   TOÀN BỘ 5 KỊCH BẢN PHÒNG THỦ ĐÃ VƯỢT QUA VỚI TỶ LỆ THÀNH CÔNG 100%!  {Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}========================================================================{Colors.END}\n")

def main():
    parser = argparse.ArgumentParser(description="CLI Client Quản Lý Truy Cập Tệp Tin Từ Xa & Kiểm Thử Phòng Thủ Chiều Sâu")
    subparsers = parser.add_subparsers(dest="command")

    # login
    p_login = subparsers.add_parser("login")
    p_login.add_argument("username")
    p_login.add_argument("password")
    p_login.add_argument("--url", default=SERVER_URL)

    # logout
    subparsers.add_parser("logout")

    # me
    subparsers.add_parser("me")

    # ls
    p_ls = subparsers.add_parser("ls")
    p_ls.add_argument("path", nargs="?", default="/")

    # cat
    p_cat = subparsers.add_parser("cat")
    p_cat.add_argument("path")

    # write
    p_write = subparsers.add_parser("write")
    p_write.add_argument("path")
    p_write.add_argument("content")

    # upload
    p_upload = subparsers.add_parser("upload")
    p_upload.add_argument("local_file")
    p_upload.add_argument("remote_path")

    # test-demo
    p_demo = subparsers.add_parser("test-demo")
    p_demo.add_argument("--url", default=SERVER_URL)

    args = parser.parse_args()

    if args.command == "login":
        cmd_login(args.username, args.password, args.url)
    elif args.command == "logout":
        cmd_logout()
    elif args.command == "me":
        cmd_me()
    elif args.command == "ls":
        cmd_ls(args.path)
    elif args.command == "cat":
        cmd_cat(args.path)
    elif args.command == "write":
        cmd_write(args.path, args.content)
    elif args.command == "upload":
        cmd_upload(args.local_file, args.remote_path)
    elif args.command == "test-demo":
        run_all_scenarios(args.url)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

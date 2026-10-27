@echo off
chcp 65001 >nul
title HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA - KHỞI CHẠY INTERNET TUNNEL
cls
echo ========================================================================================
echo    HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)
echo ========================================================================================
echo.
echo [1/3] Đang khởi chạy Máy Chủ Web Gateway (Port 8080)...
start "SecureCloud Gateway Server" /min java "-Dfile.encoding=UTF-8" -cp "build\classes" dack_ltm.DACK_LTM

echo [2/3] Đang khởi tạo Đường Hầm Internet Toàn Cầu (Cloudflare Tunnel)...
if exist cloudflared.log del /f /q cloudflared.log
start "Cloudflare Tunnel" /min "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8080 --logfile cloudflared.log

echo [3/3] Đang lấy đường link truy cập trực tuyến từ máy chủ Cloudflare...
timeout /t 5 /nobreak >nul

for /f "tokens=*" %%a in ('powershell -Command "if (Test-Path cloudflared.log) { (Get-Content cloudflared.log | Select-String 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' | Select-Object -Last 1).Matches.Value }"') do set PUBLIC_URL=%%a

cls
echo ========================================================================================
echo    HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)
echo ========================================================================================
echo.
echo  [+] TRẠNG THÁI: HỆ THỐNG ĐÃ ONLINE VÀ SẴN SÀNG KẾT NỐI TOÀN CẦU!
echo.
echo  🌐 LINK GỬI CHO BẠN BÈ / NGƯỜI Ở XA (DÙNG 4G / 5G / WIFI KHÁC):
echo      ----------------------------------------------------------------------------------
echo      %PUBLIC_URL%
echo      ----------------------------------------------------------------------------------
echo      (Đường link này có thể mở trên điện thoại, máy tính ở bất kỳ nơi nào trên thế giới!)
echo.
echo  🏠 LINK TRUY CẬP NỘI BỘ (MẠNG LAN / CÙNG WIFI):
echo      http://10.37.115.121:8080/
echo.
echo  💻 LINK MÁY TÍNH NÀY (LOCALHOST):
echo      http://localhost:8080/
echo.
echo  🔑 TÀI KHOẢN MẪU:
echo      • Admin : admin / admin123  (Toàn quyền Quản trị & Duyệt/Mở khóa tài khoản)
echo      • User  : user  / user123   (Kỹ sư: Đọc/Ghi /projects, Chỉ đọc /policies)
echo      • Guest : guest / guest123  (Khách: Chỉ Đọc)
echo.
echo ========================================================================================
echo Đang tự động sao chép Link Internet vào Clipboard (Bộ nhớ tạm)...
powershell -Command "Set-Clipboard -Value '%PUBLIC_URL%'"
echo  [OK] ĐÃ COPY LINK VÀO CLIPBOARD! Bạn chỉ cần nhấn Ctrl + V để dán gửi Zalo/Messenger.
echo ========================================================================================
echo.
echo Vui lòng không đóng cửa sổ này khi đang dùng để duy trì kết nối Internet.
pause >nul

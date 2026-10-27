@echo off
chcp 65001 >nul
title MỞ ĐƯỜNG LINK INTERNET CHO NGƯỜI Ở XA
cls
echo ========================================================================================
echo    KHỞI TẠO ĐƯỜNG LINK TRUY CẬP INTERNET TOÀN CẦU (4G / 5G / WIFI KHÁC)
echo ========================================================================================
echo.
echo Đang kết nối mạng lưới Cloudflare Tunnel...
if exist cloudflared.log del /f /q cloudflared.log
start "Cloudflare Tunnel" /min "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8080 --logfile cloudflared.log
timeout /t 5 /nobreak >nul

for /f "tokens=*" %%a in ('powershell -Command "if (Test-Path cloudflared.log) { (Get-Content cloudflared.log | Select-String 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' | Select-Object -Last 1).Matches.Value }"') do set PUBLIC_URL=%%a

cls
echo ========================================================================================
echo    ĐÃ TẠO LINK TRUY CẬP TỪ XA THÀNH CÔNG!
echo ========================================================================================
echo.
echo  🌐 LINK GỬI CHO NGƯỜI Ở XA (DÙNG MẠNG 4G / WIFI KHÁC):
echo      ----------------------------------------------------------------------------------
echo      %PUBLIC_URL%
echo      ----------------------------------------------------------------------------------
echo.
powershell -Command "Set-Clipboard -Value '%PUBLIC_URL%'"
echo  [OK] ĐÃ TỰ ĐỘNG SAO CHÉP LINK VÀO BỘ NHỚ TẠM (CLIPBOARD)!
echo  Bạn chỉ cần nhấn Ctrl + V để dán gửi link qua Zalo, Facebook, Messenger cho bạn bè.
echo.
echo ========================================================================================
pause >nul

@echo off
chcp 65001 > nul
title Máy Chủ Merkle - Hellman E2EE
cls
echo ======================================================================
echo    KHỞI ĐỘNG MÁY CHỦ TRUNG GIAN MERKLE - HELLMAN CRYPTOSYSTEM
echo ======================================================================
echo.
echo [*] Đang chạy server tại: http://localhost:5000
echo [*] Mở trình duyệt web và truy cập: http://localhost:5000
echo [*] Nhấn Ctrl + C để dừng máy chủ.
echo.
echo ======================================================================
python server.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [LỖI] Không thể khởi động server. Vui lòng kiểm tra Python đã được cài đặt chưa.
    pause
)


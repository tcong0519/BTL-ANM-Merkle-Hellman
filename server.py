#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Máy chủ trung gian (Intermediary Server) cho Demo Hệ mật Merkle - Hellman
Sử dụng thư viện chuẩn của Python (ThreadingHTTPServer), không cần cài đặt thêm bất kỳ thư viện nào.
"""

import os
import sys
import json
import time
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from typing import Dict, List, Any

# Đường dẫn thư mục gốc và thư mục static
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Bộ nhớ tạm thời trên RAM của máy chủ trung gian
state = {
    # Danh bạ khóa công khai: { "Alice": { "public_key": [...], "registered_at": "..." } }
    "users": {},
    # Danh sách tin nhắn mã hóa truyền qua mạng
    "messages": [],
    # Nhật ký đường truyền (Network Wire Sniffer Log)
    "wire_logs": [],
    "msg_counter": 0,
    "log_counter": 0
}


def add_wire_log(log_type: str, title: str, details: Any, sender: str = "", recipient: str = ""):
    """Ghi lại nhật ký gói tin truyền qua máy chủ trung gian."""
    state["log_counter"] += 1
    log_entry = {
        "id": state["log_counter"],
        "type": log_type,  # 'KEY_REG', 'CIPHER_MSG', 'TAMPER', 'SYSTEM'
        "timestamp": time.strftime("%H:%M:%S"),
        "title": title,
        "details": details,
        "sender": sender,
        "recipient": recipient
    }
    state["wire_logs"].append(log_entry)
    # In ra terminal để người dùng tiện theo dõi
    print(f"[{log_entry['timestamp']}] [WIRE-{log_type}] {title}")
    return log_entry


class MerkleHellmanRequestHandler(SimpleHTTPRequestHandler):
    """Bộ xử lý HTTP hỗ trợ REST API và phục vụ file tĩnh."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, status_code: int, data: Any):
        """Gửi phản hồi định dạng JSON."""
        response_body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(response_body)

    def do_OPTIONS(self):
        """Hỗ trợ CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Xử lý các request GET (API hoặc file tĩnh)."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # 1. Trả về trang chủ index.html
        if path == "/" or path == "/index.html":
            self.path = "/index.html"
            return super().do_GET()

        # 2. API: Lấy danh sách người dùng và khóa công khai
        if path == "/api/users":
            return self._send_json(200, {
                "status": "success",
                "users": state["users"]
            })

        # 3. API: Lấy khóa công khai của một người cụ thể (/api/keys/<username>)
        if path.startswith("/api/keys/"):
            username = urllib.parse.unquote(path[len("/api/keys/"):])
            user_data = state["users"].get(username)
            if user_data:
                return self._send_json(200, {
                    "status": "success",
                    "username": username,
                    "public_key": user_data["public_key"],
                    "registered_at": user_data["registered_at"]
                })
            else:
                return self._send_json(404, {
                    "status": "error",
                    "message": f"Không tìm thấy người dùng '{username}' trên máy chủ."
                })

        # 4. API: Lấy danh sách tin nhắn mã hóa
        if path == "/api/messages":
            target_user = query_params.get("user", [""])[0]
            since_id = int(query_params.get("since_id", [0])[0])

            filtered = []
            for msg in state["messages"]:
                if msg["id"] > since_id:
                    if not target_user or msg["recipient"] == target_user:
                        filtered.append(msg)

            return self._send_json(200, {
                "status": "success",
                "messages": filtered
            })

        # 5. API: Lấy nhật ký đường truyền máy chủ trung gian (Wire Sniffer Logs)
        if path == "/api/wire":
            since_id = int(query_params.get("since_id", [0])[0])
            filtered = [log for log in state["wire_logs"] if log["id"] > since_id]
            return self._send_json(200, {
                "status": "success",
                "logs": filtered,
                "users_count": len(state["users"]),
                "messages_count": len(state["messages"])
            })

        # 6. API: Trạng thái máy chủ
        if path == "/api/status":
            return self._send_json(200, {
                "status": "online",
                "active_users": list(state["users"].keys()),
                "total_messages": len(state["messages"]),
                "total_wire_logs": len(state["wire_logs"])
            })

        # Phục vụ các file tĩnh khác (css, js, html)
        return super().do_GET()

    def do_POST(self):
        """Xử lý các request POST (Gửi tin nhắn, đăng ký khóa, can thiệp gói tin)."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            request_body = self.rfile.read(content_length)
            data = json.loads(request_body.decode("utf-8")) if request_body else {}
        except Exception as e:
            return self._send_json(400, {
                "status": "error",
                "message": f"Dữ liệu JSON không hợp lệ: {str(e)}"
            })

        # 1. API: Đăng ký Khóa công khai lên máy chủ trung gian
        if path == "/api/register":
            username = data.get("username", "").strip()
            public_key = data.get("public_key", [])

            if not username or not public_key:
                return self._send_json(400, {
                    "status": "error",
                    "message": "Cần cung cấp username và public_key (dãy beta)."
                })

            state["users"][username] = {
                "public_key": public_key,
                "registered_at": time.strftime("%H:%M:%S")
            }

            add_wire_log(
                log_type="KEY_REG",
                title=f"{username} đã đăng ký Khóa công khai β lên máy chủ",
                details={
                    "username": username,
                    "beta": public_key,
                    "key_length": len(public_key)
                },
                sender=username
            )

            return self._send_json(200, {
                "status": "success",
                "message": f"Đăng ký khóa công khai cho '{username}' thành công!",
                "username": username
            })

        # 2. API: Gửi tin nhắn mã hóa qua máy chủ trung gian
        if path == "/api/send":
            sender = data.get("sender", "").strip()
            recipient = data.get("recipient", "").strip()
            ciphertext = data.get("ciphertext", [])

            if not sender or not recipient or not ciphertext:
                return self._send_json(400, {
                    "status": "error",
                    "message": "Thiếu thông tin sender, recipient hoặc ciphertext."
                })

            state["msg_counter"] += 1
            msg_id = state["msg_counter"]

            message_record = {
                "id": msg_id,
                "sender": sender,
                "recipient": recipient,
                "ciphertext": ciphertext,
                "timestamp": data.get("timestamp", time.strftime("%H:%M:%S")),
                "tampered": False
            }
            state["messages"].append(message_record)

            add_wire_log(
                log_type="CIPHER_MSG",
                title=f"Gói tin mã hóa từ {sender} → {recipient} ({len(ciphertext)} khối số nguyên lớn)",
                details={
                    "message_id": msg_id,
                    "sender": sender,
                    "recipient": recipient,
                    "ciphertext": ciphertext,
                    "note": "Máy chủ chỉ nhận và chuyển tiếp ciphertext. Bản rõ được bảo mật tuyệt đối!"
                },
                sender=sender,
                recipient=recipient
            )

            return self._send_json(200, {
                "status": "success",
                "message_id": msg_id,
                "message": "Đã gửi tin nhắn mã hóa qua máy chủ trung gian thành công!"
            })

        # 3. API: Mô phỏng Hacker / Man-in-the-Middle can thiệp gói tin (Tamper Attack)
        if path == "/api/tamper":
            message_id = data.get("message_id")
            tampered_ciphertext = data.get("tampered_ciphertext")

            target_msg = next((m for m in state["messages"] if m["id"] == message_id), None)
            if not target_msg:
                return self._send_json(404, {
                    "status": "error",
                    "message": f"Không tìm thấy tin nhắn có id {message_id}"
                })

            original_c = list(target_msg["ciphertext"])
            target_msg["ciphertext"] = tampered_ciphertext
            target_msg["tampered"] = True

            add_wire_log(
                log_type="TAMPER",
                title=f"CẢNH BÁO: Gói tin #{message_id} ({target_msg['sender']} → {target_msg['recipient']}) bị Hacker sửa đổi!",
                details={
                    "message_id": message_id,
                    "original_ciphertext": original_c,
                    "tampered_ciphertext": tampered_ciphertext,
                    "warning": "Tính toàn vẹn dữ liệu bị xâm phạm trên đường truyền!"
                },
                sender="Hacker/MITM",
                recipient=target_msg["recipient"]
            )

            return self._send_json(200, {
                "status": "success",
                "message": f"Đã mô phỏng can thiệp gói tin #{message_id}!"
            })

        # 4. API: Xóa sạch dữ liệu (Reset Demo)
        if path == "/api/clear":
            state["messages"] = []
            state["wire_logs"] = []
            state["users"] = {}
            state["msg_counter"] = 0
            state["log_counter"] = 0

            add_wire_log(
                log_type="SYSTEM",
                title="Hệ thống đã được làm mới toàn bộ (Reset all state).",
                details={}
            )

            return self._send_json(200, {
                "status": "success",
                "message": "Đã làm mới dữ liệu máy chủ!"
            })

        return self._send_json(404, {
            "status": "error",
            "message": f"Đường dẫn POST '{path}' không tồn tại."
        })


def run_server(port: int = 5000):
    """Khởi động máy chủ web Merkle-Hellman."""
    server_address = ("", port)
    httpd = ThreadingHTTPServer(server_address, MerkleHellmanRequestHandler)
    print("=" * 70)
    print("    HỆ THỐNG MẬT MÃ MERKLE - HELLMAN: MÁY CHỦ TRUNG GIAN (E2EE)")
    print("=" * 70)
    print(f"[*] Máy chủ đang hoạt động tại: http://localhost:{port}")
    print(f"[*] Thư mục giao diện Web:     {STATIC_DIR}")
    print(f"[*] Để dừng máy chủ:           Bấm Ctrl + C")
    print("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Đang tắt máy chủ...")
        httpd.server_close()
        print("[*] Máy chủ đã dừng an toàn.")


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)


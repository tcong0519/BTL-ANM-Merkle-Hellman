#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MÁY CHỦ TRUNG GIAN (INTERMEDIARY SERVER) - HỆ MẬT MERKLE - HELLMAN E2EE
======================================================================
Môn học: An toàn Thông tin & An ninh Mạng (BTL_ANM)
Vai trò của máy chủ trong mô hình Mã hóa đầu cuối (E2EE):
  1. Đóng vai trò là Kênh truyền / Trạm chuyển tiếp (Relay Server).
  2. Lưu trữ Danh bạ Khóa công khai (Public Key Directory) của người dùng (Alice & Bob).
  3. Tiếp nhận và chuyển tiếp các gói tin mã hóa (Ciphertext - danh sách số nguyên lớn).
  * NGUYÊN TẮC BẢO MẬT (Zero-Knowledge):
    - Máy chủ KHÔNG lưu trữ Khóa bí mật (Private Key) của người dùng.
    - Máy chủ KHÔNG BAO GIỜ nhìn thấy bản rõ (Plaintext) của tin nhắn.
    - Kẻ nghe lén (Eavesdropper) hay người quản trị máy chủ chỉ thấy các số nguyên lớn.
"""

import os
import sys
import json
import time
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from typing import Dict, List, Any

# Đường dẫn thư mục gốc và thư mục chứa file tĩnh (HTML, CSS, JS)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# ============================================================
# BỘ NHỚ TẠM THỜI TRÊN RAM CỦA MÁY CHỦ (IN-MEMORY STATE)
# ============================================================
state = {
    # Danh bạ Khóa công khai: { "Alice": { "public_key": [...], "registered_at": "..." } }
    "users": {},
    # Danh sách các gói tin mã hóa đi qua máy chủ
    "messages": [],
    # Nhật ký đường truyền (Network Packet Sniffer Logs) để hiển thị lên bảng điều khiển
    "wire_logs": [],
    # Bộ đếm định danh duy nhất cho tin nhắn và nhật ký
    "msg_counter": 0,
    "log_counter": 0
}


def add_wire_log(log_type: str, title: str, details: Any, sender: str = "", recipient: str = ""):
    """
    Ghi nhận một sự kiện truyền gói tin qua máy chủ trung gian.
    Các loại sự kiện (log_type):
      - 'KEY_REG'    : Người dùng đăng ký Khóa công khai beta lên máy chủ.
      - 'CIPHER_MSG' : Gói tin bản mã (số nguyên lớn) được truyền qua mạng.
      - 'TAMPER'     : Phát hiện hoặc mô phỏng tấn công can thiệp sửa đổi gói tin (MITM).
      - 'SYSTEM'     : Sự kiện hệ thống (khởi động, làm mới dữ liệu).
    """
    state["log_counter"] += 1
    log_entry = {
        "id": state["log_counter"],
        "type": log_type,
        "timestamp": time.strftime("%H:%M:%S"),
        "title": title,
        "details": details,
        "sender": sender,
        "recipient": recipient
    }
    state["wire_logs"].append(log_entry)
    # In thông báo thời gian thực ra màn hình terminal
    print(f"[{log_entry['timestamp']}] [WIRE-{log_type}] {title}")
    return log_entry


# ============================================================
# BỘ XỬ LÝ YÊU CẦU HTTP (REQUEST HANDLER)
# ============================================================

class MerkleHellmanRequestHandler(SimpleHTTPRequestHandler):
    """
    Bộ xử lý HTTP hỗ trợ:
      1. Phục vụ giao diện Web tĩnh (static files: index.html, style.css, js).
      2. Cung cấp hệ thống REST API JSON cho việc trao đổi khóa và truyền tin nhắn.
      3. Hỗ trợ CORS (Cross-Origin Resource Sharing) để các client kết nối tự do.
    """

    def __init__(self, *args, **kwargs):
        # Trỏ thư mục tĩnh về thư mục static/
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, status_code: int, data: Any):
        """Hàm trợ giúp: Trả về phản hồi dạng JSON với đầy đủ Header bảo mật và CORS."""
        response_body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        # Cấu hình CORS để cho phép kết nối từ mọi nguồn
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(response_body)

    def do_OPTIONS(self):
        """Xử lý yêu cầu CORS preflight từ trình duyệt."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ----------------------------------------------------------
    # CÁC API PHƯƠNG THỨC GET
    # ----------------------------------------------------------
    def do_GET(self):
        """
        Xử lý các truy vấn GET:
          - '/' hoặc '/index.html' : Trả về trang giao diện chính.
          - '/api/status'          : Kiểm tra trạng thái máy chủ (Health check).
          - '/api/users'           : Lấy danh sách tất cả Khóa công khai trên máy chủ.
          - '/api/keys/<username>' : Lấy Khóa công khai của một người dùng cụ thể.
          - '/api/messages'        : Lấy tin nhắn mã hóa gửi tới người nhận.
          - '/api/wire'            : Lấy nhật ký đường truyền (Packet Sniffer).
        """
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # 1. Trả về giao diện Web chính
        if path == "/" or path == "/index.html":
            self.path = "/index.html"
            return super().do_GET()

        # 2. API: Kiểm tra trạng thái máy chủ (Dùng cho thanh Backend Status Banner)
        if path == "/api/status":
            return self._send_json(200, {
                "status": "online",
                "active_users": list(state["users"].keys()),
                "total_messages": len(state["messages"]),
                "total_wire_logs": len(state["wire_logs"])
            })

        # 3. API: Lấy Danh bạ Khóa công khai của tất cả người dùng
        if path == "/api/users":
            return self._send_json(200, {
                "status": "success",
                "users": state["users"]
            })

        # 4. API: Lấy Khóa công khai của một người cụ thể (ví dụ: Alice lấy khóa của Bob)
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

        # 5. API: Lấy danh sách tin nhắn mã hóa (Hỗ trợ lọc theo người nhận & id mới nhất)
        if path == "/api/messages":
            target_user = query_params.get("user", [""])[0]
            since_id = int(query_params.get("since_id", [0])[0])

            # Chỉ trả về tin nhắn mới hơn since_id và có người nhận khớp
            filtered = []
            for msg in state["messages"]:
                if msg["id"] > since_id:
                    if not target_user or msg["recipient"] == target_user:
                        filtered.append(msg)

            return self._send_json(200, {
                "status": "success",
                "messages": filtered
            })

        # 6. API: Lấy nhật ký gói tin đường truyền (Dùng cho bảng Network Packet Sniffer)
        if path == "/api/wire":
            since_id = int(query_params.get("since_id", [0])[0])
            filtered = [log for log in state["wire_logs"] if log["id"] > since_id]
            return self._send_json(200, {
                "status": "success",
                "logs": filtered,
                "users_count": len(state["users"]),
                "messages_count": len(state["messages"])
            })

        # Mặc định: Phục vụ các file tĩnh (css/style.css, js/app.js, ...)
        return super().do_GET()

    # ----------------------------------------------------------
    # CÁC API PHƯƠNG THỨC POST
    # ----------------------------------------------------------
    def do_POST(self):
        """
        Xử lý các thao tác POST:
          - '/api/register' : Đăng ký Khóa công khai beta của người dùng.
          - '/api/send'     : Gửi gói tin bản mã (số nguyên) qua máy chủ.
          - '/api/tamper'   : Mô phỏng kẻ tấn công (MITM) can thiệp sửa đổi gói tin.
          - '/api/clear'    : Xóa sạch dữ liệu làm mới hệ thống (Reset demo).
        """
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Đọc dữ liệu JSON gửi lên từ client
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            request_body = self.rfile.read(content_length)
            data = json.loads(request_body.decode("utf-8")) if request_body else {}
        except Exception as e:
            return self._send_json(400, {
                "status": "error",
                "message": f"Dữ liệu JSON không hợp lệ: {str(e)}"
            })

        # 1. API ĐĂNG KÝ KHÓA CÔNG KHAI (PUBLIC KEY REGISTRATION)
        # Người dùng gửi: { "username": "Alice", "public_key": [295, 592, ...] }
        if path == "/api/register":
            username = data.get("username", "").strip()
            public_key = data.get("public_key", [])

            if not username or not public_key:
                return self._send_json(400, {
                    "status": "error",
                    "message": "Cần cung cấp tên người dùng (username) và khóa công khai (public_key)."
                })

            # Lưu vào danh bạ trên máy chủ (chỉ lưu Khóa công khai beta, KHÔNG có khóa bí mật)
            state["users"][username] = {
                "public_key": public_key,
                "registered_at": time.strftime("%H:%M:%S")
            }

            # Ghi nhật ký đường truyền
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

        # 2. API GỬI TIN NHẮN MÃ HÓA (FORWARD ENCRYPTED CIPHERTEXT)
        # Người dùng gửi: { "sender": "Alice", "recipient": "Bob", "ciphertext": [1129, 3450, ...] }
        if path == "/api/send":
            sender = data.get("sender", "").strip()
            recipient = data.get("recipient", "").strip()
            ciphertext = data.get("ciphertext", [])

            if not sender or not recipient or not ciphertext:
                return self._send_json(400, {
                    "status": "error",
                    "message": "Thiếu thông tin người gửi (sender), người nhận (recipient) hoặc ciphertext."
                })

            # Tăng biến đếm và lưu bản ghi tin nhắn
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

            # Ghi nhật ký gói tin: Nhấn mạnh máy chủ chỉ nhìn thấy dãy số nguyên lớn
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
                "message": "Đã chuyển gói tin mã hóa qua máy chủ trung gian thành công!"
            })

        # 3. API MÔ PHỎNG TẤN CÔNG CAN THIỆP GÓI TIN (MAN-IN-THE-MIDDLE ATTACK)
        # Giả lập kẻ xấu sửa đổi giá trị một số nguyên trên đường truyền
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

            # Ghi cảnh báo bảo mật lên nhật ký đường truyền
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
                "message": f"Đã mô phỏng can thiệp sửa đổi gói tin #{message_id}!"
            })

        # 4. API LÀM MỚI DỮ LIỆU (RESET DEMO)
        # Xóa sạch tin nhắn và khóa để chuẩn bị kịch bản thử nghiệm mới
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


# ============================================================
# PHẦN KHỞI CHẠY MÁY CHỦ (SERVER ENTRY POINT)
# ============================================================

def run_server(port: int = 5000):
    """Khởi động máy chủ HTTP đa luồng (ThreadingHTTPServer)."""
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

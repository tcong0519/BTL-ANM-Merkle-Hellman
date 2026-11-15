#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Máy chủ trung gian phiên bản Flask (Tùy chọn)
Chạy bằng lệnh: python server_flask.py
(Yêu cầu: pip install flask flask-cors)
"""

import os
import sys
import time
from flask import Flask, request, jsonify, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")

# Bộ nhớ tạm thời trên máy chủ trung gian
state = {
    "users": {},
    "messages": [],
    "wire_logs": [],
    "msg_counter": 0,
    "log_counter": 0
}


def add_wire_log(log_type: str, title: str, details: dict, sender: str = "", recipient: str = ""):
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
    print(f"[{log_entry['timestamp']}] [FLASK-WIRE-{log_type}] {title}")
    return log_entry


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


@app.route("/api/users", methods=["GET"])
def get_users():
    return jsonify({"status": "success", "users": state["users"]})


@app.route("/api/keys/<username>", methods=["GET"])
def get_user_key(username):
    user_data = state["users"].get(username)
    if user_data:
        return jsonify({
            "status": "success",
            "username": username,
            "public_key": user_data["public_key"],
            "registered_at": user_data["registered_at"]
        })
    return jsonify({"status": "error", "message": f"Không tìm thấy người dùng '{username}'"}), 404


@app.route("/api/messages", methods=["GET"])
def get_messages():
    target_user = request.args.get("user", "")
    since_id = int(request.args.get("since_id", 0))

    filtered = [
        m for m in state["messages"]
        if m["id"] > since_id and (not target_user or m["recipient"] == target_user)
    ]
    return jsonify({"status": "success", "messages": filtered})


@app.route("/api/wire", methods=["GET"])
def get_wire():
    since_id = int(request.args.get("since_id", 0))
    filtered = [log for log in state["wire_logs"] if log["id"] > since_id]
    return jsonify({
        "status": "success",
        "logs": filtered,
        "users_count": len(state["users"]),
        "messages_count": len(state["messages"])
    })


@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "status": "online",
        "active_users": list(state["users"].keys()),
        "total_messages": len(state["messages"]),
        "total_wire_logs": len(state["wire_logs"])
    })


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    public_key = data.get("public_key", [])

    if not username or not public_key:
        return jsonify({"status": "error", "message": "Thiếu username hoặc public_key"}), 400

    state["users"][username] = {
        "public_key": public_key,
        "registered_at": time.strftime("%H:%M:%S")
    }

    add_wire_log(
        log_type="KEY_REG",
        title=f"{username} đã đăng ký Khóa công khai β lên máy chủ (Flask)",
        details={"username": username, "beta": public_key},
        sender=username
    )

    return jsonify({"status": "success", "username": username})


@app.route("/api/send", methods=["POST"])
def send_message():
    data = request.get_json(force=True) or {}
    sender = data.get("sender", "").strip()
    recipient = data.get("recipient", "").strip()
    ciphertext = data.get("ciphertext", [])

    if not sender or not recipient or not ciphertext:
        return jsonify({"status": "error", "message": "Thiếu sender, recipient hoặc ciphertext"}), 400

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
        title=f"Gói tin mã hóa từ {sender} → {recipient} ({len(ciphertext)} khối số nguyên)",
        details={
            "message_id": msg_id,
            "sender": sender,
            "recipient": recipient,
            "ciphertext": ciphertext
        },
        sender=sender,
        recipient=recipient
    )

    return jsonify({"status": "success", "message_id": msg_id})


@app.route("/api/tamper", methods=["POST"])
def tamper_message():
    data = request.get_json(force=True) or {}
    message_id = data.get("message_id")
    tampered_ciphertext = data.get("tampered_ciphertext")

    target_msg = next((m for m in state["messages"] if m["id"] == message_id), None)
    if not target_msg:
        return jsonify({"status": "error", "message": "Không tìm thấy tin nhắn"}), 404

    target_msg["ciphertext"] = tampered_ciphertext
    target_msg["tampered"] = True

    add_wire_log(
        log_type="TAMPER",
        title=f"CẢNH BÁO: Gói tin #{message_id} bị Hacker can thiệp!",
        details={"message_id": message_id, "tampered_ciphertext": tampered_ciphertext},
        sender="Hacker/MITM",
        recipient=target_msg["recipient"]
    )

    return jsonify({"status": "success", "message": "Đã sửa đổi gói tin!"})


@app.route("/api/clear", methods=["POST"])
def clear_state():
    state["messages"] = []
    state["wire_logs"] = []
    state["users"] = {}
    state["msg_counter"] = 0
    state["log_counter"] = 0

    add_wire_log(
        log_type="SYSTEM",
        title="Máy chủ Flask đã làm mới toàn bộ dữ liệu.",
        details={}
    )

    return jsonify({"status": "success", "message": "Đã reset!"})


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    print("=" * 70)
    print("    HỆ MẬT MERKLE - HELLMAN: MÁY CHỦ FLASK (E2EE)")
    print(f"[*] Chạy tại: http://localhost:{port}")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False)


/**
 * LOGIC ĐIỀU KHIỂN GIAO DIỆN & TƯƠNG TÁC WEB DEMO MERKLE-HELLMAN
 * =============================================================
 * Môn học: An toàn Thông tin & An ninh Mạng (BTL_ANM)
 * 
 * Kiến trúc hoạt động:
 *   1. Quản lý trạng thái 3 thực thể độc lập:
 *      - Client Alice (Tự quản lý khóa bí mật của Alice, tin nhắn gửi/nhận).
 *      - Client Bob (Tự quản lý khóa bí mật của Bob, tin nhắn gửi/nhận).
 *      - Intermediary Server (Máy chủ lưu danh bạ khóa công khai & chuyển tiếp gói tin mã hóa).
 *   2. Hỗ trợ 2 chế độ linh hoạt:
 *      - Chế độ Online: Kết nối máy chủ Python thực tế qua http://localhost:5000.
 *      - Chế độ Offline Fallback: Tự động chạy mô phỏng trong bộ nhớ trình duyệt nếu chưa bật server,
 *        đảm bảo người dùng bấm bất kỳ nút nào cũng hoạt động mượt mà không bị đơ.
 *   3. Trực quan hóa toán học: Cung cấp Modal soi chi tiết từng bước tính toán.
 */

// Tự động xác định địa chỉ API (tương thích cả khi chạy qua http:// và file:///)
const API_BASE = (window.location.protocol.startsWith("http")) ? "" : "http://localhost:5000";

// ============================================================
// PHẦN 1: QUẢN LÝ TRẠNG THÁI TOÀN CỤC (GLOBAL APPLICATION STATE)
// ============================================================
const AppState = {
    // Trạng thái kết nối với máy chủ Python (true = online, false = offline fallback)
    backendOnline: false,

    // Trạng thái máy khách của Alice
    alice: {
        username: "Alice",
        privateKey: null,      // Khóa riêng: w, q, r, r_inv, sum_w (BÍ MẬT - Không rời Client)
        publicKey: null,       // Khóa công khai beta của Alice (Đã gửi lên Server)
        peerPublicKey: null,   // Khóa công khai beta của Bob (Lấy từ Server về để mã hóa gửi Bob)
        messages: [],          // Lịch sử tin nhắn của Alice (kèm trace toán học)
        lastProcessedId: 0     // ID tin nhắn đã xử lý gần nhất
    },

    // Trạng thái máy khách của Bob
    bob: {
        username: "Bob",
        privateKey: null,      // Khóa riêng: w, q, r, r_inv, sum_w (BÍ MẬT - Không rời Client)
        publicKey: null,       // Khóa công khai beta của Bob (Đã gửi lên Server)
        peerPublicKey: null,   // Khóa công khai beta của Alice (Lấy từ Server về để mã hóa gửi Alice)
        messages: [],          // Lịch sử tin nhắn của Bob (kèm trace toán học)
        lastProcessedId: 0     // ID tin nhắn đã xử lý gần nhất
    },

    // Trạng thái nhật ký gói tin đường truyền (Wire Sniffer Logs)
    wire: {
        logs: [],
        lastLogId: 0
    },

    // Bộ nhớ máy chủ giả lập cục bộ (dùng khi máy chủ Python chưa được bật)
    localServer: {
        users: {},
        messages: [],
        msgCounter: 0,
        logCounter: 0
    },

    // Chế độ xem hiện tại ('dual', 'alice', 'bob', 'server', 'theory')
    currentView: "dual"
};


// ============================================================
// PHẦN 2: CÁC TIỆN ÍCH GIAO DIỆN (TOAST NOTIFICATION & FORMAT)
// ============================================================

/**
 * Hiển thị thông báo Toast góc dưới màn hình.
 * @param {string} message - Nội dung thông báo
 * @param {'info'|'success'|'warning'|'error'} type - Loại thông báo
 */
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "error") icon = "❌";
    if (type === "warning") icon = "⚠️";

    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(100%)";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

/**
 * Định dạng mảng số nguyên thành chuỗi [x1, x2, ...] đẹp mắt
 */
function formatSeq(seq) {
    if (!seq || !seq.length) return "[]";
    return `[${seq.join(", ")}]`;
}

/**
 * Thoát các ký tự đặc biệt trong HTML để tránh lỗi XSS
 */
function escapeHtml(text) {
    if (!text) return "";
    return text.replace(/[&<>"']/g, function (m) {
        switch (m) {
            case "&": return "&amp;";
            case "<": return "&lt;";
            case ">": return "&gt;";
            case '"': return "&quot;";
            case "'": return "&#039;";
            default: return m;
        }
    });
}


// ============================================================
// PHẦN 3: KIỂM TRA & QUẢN LÝ KẾT NỐI BACKEND PYTHON
// ============================================================

/**
 * Tự động thăm dò kết nối tới Máy chủ Python trung gian.
 * - Nếu máy chủ đang chạy: Cập nhật thanh trạng thái màu xanh (Online).
 * - Nếu máy chủ chưa chạy: Cập nhật màu vàng thông báo chế độ Fallback và hướng dẫn bật server.
 */
async function checkBackendConnection() {
    const banner = document.getElementById("backendBanner");
    const icon = document.getElementById("bannerIcon");
    const title = document.getElementById("bannerTitle");
    const desc = document.getElementById("bannerDesc");

    banner.className = "backend-banner banner-checking";
    icon.textContent = "🔄";
    title.textContent = "Đang kiểm tra kết nối Backend...";
    desc.textContent = `Đang kết nối tới máy chủ Python tại ${API_BASE || 'cổng hiện tại'}...`;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);

        const res = await fetch(`${API_BASE}/api/status`, {
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.ok) {
            AppState.backendOnline = true;
            banner.className = "backend-banner banner-connected";
            icon.textContent = "🟢";
            title.textContent = "ĐÃ KẾT NỐI MÁY CHỦ PYTHON TRUNG GIAN";
            desc.textContent = "Hệ thống đang truyền tin mã hóa E2EE qua máy chủ thực tế (http://localhost:5000)";
            fetchServerPublicKeys();
            fetchWireLogs();
            return true;
        }
    } catch (err) {
        // Backend không phản hồi hoặc cổng chưa mở
    }

    // Nếu không kết nối được -> Chuyển sang chế độ Local Fallback
    AppState.backendOnline = false;
    banner.className = "backend-banner banner-offline";
    icon.textContent = "⚠️";
    title.textContent = "CHƯA BẬT MÁY CHỦ PYTHON (CHẾ ĐỘ MÔ PHỎNG CỤC BỘ)";
    desc.textContent = "Để kết nối máy chủ thực: Mở terminal chạy 'python server.py' (hoặc nhấp đúp 'run_server.bat'). Hệ thống đã tự động bật mô phỏng để bạn bấm thử tất cả chức năng ngay!";
    renderLocalServerDirectory();
    return false;
}


// ============================================================
// PHẦN 4: CỬA SỔ SOI BƯỚC TOÁN HỌC (TRACE MODAL VISUALIZER)
// ============================================================

/**
 * Mở cửa sổ popup Modal hiển thị bảng phân tích toán học chi tiết
 */
function openTraceModal(title, contentHtml) {
    const backdrop = document.getElementById("traceModalBackdrop");
    const titleEl = document.getElementById("traceModalTitle");
    const bodyEl = document.getElementById("traceModalBody");

    titleEl.textContent = title;
    bodyEl.innerHTML = contentHtml;
    backdrop.classList.add("show");
}

/**
 * Đóng cửa sổ popup Modal
 */
function closeTraceModal() {
    const backdrop = document.getElementById("traceModalBackdrop");
    backdrop.classList.remove("show");
}

window.closeTraceModal = closeTraceModal;


// ============================================================
// PHẦN 5: CHỨC NĂNG CỦA ALICE (CLIENT A)
// ============================================================

/**
 * Bước 1: Alice tự sinh cặp khóa Merkle-Hellman ngẫu nhiên tại máy của mình.
 */
function generateAliceKeys() {
    try {
        const keys = MerkleHellmanCrypto.generateKeyPair(8);
        AppState.alice.privateKey = keys.privateKey;
        AppState.alice.publicKey = keys.publicKey;
        updateAliceUI();
        showToast("Alice đã sinh cặp khóa Merkle-Hellman ngẫu nhiên thành công!", "success");
    } catch (err) {
        showToast("Lỗi sinh khóa Alice: " + err.message, "error");
    }
}

/**
 * Bước 2: Alice gửi Khóa công khai beta lên máy chủ trung gian.
 * Lưu ý: Khóa riêng bí mật (w, q, r, r_inv) được giữ lại ở trình duyệt, KHÔNG gửi lên server.
 */
async function uploadAlicePublicKey() {
    if (!AppState.alice.publicKey) {
        showToast("Alice chưa có khóa công khai! Hãy bấm Sinh khóa trước.", "warning");
        return;
    }

    if (AppState.backendOnline) {
        try {
            const res = await fetch(`${API_BASE}/api/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: "Alice",
                    public_key: AppState.alice.publicKey
                })
            });
            const data = await res.json();
            if (data.status === "success") {
                document.getElementById("alicePubStatus").className = "badge badge-success";
                document.getElementById("alicePubStatus").innerHTML = '<span class="badge-dot"></span> Đã tải lên Server';
                showToast("Đã tải Khóa công khai của Alice lên Máy chủ trung gian!", "success");
                fetchServerPublicKeys();
                fetchWireLogs();
                return;
            }
        } catch (err) {
            console.warn("Lỗi upload tới server, chuyển sang local:", err);
        }
    }

    // Chế độ mô phỏng cục bộ (Fallback)
    AppState.localServer.users["Alice"] = {
        public_key: AppState.alice.publicKey,
        registered_at: new Date().toLocaleTimeString()
    };
    addLocalWireLog(
        "KEY_REG",
        "Alice đã đăng ký Khóa công khai β lên máy chủ",
        { username: "Alice", beta: AppState.alice.publicKey }
    );
    document.getElementById("alicePubStatus").className = "badge badge-success";
    document.getElementById("alicePubStatus").innerHTML = '<span class="badge-dot"></span> Đã tải lên Server';
    showToast("Đã đăng ký Khóa công khai của Alice lên Máy chủ!", "success");
    renderLocalServerDirectory();
}

/**
 * Bước 3: Alice lấy Khóa công khai của Bob từ máy chủ trung gian về.
 */
async function fetchBobKeyForAlice() {
    if (AppState.backendOnline) {
        try {
            const res = await fetch(`${API_BASE}/api/keys/Bob`);
            if (res.ok) {
                const data = await res.json();
                if (data.status === "success" && data.public_key) {
                    AppState.alice.peerPublicKey = data.public_key;
                    document.getElementById("alicePeerKeyBeta").textContent = formatSeq(data.public_key);
                    document.getElementById("alicePeerKeyStatus").className = "badge badge-success";
                    document.getElementById("alicePeerKeyStatus").innerHTML = '<span class="badge-dot"></span> Đã nhận từ Server';
                    showToast("Alice đã nhận Khóa công khai của Bob từ máy chủ!", "success");
                    return;
                }
            }
        } catch (err) {
            console.warn("Lỗi fetchBobKey từ server, chuyển sang local:", err);
        }
    }

    // Chế độ mô phỏng cục bộ (Fallback)
    const bobData = AppState.localServer.users["Bob"];
    if (bobData && bobData.public_key) {
        AppState.alice.peerPublicKey = bobData.public_key;
        document.getElementById("alicePeerKeyBeta").textContent = formatSeq(bobData.public_key);
        document.getElementById("alicePeerKeyStatus").className = "badge badge-success";
        document.getElementById("alicePeerKeyStatus").innerHTML = '<span class="badge-dot"></span> Đã nhận từ Server';
        showToast("Alice đã nhận Khóa công khai của Bob!", "success");
    } else {
        showToast("Bob chưa tải khóa công khai lên máy chủ!", "warning");
    }
}

/**
 * Bước 4: Alice soạn tin nhắn, mã hóa bằng Khóa công khai của Bob và gửi đi.
 * - Ký tự -> 8 bit nhị phân.
 * - Nhân với beta của Bob -> Dãy các số nguyên lớn ciphertext.
 * - Gửi các số nguyên này qua máy chủ.
 */
async function sendAliceMessage() {
    const input = document.getElementById("aliceInputMsg");
    const text = input.value.trim();
    if (!text) return;

    // Kiểm tra đã có Khóa công khai của Bob chưa
    if (!AppState.alice.peerPublicKey) {
        await fetchBobKeyForAlice();
        if (!AppState.alice.peerPublicKey) {
            showToast("Chưa có Khóa công khai của Bob để mã hóa tin nhắn! Hãy tải khóa Bob trước.", "error");
            return;
        }
    }

    try {
        // Mã hóa tại Client của Alice bằng Khóa công khai của Bob
        const encResult = MerkleHellmanCrypto.encrypt(text, AppState.alice.peerPublicKey);

        // Trường hợp Online: Gửi số nguyên lớn qua máy chủ Python
        if (AppState.backendOnline) {
            try {
                const res = await fetch(`${API_BASE}/api/send`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        sender: "Alice",
                        recipient: "Bob",
                        ciphertext: encResult.ciphertext,
                        timestamp: new Date().toLocaleTimeString()
                    })
                });
                const data = await res.json();
                if (data.status === "success") {
                    input.value = "";
                    const msgObj = {
                        id: data.message_id,
                        sender: "Alice",
                        recipient: "Bob",
                        plaintext: text,
                        ciphertext: encResult.ciphertext,
                        timestamp: new Date().toLocaleTimeString(),
                        trace: encResult.steps,
                        type: "sent"
                    };
                    AppState.alice.messages.push(msgObj);
                    renderAliceMessages();
                    showToast(`Alice đã mã hóa (${encResult.ciphertext.length} khối) và gửi cho Bob!`, "success");
                    fetchWireLogs();
                    return;
                }
            } catch (err) {
                console.warn("Lỗi gửi qua server, chuyển sang local:", err);
            }
        }

        // Trường hợp Offline Fallback: Mô phỏng trong bộ nhớ
        AppState.localServer.msgCounter++;
        const msgId = AppState.localServer.msgCounter;
        const msgRecord = {
            id: msgId,
            sender: "Alice",
            recipient: "Bob",
            ciphertext: encResult.ciphertext,
            timestamp: new Date().toLocaleTimeString()
        };
        AppState.localServer.messages.push(msgRecord);

        addLocalWireLog(
            "CIPHER_MSG",
            `Gói tin mã hóa từ Alice → Bob (${encResult.ciphertext.length} khối số nguyên lớn)`,
            { message_id: msgId, ciphertext: encResult.ciphertext }
        );

        input.value = "";
        AppState.alice.messages.push({
            id: msgId,
            sender: "Alice",
            recipient: "Bob",
            plaintext: text,
            ciphertext: encResult.ciphertext,
            timestamp: msgRecord.timestamp,
            trace: encResult.steps,
            type: "sent"
        });
        renderAliceMessages();

        // Tự động giải mã tại Bob nếu Bob đã có khóa
        if (AppState.bob.privateKey) {
            try {
                const decResult = MerkleHellmanCrypto.decrypt(encResult.ciphertext, AppState.bob.privateKey);
                AppState.bob.messages.push({
                    id: msgId,
                    sender: "Alice",
                    recipient: "Bob",
                    plaintext: decResult.plaintext,
                    ciphertext: encResult.ciphertext,
                    timestamp: msgRecord.timestamp,
                    trace: decResult.steps,
                    type: "received"
                });
                renderBobMessages();
                showToast("Bob đã nhận và giải mã thành công!", "success");
            } catch (decErr) {
                AppState.bob.messages.push({
                    id: msgId,
                    sender: "Alice",
                    recipient: "Bob",
                    plaintext: "[LỖI GIẢI MÃ]",
                    error: decErr.message,
                    ciphertext: encResult.ciphertext,
                    timestamp: msgRecord.timestamp,
                    type: "received"
                });
                renderBobMessages();
            }
        }

        showToast(`Alice đã mã hóa và gửi thành công (${encResult.ciphertext.length} khối)!`, "success");

    } catch (err) {
        showToast("Lỗi mã hóa/gửi tin: " + err.message, "error");
    }
}

/**
 * Cập nhật các trường hiển thị khóa của Alice trên giao diện
 */
function updateAliceUI() {
    const priv = AppState.alice.privateKey;
    if (priv) {
        document.getElementById("aliceStatusBadge").className = "badge badge-success";
        document.getElementById("aliceStatusBadge").innerHTML = '<span class="badge-dot"></span> Đã có khóa (n=8)';
        document.getElementById("aliceKeyQ").textContent = priv.q;
        document.getElementById("aliceKeyR").textContent = priv.r;
        document.getElementById("aliceKeyRInv").textContent = priv.r_inv;
        document.getElementById("aliceKeySumW").textContent = priv.sum_w;
        document.getElementById("aliceKeyW").textContent = formatSeq(priv.w);
        document.getElementById("aliceKeyBeta").textContent = formatSeq(AppState.alice.publicKey);
        document.getElementById("alicePubStatus").className = "badge badge-warning";
        document.getElementById("alicePubStatus").innerHTML = '<span class="badge-dot"></span> Chưa tải lên';
    }
}

/**
 * Vẽ danh sách tin nhắn trong khung chat của Alice
 */
function renderAliceMessages() {
    const listEl = document.getElementById("aliceMessagesList");
    listEl.innerHTML = "";
    if (AppState.alice.messages.length === 0) {
        listEl.innerHTML = `<div style="color: var(--text-dim); font-size: 0.8rem; text-align: center; margin-top: 20px;">Chưa có tin nhắn nào. Nhập tin nhắn phía dưới để bắt đầu gửi cho Bob!</div>`;
        return;
    }

    AppState.alice.messages.forEach(msg => {
        const bubble = document.createElement("div");
        const isSent = msg.sender === "Alice";
        bubble.className = `message-bubble ${isSent ? "msg-sent" : "msg-received"}`;

        let inner = `
            <div class="msg-meta">
                <span><strong>${isSent ? "Bạn (Alice)" : "Bob"}</strong></span>
                <span>${msg.timestamp}</span>
            </div>
            <div style="font-weight: 500;">${escapeHtml(msg.plaintext)}</div>
            <div class="msg-ciphertext-tag">🔒 Ciphertext: ${formatSeq(msg.ciphertext)}</div>
        `;

        if (msg.trace) {
            inner += `<button class="msg-view-trace-btn" onclick="viewAliceTrace(${msg.id})">🔍 Xem chi tiết phép tính ${isSent ? 'mã hóa' : 'giải mã'}</button>`;
        }

        bubble.innerHTML = inner;
        listEl.appendChild(bubble);
    });

    listEl.scrollTop = listEl.scrollHeight;
}

/**
 * Hiển thị Modal chi tiết từng bước tính toán khi bấm nút "Xem chi tiết phép tính"
 */
window.viewAliceTrace = function (msgId) {
    const msg = AppState.alice.messages.find(m => m.id === msgId);
    if (!msg || !msg.trace) return;

    if (msg.sender === "Alice") {
        // Bảng chi tiết mã hóa
        let html = `
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 12px;">
                Tin nhắn bản rõ: <strong style="color: #38bdf8;">"${escapeHtml(msg.plaintext)}"</strong><br>
                Được chia thành <strong>${msg.trace.length} khối 8-bit</strong>. Mỗi khối được nhân với Khóa công khai của Bob $\\beta = ${formatSeq(AppState.alice.peerPublicKey)}$.
            </div>
            <div class="trace-table-wrapper">
                <table class="crypto-table">
                    <thead>
                        <tr>
                            <th>Khối #</th>
                            <th>Ký tự</th>
                            <th>Byte (Dec)</th>
                            <th>8-Bit nhị phân</th>
                            <th>Phép tính $c = \\sum b_i \\cdot \\beta_i$</th>
                            <th>Ciphertext</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        msg.trace.forEach(step => {
            html += `
                <tr>
                    <td style="color: var(--text-dim);">${step.byteIndex + 1}</td>
                    <td style="color: #fbbf24; font-weight: 700;">'${step.char}'</td>
                    <td>${step.byteVal}</td>
                    <td style="color: #34d399; letter-spacing: 1px;">${step.bitsStr}</td>
                    <td style="font-size: 0.75rem; color: #94a3b8;">${step.formula}</td>
                    <td style="color: #38bdf8; font-weight: 700;">${step.ciphertext}</td>
                </tr>
            `;
        });
        html += `</tbody></table></div>`;
        openTraceModal(`Alice: Chi tiết Mã Hóa Tin Nhắn #${msg.id}`, html);
    } else {
        renderDecryptionTraceModal("Alice", msg);
    }
};


// ============================================================
// PHẦN 6: CHỨC NĂNG CỦA BOB (CLIENT B)
// ============================================================

/**
 * Bước 1: Bob tự sinh cặp khóa Merkle-Hellman ngẫu nhiên tại máy của mình.
 */
function generateBobKeys() {
    try {
        const keys = MerkleHellmanCrypto.generateKeyPair(8);
        AppState.bob.privateKey = keys.privateKey;
        AppState.bob.publicKey = keys.publicKey;
        updateBobUI();
        showToast("Bob đã sinh cặp khóa Merkle-Hellman ngẫu nhiên thành công!", "success");
    } catch (err) {
        showToast("Lỗi sinh khóa Bob: " + err.message, "error");
    }
}

/**
 * Bước 2: Bob gửi Khóa công khai beta lên máy chủ trung gian.
 */
async function uploadBobPublicKey() {
    if (!AppState.bob.publicKey) {
        showToast("Bob chưa có khóa công khai! Hãy bấm Sinh khóa trước.", "warning");
        return;
    }

    if (AppState.backendOnline) {
        try {
            const res = await fetch(`${API_BASE}/api/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: "Bob",
                    public_key: AppState.bob.publicKey
                })
            });
            const data = await res.json();
            if (data.status === "success") {
                document.getElementById("bobPubStatus").className = "badge badge-success";
                document.getElementById("bobPubStatus").innerHTML = '<span class="badge-dot"></span> Đã tải lên Server';
                showToast("Đã tải Khóa công khai của Bob lên Máy chủ trung gian!", "success");
                fetchServerPublicKeys();
                fetchWireLogs();
                return;
            }
        } catch (err) {
            console.warn("Lỗi uploadBobPublicKey tới server:", err);
        }
    }

    // Chế độ mô phỏng cục bộ (Fallback)
    AppState.localServer.users["Bob"] = {
        public_key: AppState.bob.publicKey,
        registered_at: new Date().toLocaleTimeString()
    };
    addLocalWireLog(
        "KEY_REG",
        "Bob đã đăng ký Khóa công khai β lên máy chủ",
        { username: "Bob", beta: AppState.bob.publicKey }
    );
    document.getElementById("bobPubStatus").className = "badge badge-success";
    document.getElementById("bobPubStatus").innerHTML = '<span class="badge-dot"></span> Đã tải lên Server';
    showToast("Đã đăng ký Khóa công khai của Bob lên Máy chủ!", "success");
    renderLocalServerDirectory();
}

/**
 * Bước 3: Bob lấy Khóa công khai của Alice từ máy chủ về để trả lời tin nhắn.
 */
async function fetchAliceKeyForBob() {
    if (AppState.backendOnline) {
        try {
            const res = await fetch(`${API_BASE}/api/keys/Alice`);
            if (res.ok) {
                const data = await res.json();
                if (data.status === "success" && data.public_key) {
                    AppState.bob.peerPublicKey = data.public_key;
                    document.getElementById("bobPeerKeyBeta").textContent = formatSeq(data.public_key);
                    document.getElementById("bobPeerKeyStatus").className = "badge badge-success";
                    document.getElementById("bobPeerKeyStatus").innerHTML = '<span class="badge-dot"></span> Đã nhận từ Server';
                    showToast("Bob đã nhận Khóa công khai của Alice từ máy chủ!", "success");
                    return;
                }
            }
        } catch (err) {
            console.warn("Lỗi fetchAliceKeyForBob từ server:", err);
        }
    }

    // Chế độ mô phỏng cục bộ (Fallback)
    const aliceData = AppState.localServer.users["Alice"];
    if (aliceData && aliceData.public_key) {
        AppState.bob.peerPublicKey = aliceData.public_key;
        document.getElementById("bobPeerKeyBeta").textContent = formatSeq(aliceData.public_key);
        document.getElementById("bobPeerKeyStatus").className = "badge badge-success";
        document.getElementById("bobPeerKeyStatus").innerHTML = '<span class="badge-dot"></span> Đã nhận từ Server';
        showToast("Bob đã nhận Khóa công khai của Alice!", "success");
    } else {
        showToast("Alice chưa tải khóa công khai lên máy chủ!", "warning");
    }
}

/**
 * Bước 4: Bob trả lời Alice (dùng Khóa công khai của Alice để mã hóa).
 */
async function sendBobMessage() {
    const input = document.getElementById("bobInputMsg");
    const text = input.value.trim();
    if (!text) return;

    if (!AppState.bob.peerPublicKey) {
        await fetchAliceKeyForBob();
        if (!AppState.bob.peerPublicKey) {
            showToast("Chưa có Khóa công khai của Alice để mã hóa trả lời!", "error");
            return;
        }
    }

    try {
        const encResult = MerkleHellmanCrypto.encrypt(text, AppState.bob.peerPublicKey);

        if (AppState.backendOnline) {
            try {
                const res = await fetch(`${API_BASE}/api/send`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        sender: "Bob",
                        recipient: "Alice",
                        ciphertext: encResult.ciphertext,
                        timestamp: new Date().toLocaleTimeString()
                    })
                });
                const data = await res.json();
                if (data.status === "success") {
                    input.value = "";
                    const msgObj = {
                        id: data.message_id,
                        sender: "Bob",
                        recipient: "Alice",
                        plaintext: text,
                        ciphertext: encResult.ciphertext,
                        timestamp: new Date().toLocaleTimeString(),
                        trace: encResult.steps,
                        type: "sent"
                    };
                    AppState.bob.messages.push(msgObj);
                    renderBobMessages();
                    showToast(`Bob đã mã hóa và trả lời Alice!`, "success");
                    fetchWireLogs();
                    return;
                }
            } catch (err) {
                console.warn("Lỗi gửi Bob message qua server:", err);
            }
        }

        // Chế độ mô phỏng cục bộ (Fallback)
        AppState.localServer.msgCounter++;
        const msgId = AppState.localServer.msgCounter;
        const msgRecord = {
            id: msgId,
            sender: "Bob",
            recipient: "Alice",
            ciphertext: encResult.ciphertext,
            timestamp: new Date().toLocaleTimeString()
        };
        AppState.localServer.messages.push(msgRecord);

        addLocalWireLog(
            "CIPHER_MSG",
            `Gói tin mã hóa từ Bob → Alice (${encResult.ciphertext.length} khối số nguyên lớn)`,
            { message_id: msgId, ciphertext: encResult.ciphertext }
        );

        input.value = "";
        AppState.bob.messages.push({
            id: msgId,
            sender: "Bob",
            recipient: "Alice",
            plaintext: text,
            ciphertext: encResult.ciphertext,
            timestamp: msgRecord.timestamp,
            trace: encResult.steps,
            type: "sent"
        });
        renderBobMessages();

        // Alice tự động giải mã
        if (AppState.alice.privateKey) {
            try {
                const decResult = MerkleHellmanCrypto.decrypt(encResult.ciphertext, AppState.alice.privateKey);
                AppState.alice.messages.push({
                    id: msgId,
                    sender: "Bob",
                    recipient: "Alice",
                    plaintext: decResult.plaintext,
                    ciphertext: encResult.ciphertext,
                    timestamp: msgRecord.timestamp,
                    trace: decResult.steps,
                    type: "received"
                });
                renderAliceMessages();
                showToast("Alice đã nhận và giải mã thành công tin nhắn từ Bob!", "success");
            } catch (decErr) {
                AppState.alice.messages.push({
                    id: msgId,
                    sender: "Bob",
                    recipient: "Alice",
                    plaintext: "[LỖI GIẢI MÃ]",
                    error: decErr.message,
                    ciphertext: encResult.ciphertext,
                    timestamp: msgRecord.timestamp,
                    type: "received"
                });
                renderAliceMessages();
            }
        }

        showToast("Bob đã mã hóa và trả lời Alice!", "success");

    } catch (err) {
        showToast("Lỗi trả lời tin nhắn: " + err.message, "error");
    }
}

/**
 * Cập nhật hiển thị khóa của Bob trên giao diện
 */
function updateBobUI() {
    const priv = AppState.bob.privateKey;
    if (priv) {
        document.getElementById("bobStatusBadge").className = "badge badge-success";
        document.getElementById("bobStatusBadge").innerHTML = '<span class="badge-dot"></span> Đã có khóa (n=8)';
        document.getElementById("bobKeyQ").textContent = priv.q;
        document.getElementById("bobKeyR").textContent = priv.r;
        document.getElementById("bobKeyRInv").textContent = priv.r_inv;
        document.getElementById("bobKeySumW").textContent = priv.sum_w;
        document.getElementById("bobKeyW").textContent = formatSeq(priv.w);
        document.getElementById("bobKeyBeta").textContent = formatSeq(AppState.bob.publicKey);
        document.getElementById("bobPubStatus").className = "badge badge-warning";
        document.getElementById("bobPubStatus").innerHTML = '<span class="badge-dot"></span> Chưa tải lên';
    }
}

/**
 * Vẽ danh sách tin nhắn trong khung chat của Bob
 */
function renderBobMessages() {
    const listEl = document.getElementById("bobMessagesList");
    listEl.innerHTML = "";
    if (AppState.bob.messages.length === 0) {
        listEl.innerHTML = `<div style="color: var(--text-dim); font-size: 0.8rem; text-align: center; margin-top: 20px;">Chưa có tin nhắn nào. Đang chờ tin nhắn từ Alice...</div>`;
        return;
    }

    AppState.bob.messages.forEach(msg => {
        const bubble = document.createElement("div");
        const isSent = msg.sender === "Bob";
        bubble.className = `message-bubble ${isSent ? "msg-sent" : "msg-received"}`;

        let inner = `
            <div class="msg-meta">
                <span><strong>${isSent ? "Bạn (Bob)" : "Alice"}</strong></span>
                <span>${msg.timestamp}</span>
            </div>
        `;

        if (msg.error) {
            inner += `
                <div style="color: #f87171; font-weight: 600;">⚠️ ${escapeHtml(msg.error)}</div>
                <div class="msg-ciphertext-tag" style="color: #f87171; background: rgba(239, 68, 68, 0.1);">Ciphertext: ${formatSeq(msg.ciphertext)}</div>
            `;
        } else {
            inner += `
                <div style="font-weight: 500;">${escapeHtml(msg.plaintext)}</div>
                <div class="msg-ciphertext-tag">🔒 Ciphertext: ${formatSeq(msg.ciphertext)}</div>
            `;
        }

        if (msg.trace) {
            inner += `<button class="msg-view-trace-btn" onclick="viewBobTrace(${msg.id})">🔍 Xem chi tiết phép tính ${isSent ? 'mã hóa' : 'giải mã'}</button>`;
        }

        bubble.innerHTML = inner;
        listEl.appendChild(bubble);
    });

    listEl.scrollTop = listEl.scrollHeight;
}

window.viewBobTrace = function (msgId) {
    const msg = AppState.bob.messages.find(m => m.id === msgId);
    if (!msg || !msg.trace) return;

    if (msg.sender === "Bob") {
        let html = `
            <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 12px;">
                Tin nhắn bản rõ: <strong style="color: #a855f7;">"${escapeHtml(msg.plaintext)}"</strong><br>
                Được chia thành <strong>${msg.trace.length} khối 8-bit</strong>. Mỗi khối được nhân với Khóa công khai của Alice $\\beta = ${formatSeq(AppState.bob.peerPublicKey)}$.
            </div>
            <div class="trace-table-wrapper">
                <table class="crypto-table">
                    <thead>
                        <tr>
                            <th>Khối #</th>
                            <th>Ký tự</th>
                            <th>Byte (Dec)</th>
                            <th>8-Bit nhị phân</th>
                            <th>Phép tính $c = \\sum b_i \\cdot \\beta_i$</th>
                            <th>Ciphertext</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        msg.trace.forEach(step => {
            html += `
                <tr>
                    <td style="color: var(--text-dim);">${step.byteIndex + 1}</td>
                    <td style="color: #fbbf24; font-weight: 700;">'${step.char}'</td>
                    <td>${step.byteVal}</td>
                    <td style="color: #34d399; letter-spacing: 1px;">${step.bitsStr}</td>
                    <td style="font-size: 0.75rem; color: #94a3b8;">${step.formula}</td>
                    <td style="color: #a855f7; font-weight: 700;">${step.ciphertext}</td>
                </tr>
            `;
        });
        html += `</tbody></table></div>`;
        openTraceModal(`Bob: Chi tiết Mã Hóa Tin Nhắn #${msg.id}`, html);
    } else {
        renderDecryptionTraceModal("Bob", msg);
    }
};

/**
 * Hiển thị bảng giải thích từng bước giải mã bằng Thuật toán tham lam trên dãy siêu tăng
 */
function renderDecryptionTraceModal(recipientName, msg) {
    const priv = recipientName === "Bob" ? AppState.bob.privateKey : AppState.alice.privateKey;
    let html = `
        <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 12px;">
            Bản rõ giải mã được: <strong style="color: #34d399;">"${escapeHtml(msg.plaintext)}"</strong><br>
            Sử dụng Khóa riêng bí mật: $r^{-1} = ${priv.r_inv}$, $q = ${priv.q}$, Dãy siêu tăng $w = ${formatSeq(priv.w)}$.<br>
            <strong>Bước 1:</strong> Đưa về bài toán siêu tăng: $c' = (c \\times r^{-1}) \\pmod q$.<br>
            <strong>Bước 2:</strong> Giải bài toán Subset-Sum bằng thuật toán tham lam (Greedy) trên dãy siêu tăng $w$ $\\rightarrow$ khôi phục 8 bit.
        </div>
        <div class="trace-table-wrapper">
            <table class="crypto-table">
                <thead>
                    <tr>
                        <th>Khối #</th>
                        <th>Ciphertext ($c$)</th>
                        <th>$c' = (c \\cdot r^{-1}) \\pmod q$</th>
                        <th>Thuật toán tham lam trên $w$</th>
                        <th>8-Bit khôi phục</th>
                        <th>Ký tự</th>
                    </tr>
                </thead>
                <tbody>
    `;

    msg.trace.forEach(step => {
        let greedyDetails = step.knapsackTrace
            .map(t => `${t.weight}: ${t.taken ? '<strong style="color: #34d399;">Chọn(1)</strong>' : '<span style="color: var(--text-dim);">Bỏ(0)</span>'}`)
            .join(" | ");

        html += `
            <tr>
                <td style="color: var(--text-dim);">${step.blockIndex + 1}</td>
                <td style="color: #38bdf8; font-weight: 600;">${step.ciphertext}</td>
                <td style="color: #fbbf24; font-size: 0.75rem;">${step.formula}</td>
                <td style="font-size: 0.72rem;">${greedyDetails}</td>
                <td style="color: #34d399; font-weight: 700; letter-spacing: 1px;">${step.bitsStr}</td>
                <td style="color: #fff; font-weight: 700; font-size: 0.95rem;">'${step.char}'</td>
            </tr>
        `;
    });

    html += `</tbody></table></div>`;
    openTraceModal(`${recipientName}: Chi tiết Giải Mã Tin Nhắn #${msg.id}`, html);
}


// ============================================================
// PHẦN 7: DANH BẠ MÁY CHỦ & BẮT GÓI TIN ĐƯỜNG TRUYỀN (WIRE)
// ============================================================

/**
 * Lấy danh sách Khóa công khai từ máy chủ trung gian
 */
async function fetchServerPublicKeys() {
    if (!AppState.backendOnline) {
        renderLocalServerDirectory();
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/api/users`);
        const data = await res.json();
        if (data.status === "success") {
            renderServerDirectory(data.users);
        }
    } catch (err) {
        renderLocalServerDirectory();
    }
}

function renderLocalServerDirectory() {
    renderServerDirectory(AppState.localServer.users);
}

function renderServerDirectory(usersMap) {
    const listEl = document.getElementById("serverDirectoryList");
    const keys = Object.keys(usersMap);
    document.getElementById("serverKeyCount").textContent = `${keys.length} Khóa`;

    if (keys.length === 0) {
        listEl.innerHTML = `<div style="font-size: 0.75rem; color: var(--text-dim); text-align: center; padding: 6px;">Chưa có bên nào tải khóa công khai lên máy chủ.</div>`;
        return;
    }

    let html = "";
    keys.forEach(username => {
        const user = usersMap[username];
        const isAlice = username === "Alice";
        html += `
            <div style="background: var(--bg-input); padding: 8px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 2px;">
                    <span style="font-weight: 700; color: ${isAlice ? 'var(--alice-primary)' : 'var(--bob-secondary)'};">👤 ${username}</span>
                    <span style="color: var(--text-dim); font-size: 0.7rem;">${user.registered_at || ''}</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.72rem; color: #cbd5e1; word-break: break-all;">
                    β: ${formatSeq(user.public_key)}
                </div>
            </div>
        `;
    });
    listEl.innerHTML = html;
}

function addLocalWireLog(type, title, details) {
    AppState.localServer.logCounter++;
    const logObj = {
        id: AppState.localServer.logCounter,
        type: type,
        timestamp: new Date().toLocaleTimeString(),
        title: title,
        details: details
    };
    appendWireLogEntry(logObj);
}

function appendWireLogEntry(log) {
    const listEl = document.getElementById("wireLogsList");
    if (AppState.wire.lastLogId === 0) {
        listEl.innerHTML = "";
    }
    AppState.wire.lastLogId = Math.max(AppState.wire.lastLogId, log.id);
    AppState.wire.logs.push(log);

    const entry = document.createElement("div");
    entry.className = `wire-log-entry wire-${log.type}`;

    let detailsText = "";
    if (log.type === "CIPHER_MSG" && log.details) {
        detailsText = `Ciphertext: ${formatSeq(log.details.ciphertext)}`;
    } else if (log.type === "KEY_REG" && log.details) {
        detailsText = `Khóa công khai β: ${formatSeq(log.details.beta)}`;
    } else if (log.type === "TAMPER" && log.details) {
        detailsText = `Đã can thiệp gói tin: ${formatSeq(log.details.tampered_ciphertext)}`;
    }

    entry.innerHTML = `
        <div class="wire-log-header">
            <span>#${log.id} • ${log.timestamp}</span>
            <span>[${log.type}]</span>
        </div>
        <div class="wire-log-title">${escapeHtml(log.title)}</div>
        ${detailsText ? `<div class="wire-log-details">${detailsText}</div>` : ''}
    `;
    listEl.appendChild(entry);
    document.getElementById("wirePacketCount").textContent = `${AppState.wire.logs.length} Gói tin`;
    listEl.scrollTop = listEl.scrollHeight;
}

async function fetchWireLogs() {
    if (!AppState.backendOnline) return;
    try {
        const res = await fetch(`${API_BASE}/api/wire?since_id=${AppState.wire.lastLogId}`);
        const data = await res.json();
        if (data.status === "success" && data.logs.length > 0) {
            data.logs.forEach(log => appendWireLogEntry(log));
        }
    } catch (err) {
        console.error("fetchWireLogs error:", err);
    }
}


// ============================================================
// PHẦN 8: CHU KỲ NHẬN & GIẢI MÃ TIN NHẮN TỰ ĐỘNG (POLLING)
// ============================================================

/**
 * Định kỳ kiểm tra tin nhắn mới trên máy chủ trung gian và tự động giải mã tại Client
 */
async function pollIncomingMessages() {
    if (!AppState.backendOnline) return;

    try {
        // Kiểm tra tin nhắn Bob nhận được từ Alice
        if (AppState.bob.privateKey) {
            const resBob = await fetch(`${API_BASE}/api/messages?user=Bob&since_id=${AppState.bob.lastProcessedId}`);
            const dataBob = await resBob.json();
            if (dataBob.status === "success" && dataBob.messages.length > 0) {
                dataBob.messages.forEach(msg => {
                    AppState.bob.lastProcessedId = Math.max(AppState.bob.lastProcessedId, msg.id);
                    // Bob giải mã bằng khóa bí mật của Bob
                    try {
                        const decResult = MerkleHellmanCrypto.decrypt(msg.ciphertext, AppState.bob.privateKey);
                        AppState.bob.messages.push({
                            id: msg.id,
                            sender: msg.sender,
                            recipient: "Bob",
                            plaintext: decResult.plaintext,
                            ciphertext: msg.ciphertext,
                            timestamp: msg.timestamp,
                            trace: decResult.steps,
                            type: "received"
                        });
                        showToast(`Bob vừa nhận và giải mã tin nhắn từ ${msg.sender}!`, "success");
                    } catch (decErr) {
                        AppState.bob.messages.push({
                            id: msg.id,
                            sender: msg.sender,
                            recipient: "Bob",
                            plaintext: "[LỖI GIẢI MÃ: Gói tin bị hỏng hoặc bị sửa đổi]",
                            error: decErr.message,
                            ciphertext: msg.ciphertext,
                            timestamp: msg.timestamp,
                            type: "received"
                        });
                        showToast(`Bob: Cảnh báo giải mã thất bại! ` + decErr.message, "error");
                    }
                });
                renderBobMessages();
            }
        }

        // Kiểm tra tin nhắn Alice nhận được từ Bob
        if (AppState.alice.privateKey) {
            const resAlice = await fetch(`${API_BASE}/api/messages?user=Alice&since_id=${AppState.alice.lastProcessedId}`);
            const dataAlice = await resAlice.json();
            if (dataAlice.status === "success" && dataAlice.messages.length > 0) {
                dataAlice.messages.forEach(msg => {
                    AppState.alice.lastProcessedId = Math.max(AppState.alice.lastProcessedId, msg.id);
                    try {
                        const decResult = MerkleHellmanCrypto.decrypt(msg.ciphertext, AppState.alice.privateKey);
                        AppState.alice.messages.push({
                            id: msg.id,
                            sender: msg.sender,
                            recipient: "Alice",
                            plaintext: decResult.plaintext,
                            ciphertext: msg.ciphertext,
                            timestamp: msg.timestamp,
                            trace: decResult.steps,
                            type: "received"
                        });
                        showToast(`Alice vừa nhận và giải mã tin nhắn từ ${msg.sender}!`, "success");
                    } catch (decErr) {
                        AppState.alice.messages.push({
                            id: msg.id,
                            sender: msg.sender,
                            recipient: "Alice",
                            plaintext: "[LỖI GIẢI MÃ: Gói tin bị hỏng]",
                            error: decErr.message,
                            ciphertext: msg.ciphertext,
                            timestamp: msg.timestamp,
                            type: "received"
                        });
                        showToast(`Alice: Cảnh báo giải mã thất bại! ` + decErr.message, "error");
                    }
                });
                renderAliceMessages();
            }
        }
    } catch (err) {
        console.error("pollIncomingMessages error:", err);
    }
}


// ============================================================
// PHẦN 9: CÁC TIỆN ÍCH THỰC NGHIỆM & KỊCH BẢN DEMO
// ============================================================

/**
 * Nút "⚡ Thiết lập nhanh": Tự động sinh cặp khóa cho cả Alice và Bob,
 * trao đổi khóa công khai qua server và điền sẵn tin nhắn mẫu.
 */
async function runQuickSetup() {
    showToast("Đang tự động khởi tạo cặp khóa cho Alice & Bob...", "info");

    // 1. Sinh khóa cho Alice & tải lên server
    generateAliceKeys();
    await uploadAlicePublicKey();

    // 2. Sinh khóa cho Bob & tải lên server
    generateBobKeys();
    await uploadBobPublicKey();

    // 3. Trao đổi khóa công khai qua server
    await fetchBobKeyForAlice();
    await fetchAliceKeyForBob();

    // 4. Điền sẵn tin nhắn mẫu
    document.getElementById("aliceInputMsg").value = "Hello Bob! Merkle-Hellman E2EE";

    showToast("⚡ Thiết lập nhanh hoàn tất! Đã điền sẵn tin nhắn mẫu. Hãy bấm 'Mã hóa & Gửi'!", "success");
}

/**
 * Nút "📖 Khóa mẫu Wikipedia": Nạp bộ khóa chuẩn theo giáo trình.
 */
async function loadWikipediaPreset() {
    showToast("Đang nạp bộ khóa chuẩn từ Wikipedia...", "info");

    // Gán khóa Wikipedia cho Bob
    const wiki = MerkleHellmanCrypto.getWikipediaKeys();
    AppState.bob.privateKey = wiki.privateKey;
    AppState.bob.publicKey = wiki.publicKey;
    updateBobUI();
    await uploadBobPublicKey();

    // Sinh khóa cho Alice nếu chưa có
    if (!AppState.alice.privateKey) {
        generateAliceKeys();
        await uploadAlicePublicKey();
    }

    await fetchBobKeyForAlice();
    await fetchAliceKeyForBob();

    document.getElementById("aliceInputMsg").value = "a";
    showToast("Đã nạp Khóa Wikipedia cho Bob và chuẩn bị sẵn ký tự 'a' ở ô chat của Alice!", "success");
}

/**
 * Nút "🗑️ Làm mới": Xóa sạch toàn bộ tin nhắn và khóa trên hệ thống.
 */
async function resetAllData() {
    if (!confirm("Bạn có chắc chắn muốn xóa toàn bộ lịch sử tin nhắn và làm mới dữ liệu?")) return;

    if (AppState.backendOnline) {
        try {
            await fetch(`${API_BASE}/api/clear`, { method: "POST" });
        } catch (e) {}
    }

    AppState.alice.messages = [];
    AppState.alice.lastProcessedId = 0;
    AppState.bob.messages = [];
    AppState.bob.lastProcessedId = 0;
    AppState.wire.logs = [];
    AppState.wire.lastLogId = 0;
    AppState.localServer.users = {};
    AppState.localServer.messages = [];
    AppState.localServer.msgCounter = 0;
    AppState.localServer.logCounter = 0;

    renderAliceMessages();
    renderBobMessages();
    document.getElementById("wireLogsList").innerHTML = `<div style="color: var(--text-dim); font-size: 0.75rem; text-align: center; margin-top: 40px;">Đang lắng nghe đường truyền... Các gói tin mã hóa đi qua sẽ hiển thị tại đây.</div>`;
    document.getElementById("wirePacketCount").textContent = "0 Gói tin";
    renderLocalServerDirectory();
    showToast("Đã làm mới toàn bộ dữ liệu demo!", "success");
}

/**
 * Nút "⚡ Mô phỏng can thiệp gói tin (MITM)": Sửa đổi 1 số nguyên trong ciphertext
 * trên đường truyền để kiểm chứng phản ứng giải mã thất bại ở bên nhận.
 */
async function tamperLastMessage() {
    let lastMsg = null;
    if (AppState.backendOnline) {
        try {
            const res = await fetch(`${API_BASE}/api/messages`);
            const data = await res.json();
            if (data.messages && data.messages.length > 0) {
                lastMsg = data.messages[data.messages.length - 1];
            }
        } catch (e) {}
    }

    if (!lastMsg && AppState.localServer.messages.length > 0) {
        lastMsg = AppState.localServer.messages[AppState.localServer.messages.length - 1];
    }

    if (!lastMsg) {
        showToast("Chưa có tin nhắn nào trên đường truyền để can thiệp!", "warning");
        return;
    }

    // Giả lập hacker sửa đổi số nguyên ciphertext đầu tiên
    const tamperedCipher = [...lastMsg.ciphertext];
    tamperedCipher[0] = tamperedCipher[0] + 777;

    if (AppState.backendOnline) {
        try {
            await fetch(`${API_BASE}/api/tamper`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    message_id: lastMsg.id,
                    tampered_ciphertext: tamperedCipher
                })
            });
            fetchWireLogs();
        } catch (e) {}
    } else {
        lastMsg.ciphertext = tamperedCipher;
        addLocalWireLog(
            "TAMPER",
            `CẢNH BÁO: Gói tin #${lastMsg.id} bị Hacker can thiệp sửa đổi trên đường truyền!`,
            { message_id: lastMsg.id, tampered_ciphertext: tamperedCipher }
        );
    }

    showToast(`⚡ Đã sửa đổi Ciphertext của gói tin #${lastMsg.id} trên đường truyền!`, "warning");
}


// ============================================================
// PHẦN 10: ĐIỀU HƯỚNG TAB & KHỞI TẠO SỰ KIỆN (EVENT LISTENERS)
// ============================================================

/**
 * Chuyển đổi giữa các chế độ xem giao diện
 */
function switchView(viewName) {
    AppState.currentView = viewName;

    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.view === viewName);
    });

    const dualView = document.getElementById("viewDual");
    const theoryView = document.getElementById("viewTheory");
    const aliceContainer = document.getElementById("aliceContainer");
    const serverContainer = document.getElementById("serverContainer");
    const bobContainer = document.getElementById("bobContainer");

    if (viewName === "theory") {
        dualView.style.display = "none";
        theoryView.style.display = "flex";
        return;
    }

    theoryView.style.display = "none";
    dualView.style.display = "grid";

    if (viewName === "dual") {
        aliceContainer.style.display = "flex";
        serverContainer.style.display = "flex";
        bobContainer.style.display = "flex";
        dualView.style.gridTemplateColumns = "1fr 1.18fr 1fr";
    } else if (viewName === "alice") {
        aliceContainer.style.display = "flex";
        serverContainer.style.display = "none";
        bobContainer.style.display = "none";
        dualView.style.gridTemplateColumns = "1fr";
    } else if (viewName === "bob") {
        aliceContainer.style.display = "none";
        serverContainer.style.display = "none";
        bobContainer.style.display = "flex";
        dualView.style.gridTemplateColumns = "1fr";
    } else if (viewName === "server") {
        aliceContainer.style.display = "none";
        serverContainer.style.display = "flex";
        bobContainer.style.display = "none";
        dualView.style.gridTemplateColumns = "1fr";
    }
}

window.switchView = switchView;

// Đăng ký toàn bộ sự kiện khi tài liệu DOM sẵn sàng
document.addEventListener("DOMContentLoaded", () => {
    // Sự kiện cho các nút của Alice
    document.getElementById("btnGenAliceKeys").addEventListener("click", generateAliceKeys);
    document.getElementById("btnUploadAliceKey").addEventListener("click", uploadAlicePublicKey);
    document.getElementById("btnFetchBobKeyForAlice").addEventListener("click", fetchBobKeyForAlice);
    document.getElementById("btnAliceSend").addEventListener("click", sendAliceMessage);
    document.getElementById("aliceInputMsg").addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendAliceMessage();
    });

    // Sự kiện cho các nút của Bob
    document.getElementById("btnGenBobKeys").addEventListener("click", generateBobKeys);
    document.getElementById("btnUploadBobKey").addEventListener("click", uploadBobPublicKey);
    document.getElementById("btnFetchAliceKeyForBob").addEventListener("click", fetchAliceKeyForBob);
    document.getElementById("btnBobSend").addEventListener("click", sendBobMessage);
    document.getElementById("bobInputMsg").addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendBobMessage();
    });

    // Sự kiện cho các nút Thao tác nhanh (Quick Actions)
    document.getElementById("btnQuickSetup").addEventListener("click", runQuickSetup);
    document.getElementById("btnLoadWiki").addEventListener("click", loadWikipediaPreset);
    document.getElementById("btnResetAll").addEventListener("click", resetAllData);
    document.getElementById("btnRefreshWire").addEventListener("click", () => {
        if (AppState.backendOnline) {
            fetchWireLogs();
            fetchServerPublicKeys();
        } else {
            renderLocalServerDirectory();
        }
        showToast("Đã cập nhật nhật ký đường truyền!", "info");
    });
    document.getElementById("btnTamperLastMsg").addEventListener("click", tamperLastMessage);
    document.getElementById("btnCheckBackend").addEventListener("click", () => {
        checkBackendConnection().then(online => {
            if (online) showToast("Đã kết nối thành công tới Máy chủ Python!", "success");
            else showToast("Chưa thấy Máy chủ Python chạy. Hãy chạy 'python server.py'!", "warning");
        });
    });

    // Sự kiện chuyển Tab xem
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            switchView(btn.dataset.view);
        });
    });

    // Kiểm tra URL parameters (ví dụ: ?user=alice hoặc ?user=bob nếu mở tab riêng)
    const urlParams = new URLSearchParams(window.location.search);
    const userParam = urlParams.get("user");
    if (userParam === "alice") {
        switchView("alice");
    } else if (userParam === "bob") {
        switchView("bob");
    } else if (userParam === "server") {
        switchView("server");
    }

    // Kiểm tra kết nối Backend ngay khi mở trang
    checkBackendConnection();

    // Chu kỳ cập nhật tự động (Polling mỗi 1.5 giây khi online)
    setInterval(() => {
        if (AppState.backendOnline) {
            pollIncomingMessages();
            fetchWireLogs();
        }
    }, 1500);

    // Chu kỳ cập nhật danh bạ khóa mỗi 4 giây khi online
    setInterval(() => {
        if (AppState.backendOnline) {
            fetchServerPublicKeys();
        }
    }, 4000);
});

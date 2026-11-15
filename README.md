# BÁO CÁO & HƯỚNG DẪN: ỨNG DỤNG WEB DEMO HỆ MẬT MERKLE – HELLMAN (KNAPSACK CRYPTOSYSTEM)
> **Môn học:** An Toàn Thông Tin / An Ninh Mạng (BTL_ANM)  
> **Chủ đề:** Hệ mật mã hóa khóa công khai Merkle–Hellman (Mã hóa đầu cuối E2EE qua máy chủ trung gian)

---

## 1. Giới thiệu tổng quan
Ứng dụng là một hệ thống web demo hoàn chỉnh mô phỏng quá trình truyền tin mật giữa hai thực thể **Alice** và **Bob** thông qua một **Máy chủ trung gian (Intermediary Server)** sử dụng **Hệ mật Merkle – Hellman** (Knapsack Cryptosystem).

### Các điểm nổi bật của đồ án:
1. **Mã hóa đầu cuối thực sự (End-to-End Encryption - E2EE):**
   - Mỗi bên (Alice và Bob) tự sinh cặp khóa trên thiết bị/trình duyệt của mình.
   - **Khóa riêng (Private Key):** Gồm dãy siêu tăng $w$, modulus $q$, hệ số nhân $r$, và nghịch đảo $r^{-1}$ được lưu trữ bí mật tại máy người dùng, **tuyệt đối không gửi lên máy chủ**.
   - **Khóa công khai (Public Key $\beta$):** Được gửi lên máy chủ trung gian để các bên khác có thể tải về và mã hóa tin nhắn.
2. **Mã hóa từng khối 8 bit (ASCII / UTF-8):**
   - Tin nhắn văn bản được chia thành các khối 8 bit tương ứng với từng byte.
   - Mỗi khối 8 bit được nhân vô hướng với Khóa công khai $\beta$ của người nhận để tạo ra một **số nguyên lớn** (Ciphertext).
   - Máy chủ chỉ nhìn thấy dãy số nguyên này và không thể đọc được nội dung bản rõ.
3. **Giải mã bằng thuật toán tham lam (Greedy Knapsack):**
   - Người nhận dùng $r^{-1} \pmod q$ để đưa số nguyên lớn về bài toán con với dãy siêu tăng $w$.
   - Giải bài toán bằng thuật toán tham lam trong $O(n)$ để khôi phục chính xác 8 bit ban đầu.
4. **Giao diện trực quan chuyên dụng để báo cáo & thuyết trình:**
   - **Chế độ Màn hình đôi (Dual View):** Hiển thị đồng thời cột của Alice, cột Kênh truyền/Máy chủ và cột của Bob trên cùng 1 màn hình.
   - **Bộ soi bước toán học (Step-by-step Math Inspector):** Bấm vào bất kỳ tin nhắn nào để xem chi tiết bảng tính toán từng bit, phép nhân $\sum b_i \beta_i$, phép nghịch đảo và từng bước tham lam trên dãy siêu tăng.
   - **Kênh bắt gói tin (Wire Sniffer):** Hiển thị các gói tin đi qua đường truyền, chứng minh máy chủ chỉ thấy số nguyên.
   - **Mô phỏng tấn công can thiệp gói tin (Tamper / MITM):** Cho phép sửa đổi 1 số nguyên trên đường truyền để chứng minh phản ứng giải mã lỗi.
   - **Nạp nhanh ví dụ Wikipedia chuẩn:** Đối chiếu từng con số chuẩn theo sách giáo trình quốc tế.

---

## 2. Cơ sở lý thuyết Toán học

### 2.1. Bài toán xếp ba lô (Subset Sum Problem)
Cho dãy số nguyên dương $A = (a_1, a_2, \dots, a_n)$ và số nguyên mục tiêu $S$. Tìm vector nhị phân $b = (b_1, b_2, \dots, b_n) \in \{0, 1\}^n$ sao cho:
$$S = \sum_{i=1}^{n} b_i \cdot a_i$$
Đây là bài toán **NP-đầy đủ (NP-complete)** trong trường hợp tổng quát.

### 2.2. Dãy siêu tăng (Superincreasing Sequence)
Một dãy $w = (w_1, w_2, \dots, w_n)$ là siêu tăng nếu mỗi phần tử lớn hơn tổng của các phần tử trước nó:
$$w_k > \sum_{i=1}^{k-1} w_i \quad (\forall k \ge 2)$$
**Tính chất:** Bài toán Subset Sum với dãy siêu tăng có thể giải cực nhanh bằng thuật toán tham lam (Greedy) từ phần tử lớn nhất $w_n$ về $w_1$ với độ phức tạp thời gian chỉ $O(n)$.

### 2.3. Ý tưởng "Cửa sập" (Trapdoor) của Merkle–Hellman
- **Tạo khóa:**
  1. Chọn dãy siêu tăng $w = (w_1, \dots, w_n)$.
  2. Chọn số nguyên $q > \sum_{i=1}^n w_i$.
  3. Chọn số nguyên $r \in [2, q-1]$ sao cho $\gcd(r, q) = 1$.
  4. Tính $r^{-1} \pmod q$ bằng thuật toán Euclid mở rộng.
  5. **Khóa bí mật:** $(w, q, r, r^{-1})$.
  6. **Khóa công khai:** $\beta = (\beta_1, \dots, \beta_n)$ với $\beta_i = (r \cdot w_i) \pmod q$.
- **Mã hóa khối 8-bit:**
  $$c = \sum_{i=1}^{n} b_i \cdot \beta_i$$
- **Giải mã:**
  $$c' = (c \cdot r^{-1}) \pmod q = \left( \sum_{i=1}^n b_i (r \cdot w_i) \cdot r^{-1} \right) \pmod q = \sum_{i=1}^n b_i \cdot w_i$$
  Vì $w$ là dãy siêu tăng và $c' < q$, người nhận dùng thuật toán tham lam trên dãy $w$ để giải tìm lại $(b_1, \dots, b_n)$.

---

## 3. Cấu trúc thư mục dự án

```text
d:\BTL_ANM\
├── merkle_hellman.py       # Core thuật toán Merkle-Hellman bằng Python (Console app)
├── server.py               # Máy chủ web chuẩn Python (chạy ngay, không cần cài thư viện)
├── server_flask.py         # Phiên bản máy chủ Flask (dành cho yêu cầu dùng Flask)
├── requirements.txt        # Danh sách thư viện nếu muốn dùng Flask (flask>=2.0.0)
├── README.md               # Báo cáo & tài liệu hướng dẫn sử dụng
└── static\
    ├── index.html          # Giao diện ứng dụng web
    ├── css\
    │   └── style.css       # Giao diện Cyber Security chuyên nghiệp, responsive
    └── js\
        ├── merkle_hellman.js # Thư viện Merkle-Hellman chạy phía Client (BigInt)
        └── app.js          # Quản lý giao diện, kết nối máy chủ, chat và bộ soi toán học
```

---

## 4. Hướng dẫn cài đặt & Khởi chạy

### Cách 1: Chạy bằng Python tiêu chuẩn (Khuyên dùng - Không cần cài đặt gì thêm)
Mở cửa sổ dòng lệnh (Terminal / PowerShell / CMD) tại thư mục `d:\BTL_ANM`:

```bash
python server.py
```
Máy chủ sẽ khởi động tại: `http://localhost:5000`  
Mở trình duyệt web và truy cập: [http://localhost:5000](http://localhost:5000)

*(Bạn cũng có thể chỉ định cổng khác nếu muốn, ví dụ: `python server.py 8080`)*

---

### Cách 2: Chạy bằng phiên bản Flask (Nếu giáo viên yêu cầu dùng Flask)
1. Cài đặt thư viện Flask:
   ```bash
   pip install flask
   ```
2. Khởi chạy:
   ```bash
   python server_flask.py
   ```
3. Truy cập vào: [http://localhost:5000](http://localhost:5000)

---

### Cách 3: Chạy ứng dụng Console (CLI) truyền thống
Nếu bạn muốn kiểm tra hoặc chạy thuật toán Merkle-Hellman trên màn hình dòng lệnh:
```bash
python merkle_hellman.py
```

---

## 5. Kịch bản Thuyết trình / Demo chấm điểm (5 Bước)

Dưới đây là kịch bản chuẩn từng bước giúp bạn ghi điểm tối đa khi báo cáo với giảng viên:

### Bước 1: Giới thiệu kiến trúc & Thiết lập cặp khóa
1. Mở trang web `http://localhost:5000`.
2. Giới thiệu 3 cột trên màn hình:
   - **Cột trái (Alice):** Đại diện cho máy khách của Alice.
   - **Cột giữa (Server):** Đại diện cho Máy chủ trung gian và Kênh truyền mạng.
   - **Cột phải (Bob):** Đại diện cho máy khách của Bob.
3. Bấm nút **"⚡ Thiết lập nhanh (Quick Setup)"**:
   - Trình duyệt tự sinh cặp khóa cho Alice và Bob.
   - Cho giảng viên thấy: Khóa riêng $(w, q, r, r^{-1})$ có huy hiệu đỏ **"Không gửi Server"** và chỉ nằm tại Client.
   - Chỉ có Khóa công khai $\beta$ được gửi lên mục **"Sổ lưu Khóa công khai trên Máy chủ"** ở cột giữa.

### Bước 2: Alice gửi tin nhắn mã hóa cho Bob
1. Tại khung chat của Alice, nhập: `Hello Bob!` rồi bấm **"Mã hóa & Gửi ➔"**.
2. Chỉ cho thầy cô thấy quá trình diễn ra:
   - Ứng dụng lấy Khóa công khai $\beta_{Bob}$ của Bob.
   - Từng ký tự được đổi thành 8 bit ASCII, nhân với $\beta_{Bob}$ để tạo thành các số nguyên lớn.
   - Cột giữa (Server Sniffer) bắt được gói tin: `[620, 1482, 1274, 1274, 1630, ...]`. **Máy chủ chỉ thấy số nguyên, hoàn toàn không biết nội dung "Hello Bob!".**
   - Cột phải (Bob) tự động nhận được gói tin, dùng khóa bí mật của mình giải mã thành công ra `Hello Bob!`.

### Bước 3: Xem chi tiết các bước toán học (Visualizer)
1. Dưới tin nhắn của Alice hoặc Bob, bấm vào liên kết **"🔍 Xem chi tiết phép tính mã hóa / giải mã"**.
2. Một bảng phân tích toán học chi tiết hiện lên:
   - **Bảng mã hóa:** Thể hiện rõ Ký tự $\rightarrow$ Mã byte $\rightarrow$ Chuỗi 8 bit nhị phân $\rightarrow$ Phép tính $\sum b_i \cdot \beta_i \rightarrow$ Giá trị Ciphertext.
   - **Bảng giải mã:** Thể hiện phép tính $c' = (c \cdot r^{-1}) \pmod q \rightarrow$ Từng bước của thuật toán tham lam Greedy trên dãy siêu tăng $w$ (chọn phần tử nào, số dư còn lại bao nhiêu) $\rightarrow$ Khôi phục 8 bit ban đầu.

### Bước 4: Bob trả lời Alice
1. Tại khung chat của Bob, gõ: `Chào Alice!` và bấm **"Trả lời ➔"**.
2. Bob dùng Khóa công khai của Alice $\beta_{Alice}$ để mã hóa.
3. Alice nhận được và giải mã bằng khóa bí mật của Alice.

### Bước 5: Mô phỏng tấn công can thiệp đường truyền (Man-in-the-Middle)
1. Ở cột giữa, trong ô đỏ **"Mô phỏng tấn công đường truyền"**, bấm nút:  
   **"⚡ Thay đổi gói tin cuối cùng trên đường truyền"**.
2. Gói tin bị sửa đổi 1 số nguyên (giả lập kẻ tấn công giả mạo dữ liệu trên đường truyền).
3. Khi bên nhận cố gắng giải mã, thuật toán tham lam trên dãy siêu tăng sẽ phát hiện số dư không thể trừ hết về 0 và đưa ra cảnh báo bảo mật:  
   `⚠️ LỖI GIẢI MÃ: Gói tin bị hỏng hoặc bị sửa đổi!`  
   $\rightarrow$ Điều này chứng minh tính toàn vẹn và an toàn của hệ thống.

---

## 6. Chế độ mở 2 Tab / 2 Thiết bị độc lập
Ngoài chế độ màn hình kép tiện lợi, ứng dụng hỗ trợ mở trên nhiều máy tính khác nhau trong cùng mạng LAN hoặc mở 2 Tab riêng biệt:
- **Tab của Alice:** `http://localhost:5000/?user=alice` (Chỉ hiện giao diện Alice)
- **Tab của Bob:** `http://localhost:5000/?user=bob` (Chỉ hiện giao diện Bob)
- **Tab của Server:** `http://localhost:5000/?user=server` (Chuyên theo dõi gói tin)

Hai người dùng có thể ngồi trên 2 máy tính khác nhau nhắn tin mã hóa qua IP của máy chủ.

---

## 7. Kết luận
Đồ án đã đáp ứng hoàn chỉnh và vượt mức các yêu cầu đặt ra:
- Thực hiện đầy đủ mô hình trao đổi khóa công khai qua máy chủ trung gian.
- Mã hóa từng khối 8 bit thành số nguyên lớn đúng chuẩn Merkle–Hellman.
- Giải mã chính xác bằng thuật toán tham lam trên dãy siêu tăng với khóa bí mật.
- Hỗ trợ cả Python tiêu chuẩn (không phụ thuộc) và Flask.
- Giao diện trực quan, khoa học, có khả năng trình diễn và đối chiếu lý thuyết toán học rõ ràng.


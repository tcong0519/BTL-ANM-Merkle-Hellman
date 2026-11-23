#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HỆ MẬT MÃ KHÓA CÔNG KHAI MERKLE – HELLMAN (KNAPSACK CRYPTOSYSTEM)
================================================================
Môn học: An toàn Thông tin & An ninh Mạng (BTL_ANM)
Nguyên lý: Dựa trên bài toán Xếp Ba Lô (Subset Sum Problem) - thuộc lớp bài toán NP-đầy đủ.
Ý tưởng:
  - Khóa riêng (Private Key): Dãy siêu tăng (superincreasing sequence) w, modulus q, số nhân r, r⁻¹.
    Bài toán con với dãy siêu tăng có thể giải cực nhanh bằng Thuật toán tham lam (Greedy).
  - Khóa công khai (Public Key): Dãy β = (r * w_i) mod q.
    Đối với người ngoài, dãy β trông như bài toán Knapsack tổng quát không có cấu trúc, cực kỳ khó giải.
"""

import math
import random
import textwrap
from typing import List, Tuple, Optional


# ============================================================
# PHẦN 1: CÁC THUẬT TOÁN TOÁN HỌC NỀN TẢNG
# ============================================================

def gcd(a: int, b: int) -> int:
    """
    Thuật toán Euclid tìm Ước chung lớn nhất (Greatest Common Divisor).
    Nguyên lý: gcd(a, b) = gcd(b, a mod b) cho đến khi b = 0.
    Dùng để kiểm tra hai số a và b có nguyên tố cùng nhau không (gcd == 1).
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Thuật toán Euclid mở rộng (Extended Euclidean Algorithm).
    Tìm nghiệm nguyên (x, y) cho phương trình đồng nhất Bézout:
        a * x + b * y = gcd(a, b)
    Trả về: (gcd, x, y)
    Được sử dụng làm nền tảng để tìm nghịch đảo modulo.
    """
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inverse(a: int, m: int) -> int:
    """
    Tìm nghịch đảo modulo: Tìm số nguyên x sao cho (a * x) ≡ 1 (mod m).
    
    Quy trình:
      - Bước 1: Gọi thuật toán Euclid mở rộng extended_gcd(a mod m, m).
      - Bước 2: Kiểm tra ước chung lớn nhất g. Nếu g ≠ 1 thì không tồn tại nghịch đảo.
      - Bước 3: Đưa x về khoảng dương [0, m - 1] bằng phép (x % m + m) % m.
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Không tồn tại nghịch đảo modulo vì gcd({a}, {m}) = {g} ≠ 1")
    return (x % m + m) % m


def is_superincreasing(seq: List[int]) -> bool:
    """
    Kiểm tra một dãy số có phải là dãy siêu tăng (superincreasing sequence) hay không.
    Điều kiện: Mỗi phần tử thứ i phải LỚN HƠN tổng của tất cả các phần tử đứng trước nó:
        w_k > sum(w_0, w_1, ..., w_{k-1}) với mọi k >= 1.
    """
    total = 0
    for x in seq:
        if x <= total:
            return False
        total += x
    return True


# ============================================================
# PHẦN 2: LỚP CHÍNH - MERKLE-HELLMAN CRYPTOSYSTEM
# ============================================================

class MerkleHellman:
    """
    Lớp triển khai trọn vẹn Hệ mật Merkle-Hellman.
    
    Cấu trúc cặp khóa:
      1. Khóa riêng (Private Key):
         - w     : Dãy siêu tăng bí mật [w_0, w_1, ..., w_{n-1}]
         - q     : Modulus bí mật (phải lớn hơn tổng của dãy w)
         - r     : Hệ số nhân bí mật (nguyên tố cùng nhau với q, tức gcd(r, q) = 1)
         - r_inv : Nghịch đảo modulo của r theo q (r * r_inv ≡ 1 mod q)
      2. Khóa công khai (Public Key):
         - beta  : Dãy khóa công khai [beta_0, beta_1, ..., beta_{n-1}]
                   với beta_i = (r * w_i) mod q
    """

    def __init__(self, n: int = 8, seed: Optional[int] = None):
        """
        Khởi tạo hệ thống Merkle-Hellman.
        :param n: Độ dài khóa (số bit của 1 khối, mặc định 8 bit = 1 byte).
        :param seed: Hạt giống ngẫu nhiên để tái tạo kết quả thử nghiệm nếu cần.
        """
        if n < 4:
            raise ValueError("Độ dài khóa n phải ≥ 4 bit.")
        self.n = n
        if seed is not None:
            random.seed(seed)

        self.w: List[int] = []          # Dãy siêu tăng (Private)
        self.q: int = 0                 # Modulus bí mật (Private)
        self.r: int = 0                 # Số nhân bí mật (Private)
        self.r_inv: int = 0             # Nghịch đảo r^-1 mod q (Private)
        self.beta: List[int] = []       # Khóa công khai (Public)

        # Tự động sinh cặp khóa khi khởi tạo
        self._generate_keys()

    # ----------------------------------------------------------
    # THUẬT TOÁN SINH CẶP KHÓA (5 BƯỚC)
    # ----------------------------------------------------------
    def _generate_superincreasing(self, n: int) -> List[int]:
        """
        Sinh ngẫu nhiên một dãy siêu tăng có n phần tử.
        Quy tắc: Mỗi phần tử mới = tổng các phần tử trước + một số ngẫu nhiên dương.
        """
        seq = []
        total = 0
        current = random.randint(2, 10) # Phần tử đầu tiên nhỏ (2..10)
        for _ in range(n):
            current = total + random.randint(1, max(3, total // 2 + 1))
            seq.append(current)
            total += current
        return seq

    def _generate_keys(self):
        """
        Thực hiện toàn bộ quy trình sinh cặp khóa Merkle-Hellman:
        
        Bước 1: Sinh dãy siêu tăng bí mật w gồm n phần tử.
        Bước 2: Chọn số nguyên modulus q lớn hơn tổng tất cả các phần tử của w (q > sum(w)).
        Bước 3: Chọn số nguyên nhân tử r trong khoảng [2, q - 1] sao cho gcd(r, q) = 1.
        Bước 4: Tính nghịch đảo modulo r_inv = r⁻¹ mod q bằng thuật toán Euclid mở rộng.
        Bước 5: Tạo khóa công khai beta với từng phần tử: beta_i = (r * w_i) mod q.
        """
        # Bước 1: Dãy siêu tăng bí mật (Private Key component)
        self.w = self._generate_superincreasing(self.n)

        # Bước 2: Modulus q bí mật (phải lớn hơn tổng dãy w để sau này phép chia dư không bị tràn)
        s = sum(self.w)
        self.q = s + random.randint(s // 2 + 1, s * 2)

        # Bước 3: Hệ số nhân r (phải nguyên tố cùng nhau với q để tồn tại nghịch đảo modulo)
        while True:
            self.r = random.randint(2, self.q - 1)
            if gcd(self.r, self.q) == 1:
                break

        # Bước 4: Tính nghịch đảo r^-1 theo modulo q
        self.r_inv = mod_inverse(self.r, self.q)

        # Bước 5: Tính Khóa công khai beta_i = (r * w_i) mod q (Public Key)
        self.beta = [(self.r * wi) % self.q for wi in self.w]

    # ----------------------------------------------------------
    # THUẬT TOÁN MÃ HÓA (ENCRYPTION)
    # ----------------------------------------------------------
    def encrypt(self, plaintext_bits: List[int]) -> int:
        """
        Mã hóa một khối nhị phân gồm n bit (ví dụ n = 8).
        
        Quy trình:
          - Đầu vào: Mảng bit b = [b_0, b_1, ..., b_{n-1}] với b_i ∈ {0, 1}.
          - Công thức: Tính tích vô hướng giữa mảng bit và Khóa công khai beta:
                c = sum(b_i * beta_i) với i từ 0 đến n-1.
          - Đầu ra: Số nguyên lớn ciphertext (c).
          
        * Lưu ý an ninh: Đối với kẻ nghe lén không biết w, q, r, việc tìm lại các bit b_i
          từ số c và dãy beta tương đương với việc giải bài toán Subset Sum tổng quát (NP-đầy đủ).
        """
        if len(plaintext_bits) != self.n:
            raise ValueError(f"Độ dài bản rõ phải đúng {self.n} bit (hiện tại: {len(plaintext_bits)})")
        if any(b not in (0, 1) for b in plaintext_bits):
            raise ValueError("Bản rõ nhị phân chỉ được chứa các giá trị 0 hoặc 1")

        # Phép tính tích vô hướng: c = Σ (b_i * beta_i)
        return sum(b * beta for b, beta in zip(plaintext_bits, self.beta))

    # ----------------------------------------------------------
    # THUẬT TOÁN GIẢI MÃ (DECRYPTION)
    # ----------------------------------------------------------
    def decrypt(self, ciphertext: int) -> List[int]:
        """
        Giải mã số nguyên ciphertext trở lại thành dãy n bit ban đầu.
        
        Quy trình 2 bước:
          Bước 1: Đưa về bài toán con dãy siêu tăng (Áp dụng 'Cửa sập' Trapdoor):
                  c' = (c * r_inv) mod q
                  Chứng minh:
                    c' = (sum(b_i * beta_i) * r_inv) mod q
                       = (sum(b_i * r * w_i) * r_inv) mod q
                       = sum(b_i * w_i * (r * r_inv)) mod q
                       = sum(b_i * w_i) mod q
                  Do q > sum(w), nên sum(b_i * w_i) < q. Phép mod q biến mất:
                    c' = sum(b_i * w_i)  (tổng Subset Sum trên dãy siêu tăng w!)
          
          Bước 2: Dùng Thuật toán Tham lam (Greedy Knapsack) giải tìm mảng bit b:
                  Duyệt từ phần tử lớn nhất w_{n-1} về phần tử nhỏ nhất w_0:
                  - Nếu w_i <= remaining: đặt b_i = 1, trừ remaining đi w_i.
                  - Ngược lại: đặt b_i = 0.
        """
        # Bước 1: Biến đổi ciphertext về bài toán siêu tăng c'
        c_prime = (ciphertext * self.r_inv) % self.q

        # Bước 2: Thuật toán tham lam giải bài toán Subset Sum trên dãy siêu tăng
        bits = [0] * self.n
        remaining = c_prime
        for i in range(self.n - 1, -1, -1):
            if self.w[i] <= remaining:
                bits[i] = 1
                remaining -= self.w[i]

        # Kiểm tra tính toàn vẹn: nếu remaining != 0 nghĩa là ciphertext bị sai hoặc bị can thiệp
        if remaining != 0:
            raise ValueError("Giải mã thất bại: Không tìm được tập con thỏa mãn (dữ liệu có thể bị lỗi).")

        return bits

    # ----------------------------------------------------------
    # XỬ LÝ VĂN BẢN (CHUYỂN ĐỔI CHUỖI ↔ KHỐI BIT)
    # ----------------------------------------------------------
    def text_to_bits(self, text: str) -> List[List[int]]:
        """
        Chuyển chuỗi văn bản thành danh sách các khối n bit.
        Hỗ trợ đầy đủ cả mã ASCII chuẩn và tiếng Việt có dấu (UTF-8).
        
        Quy trình:
          - Bước 1: Encode chuỗi thành danh sách byte UTF-8.
          - Bước 2: Chuyển mỗi byte (0..255) thành chuỗi 8 bit nhị phân.
          - Bước 3: Chia chuỗi bit thành các khối có độ dài n bit (padding '0' nếu thiếu).
        """
        raw_bytes = text.encode("utf-8")
        bit_string = "".join(f"{b:08b}" for b in raw_bytes)

        # Chia dòng bit liên tục thành các khối độ dài n
        blocks = []
        for i in range(0, len(bit_string), self.n):
            block = bit_string[i:i + self.n]
            # Padding thêm bit 0 nếu khối cuối cùng không đủ n bit
            if len(block) < self.n:
                block = block.ljust(self.n, "0")
            blocks.append([int(b) for b in block])
        return blocks

    def bits_to_text(self, blocks: List[List[int]]) -> str:
        """
        Ghép danh sách các khối n bit trở lại thành chuỗi văn bản gốc UTF-8 / ASCII.
        
        Quy trình:
          - Bước 1: Nối tất cả các khối bit thành chuỗi bit dài.
          - Bước 2: Tách từng đoạn 8 bit chuyển thành giá trị số nguyên byte (0..255).
          - Bước 3: Decode mảng byte thành chuỗi ký tự UTF-8.
        """
        bit_string = "".join("".join(str(b) for b in block) for block in blocks)

        raw_bytes = bytearray()
        for i in range(0, len(bit_string), 8):
            byte = bit_string[i:i + 8]
            if len(byte) < 8:
                break
            val = int(byte, 2)
            if val == 0:          # Ký tự null hoặc padding
                continue
            raw_bytes.append(val)
        return raw_bytes.decode("utf-8", errors="replace")

    def encrypt_text(self, text: str) -> List[int]:
        """
        Mã hóa toàn bộ một chuỗi văn bản.
        Trả về danh sách các số nguyên lớn ciphertext (mỗi khối bit tạo ra 1 số nguyên).
        """
        blocks = self.text_to_bits(text)
        return [self.encrypt(block) for block in blocks]

    def decrypt_text(self, cipher_list: List[int]) -> str:
        """
        Giải mã toàn bộ danh sách số nguyên ciphertext trở lại thành chuỗi văn bản gốc.
        """
        blocks = [self.decrypt(c) for c in cipher_list]
        return self.bits_to_text(blocks)

    # ----------------------------------------------------------
    # XUẤT THÔNG TIN KHÓA
    # ----------------------------------------------------------
    def public_key(self) -> List[int]:
        """Trả về Khóa công khai beta."""
        return self.beta.copy()

    def private_key(self) -> dict:
        """Trả về Khóa riêng bí mật (w, q, r, r_inv)."""
        return {
            "w": self.w.copy(),
            "q": self.q,
            "r": self.r,
            "r_inv": self.r_inv
        }

    def summary(self) -> str:
        """Tóm tắt trực quan toàn bộ thông tin của cặp khóa."""
        lines = [
            "=" * 60,
            "  THÔNG TIN KHÓA HỆ MẬT MERKLE – HELLMAN",
            "=" * 60,
            f"Độ dài khối (n)          : {self.n} bit",
            f"Dãy siêu tăng bí mật (w) : {self.w}",
            f"Tổng dãy w (sum_w)       : {sum(self.w)}",
            f"Modulus bí mật (q)       : {self.q} (thỏa mãn q > {sum(self.w)})",
            f"Hệ số nhân bí mật (r)    : {self.r} (nguyên tố cùng nhau với q)",
            f"Nghịch đảo r⁻¹ mod q     : {self.r_inv}",
            f"Khóa công khai (β)       : {self.beta}",
            f"Kiểm tra dãy siêu tăng   : {'✓ Hợp lệ' if is_superincreasing(self.w) else '✗ Không hợp lệ'}",
            "=" * 60,
        ]
        return "\n".join(lines)


# ============================================================
# PHẦN 3: BỘ DỮ LIỆU MẪU CHUẨN TỪ WIKIPEDIA (ĐỂ KIỂM CHỨNG)
# ============================================================

def demo_wikipedia():
    """
    Chạy bộ dữ liệu mẫu kinh điển từ Wikipedia để kiểm chứng tính toán số học.
    Khóa Wikipedia:
      w = [2, 7, 11, 21, 42, 89, 180, 354]
      q = 881, r = 588  --> r_inv = 442
      beta = [295, 592, 301, 14, 28, 353, 120, 236]
    """
    print("\n" + "═" * 60)
    print("  DEMO KIỂM CHỨNG THEO VÍ DỤ CHUẨN WIKIPEDIA")
    print("═" * 60)

    w = [2, 7, 11, 21, 42, 89, 180, 354]
    q = 881
    r = 588

    # Tính r_inv và beta
    r_inv = mod_inverse(r, q)
    beta = [(r * wi) % q for wi in w]

    print(f"1. Dãy siêu tăng bí mật w = {w}")
    print(f"2. Modulus bí mật q       = {q}")
    print(f"3. Hệ số nhân bí mật r    = {r}")
    print(f"4. Nghịch đảo r⁻¹ mod q   = {r_inv} (Wikipedia: 442)")
    print(f"5. Khóa công khai β       = {beta}")
    print(f"   (Đối chiếu Wikipedia   : [295, 592, 301, 14, 28, 353, 120, 236])")

    # Bản rõ: Ký tự 'a' (ASCII 97 = 01100001)
    message_bits = [0, 1, 1, 0, 0, 0, 0, 1]
    char_val = chr(int("".join(map(str, message_bits)), 2))
    print(f"\n[MÃ HÓA] Bản rõ nhị phân = {message_bits}  --> Ký tự: '{char_val}'")

    # Mã hóa: c = Σ (b_i * beta_i)
    cipher = sum(m * b for m, b in zip(message_bits, beta))
    print(f"--> Ciphertext thu được   = {cipher}  (Wikipedia chuẩn: 1129)")

    # Giải mã bước 1: c' = (c * r_inv) mod q
    c_prime = (cipher * r_inv) % q
    print(f"\n[GIẢI MÃ] Bước 1: c' = ({cipher} × {r_inv}) mod {q} = {c_prime}  (Wikipedia: 372)")

    # Giải mã bước 2: Thuật toán tham lam
    recovered_bits = [0] * 8
    remaining = c_prime
    print("   Bước 2: Thuật toán tham lam trên dãy w:")
    for i in range(7, -1, -1):
        if w[i] <= remaining:
            recovered_bits[i] = 1
            remaining -= w[i]
            print(f"     - w[{i}] = {w[i]:3d} <= {remaining + w[i]:3d} --> CHỌN (bit = 1), còn lại {remaining}")
        else:
            print(f"     - w[{i}] = {w[i]:3d} >  {remaining:3d} --> BỎ   (bit = 0)")

    print(f"--> Bản rõ khôi phục được = {recovered_bits}")
    print(f"--> Kết quả đối chiếu     : {'✓ THÀNH CÔNG (Khớp 100%)' if recovered_bits == message_bits else '✗ THẤT BẠI'}")


# ============================================================
# PHẦN 4: GIAO DIỆN DÒNG LỆNH (CONSOLE / TERMINAL)
# ============================================================

def print_banner():
    banner = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          HỆ MẬT MERKLE – HELLMAN (KNAPSACK)                  ║
║              Ứng dụng thử nghiệm giáo dục                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_menu():
    menu = """
┌────────────────── MENU CHÍNH ──────────────────┐
│  1. Sinh khóa mới (random)                     │
│  2. Xem thông tin khóa hiện tại                │
│  3. Mã hóa văn bản                             │
│  4. Giải mã ciphertext                         │
│  5. Demo ví dụ Wikipedia (kiểm chứng)          │
│  6. Mã hóa / Giải mã một khối bit tùy chỉnh    │
│  0. Thoát                                      │
└────────────────────────────────────────────────┘
"""
    print(menu)


def main():
    print_banner()

    # Khởi tạo mặc định khóa 8 bit
    mh = MerkleHellman(n=8)
    print("Đã sinh khóa mặc định với n = 8 bit.")
    print(mh.summary())

    last_cipher: List[int] = []

    while True:
        print_menu()
        choice = input("Chọn chức năng (0-6): ").strip()

        if choice == "0":
            print("\nTạm biệt! Cảm ơn bạn đã sử dụng ứng dụng.")
            break

        elif choice == "1":
            try:
                n = int(input("Nhập độ dài khóa n (khuyến nghị 8–16 bit): ").strip() or "8")
                if n < 4 or n > 64:
                    print("n nên nằm trong khoảng 4–64.")
                    continue
                seed_input = input("Nhập seed (Enter để ngẫu nhiên): ").strip()
                seed = int(seed_input) if seed_input else None
                mh = MerkleHellman(n=n, seed=seed)
                last_cipher = []
                print("\n✓ Đã sinh khóa mới thành công!")
                print(mh.summary())
            except ValueError as e:
                print(f"Lỗi: {e}")

        elif choice == "2":
            print(mh.summary())

        elif choice == "3":
            text = input("Nhập văn bản cần mã hóa: ").strip()
            if not text:
                print("Văn bản trống.")
                continue
            try:
                cipher_list = mh.encrypt_text(text)
                last_cipher = cipher_list
                print("\n─── KẾT QUẢ MÃ HÓA ───")
                print(f"Bản rõ        : {text}")
                print(f"Số khối (byte): {len(cipher_list)}")
                print(f"Ciphertext   : {cipher_list}")
                print("(Đã lưu ciphertext để có thể dùng ngay cho chức năng 4)")
            except Exception as e:
                print(f"Lỗi mã hóa: {e}")

        elif choice == "4":
            if not last_cipher:
                raw = input("Nhập danh sách ciphertext (cách nhau bởi dấu phẩy): ").strip()
                try:
                    cipher_list = [int(x.strip()) for x in raw.split(",") if x.strip()]
                except ValueError:
                    print("Định dạng không hợp lệ.")
                    continue
            else:
                use_last = input(f"Dùng ciphertext vừa mã hóa ({last_cipher})? (Y/n): ").strip().lower()
                if use_last in ("", "y", "yes"):
                    cipher_list = last_cipher
                else:
                    raw = input("Nhập danh sách ciphertext (cách nhau bởi dấu phẩy): ").strip()
                    try:
                        cipher_list = [int(x.strip()) for x in raw.split(",") if x.strip()]
                    except ValueError:
                        print("Định dạng không hợp lệ.")
                        continue

            try:
                plain = mh.decrypt_text(cipher_list)
                print("\n─── KẾT QUẢ GIẢI MÃ ───")
                print(f"Ciphertext   : {cipher_list}")
                print(f"Bản rõ       : {plain}")
            except Exception as e:
                print(f"Lỗi giải mã: {e}")

        elif choice == "5":
            demo_wikipedia()

        elif choice == "6":
            print(f"\nNhập đúng {mh.n} bit (0 hoặc 1), ví dụ: 0 1 1 0 0 0 0 1")
            raw = input("Bits: ").strip()
            try:
                bits = [int(x) for x in raw.replace(",", " ").split()]
                if len(bits) != mh.n:
                    print(f"Cần đúng {mh.n} bit, bạn nhập {len(bits)} bit.")
                    continue
                cipher = mh.encrypt(bits)
                recovered = mh.decrypt(cipher)
                print(f"\nBản rõ gốc   : {bits}")
                print(f"Ciphertext   : {cipher}")
                print(f"Giải mã được : {recovered}")
                print(f"Kết quả      : {'✓ Thành công' if recovered == bits else '✗ Thất bại'}")
            except Exception as e:
                print(f"Lỗi: {e}")

        else:
            print("Lựa chọn không hợp lệ. Vui lòng chọn lại.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ứng dụng thử nghiệm Hệ mật Merkle – Hellman (Knapsack Cryptosystem)
-----------------------------------------------------------------
Hệ mật khóa công khai dựa trên bài toán Subset Sum (NP-complete).
Khóa riêng: dãy siêu tăng (superincreasing sequence).
Khóa công khai: biến đổi modulo của dãy siêu tăng.

Tác giả: Ứng dụng demo giáo dục
"""

import math
import random
import textwrap
from typing import List, Tuple, Optional


# ============================================================
# CÁC HÀM HỖ TRỢ TOÁN HỌC
# ============================================================

def gcd(a: int, b: int) -> int:
    """Ước chung lớn nhất (Euclid)."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Thuật toán Euclid mở rộng.
    Trả về (g, x, y) sao cho a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inverse(a: int, m: int) -> int:
    """Tìm nghịch đảo modulo của a theo modulo m (a * inv ≡ 1 mod m)."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Không tồn tại nghịch đảo modulo vì gcd({a}, {m}) = {g} ≠ 1")
    return x % m


def is_superincreasing(seq: List[int]) -> bool:
    """Kiểm tra dãy có phải siêu tăng không: mỗi phần tử > tổng các phần tử trước nó."""
    total = 0
    for x in seq:
        if x <= total:
            return False
        total += x
    return True


# ============================================================
# LỚP CHÍNH: MERKLE-HELLMAN CRYPTOSYSTEM
# ============================================================

class MerkleHellman:
    """
    Hệ mật Merkle-Hellman.

    Khóa riêng (private key):
        - w : dãy siêu tăng (superincreasing sequence)
        - q : modulus (q > tổng của w)
        - r : hệ số nhân (gcd(r, q) = 1)

    Khóa công khai (public key):
        - beta = (r * w_i) mod q   (i = 1..n)
    """

    def __init__(self, n: int = 8, seed: Optional[int] = None):
        """
        n     : độ dài khóa (số bit / số phần tử của dãy).
        seed  : hạt giống ngẫu nhiên (để tái tạo kết quả).
        """
        if n < 4:
            raise ValueError("Độ dài khóa n phải ≥ 4")
        self.n = n
        if seed is not None:
            random.seed(seed)

        self.w: List[int] = []          # dãy siêu tăng (private)
        self.q: int = 0                 # modulus
        self.r: int = 0                 # multiplier
        self.r_inv: int = 0             # r^{-1} mod q
        self.beta: List[int] = []       # khóa công khai

        self._generate_keys()

    # ----------------------------------------------------------
    # Sinh khóa
    # ----------------------------------------------------------
    def _generate_superincreasing(self, n: int) -> List[int]:
        """Sinh dãy siêu tăng ngẫu nhiên có n phần tử."""
        seq = []
        total = 0
        # Phần tử đầu tiên nhỏ
        current = random.randint(2, 10)
        for _ in range(n):
            # Mỗi phần tử tiếp theo lớn hơn tổng trước đó
            current = total + random.randint(1, max(3, total // 2 + 1))
            seq.append(current)
            total += current
        return seq

    def _generate_keys(self):
        """Sinh khóa riêng và khóa công khai."""
        # 1. Dãy siêu tăng
        self.w = self._generate_superincreasing(self.n)

        # 2. Modulus q > tổng dãy
        s = sum(self.w)
        self.q = s + random.randint(s // 2 + 1, s * 2)

        # 3. Hệ số nhân r (nguyên tố cùng nhau với q)
        while True:
            self.r = random.randint(2, self.q - 1)
            if gcd(self.r, self.q) == 1:
                break

        # 4. Nghịch đảo của r
        self.r_inv = mod_inverse(self.r, self.q)

        # 5. Khóa công khai beta_i = (r * w_i) mod q
        self.beta = [(self.r * wi) % self.q for wi in self.w]

    # ----------------------------------------------------------
    # Mã hóa / Giải mã
    # ----------------------------------------------------------
    def encrypt(self, plaintext_bits: List[int]) -> int:
        """
        Mã hóa một khối bit (độ dài = n).
        plaintext_bits: list[0/1] có đúng n phần tử.
        Trả về ciphertext (số nguyên).
        """
        if len(plaintext_bits) != self.n:
            raise ValueError(f"Độ dài bản rõ phải đúng {self.n} bit")
        if any(b not in (0, 1) for b in plaintext_bits):
            raise ValueError("Bản rõ chỉ được chứa 0 và 1")

        return sum(b * beta for b, beta in zip(plaintext_bits, self.beta))

    def decrypt(self, ciphertext: int) -> List[int]:
        """
        Giải mã ciphertext về dãy bit.
        """
        # Biến đổi về bài toán siêu tăng
        c_prime = (ciphertext * self.r_inv) % self.q

        # Giải bài toán subset-sum trên dãy siêu tăng (greedy)
        bits = [0] * self.n
        remaining = c_prime
        for i in range(self.n - 1, -1, -1):
            if self.w[i] <= remaining:
                bits[i] = 1
                remaining -= self.w[i]

        if remaining != 0:
            raise ValueError("Giải mã thất bại: không tìm được subset (có thể ciphertext bị lỗi)")

        return bits

    # ----------------------------------------------------------
    # Xử lý văn bản (ASCII & UTF-8)
    # ----------------------------------------------------------
    def text_to_bits(self, text: str) -> List[List[int]]:
        """
        Chuyển chuỗi thành các khối bit độ dài n.
        Mỗi byte (ASCII hoặc UTF-8) → 8 bit, sau đó chia thành khối n bit (padding 0 nếu cần).
        """
        raw_bytes = text.encode("utf-8")
        bit_string = "".join(f"{b:08b}" for b in raw_bytes)

        # Chia thành các khối n bit
        blocks = []
        for i in range(0, len(bit_string), self.n):
            block = bit_string[i:i + self.n]
            # Padding 0 ở cuối nếu thiếu
            if len(block) < self.n:
                block = block.ljust(self.n, "0")
            blocks.append([int(b) for b in block])
        return blocks

    def bits_to_text(self, blocks: List[List[int]]) -> str:
        """
        Ghép các khối bit thành chuỗi ký tự (giải mã UTF-8 / ASCII).
        """
        bit_string = "".join("".join(str(b) for b in block) for block in blocks)

        # Cắt thành từng nhóm 8 bit
        raw_bytes = bytearray()
        for i in range(0, len(bit_string), 8):
            byte = bit_string[i:i + 8]
            if len(byte) < 8:
                break
            val = int(byte, 2)
            if val == 0:          # padding hoặc kết thúc
                continue
            raw_bytes.append(val)
        return raw_bytes.decode("utf-8", errors="replace")

    def encrypt_text(self, text: str) -> List[int]:
        """Mã hóa toàn bộ chuỗi văn bản → danh sách ciphertext."""
        blocks = self.text_to_bits(text)
        return [self.encrypt(block) for block in blocks]

    def decrypt_text(self, cipher_list: List[int]) -> str:
        """Giải mã danh sách ciphertext → chuỗi văn bản."""
        blocks = [self.decrypt(c) for c in cipher_list]
        return self.bits_to_text(blocks)

    # ----------------------------------------------------------
    # Thông tin khóa
    # ----------------------------------------------------------
    def public_key(self) -> List[int]:
        return self.beta.copy()

    def private_key(self) -> dict:
        return {
            "w": self.w.copy(),
            "q": self.q,
            "r": self.r,
            "r_inv": self.r_inv
        }

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  THÔNG TIN KHÓA HỆ MẬT MERKLE – HELLMAN",
            "=" * 60,
            f"Độ dài khóa (n)          : {self.n}",
            f"Dãy siêu tăng (w)        : {self.w}",
            f"Modulus (q)              : {self.q}",
            f"Hệ số nhân (r)           : {self.r}",
            f"Nghịch đảo r⁻¹ mod q     : {self.r_inv}",
            f"Khóa công khai (β)       : {self.beta}",
            f"Tổng dãy siêu tăng      : {sum(self.w)}",
            f"Kiểm tra siêu tăng      : {'✓ Đúng' if is_superincreasing(self.w) else '✗ Sai'}",
            "=" * 60,
        ]
        return "\n".join(lines)


# ============================================================
# DEMO CỐ ĐỊNH (theo ví dụ Wikipedia)
# ============================================================

def demo_wikipedia():
    """Chạy ví dụ kinh điển từ Wikipedia để kiểm chứng thuật toán."""
    print("\n" + "═" * 60)
    print("  DEMO THEO VÍ DỤ WIKIPEDIA")
    print("═" * 60)

    # Khóa riêng cố định từ Wikipedia
    # W = {2, 7, 11, 21, 42, 89, 180, 354}, q = 881, r = 588
    w = [2, 7, 11, 21, 42, 89, 180, 354]
    q = 881
    r = 588

    r_inv = mod_inverse(r, q)
    beta = [(r * wi) % q for wi in w]

    print(f"Dãy siêu tăng w  = {w}")
    print(f"Modulus q        = {q}")
    print(f"Multiplier r     = {r}")
    print(f"r⁻¹ mod q        = {r_inv}")
    print(f"Khóa công khai β = {beta}")
    print(f"(Wikipedia: β = [295, 592, 301, 14, 28, 353, 120, 236])")

    # Bản rõ 8 bit: 01100001  (ký tự 'a' = 97)
    message = [0, 1, 1, 0, 0, 0, 0, 1]
    print(f"\nBản rõ (bits)    = {message}  →  '{chr(int(''.join(map(str, message)), 2))}'")

    # Mã hóa
    cipher = sum(m * b for m, b in zip(message, beta))
    print(f"Ciphertext       = {cipher}  (Wikipedia: 1129)")

    # Giải mã
    c_prime = (cipher * r_inv) % q
    print(f"c' = c·r⁻¹ mod q = {c_prime}  (Wikipedia: 372)")

    # Greedy
    bits = [0] * 8
    remaining = c_prime
    for i in range(7, -1, -1):
        if w[i] <= remaining:
            bits[i] = 1
            remaining -= w[i]
    print(f"Bản rõ giải được = {bits}")
    print(f"Khớp với gốc?    : {'✓ Thành công' if bits == message else '✗ Thất bại'}")


# ============================================================
# GIAO DIỆN CONSOLE
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

    # Khởi tạo hệ thống mặc định n = 8
    mh = MerkleHellman(n=8)
    print("Đã sinh khóa mặc định với n = 8.")
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
                n = int(input("Nhập độ dài khóa n (khuyến nghị 8–16): ").strip() or "8")
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
                print(f"Số khối      : {len(cipher_list)}")
                print(f"Ciphertext   : {cipher_list}")
                print("(Đã lưu ciphertext để dùng cho chức năng 4)")
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

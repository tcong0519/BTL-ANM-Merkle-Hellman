/**
 * THƯ VIỆN MẬT MÃ MERKLE - HELLMAN PHÍA TRÌNH DUYỆT (CLIENT-SIDE)
 * =============================================================
 * Môn học: An toàn Thông tin & An ninh Mạng (BTL_ANM)
 * Chức năng:
 *   - Thực hiện sinh cặp khóa, mã hóa và giải mã trực tiếp trên trình duyệt của Alice & Bob.
 *   - Sử dụng kiểu dữ liệu BigInt của JavaScript để đảm bảo độ chính xác số học tuyệt đối,
 *     tránh hiện tượng tràn số khi thực hiện phép tính với các số nguyên lớn.
 *   - Tạo ra dữ liệu theo dõi chi tiết (Mathematical Trace) phục vụ việc trực quan hóa
 *     từng bước tính toán trên giao diện người dùng.
 */

const MerkleHellmanCrypto = (function () {

    // ============================================================
    // PHẦN 1: CÁC THUẬT TOÁN TOÁN HỌC NỀN TẢNG (BIGINT)
    // ============================================================

    /**
     * Thuật toán Euclid tìm Ước chung lớn nhất (GCD) giữa 2 số BigInt.
     * Dùng để kiểm tra điều kiện nguyên tố cùng nhau: gcd(r, q) === 1.
     */
    function gcd(a, b) {
        let x = BigInt(a);
        let y = BigInt(b);
        while (y !== 0n) {
            let t = y;
            y = x % y;
            x = t;
        }
        return x;
    }

    /**
     * Thuật toán Euclid mở rộng (Extended Euclidean Algorithm).
     * Tìm nghiệm nguyên (x, y) cho phương trình: a*x + b*y = gcd(a, b).
     * Trả về object: { g: gcd, x: BigInt, y: BigInt }
     */
    function extendedGCD(a, b) {
        let aVal = BigInt(a);
        let bVal = BigInt(b);
        if (aVal === 0n) {
            return { g: bVal, x: 0n, y: 1n };
        }
        let { g, x: x1, y: y1 } = extendedGCD(bVal % aVal, aVal);
        let x = y1 - (bVal / aVal) * x1;
        let y = x1;
        return { g, x, y };
    }

    /**
     * Thuật toán tìm Nghịch đảo Modulo: Tìm x sao cho (a * x) ≡ 1 (mod m).
     * Sử dụng thuật toán Euclid mở rộng.
     * Ném ra lỗi nếu gcd(a, m) !== 1 (không tồn tại nghịch đảo).
     */
    function modInverse(a, m) {
        let aVal = BigInt(a);
        let mVal = BigInt(m);
        // Đưa về khoảng dương
        let aMod = ((aVal % mVal) + mVal) % mVal;
        let { g, x } = extendedGCD(aMod, mVal);
        if (g !== 1n) {
            throw new Error(`Không tồn tại nghịch đảo modulo vì gcd(${a}, ${m}) = ${g} ≠ 1`);
        }
        return ((x % mVal) + mVal) % mVal;
    }

    /**
     * Kiểm tra dãy số có thỏa mãn tính chất siêu tăng (superincreasing) hay không.
     * Điều kiện: Mỗi phần tử phải lớn hơn tổng của tất cả các phần tử trước nó:
     *   w[k] > sum(w[0] ... w[k-1]) với mọi k >= 1.
     */
    function isSuperincreasing(seq) {
        let total = 0n;
        for (let item of seq) {
            let val = BigInt(item);
            if (val <= total) return false;
            total += val;
        }
        return true;
    }

    /**
     * Sinh ngẫu nhiên dãy siêu tăng bí mật w gồm n phần tử.
     * Quy tắc: Mỗi phần tử = tổng trước đó + một số ngẫu nhiên dương.
     */
    function generateSuperincreasing(n = 8) {
        let seq = [];
        let total = 0n;
        // Phần tử đầu tiên ngẫu nhiên nhỏ từ 2 đến 9
        let current = BigInt(Math.floor(Math.random() * 8) + 2);
        for (let i = 0; i < n; i++) {
            let randInc = BigInt(Math.floor(Math.random() * Math.max(3, Number(total / 2n) + 1)) + 1);
            current = total + randInc;
            seq.push(current);
            total += current;
        }
        return seq;
    }

    // ============================================================
    // PHẦN 2: QUY TRÌNH SINH CẶP KHÓA (KEY GENERATION - 5 BƯỚC)
    // ============================================================

    /**
     * Sinh cặp khóa Merkle-Hellman ngẫu nhiên hoàn chỉnh.
     * 
     * Bước 1: Sinh dãy siêu tăng bí mật w gồm n phần tử.
     * Bước 2: Chọn modulus q > tổng dãy w.
     * Bước 3: Chọn hệ số nhân r sao cho gcd(r, q) = 1.
     * Bước 4: Tính nghịch đảo r_inv = r⁻¹ mod q bằng Euclid mở rộng.
     * Bước 5: Tính Khóa công khai beta = (r * w_i) mod q.
     */
    function generateKeyPair(n = 8) {
        // Bước 1: Dãy siêu tăng bí mật (Private Key component)
        let w = generateSuperincreasing(n);

        // Bước 2: Modulus q bí mật (q > sum(w))
        let sumW = w.reduce((acc, v) => acc + v, 0n);
        let qAdd = BigInt(Math.floor(Math.random() * Number(sumW)) + Number(sumW / 2n) + 1);
        let q = sumW + qAdd;

        // Bước 3: Hệ số nhân r bí mật thỏa mãn gcd(r, q) = 1
        let r = 0n;
        while (true) {
            let cand = BigInt(Math.floor(Math.random() * Number(q - 3n)) + 2);
            if (gcd(cand, q) === 1n) {
                r = cand;
                break;
            }
        }

        // Bước 4: Tính nghịch đảo r⁻¹ mod q
        let r_inv = modInverse(r, q);

        // Bước 5: Tạo Khóa công khai beta_i = (r * w_i) mod q (Public Key)
        let beta = w.map(wi => (r * wi) % q);

        return {
            privateKey: {
                w: w.map(x => Number(x)),
                q: Number(q),
                r: Number(r),
                r_inv: Number(r_inv),
                n: n,
                sum_w: Number(sumW)
            },
            publicKey: beta.map(x => Number(x)),
            n: n
        };
    }

    /**
     * Bộ khóa chuẩn từ Wikipedia (dùng để đối chiếu số liệu mẫu khi thuyết trình).
     * w = [2, 7, 11, 21, 42, 89, 180, 354], q = 881, r = 588, r_inv = 442
     * beta = [295, 592, 301, 14, 28, 353, 120, 236]
     */
    function getWikipediaKeys() {
        let w = [2, 7, 11, 21, 42, 89, 180, 354];
        let q = 881;
        let r = 588;
        let r_inv = Number(modInverse(r, q)); // 442
        let beta = w.map(wi => Number((BigInt(r) * BigInt(wi)) % BigInt(q)));

        return {
            privateKey: {
                w: w,
                q: q,
                r: r,
                r_inv: r_inv,
                n: 8,
                sum_w: w.reduce((a, b) => a + b, 0)
            },
            publicKey: beta,
            n: 8
        };
    }

    // ============================================================
    // PHẦN 3: XỬ LÝ CHUYỂN ĐỔI BIT & KÝ TỰ
    // ============================================================

    /**
     * Chuyển chuỗi văn bản thành danh sách byte UTF-8
     */
    function textToBytes(text) {
        return Array.from(new TextEncoder().encode(text));
    }

    /**
     * Chuyển danh sách byte UTF-8 thành chuỗi văn bản
     */
    function bytesToText(bytes) {
        return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
    }

    /**
     * Chuyển một byte số nguyên (0..255) thành mảng 8 bit [b0, b1, ..., b7] (MSB -> LSB)
     */
    function byteToBits(b) {
        let bits = [];
        for (let i = 7; i >= 0; i--) {
            bits.push((b >> i) & 1);
        }
        return bits;
    }

    /**
     * Chuyển mảng 8 bit [b0, b1, ..., b7] trở lại thành giá trị byte (0..255)
     */
    function bitsToByte(bits) {
        let val = 0;
        for (let i = 0; i < 8; i++) {
            val = (val << 1) | (bits[i] || 0);
        }
        return val;
    }

    // ============================================================
    // PHẦN 4: THUẬT TOÁN MÃ HÓA (ENCRYPTION TẠI CLIENT)
    // ============================================================

    /**
     * Mã hóa văn bản sử dụng Khóa công khai beta của người nhận.
     * 
     * Quy trình từng bước:
     *   Bước 1: Chuyển chuỗi văn bản thành các byte UTF-8 / ASCII.
     *   Bước 2: Chuyển mỗi byte thành mảng 8 bit [b0, b1, ..., b7].
     *   Bước 3: Với mỗi khối 8 bit, tính tổng tích vô hướng:
     *           c = sum(b_i * beta_i) với i từ 0 đến 7.
     *   Bước 4: Lưu vết chi tiết (trace) phục vụ bảng soi bước toán học trên giao diện.
     * 
     * Trả về: { ciphertext: [c1, c2, ...], steps: [thông tin chi tiết từng bước] }
     */
    function encrypt(text, beta) {
        if (!beta || !beta.length) {
            throw new Error("Khóa công khai (β) chưa được cung cấp!");
        }
        let bytes = textToBytes(text);
        let ciphertext = [];
        let steps = [];

        // Duyệt qua từng byte của văn bản
        for (let idx = 0; idx < bytes.length; idx++) {
            let b = bytes[idx];
            let bits = byteToBits(b); // 8 bit nhị phân
            let sum = 0n;
            let bitCalculations = [];

            // Tính tích vô hướng: c = Σ (b_i * beta_i)
            for (let i = 0; i < 8; i++) {
                let bitVal = bits[i];
                let betaVal = BigInt(beta[i] || 0);
                let prod = BigInt(bitVal) * betaVal;
                sum += prod;

                bitCalculations.push({
                    bitIndex: i,
                    bit: bitVal,
                    beta: Number(betaVal),
                    product: Number(prod)
                });
            }

            let cipherVal = Number(sum);
            ciphertext.push(cipherVal);

            // Ký tự hiển thị (định dạng ký tự ASCII in được hoặc mã hex)
            let charRepr = (b >= 32 && b <= 126) ? String.fromCharCode(b) : `0x${b.toString(16).toUpperCase()}`;

            // Lưu vết chi tiết từng phép toán phục vụ Modal visualizer
            steps.push({
                byteIndex: idx,
                char: charRepr,
                byteVal: b,
                bits: bits,
                bitsStr: bits.join(""),
                bitCalculations: bitCalculations,
                formula: bitCalculations.map(c => `${c.bit}×${c.beta}`).join(" + "),
                ciphertext: cipherVal
            });
        }

        return {
            ciphertext: ciphertext,
            steps: steps
        };
    }

    // ============================================================
    // PHẦN 5: THUẬT TOÁN GIẢI MÃ (DECRYPTION TẠI CLIENT)
    // ============================================================

    /**
     * Giải mã danh sách ciphertext bằng Khóa riêng bí mật (w, q, r_inv).
     * 
     * Quy trình từng bước:
     *   Bước 1: Áp dụng 'Cửa sập' Trapdoor: Tính c' = (c * r_inv) mod q.
     *           Phép nhân này biến bài toán Knapsack tổng quát thành bài toán Knapsack
     *           trên dãy siêu tăng w: c' = sum(b_i * w_i).
     *   Bước 2: Áp dụng Thuật toán Tham lam (Greedy Knapsack):
     *           Duyệt từ phần tử lớn nhất w[7] lùi về w[0]:
     *           - Nếu w[i] <= remaining: Đặt bit b[i] = 1, trừ remaining đi w[i].
     *           - Ngược lại: Đặt bit b[i] = 0.
     *   Bước 3: Kiểm tra nếu remaining !== 0 thì phát hiện dữ liệu bị hỏng hoặc bị sửa đổi.
     *   Bước 4: Ghép 8 bit thành mã byte và giải mã trở lại thành ký tự ban đầu.
     */
    function decrypt(ciphertext, privateKey) {
        let { w, q, r_inv } = privateKey;
        if (!w || !q || !r_inv) {
            throw new Error("Khóa riêng không đầy đủ (cần có w, q, r_inv)!");
        }

        let qBig = BigInt(q);
        let rInvBig = BigInt(r_inv);
        let wBig = w.map(x => BigInt(x));

        let recoveredBytes = [];
        let steps = [];

        // Duyệt qua từng số nguyên lớn trong ciphertext
        for (let idx = 0; idx < ciphertext.length; idx++) {
            let c = BigInt(ciphertext[idx]);

            // Bước 1: Biến đổi về bài toán siêu tăng c' = (c * r_inv) mod q
            let c_prime = (c * rInvBig) % qBig;

            // Bước 2: Thuật toán tham lam giải bài toán dãy siêu tăng (Greedy Knapsack)
            let bits = new Array(w.length).fill(0);
            let remaining = c_prime;
            let knapsackTrace = [];

            for (let i = w.length - 1; i >= 0; i--) {
                let wi = wBig[i];
                let remBefore = remaining;
                let taken = false;

                if (wi <= remaining) {
                    bits[i] = 1;
                    remaining -= wi;
                    taken = true;
                }

                // Ghi lại từng quyết định chọn/bỏ để hiển thị lên bảng giải thích
                knapsackTrace.push({
                    index: i,
                    weight: Number(wi),
                    remainingBefore: Number(remBefore),
                    taken: taken,
                    remainingAfter: Number(remaining)
                });
            }

            // Bước 3: Kiểm tra tính toàn vẹn dữ liệu
            if (remaining !== 0n) {
                throw new Error(`Giải mã lỗi ở khối ${idx}: Cipher ${c} không giải được về dãy siêu tăng w (dữ liệu có thể bị lỗi hoặc sai khóa).`);
            }

            // Bước 4: Chuyển 8 bit thành byte
            let byteVal = bitsToByte(bits);
            recoveredBytes.push(byteVal);

            let charRepr = (byteVal >= 32 && byteVal <= 126) ? String.fromCharCode(byteVal) : `0x${byteVal.toString(16).toUpperCase()}`;

            steps.push({
                blockIndex: idx,
                ciphertext: Number(c),
                c_prime: Number(c_prime),
                formula: `(${c} × ${r_inv}) mod ${q} = ${c_prime}`,
                knapsackTrace: knapsackTrace,
                recoveredBits: bits,
                bitsStr: bits.join(""),
                byteVal: byteVal,
                char: charRepr
            });
        }

        // Tái tạo lại chuỗi văn bản hoàn chỉnh
        let plaintext = bytesToText(recoveredBytes);

        return {
            plaintext: plaintext,
            bytes: recoveredBytes,
            steps: steps
        };
    }

    // Xuất các phương thức công khai
    return {
        gcd,
        extendedGCD,
        modInverse,
        isSuperincreasing,
        generateSuperincreasing,
        generateKeyPair,
        getWikipediaKeys,
        textToBytes,
        bytesToText,
        byteToBits,
        bitsToByte,
        encrypt,
        decrypt
    };
})();

// Xuất cho môi trường Node hoặc trình duyệt
if (typeof module !== "undefined" && module.exports) {
    module.exports = MerkleHellmanCrypto;
}

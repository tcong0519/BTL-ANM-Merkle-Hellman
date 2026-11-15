/**
 * Thư viện Mật mã Merkle-Hellman (Knapsack Cryptosystem) dành cho Web Client
 * Sử dụng BigInt để đảm bảo độ chính xác số học tuyệt đối.
 */

const MerkleHellmanCrypto = (function () {
    /**
     * Ước chung lớn nhất (Euclid)
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
     * Thuật toán Euclid mở rộng: a*x + b*y = gcd(a, b)
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
     * Tìm nghịch đảo modulo: a * inv ≡ 1 (mod m)
     */
    function modInverse(a, m) {
        let aVal = BigInt(a);
        let mVal = BigInt(m);
        let aMod = ((aVal % mVal) + mVal) % mVal;
        let { g, x } = extendedGCD(aMod, mVal);
        if (g !== 1n) {
            throw new Error(`Không tồn tại nghịch đảo modulo vì gcd(${a}, ${m}) = ${g} ≠ 1`);
        }
        return ((x % mVal) + mVal) % mVal;
    }

    /**
     * Kiểm tra dãy có siêu tăng hay không (mỗi số > tổng các số trước nó)
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
     * Sinh dãy siêu tăng ngẫu nhiên độ dài n
     */
    function generateSuperincreasing(n = 8) {
        let seq = [];
        let total = 0n;
        let current = BigInt(Math.floor(Math.random() * 8) + 2); // 2..9
        for (let i = 0; i < n; i++) {
            let randInc = BigInt(Math.floor(Math.random() * Math.max(3, Number(total / 2n) + 1)) + 1);
            current = total + randInc;
            seq.push(current);
            total += current;
        }
        return seq;
    }

    /**
     * Sinh cặp khóa Merkle-Hellman ngẫu nhiên
     */
    function generateKeyPair(n = 8) {
        // 1. Dãy siêu tăng w (private)
        let w = generateSuperincreasing(n);

        // 2. Modulus q > sum(w)
        let sumW = w.reduce((acc, v) => acc + v, 0n);
        let qAdd = BigInt(Math.floor(Math.random() * Number(sumW)) + Number(sumW / 2n) + 1);
        let q = sumW + qAdd;

        // 3. Hệ số nhân r nguyên tố cùng nhau với q
        let r = 0n;
        while (true) {
            let cand = BigInt(Math.floor(Math.random() * Number(q - 3n)) + 2);
            if (gcd(cand, q) === 1n) {
                r = cand;
                break;
            }
        }

        // 4. Nghịch đảo của r theo modulo q
        let r_inv = modInverse(r, q);

        // 5. Khóa công khai beta = (r * w_i) mod q
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
     * Khóa kinh điển từ Wikipedia (dùng để đối chiếu/giảng dạy)
     */
    function getWikipediaKeys() {
        let w = [2, 7, 11, 21, 42, 89, 180, 354];
        let q = 881;
        let r = 588;
        let r_inv = Number(modInverse(r, q)); // 442
        let beta = w.map(wi => Number((BigInt(r) * BigInt(wi)) % BigInt(q))); // [295, 592, 301, 14, 28, 353, 120, 236]

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
     * Chuyển 1 byte (0..255) thành mảng 8 bit [b0, b1, ..., b7] (MSB -> LSB)
     */
    function byteToBits(b) {
        let bits = [];
        for (let i = 7; i >= 0; i--) {
            bits.push((b >> i) & 1);
        }
        return bits;
    }

    /**
     * Chuyển mảng 8 bit thành 1 byte số nguyên
     */
    function bitsToByte(bits) {
        let val = 0;
        for (let i = 0; i < 8; i++) {
            val = (val << 1) | (bits[i] || 0);
        }
        return val;
    }

    /**
     * Mã hóa văn bản sử dụng khóa công khai beta
     * Trả về cả ciphertext và mảng chi tiết các bước toán học (trace) để trực quan hóa
     */
    function encrypt(text, beta) {
        if (!beta || !beta.length) {
            throw new Error("Khóa công khai (β) chưa được cung cấp!");
        }
        let bytes = textToBytes(text);
        let ciphertext = [];
        let steps = [];

        for (let idx = 0; idx < bytes.length; idx++) {
            let b = bytes[idx];
            let bits = byteToBits(b);
            let sum = 0n;
            let bitCalculations = [];

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

            // Ký tự hiển thị (nếu ký tự ASCII in được hoặc placeholder)
            let charRepr = (b >= 32 && b <= 126) ? String.fromCharCode(b) : `0x${b.toString(16).toUpperCase()}`;

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

    /**
     * Giải mã danh sách ciphertext bằng khóa bí mật (w, q, r_inv)
     * Trả về chuỗi bản rõ và mảng chi tiết các bước toán học giải bài toán Knapsack
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

        for (let idx = 0; idx < ciphertext.length; idx++) {
            let c = BigInt(ciphertext[idx]);
            // 1. Biến đổi c' = (c * r^-1) mod q
            let c_prime = (c * rInvBig) % qBig;

            // 2. Thuật toán tham lam giải bài toán dãy siêu tăng (Greedy Knapsack)
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

                knapsackTrace.push({
                    index: i,
                    weight: Number(wi),
                    remainingBefore: Number(remBefore),
                    taken: taken,
                    remainingAfter: Number(remaining)
                });
            }

            if (remaining !== 0n) {
                throw new Error(`Giải mã lỗi ở khối ${idx}: Cipher ${c} không giải được về dãy siêu tăng w (dữ liệu có thể bị lỗi hoặc sai khóa).`);
            }

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

        let plaintext = bytesToText(recoveredBytes);

        return {
            plaintext: plaintext,
            bytes: recoveredBytes,
            steps: steps
        };
    }

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


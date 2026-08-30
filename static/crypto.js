// ============================================================
//  密码传输加密 · 客户端 (RSA-OAEP / SHA-256，纯 JS 实现)
// ============================================================
//  为什么不用 WebCrypto：
//    crypto.subtle 只在“安全上下文”（HTTPS 或 localhost）里存在。而本项目最典型
//    的用法就是内网 http://192.168.x.x:5000 —— 那里 crypto.subtle 是 undefined，
//    用它反而会在最需要加密的场景下失效。所以这里自带一份 RSA-OAEP 加密实现。
//    （crypto.getRandomValues 没有安全上下文限制，随机数仍然走浏览器 CSPRNG。）
//
//  流程：
//    1. GET /api/pubkey 取服务端 RSA 公钥 (modulus n / 指数 e) 与服务端当前时间
//    2. 明文包成 {v,f,p,t,n} 的小 JSON：字段名 f 绑定用途、t 防过期、n 防重放
//    3. EME-OAEP(SHA-256) 填充后做 m^e mod n，Base64 后发给服务端
//
//  注意：这只防“被动嗅听到明文密码”。中间人仍可劫持会话 cookie —— 真正的
//  端到端安全依旧要靠 HTTPS，本模块只是在纯 HTTP 内网场景下把密码本身保住。
// ============================================================
window.PwCrypto = (function () {
  "use strict";

  const ENVELOPE_VERSION = 1;
  const HLEN = 32; // SHA-256 输出长度

  // ---------- SHA-256 ----------
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  function sha256(msg) {
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const len = msg.length;
    const buf = new Uint8Array(((((len + 8) >> 6) + 1) * 64));
    buf.set(msg);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(buf.length - 8, Math.floor(len / 536870912)); // (len*8) 高 32 位
    dv.setUint32(buf.length - 4, (len * 8) >>> 0);

    const w = new Uint32Array(64);
    for (let off = 0; off < buf.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15], y = w[i - 2];
        const s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
        const s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0;
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
        const ch = ((e & f) ^ (~e & g)) >>> 0;
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
        const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
    return out;
  }

  // ---------- MGF1 (RFC 8017 B.2.1) ----------
  function mgf1(seed, length) {
    const out = new Uint8Array(length);
    const block = new Uint8Array(seed.length + 4);
    block.set(seed);
    const dv = new DataView(block.buffer, seed.length, 4);
    for (let counter = 0, pos = 0; pos < length; counter++) {
      dv.setUint32(0, counter);
      out.set(sha256(block).subarray(0, Math.min(HLEN, length - pos)), pos);
      pos += HLEN;
    }
    return out;
  }

  // ---------- EME-OAEP 编码 (RFC 8017 7.1.1，空 label) ----------
  function oaepEncode(msg, k) {
    if (msg.length > k - 2 * HLEN - 2) throw new Error("内容过长，无法加密");
    const em = new Uint8Array(k);              // em[0] 保持 0x00
    const seed = em.subarray(1, 1 + HLEN);
    const maskedDb = em.subarray(1 + HLEN);    // 长度 k - HLEN - 1

    const db = new Uint8Array(k - HLEN - 1);
    db.set(sha256(new Uint8Array(0)));         // lHash = SHA-256("")
    db[db.length - msg.length - 1] = 0x01;     // PS 之后的 0x01 分隔符
    db.set(msg, db.length - msg.length);

    crypto.getRandomValues(seed);
    const dbMask = mgf1(seed, db.length);
    for (let i = 0; i < db.length; i++) maskedDb[i] = db[i] ^ dbMask[i];
    const seedMask = mgf1(maskedDb, HLEN);
    for (let i = 0; i < HLEN; i++) seed[i] ^= seedMask[i];
    return em;
  }

  // ---------- 大整数 ----------
  function bytesToBigInt(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
    return hex ? BigInt("0x" + hex) : 0n;
  }

  function bigIntToBytes(v, length) {
    const out = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }

  function modPow(base, exp, mod) {
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  }

  // ---------- Base64 ----------
  function toB64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function fromB64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- 公钥 ----------
  async function fetchKey() {
    if (typeof BigInt !== "function" || !window.crypto || !crypto.getRandomValues) {
      throw new Error("浏览器版本过旧，不支持加密传输");
    }
    const res = await fetch("/api/pubkey", { cache: "no-store" });
    if (!res.ok) throw new Error("无法获取加密公钥，请刷新重试");
    const data = await res.json();
    if (data.alg !== "RSA-OAEP-256") throw new Error("服务端加密方式不受支持");
    const nBytes = fromB64(data.n);
    return { n: bytesToBigInt(nBytes), e: BigInt(data.e), k: nBytes.length, ts: data.ts };
  }

  // 把一个字段封成信封：字段名一并加密，服务端会核对，避免信封被挪作他用
  function seal(key, field, value) {
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const plain = new TextEncoder().encode(JSON.stringify({
      v: ENVELOPE_VERSION, f: field, p: String(value), t: key.ts, n: toB64(nonce),
    }));
    const em = oaepEncode(plain, key.k);
    return toB64(bigIntToBytes(modPow(bytesToBigInt(em), key.e, key.n), key.k));
  }

  /**
   * 加密一组密码字段。
   *   await PwCrypto.encrypt({ login: "明文" })  ->  { login: "<base64 密文>" }
   * 一次取公钥，多个字段共用，减少往返。
   */
  async function encrypt(fields) {
    const key = await fetchKey();
    const out = {};
    for (const name of Object.keys(fields)) out[name] = seal(key, name, fields[name]);
    return out;
  }

  return { encrypt, _sha256: sha256, _oaepEncode: oaepEncode };
})();

// 成绩查询：共用加密逻辑（浏览器与 Node 18+ 通用）
// 思路：仓库里不放任何明文。每个学生的成绩用「姓名+身份证号」派生出的密钥单独加密，
// 只有输入正确的姓名和身份证号才能解开自己那一条。
(function (root) {
  const ITERATIONS = 600000; // PBKDF2 轮数：越大越难暴力破解，单次查询约 0.3~1 秒
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const subtle = (root.crypto || globalThis.crypto).subtle;

  function normName(s) {
    return String(s || '').replace(/[\s　·•.]/g, '').trim();
  }
  function normId(s) {
    return String(s || '').replace(/[\s　-]/g, '').toUpperCase();
  }
  // 18 位身份证校验（只用于提示输错，不参与安全）
  function checkId(id) {
    if (!/^\d{17}[\dX]$/.test(id)) return false;
    const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const c = '10X98765432';
    let sum = 0;
    for (let i = 0; i < 17; i++) sum += Number(id[i]) * w[i];
    return c[sum % 11] === id[17];
  }

  const b64 = {
    enc(buf) {
      const b = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
      return btoa(s);
    },
    dec(str) {
      const s = atob(str);
      const b = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
      return b;
    },
  };
  const hex = (buf) => Array.from(new Uint8Array(buf), (x) => x.toString(16).padStart(2, '0')).join('');

  // 由 姓名+身份证号 派生：前 32 字节作 AES 密钥，后 16 字节作查找编号
  async function derive(name, id, saltB64, iterations) {
    const base = await subtle.importKey('raw', enc.encode(normName(name) + '|' + normId(id)), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64.dec(saltB64), iterations: iterations || ITERATIONS },
      base,
      384
    );
    const key = await subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { key, lookup: hex(bits.slice(32, 48)) };
  }

  async function encryptRecord(name, id, payload, saltB64) {
    const { key, lookup } = await derive(name, id, saltB64);
    const iv = (root.crypto || globalThis.crypto).getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(payload)));
    return [lookup, b64.enc(iv) + '.' + b64.enc(ct)];
  }

  async function lookup(data, name, id) {
    const { key, lookup } = await derive(name, id, data.salt, data.iterations);
    const hit = data.records[lookup];
    if (!hit) return null;
    const [iv, ct] = hit.split('.');
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(iv) }, key, b64.dec(ct));
    return JSON.parse(dec.decode(pt));
  }

  function newSalt() {
    return b64.enc((root.crypto || globalThis.crypto).getRandomValues(new Uint8Array(16)));
  }

  // 6 位随机查询码，去掉易混淆的 0/O/1/I/L，约 8 亿种组合
  function newCode() {
    const A = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    const r = (root.crypto || globalThis.crypto).getRandomValues(new Uint32Array(6));
    return Array.from(r, (x) => A[x % A.length]).join('');
  }

  root.ScoreLib = { ITERATIONS, normName, normId, checkId, encryptRecord, lookup, newSalt, newCode };
})(typeof window !== 'undefined' ? window : globalThis);

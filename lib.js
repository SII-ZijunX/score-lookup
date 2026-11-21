// 成绩查询：共用逻辑（浏览器与 Node 18+ 通用）
// 仓库里不放任何明文。每个学生每张表的成绩，都用「姓名+身份证号（或查询码）」派生出的密钥单独加密，
// 只有输入正确的姓名和凭证才能解开自己的那几条。
// data.json 结构：{ title, keyLabel, salt, iterations, tables: [{ title, records: { 查找编号: 密文 } }] }
(function (root) {
  const ITERATIONS = 600000; // PBKDF2 轮数：越大越难暴力破解，单次查询约 0.3~1 秒
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const cr = root.crypto || globalThis.crypto;
  const subtle = cr.subtle;

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

  // 由 姓名+凭证 派生：前 32 字节作 AES 密钥，后 16 字节作查找编号
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

  // 一次派生密钥，可加密同一学生在多张表里的记录
  async function encryptor(name, id, saltB64) {
    const { key, lookup } = await derive(name, id, saltB64);
    return async (payload) => {
      const iv = cr.getRandomValues(new Uint8Array(12));
      const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(payload)));
      return [lookup, b64.enc(iv) + '.' + b64.enc(ct)];
    };
  }

  // 返回 { name, tables: [{ title, items }] }，一张都没有则返回 null
  async function lookup(data, name, id) {
    const { key, lookup } = await derive(name, id, data.salt, data.iterations);
    const found = [];
    for (const t of data.tables || []) {
      const hit = t.records[lookup];
      if (!hit) continue;
      const [iv, ct] = hit.split('.');
      const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(iv) }, key, b64.dec(ct));
      found.push({ title: t.title, ...JSON.parse(dec.decode(pt)) });
    }
    return found.length ? { name: normName(name), tables: found } : null;
  }

  // 把表格的一行变成要显示的条目
  //   「等第/等地/等级」列 → 挂到前一科的标签上；「班名/级名/排名/名次」列 → 挂到前一科的附注上
  //   「第N大题」→ 分组标题；「满分」行 → 每项的满分
  const TAG = /^(等地|等第|等级)$/;
  const RANK = /班名|级名|排名|名次|排序/;
  function buildItems(head, row, fullRow, keepIdx) {
    const items = [];
    for (const i of keepIdx) {
      const k = String(head[i] ?? '').trim();
      const v = String(row[i] ?? '').trim();
      const last = items[items.length - 1];
      if (TAG.test(k)) { if (last && v) last.tag = v; continue; }
      if (RANK.test(k)) {
        const txt = /^班名$/.test(k) ? `班级第 ${v} 名` : /^级名$/.test(k) ? `年级第 ${v} 名` : `${k} ${v}`;
        if (last && v) (last.extra = last.extra || []).push(txt);
        continue;
      }
      const it = { k, v };
      const f = fullRow ? String(fullRow[i] ?? '').trim() : '';
      if (f) it.full = f;
      if (/大题/.test(k)) it.group = true;
      items.push(it);
    }
    return items;
  }

  function newSalt() {
    return b64.enc(cr.getRandomValues(new Uint8Array(16)));
  }

  // 6 位随机查询码，去掉易混淆的 0/O/1/I/L，约 8 亿种组合
  function newCode() {
    const A = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    const r = cr.getRandomValues(new Uint32Array(6));
    return Array.from(r, (x) => A[x % A.length]).join('');
  }

  root.ScoreLib = { ITERATIONS, TAG, RANK, normName, normId, checkId, encryptor, lookup, buildItems, newSalt, newCode };
})(typeof window !== 'undefined' ? window : globalThis);

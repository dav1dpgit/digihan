// OpenTimestamps proofs: "this seal existed no later than Bitcoin block H".
// Reads and writes the standard .ots format (opentimestamps.org); the proof is over SHA-256 of the seal's
// 78-byte payload. The scanner verifies; the sealing page also stamps (asks the calendars) and upgrades
// (fetches the Bitcoin part). Runs in browsers and in Node 20+ (globalThis.crypto.subtle). See
// docs/TIME-PROOF.md and python/ots.py (the same code in Python; both write byte-identical proofs).
"use strict";

const DHO = (() => {
  const MAGIC = [0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
                 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94];
  const PENDING = "83dfe30d2ef90c8e", BITCOIN = "0588960d73d71901";
  const APPEND = 0xf0, PREPEND = 0xf1, REVERSE = 0xf2, HEXLIFY = 0xf3, SHA1 = 0x02, RIPEMD160 = 0x03,
        SHA256 = 0x08, KECCAK256 = 0x67;
  const MAX_LEN = 4096, MAX_PAYLOAD = 8192, MAX_URI = 1000, MAX_DEPTH = 256;
  const HASH_LEN = { [SHA256]: 32, [SHA1]: 20, [RIPEMD160]: 20, [KECCAK256]: 32 };
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
  const fail = m => { throw new Error(m); };

  function reader(b) {
    let i = 0;
    const bytes = n => { if (i + n > b.length) fail("proof ends early"); const r = b.slice(i, i + n); i += n; return r; };
    const varuint = () => { let v = 0, mul = 1; for (let k = 0; k < 9; k++) { const c = bytes(1)[0]; v += (c & 0x7f) * mul; if (!(c & 0x80)) return v; mul *= 128; } fail("number too long"); };
    const varbytes = (max, min = 0) => { const n = varuint(); if (n > max || n < min) fail("field length out of range"); return bytes(n); };
    return { bytes, varuint, varbytes, pos: () => i };
  }
  const isProof = b => b.length > MAGIC.length && MAGIC.every((x, k) => b[k] === x);

  function readAtt(rd) {
    const tag = hex(rd.bytes(8)), payload = rd.varbytes(MAX_PAYLOAD), p = reader(payload);
    let att;
    if (tag === PENDING) att = { kind: "pending", uri: new TextDecoder().decode(p.varbytes(MAX_URI)) };
    else if (tag === BITCOIN) att = { kind: "bitcoin", height: p.varuint() };
    else return { kind: "other", tag, payload };
    if (p.pos() !== payload.length) fail("attestation has extra bytes");
    return att;
  }
  function readOp(rd, tag) {
    if (tag === APPEND || tag === PREPEND) return { tag, arg: rd.varbytes(MAX_LEN, 1) };
    if ([REVERSE, HEXLIFY, SHA1, RIPEMD160, SHA256, KECCAK256].includes(tag)) return { tag, arg: null };
    fail("unknown operation 0x" + tag.toString(16));
  }
  // Parse the tree first (structure only); messages are worked out afterwards (hashing is async here).
  function readTree(rd, depth) {
    if (depth <= 0) fail("proof is nested too deeply");
    const node = { msg: null, atts: [], ops: [] };
    const one = tag => {
      if (tag === 0x00) { const a = readAtt(rd); if (!node.atts.some(x => cmpAtt(x, a) === 0)) node.atts.push(a); }
      else node.ops.push({ op: readOp(rd, tag), next: readTree(rd, depth - 1) });
    };
    let tag = rd.bytes(1)[0];
    while (tag === 0xff) { one(rd.bytes(1)[0]); tag = rd.bytes(1)[0]; }
    one(tag);
    return node;
  }
  // RIPEMD-160 (older proofs from 2015-2016 use it once; WebCrypto has no RIPEMD-160)
  const RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e], KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  const F = (j, x, y, z) => j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z : j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z);
  function ripemd160(msg) {
    const n = msg.length, padLen = ((n + 8) >> 6 << 6) + 64, m = new Uint8Array(padLen);
    m.set(msg); m[n] = 0x80;
    const bits = n * 8; for (let k = 0; k < 8; k++) m[padLen - 8 + k] = k < 4 ? (bits >>> (8 * k)) & 0xff : Math.floor(bits / 2 ** (8 * k)) & 0xff;
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const X = new Int32Array(16);
    for (let off = 0; off < padLen; off += 64) {
      for (let k = 0; k < 16; k++) X[k] = m[off + 4 * k] | (m[off + 4 * k + 1] << 8) | (m[off + 4 * k + 2] << 16) | (m[off + 4 * k + 3] << 24);
      let a = h0, b = h1, c = h2, d = h3, e = h4, a2 = h0, b2 = h1, c2 = h2, d2 = h3, e2 = h4;
      for (let j = 0; j < 80; j++) {
        let t = (rotl((a + F(j, b, c, d) + X[RL[j]] + KL[j >> 4]) | 0, SL[j]) + e) | 0;
        a = e; e = d; d = rotl(c, 10); c = b; b = t;
        t = (rotl((a2 + F(79 - j, b2, c2, d2) + X[RR[j]] + KR[j >> 4]) | 0, SR[j]) + e2) | 0;
        a2 = e2; e2 = d2; d2 = rotl(c2, 10); c2 = b2; b2 = t;
      }
      const t = (h1 + c + d2) | 0;
      h1 = (h2 + d + e2) | 0; h2 = (h3 + e + a2) | 0; h3 = (h4 + a + b2) | 0; h4 = (h0 + b + c2) | 0; h0 = t;
    }
    const out = new Uint8Array(20);
    [h0, h1, h2, h3, h4].forEach((h, k) => { for (let i = 0; i < 4; i++) out[4 * k + i] = (h >>> (8 * i)) & 0xff; });
    return out;
  }

  async function apply(op, msg) {
    if (msg.length > MAX_LEN) fail("message too long");
    let r;
    switch (op.tag) {
      case APPEND: r = cat(msg, op.arg); break;
      case PREPEND: r = cat(op.arg, msg); break;
      case REVERSE: r = msg.slice().reverse(); break;
      case HEXLIFY: r = new TextEncoder().encode(hex(msg)); break;
      case SHA256: r = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", msg)); break;
      case SHA1: r = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-1", msg)); break;
      case RIPEMD160: r = ripemd160(msg); break;
      default: return null;          // keccak256: Ethereum branches only; such a branch is skipped
    }
    if (r.length > MAX_LEN) fail("result too long");
    return r;
  }
  async function fill(node, msg) {                     // work out every node's message
    node.msg = msg;
    for (const { op, next } of node.ops) await fill(next, msg === null ? null : await apply(op, msg));
    return node;
  }
  function walk(node, out) {
    for (const a of node.atts) out.push({ msg: node.msg, att: a });
    for (const { next } of node.ops) walk(next, out);
    return out;
  }

  // ---- writing: the reference client's order, so a proof read and written back is byte-identical ----
  const enc = new TextEncoder();
  const concat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
  const unhex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
  const varuintB = v => { const out = []; do { const c = v % 128; v = Math.floor(v / 128); out.push(c | (v ? 0x80 : 0)); } while (v); return Uint8Array.from(out); };
  const varbytesB = b => concat(varuintB(b.length), b);
  const cmpBytes = (a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
  const tagOf = a => a.kind === "pending" ? PENDING : a.kind === "bitcoin" ? BITCOIN : a.tag;
  function cmpAtt(a, b) {
    const ta = tagOf(a), tb = tagOf(b);
    if (ta !== tb) return ta < tb ? -1 : 1;
    if (a.kind === "pending") return a.uri < b.uri ? -1 : a.uri > b.uri ? 1 : 0;
    if (a.kind === "bitcoin") return a.height - b.height;
    return cmpBytes(a.payload, b.payload);
  }
  const cmpOp = (a, b) => a.tag !== b.tag ? a.tag - b.tag : cmpBytes(a.arg || new Uint8Array(0), b.arg || new Uint8Array(0));
  function attBytes(a) {
    const payload = a.kind === "pending" ? varbytesB(enc.encode(a.uri)) : a.kind === "bitcoin" ? varuintB(a.height) : a.payload;
    return concat(unhex(tagOf(a)), varbytesB(payload));
  }
  const opBytes = op => (op.tag === APPEND || op.tag === PREPEND) ? concat(Uint8Array.of(op.tag), varbytesB(op.arg)) : Uint8Array.of(op.tag);
  function serialize(node) {
    const atts = [...node.atts].sort(cmpAtt), ops = [...node.ops].sort((x, y) => cmpOp(x.op, y.op)), out = [];
    if (!atts.length && !ops.length) fail("empty timestamp");
    for (const a of atts.slice(0, -1)) out.push(Uint8Array.of(0xff, 0x00), attBytes(a));
    if (!ops.length) { out.push(Uint8Array.of(0x00), attBytes(atts.at(-1))); return concat(...out); }
    if (atts.length) out.push(Uint8Array.of(0xff, 0x00), attBytes(atts.at(-1)));
    ops.forEach((o, i) => out.push(...(i < ops.length - 1 ? [Uint8Array.of(0xff)] : []), opBytes(o.op), serialize(o.next)));
    return concat(...out);
  }
  function merge(a, b) {                              // b's attestations and branches into a (same message)
    for (const x of b.atts) if (!a.atts.some(y => cmpAtt(x, y) === 0)) a.atts.push(x);
    for (const o of b.ops) {
      const same = a.ops.find(p => cmpOp(p.op, o.op) === 0);
      if (same) merge(same.next, o.next); else a.ops.push(o);
    }
  }
  const detached = (hashOp, digest, tree) => concat(Uint8Array.from(MAGIC), varuintB(1), Uint8Array.of(hashOp), digest, serialize(tree));

  // load(bytes) -> {hashOp, digest, tree} with every node's message worked out
  async function load(b) {
    const rd = reader(b);
    if (!isProof(b)) fail("not an OpenTimestamps proof");
    rd.bytes(MAGIC.length);
    if (rd.varuint() !== 1) fail("unknown proof version");
    const hashOp = rd.bytes(1)[0];
    if (!HASH_LEN[hashOp]) fail("unknown file hash");
    const digest = rd.bytes(HASH_LEN[hashOp]);
    const tree = readTree(rd, MAX_DEPTH);
    if (rd.pos() !== b.length) fail("extra bytes after the proof");
    await fill(tree, digest);
    return { hashOp, digest, tree };
  }
  const write = p => detached(p.hashOp, p.digest, p.tree);

  // ---- asking the calendars (the sealing page) ----
  // These three accept requests from a web page (checked 2026-11-23); catallaxy does not.
  const CALENDARS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com"];
  const CALENDAR_OK = /^https:\/\/([a-z0-9-]+\.)*(calendar\.opentimestamps\.org|calendar\.eternitywall\.com|calendar\.catallaxy\.com|pool\.opentimestamps\.org|pool\.eternitywall\.com|btc\.catallaxy\.com)\/?$/;
  const ACCEPT = { Accept: "application/vnd.opentimestamps.v1" };   // a CORS-safe header: no preflight
  async function readReply(r, msg) {
    const body = new Uint8Array(await r.arrayBuffer()), rd = reader(body);
    const t = readTree(rd, MAX_DEPTH);
    if (rd.pos() !== body.length) fail("calendar reply has extra bytes");
    return fill(t, msg);
  }
  // stamp(payload) -> pending proof bytes (SHA-256 of the payload sent to the calendars; no nonce: a seal is public)
  async function stamp(payload, opts = {}) {
    const f = opts.fetch || globalThis.fetch, need = opts.need || 2;
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", payload));
    const root = { msg: digest, atts: [], ops: [] }, ok = [];
    await Promise.all((opts.calendars || CALENDARS).map(async cal => {
      try {
        const r = await f(cal + "/digest", { method: "POST", body: digest, headers: ACCEPT });
        if (!r.ok) return;
        merge(root, await readReply(r, digest)); ok.push(cal);
      } catch (e) {}
    }));
    if (ok.length < need) fail("Only " + ok.length + " of the timestamp servers answered (need " + need + ").");
    return { bytes: detached(SHA256, digest, root), calendars: ok };
  }
  // upgrade(proof bytes) -> {bytes, added}: asks each known calendar for the Bitcoin part of a pending proof
  async function upgrade(b, opts = {}) {
    const f = opts.fetch || globalThis.fetch, p = await load(b);
    let added = 0;
    const leaves = []; (function collect(n) { if (n.atts.length) leaves.push(n); n.ops.forEach(o => collect(o.next)); })(p.tree);
    for (const node of leaves) {
      if (node.msg === null) continue;
      for (const a of [...node.atts]) {
        if (a.kind !== "pending" || !CALENDAR_OK.test(a.uri)) continue;
        try {
          const r = await f(a.uri.replace(/\/$/, "") + "/timestamp/" + hex(node.msg), { headers: ACCEPT });
          if (!r.ok) continue;                                   // not ready yet (404)
          const t = await readReply(r, node.msg);
          if (walk(t, []).some(x => x.att.kind === "bitcoin")) { merge(node, t); added++; }
        } catch (e) {}
      }
    }
    return { bytes: write(p), added };
  }

  // parse(bytes) -> {digest, hashOp, bitcoin: [{height, root}], pending: [uri]}; root in display order
  async function parse(b) {
    const { hashOp, digest, tree } = await load(b);
    const all = walk(tree, []);
    const seen = new Set(), bitcoin = [], pending = [];
    for (const { msg, att } of all) {
      if (att.kind === "bitcoin" && msg && msg.length === 32) {
        const root = hex(msg.slice().reverse()), k = att.height + ":" + root;
        if (!seen.has(k)) { seen.add(k); bitcoin.push({ height: att.height, root }); }
      } else if (att.kind === "pending" && !pending.includes(att.uri)) pending.push(att.uri);
    }
    bitcoin.sort((a, b) => a.height - b.height);
    return { digest, hashOp, bitcoin, pending: pending.sort() };
  }

  // verify(bytes, payload, merkleAt) -> {height, time}; merkleAt(height) -> {root, time} | null.
  // Throws an Error with one plain sentence when the proof does not hold.
  async function verify(b, payload, merkleAt) {
    const p = await parse(b);
    const d = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", payload));
    if (p.hashOp !== SHA256 || hex(p.digest) !== hex(d)) fail("This time proof is for a different seal.");
    if (!p.bitcoin.length) fail(p.pending.length ? "The time proof is still pending: no Bitcoin block yet." : "The time proof has no Bitcoin block.");
    const errs = [];
    for (const c of p.bitcoin) {
      const got = await merkleAt(c.height);
      if (!got) { errs.push("block " + c.height + " could not be fetched"); continue; }
      if (got.root.toLowerCase() === c.root) return { height: c.height, time: got.time };
      errs.push("the proof does not match block " + c.height);
    }
    fail("Time proof not confirmed: " + errs.join("; ") + ".");
  }

  return { isProof, parse, verify, ripemd160, load, write, stamp, upgrade, CALENDARS };
})();
if (typeof module !== "undefined" && module.exports) module.exports = DHO;

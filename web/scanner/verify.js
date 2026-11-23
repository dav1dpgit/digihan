// DigiHan signature check for the phone scanner (format v0.4, payload version 1).
// Self-contained: BIP340 Schnorr verification over secp256k1 with BigInt, SHA-256 via
// WebCrypto, bech32 (npub), Nostr event checks (NIP-01). Verification only: no secret keys here.
// Runs in browsers and in Node 20+ (globalThis.crypto.subtle).
"use strict";

const DHV = (() => {
  const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
  const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
  const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
  const enc = new TextEncoder();

  // ---- bytes ----
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const unhex = h => { const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16); return o; };
  const cat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
  const toInt = b => BigInt("0x" + (hex(b) || "0"));
  const toBytes32 = x => unhex(x.toString(16).padStart(64, "0"));
  const sha256 = async b => new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", b));
  const taggedHash = async (tag, msg) => { const t = await sha256(enc.encode(tag)); return sha256(cat(t, t, msg)); };

  // ---- field and curve (Jacobian coordinates) ----
  const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
  const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
  const inv = a => pow(a, P - 2n);
  const INF = null;
  function dbl(A) {
    if (A === INF) return INF;
    const [X, Y, Z] = A;
    if (Y === 0n) return INF;
    const S = mod(4n * X * Y * Y), M = mod(3n * X * X);
    const X3 = mod(M * M - 2n * S), Y3 = mod(M * (S - X3) - 8n * Y * Y * Y * Y), Z3 = mod(2n * Y * Z);
    return [X3, Y3, Z3];
  }
  function add(A, B) {
    if (A === INF) return B; if (B === INF) return A;
    const [X1, Y1, Z1] = A, [X2, Y2, Z2] = B;
    const Z1Z1 = mod(Z1 * Z1), Z2Z2 = mod(Z2 * Z2);
    const U1 = mod(X1 * Z2Z2), U2 = mod(X2 * Z1Z1), S1 = mod(Y1 * Z2 * Z2Z2), S2 = mod(Y2 * Z1 * Z1Z1);
    if (U1 === U2) return S1 === S2 ? dbl(A) : INF;
    const H = mod(U2 - U1), R = mod(S2 - S1), HH = mod(H * H), HHH = mod(H * HH), V = mod(U1 * HH);
    const X3 = mod(R * R - HHH - 2n * V), Y3 = mod(R * (V - X3) - S1 * HHH), Z3 = mod(H * Z1 * Z2);
    return [X3, Y3, Z3];
  }
  function mul(A, k) { let R = INF; while (k > 0n) { if (k & 1n) R = add(R, A); A = dbl(A); k >>= 1n; } return R; }
  function affine(A) { if (A === INF) return INF; const zi = inv(A[2]), zi2 = zi * zi % P; return [A[0] * zi2 % P, A[1] * zi2 % P * zi % P]; }
  function liftX(x) {
    if (x >= P) return null;
    const c = mod(x * x * x + 7n), y = pow(c, (P + 1n) / 4n);
    if (y * y % P !== c) return null;
    return [x, (y & 1n) === 0n ? y : P - y, 1n];
  }

  // ---- BIP340 verify ----
  async function schnorrVerify(msg, pub, sig) {
    if (pub.length !== 32 || sig.length !== 64) return false;
    const Pt = liftX(toInt(pub));
    if (!Pt) return false;
    const r = toInt(sig.slice(0, 32)), s = toInt(sig.slice(32));
    if (r >= P || s >= N) return false;
    const e = toInt(await taggedHash("BIP0340/challenge", cat(sig.slice(0, 32), pub, msg))) % N;
    const R = affine(add(mul([GX, GY, 1n], s), mul(Pt, mod(N - e, N))));
    return R !== INF && (R[1] & 1n) === 0n && R[0] === r;
  }

  // ---- bech32 (NIP-19 npub) ----
  const CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const polymod = v => { const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1; for (const x of v) { const b = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) c ^= G[i]; } return c >>> 0; };
  const hrpExpand = h => [...[...h].map(c => c.charCodeAt(0) >> 5), 0, ...[...h].map(c => c.charCodeAt(0) & 31)];
  function convert(data, from, to, pad) { let acc = 0, bits = 0; const out = [], maxv = (1 << to) - 1; for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } } if (pad && bits) out.push((acc << (to - bits)) & maxv); else if (!pad && (bits >= from || ((acc << (to - bits)) & maxv))) return null; return out; }
  function npubEncode(pub) { const d = convert(pub, 8, 5, true), chk = polymod([...hrpExpand("npub"), ...d, 0, 0, 0, 0, 0, 0]) ^ 1; return "npub1" + [...d, ...[0, 1, 2, 3, 4, 5].map(i => (chk >> (5 * (5 - i))) & 31)].map(x => CH[x]).join(""); }
  function npubDecode(s) {
    s = s.trim().toLowerCase(); const p = s.lastIndexOf("1"); if (s.slice(0, p) !== "npub") return null;
    const d = [...s.slice(p + 1)].map(c => CH.indexOf(c)); if (d.some(x => x < 0) || d.length < 7) return null;
    if (polymod([...hrpExpand("npub"), ...d]) !== 1) return null;
    const b = convert(d.slice(0, -6), 5, 8, false); return b && b.length === 32 ? new Uint8Array(b) : null;
  }

  // ---- Nostr event (NIP-01) and the DigiHan registration ----
  async function eventValid(ev) {
    try {
      const ser = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
      const id = await sha256(enc.encode(ser));
      return hex(id) === ev.id && await schnorrVerify(id, unhex(ev.pubkey), unhex(ev.sig));
    } catch (e) { return false; }
  }
  const tag = (ev, name) => { const t = (ev.tags || []).find(t => t[0] === name); return t ? t[1] : null; };
  async function fingerprint(pub) { return hex((await sha256(pub)).slice(0, 8)); }

  // ---- the seal ----
  function parse(p) {
    let ts = 0; for (let i = 9; i < 14; i++) ts = ts * 256 + p[i];
    return { version: p[0] >> 4, flags: p[0] & 0xf, fp: hex(p.slice(1, 9)), ts, tsBytes: p.slice(9, 14), sig: p.slice(14, 78) };
  }
  async function signedMessage(docHash, tsBytes, fpBytes, centerHash, blockHash) {
    const parts = [docHash, tsBytes, fpBytes];
    if (centerHash) parts.push(centerHash);
    if (blockHash) parts.push(blockHash);          // anchored seal (v0.4): the block's hash, in display order
    return taggedHash("DigiHan/v1", cat(...parts));
  }
  // Check one seal against one key, one document hash and (if committed) the registrations.
  // blockHashAt(height) -> Uint8Array(32) | null is needed only for anchored seals (format v0.4).
  // Returns {ok, reason, reg, anchored}. reason is one plain sentence.
  async function checkSeal(payload, pub, docHash, registrations, blockHashAt) {
    const f = parse(payload);
    if (f.version !== 1 || (f.flags & ~5 & 0xf)) return { ok: false, reason: "Unknown seal version or reserved flag." };
    if (await fingerprint(pub) !== f.fp) return { ok: false, reason: "This key does not match the seal's key id." };
    const fpB = payload.slice(1, 9);
    let bh = null;
    if (f.flags & 1) {
      bh = blockHashAt ? await blockHashAt(f.ts) : null;
      if (!bh) return { ok: false, reason: "This seal is anchored to Bitcoin block " + f.ts + ", and that block's hash could not be fetched." };
    }
    const anchored = (f.flags & 1) ? f.ts : null;
    if (f.flags & 4) {
      for (const reg of registrations || []) {
        if (reg.pubkey !== hex(pub) || !(await eventValid(reg))) continue;
        const ch = tag(reg, "center_hash"); if (!ch) continue;
        if (await schnorrVerify(await signedMessage(docHash, f.tsBytes, fpB, unhex(ch), bh), pub, f.sig)) return { ok: true, reg, anchored };
      }
      return { ok: false, reason: (registrations || []).some(r => r.pubkey === hex(pub)) ? "The signature does not match this document." : "No valid artwork registration for this key." };
    }
    return (await schnorrVerify(await signedMessage(docHash, f.tsBytes, fpB, null, bh), pub, f.sig))
      ? { ok: true, reg: null, anchored } : { ok: false, reason: "The signature does not match this document." };
  }

  // curve: the arithmetic the sealing page's signer uses (dhseal.js); verification itself needs none of it exposed
  const curve = { P, N, G: [GX, GY, 1n], mod, mul, affine, liftX, toInt, toBytes32 };
  return { hex, unhex, sha256, taggedHash, schnorrVerify, npubEncode, npubDecode, eventValid, tag, fingerprint, parse, signedMessage, checkSeal, curve };
})();
if (typeof module !== "undefined" && module.exports) module.exports = DHV;

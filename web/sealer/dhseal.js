// DigiHan sealing in the browser (format v0.4): the ring's bit stream (Reed-Solomon), the seal drawn on a
// canvas, BIP340 signing, the signed payload, the registration record and the encrypted key file.
// Needs verify.js (DHV) loaded first. Mirrors python/digihan.py, dhsign.py and sign_pdf.py; the tests in
// web/sealer/dhseal.test.js check the stream and the signatures against the Python code and BIP340's vectors.
// The signer is plain BigInt arithmetic and not constant-time, like python/bip340.py.
"use strict";

const DHS = (() => {
  const { hex, unhex, sha256, taggedHash, schnorrVerify, npubEncode, fingerprint } = DHV;
  const { P, N, G, mod, mul, affine, toInt, toBytes32 } = DHV.curve;
  const enc = new TextEncoder();
  const cat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };

  // ---- Reed-Solomon RS(123, 78) over GF(2^8), primitive 0x11D, generator 2, first root alpha^0 (reedsolo) ----
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (() => { let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; } for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]; })();
  const gmul = (a, b) => (a && b) ? EXP[LOG[a] + LOG[b]] : 0;
  function rsGenerator(nsym) {
    let g = [1];
    for (let i = 0; i < nsym; i++) {
      const r = new Array(g.length + 1).fill(0), root = EXP[i];
      for (let j = 0; j < g.length; j++) { r[j] ^= g[j]; r[j + 1] ^= gmul(g[j], root); }
      g = r;
    }
    return g;
  }
  function rsEncode(msg, nsym) {
    const gen = rsGenerator(nsym), out = new Uint8Array(msg.length + nsym);
    out.set(msg);
    for (let i = 0; i < msg.length; i++) {
      const coef = out[i];
      if (coef) for (let j = 1; j < gen.length; j++) out[i + j] ^= gmul(gen[j], coef);
    }
    out.set(msg);
    return out;
  }

  // ---- the ring ----
  const SYNC = [1,1,1,0,0,1,1,1, 0,1,1,0,1,0,0,1, 1,1,0,0,0,1,0,1, 0,1,1,1];
  const NSYM = 45, START = -Math.PI / 2;
  function geometry() {                                     // python/digihan.py Geometry(45, 5, 0.6)
    const g = { d: 45, nTracks: 5, module: 0.6 };
    g.rRimOut = 22.5; g.rRimIn = g.rRimOut - 0.9; g.rBandOut = g.rRimIn - 0.5; g.trackH = 0.6 * 1.15;
    g.rBandIn = g.rBandOut - 5 * g.trackH; g.rLocOut = g.rBandIn - 0.4; g.rLocator = g.rLocOut - 0.7;
    g.rCenter = g.rLocator - 1.2;
    g.trackR = [0, 1, 2, 3, 4].map(i => g.rBandIn + (i + 0.5) * g.trackH);
    g.cells = g.trackR.map(r => Math.floor(2 * Math.PI * r / 0.6));
    return g;
  }
  const GEOM = geometry();
  function buildStream(payload) {
    const cw = rsEncode(payload, NSYM), bits = [...SYNC];
    for (const b of cw) for (let k = 7; k >= 0; k--) bits.push((b >> k) & 1);
    return Uint8Array.from(bits);
  }
  // drawSeal(ctx, payload, art, dpmm): white paper, vermilion ink, the center art inside its free zone.
  // art = an image or canvas (drawn to fill the center circle), or null. The canvas must be sealSize(dpmm) square.
  const sealSize = dpmm => Math.ceil(45 * dpmm) + 8;
  function drawSeal(ctx, payload, art, dpmm, ink = "rgb(178,56,44)") {
    const g = GEOM, S = sealSize(dpmm), c = S / 2, mm = v => v * dpmm, stream = buildStream(payload);
    ctx.save();
    ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, S, S);
    const disc = (r, fill) => { ctx.beginPath(); ctx.arc(c, c, mm(r), 0, 2 * Math.PI); ctx.fillStyle = fill; ctx.fill(); };
    const ring = (rIn, rOut) => { ctx.beginPath(); ctx.arc(c, c, mm(rOut), 0, 2 * Math.PI); ctx.arc(c, c, mm(rIn), 0, 2 * Math.PI, true); ctx.fillStyle = ink; ctx.fill(); };
    ring(g.rRimIn, g.rRimOut);
    let k = 0;
    for (let t = 0; t < g.nTracks; t++) {
      const rIn = g.rBandIn + t * g.trackH + 0.06, rOut = rIn + g.trackH - 0.12, rMid = (rIn + rOut) / 2;
      const rDot = Math.min(g.module, rOut - rIn) * 0.46, C = g.cells[t];
      ctx.fillStyle = ink;
      for (let i = 0; i < C; i++, k++) {
        if (!stream[k]) continue;
        const a = START + 2 * Math.PI * (i + 0.43) / C;
        ctx.beginPath(); ctx.arc(c + mm(rMid) * Math.cos(a), c + mm(rMid) * Math.sin(a), mm(rDot), 0, 2 * Math.PI); ctx.fill();
      }
    }
    ring(g.rLocator, g.rLocOut);
    for (let j = 0; j < 8; j++) {                           // the eight bridges; the 12 o'clock one double width
      const ang = (90 - j * 45) * Math.PI / 180, w = mm(j === 0 ? 1.6 : 0.8);
      const r0 = mm(g.rCenter - 0.2), r1 = mm(g.rLocator + 0.3), ux = Math.cos(ang), uy = -Math.sin(ang), px = -uy, py = ux;
      ctx.beginPath();
      ctx.moveTo(c + r0 * ux + w / 2 * px, c + r0 * uy + w / 2 * py); ctx.lineTo(c + r1 * ux + w / 2 * px, c + r1 * uy + w / 2 * py);
      ctx.lineTo(c + r1 * ux - w / 2 * px, c + r1 * uy - w / 2 * py); ctx.lineTo(c + r0 * ux - w / 2 * px, c + r0 * uy - w / 2 * py);
      ctx.closePath(); ctx.fillStyle = ink; ctx.fill();
    }
    if (art) {                                              // fills the center, clipped inside the free zone
      ctx.beginPath(); ctx.arc(c, c, mm(g.rCenter - 0.05), 0, 2 * Math.PI); ctx.clip();
      const side = 2 * mm(g.rCenter - 0.1);
      ctx.drawImage(art, c - side / 2, c - side / 2, side, side);
    }
    ctx.restore();
    return S;
  }

  // ---- BIP340 ----
  const hasEvenY = Q => (Q[1] & 1n) === 0n;
  function pubFromSecret(sk) {
    const d = toInt(sk);
    if (d < 1n || d >= N) throw new Error("secret key out of range");
    return toBytes32(affine(mul(G, d))[0]);
  }
  async function schnorrSign(msg, sk, aux) {
    const d0 = toInt(sk);
    if (d0 < 1n || d0 >= N) throw new Error("secret key out of range");
    const Pt = affine(mul(G, d0)), d = hasEvenY(Pt) ? d0 : N - d0, px = toBytes32(Pt[0]);
    const t = toBytes32(d ^ toInt(await taggedHash("BIP0340/aux", aux)));
    const k0 = toInt(await taggedHash("BIP0340/nonce", cat(t, px, msg))) % N;
    if (k0 === 0n) throw new Error("nonce is zero");
    const R = affine(mul(G, k0)), k = hasEvenY(R) ? k0 : N - k0, rx = toBytes32(R[0]);
    const e = toInt(await taggedHash("BIP0340/challenge", cat(rx, px, msg))) % N;
    const sig = cat(rx, toBytes32(mod(k + e * d, N)));
    if (!(await schnorrVerify(msg, px, sig))) throw new Error("signature failed its own check");
    return sig;
  }
  const random = n => globalThis.crypto.getRandomValues(new Uint8Array(n));
  function newSecret() { for (;;) { const sk = random(32), d = toInt(sk); if (d >= 1n && d < N) return sk; } }

  // ---- the payload (78 bytes) and the registration record ----
  // anchor = {height, hash: Uint8Array(32) in display order} makes an anchored seal (flag bit 0)
  async function sealPayload(sk, pub, docHash, ts, centerHash, anchor) {
    const fp = (await sha256(pub)).slice(0, 8);
    if (anchor) ts = anchor.height;
    const tsB = new Uint8Array(5); let v = ts; for (let i = 4; i >= 0; i--) { tsB[i] = v % 256; v = Math.floor(v / 256); }
    const parts = [docHash, tsB, fp]; if (centerHash) parts.push(centerHash); if (anchor) parts.push(anchor.hash);
    const sig = await schnorrSign(await taggedHash("DigiHan/v1", cat(...parts)), sk, random(32));
    const flags = (centerHash ? 4 : 0) | (anchor ? 1 : 0);
    return cat(Uint8Array.of(0x10 | flags), fp, tsB, sig);
  }
  async function registration(sk, pub, centerPng, createdAt) {
    const ch = hex(await sha256(centerPng)), pk = hex(pub);
    const ev = { pubkey: pk, created_at: createdAt || Math.floor(Date.now() / 1000), kind: 30078,
      tags: [["d", "digihan-center:" + ch], ["center_hash", ch], ["f", await fingerprint(pub)], ["alt", "DigiHan seal: artwork registration"]],
      content: JSON.stringify({ app: "DigiHan", format: "v0.4", center_hash: ch }) };
    const id = await sha256(enc.encode(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])));
    ev.id = hex(id); ev.sig = hex(await schnorrSign(id, sk, random(32)));
    return ev;
  }

  // ---- the key file: the secret key encrypted with a password (PBKDF2-SHA256 -> AES-256-GCM, pubkey as AAD) ----
  const ITER = 600000;
  async function aesKey(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  const b64 = u8 => btoa(String.fromCharCode(...u8));
  const unb64 = s => Uint8Array.from(atob(s), ch => ch.charCodeAt(0));
  async function lockKey(sk, pub, password, centerPng, reg) {
    const salt = random(16), nonce = random(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: pub }, await aesKey(password, salt, ITER), sk));
    return { format: "digihan-keyfile-v1", kdf: "pbkdf2-sha256", iterations: ITER, cipher: "aes-256-gcm",
      salt: hex(salt), nonce: hex(nonce), ciphertext: hex(ct), pubkey: hex(pub),
      center_png: b64(centerPng), registration: reg };
  }
  async function unlockKey(kf, password) {
    if (kf.format !== "digihan-keyfile-v1" || kf.kdf !== "pbkdf2-sha256" || kf.cipher !== "aes-256-gcm")
      throw new Error("This key file was made by the Python tools; this page reads key files it made itself.");
    try {
      const sk = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unhex(kf.nonce), additionalData: unhex(kf.pubkey) },
        await aesKey(password, unhex(kf.salt), kf.iterations), unhex(kf.ciphertext)));
      if (hex(pubFromSecret(sk)) !== kf.pubkey) throw new Error("x");
      return sk;
    } catch (e) { throw new Error("Wrong password for this key file."); }
  }

  return { NSYM, GEOM, rsEncode, buildStream, sealSize, drawSeal, pubFromSecret, schnorrSign, newSecret, sealPayload,
           registration, lockKey, unlockKey, b64, unb64, npubEncode };
})();
if (typeof module !== "undefined" && module.exports) module.exports = DHS;

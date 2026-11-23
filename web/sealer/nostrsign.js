// Nostr signers for the stamping page (stamping page v16, format v0.5).
// A signer app or browser extension holds the key; this page asks it to sign. Nostr signers sign whole events
// only, so a seal stamped this way is payload version 2: the signature is over a stamp event (SPEC.md, 6.2).
//   NIP-07: window.nostr, from a browser extension or the built-in browser of a Nostr app.
//   NIP-46: a remote signer ("bunker") reached over relays. Each request is a kind-24133 event from this page's
//           own connection key, encrypted with NIP-44 (version 2). The connection key is not your key: it only
//           lets the signer recognise this page; the signer still decides what to sign.
// Needs verify.js (DHV) and dhseal.js (DHS). Runs in browsers and in Node 20+ (tests).
"use strict";

const DHN = (() => {
  const { hex, unhex, curve } = DHV;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const cat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
  const b64 = u => { let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const rnd = n => crypto.getRandomValues(new Uint8Array(n));
  const now = () => Math.floor(Date.now() / 1000);

  // ---- HMAC-SHA256 and HKDF-expand (RFC 5869) with WebCrypto ----
  async function hmac(key, ...parts) {
    const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", k, cat(...parts)));
  }
  async function hkdfExpand(prk, info, L) {
    const out = new Uint8Array(L); let t = new Uint8Array(0);
    for (let i = 1, pos = 0; pos < L; i++, pos += 32) { t = await hmac(prk, t, info, Uint8Array.of(i)); out.set(t.subarray(0, Math.min(32, L - pos)), pos); }
    return out;
  }

  // ---- ChaCha20 (RFC 8439), block counter from 0 ----
  function chacha20(key, nonce, data) {
    const k = new Uint32Array(8), n = new Uint32Array(3), st = new Uint32Array(16), x = new Uint32Array(16);
    const kv = new DataView(key.buffer, key.byteOffset, 32), nv = new DataView(nonce.buffer, nonce.byteOffset, 12);
    for (let i = 0; i < 8; i++) k[i] = kv.getUint32(4 * i, true);
    for (let i = 0; i < 3; i++) n[i] = nv.getUint32(4 * i, true);
    const out = new Uint8Array(data.length), blk = new Uint8Array(64), bv = new DataView(blk.buffer);
    const r = (v, c) => (v << c) | (v >>> (32 - c));
    const q = (a, b, c, d) => {
      x[a] += x[b]; x[d] = r(x[d] ^ x[a], 16); x[c] += x[d]; x[b] = r(x[b] ^ x[c], 12);
      x[a] += x[b]; x[d] = r(x[d] ^ x[a], 8);  x[c] += x[d]; x[b] = r(x[b] ^ x[c], 7);
    };
    for (let ctr = 0, pos = 0; pos < data.length; ctr++, pos += 64) {
      st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
      st.set(k, 4); st[12] = ctr; st.set(n, 13); x.set(st);
      for (let i = 0; i < 10; i++) { q(0, 4, 8, 12); q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15); q(0, 5, 10, 15); q(1, 6, 11, 12); q(2, 7, 8, 13); q(3, 4, 9, 14); }
      for (let i = 0; i < 16; i++) bv.setUint32(4 * i, (x[i] + st[i]) >>> 0, true);
      for (let i = 0; i < 64 && pos + i < data.length; i++) out[pos + i] = data[pos + i] ^ blk[i];
    }
    return out;
  }

  // ---- NIP-44 version 2 ----
  function sharedX(sk, pubHex) {                       // ECDH on secp256k1: the x coordinate, not hashed
    const P = curve.liftX(curve.toInt(unhex(pubHex)));
    if (!P) throw new Error("That is not a valid public key.");
    return curve.toBytes32(curve.affine(curve.mul(P, curve.toInt(sk)))[0]);
  }
  const conversationKey = (sk, pubHex) => hmac(enc.encode("nip44-v2"), sharedX(sk, pubHex));   // HKDF-extract
  function padLen(n) {
    if (n <= 32) return 32;
    const next = 2 ** (Math.floor(Math.log2(n - 1)) + 1), chunk = next <= 256 ? 32 : next / 8;
    return chunk * (Math.floor((n - 1) / chunk) + 1);
  }
  async function messageKeys(ck, nonce) {
    const k = await hkdfExpand(ck, nonce, 76);
    return { chachaKey: k.slice(0, 32), chachaNonce: k.slice(32, 44), hmacKey: k.slice(44, 76) };
  }
  async function encrypt(ck, text, nonce) {
    nonce = nonce || rnd(32);
    const pt = enc.encode(text);
    if (pt.length < 1 || pt.length > 65535) throw new Error("A message must be 1 to 65535 bytes.");
    const padded = new Uint8Array(2 + padLen(pt.length)); padded[0] = pt.length >> 8; padded[1] = pt.length & 255; padded.set(pt, 2);
    const mk = await messageKeys(ck, nonce), ct = chacha20(mk.chachaKey, mk.chachaNonce, padded);
    return b64(cat(Uint8Array.of(2), nonce, ct, await hmac(mk.hmacKey, nonce, ct)));
  }
  async function decrypt(ck, payload) {
    if (!payload || payload[0] === "#") throw new Error("Unknown encryption version.");
    const d = unb64(payload);
    if (d.length < 99 || d.length > 65603 || d[0] !== 2) throw new Error("Unknown encryption version or length.");
    const nonce = d.slice(1, 33), ct = d.slice(33, d.length - 32), mac = d.slice(d.length - 32);
    const mk = await messageKeys(ck, nonce), want = await hmac(mk.hmacKey, nonce, ct);
    let diff = 0; for (let i = 0; i < 32; i++) diff |= want[i] ^ mac[i];
    if (diff) throw new Error("The message's authentication code does not match.");
    const padded = chacha20(mk.chachaKey, mk.chachaNonce, ct), n = (padded[0] << 8) | padded[1];
    if (n < 1 || padded.length !== 2 + padLen(n)) throw new Error("The message's padding is wrong.");
    return dec.decode(padded.slice(2, 2 + n));
  }

  // ---- events this page signs with its own connection key ----
  async function signOwn(sk, ev) {
    const e = { pubkey: hex(DHS.pubFromSecret(sk)), created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content };
    const id = await DHV.eventId(e);
    return { ...e, id: hex(id), sig: hex(await DHS.schnorrSign(id, sk, rnd(32))) };
  }

  // What the signer returns must be exactly the event this page asked for (SPEC.md, section 6.2).
  async function checkSigned(asked, got, pubHex) {
    if (typeof got === "string") { try { got = JSON.parse(got); } catch (e) { throw new Error("Your signer's answer is not an event."); } }
    if (!got || typeof got.sig !== "string") throw new Error("Your signer did not return a signature.");
    if (got.pubkey !== pubHex) throw new Error("Your signer signed with a different key than this seal's key.");
    const same = got.created_at === asked.created_at && got.kind === asked.kind && got.content === asked.content
      && JSON.stringify(got.tags) === JSON.stringify(asked.tags);
    if (!same) throw new Error("Your signer changed the record before signing it (a tag, the time or the text), so the seal could not be checked. Nothing was stamped.");
    if (!(await DHV.eventValid(got))) throw new Error("Your signer's signature does not check.");
    return unhex(got.sig);
  }

  // ---- NIP-07 ----
  const hasExtension = () => typeof window !== "undefined" && !!window.nostr && typeof window.nostr.signEvent === "function"
    && typeof window.nostr.getPublicKey === "function";
  const extension = {
    async publicKey() { const p = String(await window.nostr.getPublicKey()).toLowerCase(); if (!/^[0-9a-f]{64}$/.test(p)) throw new Error("The signer gave no public key."); return p; },
    async sign(ev) { return window.nostr.signEvent({ kind: ev.kind, created_at: ev.created_at, tags: ev.tags, content: ev.content }); },
  };

  // ---- NIP-46 ----
  const SIGNER_RELAYS = ["wss://relay.nsec.app", "wss://relay.damus.io", "wss://nos.lol"];   // for nostrconnect://
  const PERMS = "get_public_key,sign_event:30078";
  function parseBunker(text) {
    const m = /^bunker:\/\/([0-9a-fA-F]{64})(?:\?(.*))?$/.exec((text || "").trim());
    if (!m) return null;
    const q = new URLSearchParams(m[2] || ""), relays = q.getAll("relay").map(r => r.trim()).filter(r => /^wss?:\/\//.test(r));
    return relays.length ? { remote: m[1].toLowerCase(), relays, secret: q.get("secret") || "" } : null;
  }
  class Session {
    constructor(clientSkHex, relays, remote) {
      this.sk = unhex(clientSkHex); this.pub = hex(DHS.pubFromSecret(this.sk));
      this.relays = relays; this.remote = remote || null; this.waiting = new Map(); this.socks = new Map();
      this.sub = "dh" + hex(rnd(5)); this.onAuth = null; this.secret = null; this.onConnect = null;
    }
    open() {
      return Promise.all(this.relays.map(url => new Promise(res => {
        let ws; try { ws = new WebSocket(url); } catch (e) { return res(); }
        const t = setTimeout(() => { try { ws.close(); } catch (e) {} res(); }, 7000);
        ws.onopen = () => { clearTimeout(t); this.socks.set(url, ws);
          ws.send(JSON.stringify(["REQ", this.sub, { kinds: [24133], "#p": [this.pub], since: now() - 120 }])); res(); };
        ws.onmessage = m => { try { const d = JSON.parse(m.data); if (d[0] === "EVENT" && d[1] === this.sub && d[2]) this.incoming(d[2]); } catch (e) {} };
        ws.onerror = () => { clearTimeout(t); res(); };
        ws.onclose = () => this.socks.delete(url);
      }))).then(() => { if (!this.socks.size) throw new Error("None of the signer's relays answered (" + this.relays.map(r => r.replace(/^wss?:\/\//, "")).join(", ") + "). Check the connection."); });
    }
    async incoming(ev) {
      try {
        if (ev.kind !== 24133 || !(await DHV.eventValid(ev))) return;
        if (this.remote && ev.pubkey !== this.remote) return;
        const m = JSON.parse(await decrypt(await conversationKey(this.sk, ev.pubkey), ev.content));
        if (!this.remote) {                              // nostrconnect://: the signer's first answer carries our secret
          if (this.secret && m.result === this.secret) { this.remote = ev.pubkey; if (this.onConnect) this.onConnect(); }
          return;
        }
        const w = this.waiting.get(m.id); if (!w) return;
        if (m.result === "auth_url") { if (this.onAuth && m.error) this.onAuth(m.error); return; }   // approve on the signer's page
        this.waiting.delete(m.id);
        if (m.error) w.reject(new Error("Your signer said: " + m.error)); else w.resolve(m.result);
      } catch (e) {}
    }
    async request(method, params, ms) {
      const id = hex(rnd(8));
      const content = await encrypt(await conversationKey(this.sk, this.remote), JSON.stringify({ id, method, params }));
      const ev = await signOwn(this.sk, { created_at: now(), kind: 24133, tags: [["p", this.remote]], content });
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => { this.waiting.delete(id); reject(new Error("Your signer did not answer in time. Open your signer app, approve the request, and try again.")); }, ms || 180000);
        this.waiting.set(id, { resolve: v => { clearTimeout(t); resolve(v); }, reject: e => { clearTimeout(t); reject(e); } });
        for (const ws of this.socks.values()) try { ws.send(JSON.stringify(["EVENT", ev])); } catch (e) {}
      });
    }
    cancel() { for (const w of this.waiting.values()) w.reject(new Error("Cancelled.")); this.waiting.clear(); }
    close() { this.cancel(); for (const ws of this.socks.values()) try { ws.close(); } catch (e) {} this.socks.clear(); }
  }
  // bunker://… pasted from the signer app: connect, then ask for the key it signs with
  async function connectBunker(text, onAuth) {
    const b = parseBunker(text);
    if (!b) throw new Error("That is not a bunker link. It starts with bunker:// and names at least one relay.");
    const link = { type: "nip46", remote: b.remote, relays: b.relays, client_sk: hex(DHS.newSecret()) };
    const s = new Session(link.client_sk, link.relays, link.remote); s.onAuth = onAuth;
    try {
      await s.open();
      await s.request("connect", [b.remote, b.secret, PERMS]);
      link.pubkey = String(await s.request("get_public_key", [])).toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(link.pubkey)) throw new Error("Your signer gave no public key.");
      return { link, session: s };
    } catch (e) { s.close(); throw e; }
  }
  // nostrconnect://…: this page shows a link or QR code; the signer app opens it and answers
  function offerConnect() {
    const sk = hex(DHS.newSecret()), secret = hex(rnd(8)), s = new Session(sk, SIGNER_RELAYS, null);
    s.secret = secret;
    const uri = "nostrconnect://" + s.pub + "?" + SIGNER_RELAYS.map(r => "relay=" + encodeURIComponent(r)).join("&")
      + "&secret=" + secret + "&perms=" + encodeURIComponent(PERMS) + "&name=DigiHan&url=" + encodeURIComponent("https://digihan.org");
    const ready = (async () => {
      await s.open();
      await new Promise((res, rej) => { s.onConnect = res; s.giveUp = rej; });
      const pubkey = String(await s.request("get_public_key", [])).toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(pubkey)) throw new Error("Your signer gave no public key.");
      return { link: { type: "nip46", remote: s.remote, relays: SIGNER_RELAYS, client_sk: sk, pubkey }, session: s };
    })();
    ready.catch(() => {});                               // whoever waits on it sees the error; nobody waiting is fine
    return { uri, ready, stop: () => { if (s.giveUp) s.giveUp(new Error("Stopped.")); s.close(); } };
  }

  // ---- one signer, whatever kind: {publicKey(), sign(event) -> 64-byte signature, close()} ----
  // link: {type: "nip07"} or {type: "nip46", remote, relays, client_sk, pubkey}
  function signerFor(link, session, onAuth) {
    if (link.type === "nip07") {
      if (!hasExtension()) throw new Error("This seal signs with a Nostr signer in the browser (an extension, or a Nostr app's built-in browser), and there is none here. Open this page where your signer is.");
      return { async sign(ev, pubHex) { return checkSigned(ev, await extension.sign(ev), pubHex); }, close() {} };
    }
    let s = session || null;
    return {
      async sign(ev, pubHex) {
        if (!s) { s = new Session(link.client_sk, link.relays, link.remote); await s.open(); }
        s.onAuth = onAuth;
        const got = await s.request("sign_event", [JSON.stringify({ kind: ev.kind, content: ev.content, tags: ev.tags, created_at: ev.created_at })]);
        return checkSigned(ev, got, pubHex);
      },
      cancel() { if (s) s.cancel(); },
      close() { if (s) s.close(); s = null; },
    };
  }
  const describe = link => link.type === "nip07" ? "the Nostr signer in this browser"
    : "your Nostr signer app (remote signing over " + link.relays.map(r => r.replace(/^wss?:\/\//, "")).join(", ") + ")";

  return { hasExtension, extension, parseBunker, connectBunker, offerConnect, signerFor, checkSigned, describe,
           nip44: { conversationKey, encrypt, decrypt, padLen, messageKeys, chacha20 }, Session };
})();
if (typeof module !== "undefined" && module.exports) module.exports = DHN;

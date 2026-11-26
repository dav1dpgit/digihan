// Making a stamp public (stamping page v21, release 0.7.0; SPEC.md section 13). Optional, off by default:
//   the public record: a Nostr event (kind 30078) signed by the seal's key: this key stamped a file with this
//     SHA-256 hash, the ring's payload, and where the public copies are;
//   public copies: the stamped PDF or stamped picture on Blossom servers (BUD-01, BUD-02, BUD-06, BUD-11);
//   the key's Blossom server list (kind 10063, BUD-03), published only if the key has none.
// Also hasLocation(): whether a JPEG or PNG carries the place it was taken (a warning before stamping); and
// (release 0.7.2) the public key's Nostr profile with the signer's name (NIP-05), which scanners confirm.
// Needs verify.js (DHV) and dhseal.js (DHS). Runs in browsers and in Node 20+ (tests).
"use strict";

const DHP = (() => {
  const RELEASE = "0.7.5";        // the page compares this with its own release, as for dhseal.js
  const { hex, sha256 } = DHV;
  const enc = new TextEncoder();
  const DEFAULT_SERVERS = ["https://blossom.primal.net", "https://blossom.band"];
  const now = () => Math.floor(Date.now() / 1000);
  const b64url = u8 => DHS.b64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  // a server typed by the person: "https://host", "host" or "https://host/" -> "https://host", or null
  function server(t) {
    t = String(t || "").trim().replace(/\/+$/, "");
    if (!t) return null;
    if (!/^[a-z]+:\/\//i.test(t)) t = "https://" + t;
    try { const u = new URL(t); return u.protocol === "https:" && !u.search && !u.hash && u.hostname.includes(".") ? u.origin + u.pathname.replace(/\/+$/, "") : null; }
    catch (e) { return null; }
  }
  const host = s => s.replace(/^https:\/\//, "");

  // ---- the events, before they are signed (the page signs them with its key, or asks the signer) ----
  // copies: [{sha, type, size, servers: [url]}], the one to fetch first first; copies no server stored are left out
  async function recordTemplate(pubHex, payload, docHash, copies, at) {
    const tags = [["d", await DHV.recordD(payload)], ["x", hex(docHash)], ["payload", hex(payload)]];
    for (const c of copies || []) if (c.servers.length) tags.push(["copy", c.sha, c.type, String(c.size), ...c.servers]);
    tags.push(["alt", "DigiHan stamp record: a seal on a document, made public"]);
    return { pubkey: pubHex, created_at: at || now(), kind: 30078, tags, content: "DigiHan stamp. Document SHA-256: " + hex(docHash) + "." };
  }
  // BUD-11: created_at in the past (a minute back, for a server whose clock is behind), an expiration ahead
  const authTemplate = (pubHex, shas) => ({ pubkey: pubHex, created_at: now() - 60, kind: 24242,
    tags: [["t", "upload"], ["expiration", String(now() + 900)], ...shas.map(s => ["x", s])], content: "Upload a stamped file (DigiHan)" });
  const listTemplate = (pubHex, servers) => ({ pubkey: pubHex, created_at: now(), kind: 10063, tags: servers.map(s => ["server", s]), content: "" });
  const authHeader = ev => "Nostr " + b64url(enc.encode(JSON.stringify(ev)));

  // ---- relays ----
  // one filter, every relay; the events that come back, each once: [{ev, relay}], with .answered: how many relays
  // said they had sent all they have (EOSE)
  function query(relays, filter, ms) {
    return new Promise(resolve => {
      const found = new Map(), socks = []; let left = relays.length, over = false, answered = 0;
      const finish = () => { if (over) return; over = true; socks.forEach(w => { try { w.close(); } catch (e) {} }); resolve(Object.assign([...found.values()], { answered })); };
      const one = () => { if (--left <= 0) finish(); };
      setTimeout(finish, ms || 5000);
      for (const url of relays) {
        let ws, ended = false; const end = () => { if (!ended) { ended = true; one(); } };
        try { ws = new WebSocket(url); } catch (e) { end(); continue; }
        socks.push(ws);
        const sub = "dp" + Math.random().toString(36).slice(2, 9);
        ws.onopen = () => { try { ws.send(JSON.stringify(["REQ", sub, filter])); } catch (e) { end(); } };
        ws.onmessage = m => {
          try { const d = JSON.parse(m.data);
            if (d[0] === "EVENT" && d[1] === sub && d[2] && !found.has(d[2].id)) found.set(d[2].id, { ev: d[2], relay: url });
            else if (d[0] === "EOSE" && d[1] === sub) { answered++; try { ws.close(); } catch (e) {} end(); }
          } catch (e) {}
        };
        ws.onerror = end; ws.onclose = end;
      }
    });
  }
  // the newest valid event of a replaceable kind for this key, or null; .answered as for query
  async function newest(relays, filter, pubHex) {        // NIP-01: the later time wins; at the same time, the lower id
    let best = null; const got = await query(relays, filter);
    for (const { ev } of got) {
      if (ev.pubkey !== pubHex || ev.kind !== filter.kinds[0] || !(await DHV.eventValid(ev))) continue;
      if (!best || ev.created_at > best.created_at || (ev.created_at === best.created_at && ev.id < best.id)) best = ev;
    }
    return { ev: best, answered: got.answered };
  }
  // the key's Blossom server list (BUD-03): {servers: [url] in the signer's order, or null if the key has none,
  // known: whether any relay answered (if none did, the key may have a list nobody could see)}
  async function serverList(relays, pubHex) {
    const { ev, answered } = await newest(relays, { kinds: [10063], authors: [pubHex], limit: 5 }, pubHex);
    const l = ev ? [...new Set(ev.tags.filter(t => t[0] === "server").map(t => server(t[1])).filter(Boolean))] : [];
    return { servers: l.length ? l : null, known: answered > 0 };
  }
  // this seal's record as published before (to keep its copies when the record is published again), or null
  async function existingRecord(relays, pubHex, payload) {
    const d = await DHV.recordD(payload);
    const { ev } = await newest(relays, { kinds: [30078], authors: [pubHex], "#d": [d], limit: 5 }, pubHex);
    const r = ev ? await DHV.readRecord(ev) : null;
    return r && hex(r.payload) === hex(payload) ? { ...r, at: ev.created_at } : null;
  }

  // ---- the signer's name (release 0.7.2): the public key's Nostr profile (kind 0) with a NIP-05 name ----
  // {ev: the newest profile or null, known: whether any relay answered}
  async function profile(relays, pubHex) {
    const { ev, answered } = await newest(relays, { kinds: [0], authors: [pubHex], limit: 5 }, pubHex);
    return { ev, known: answered > 0 };
  }
  // The profile with its NIP-05 name set to name ("dp@example.com"). Everything else in an existing profile is
  // kept (a profile is replaceable: what is left out is lost). An existing profile that cannot be read is left
  // alone: this throws.
  function profileTemplate(pubHex, old, name, at) {
    let c = {};
    if (old) {
      let j = null; try { j = JSON.parse(old.content); } catch (e) {}
      if (!j || typeof j !== "object" || Array.isArray(j)) throw new Error("This public key's Nostr profile could not be read, so it was left as it is.");
      c = j;
    }
    return { pubkey: pubHex, created_at: Math.max(at || now(), old ? old.created_at + 1 : 0), kind: 0,
             tags: old && Array.isArray(old.tags) ? old.tags : [], content: JSON.stringify({ ...c, nip05: name }) };
  }

  // ---- Blossom ----
  const WHY = { 400: "did not accept the request", 401: "needs an account there", 402: "needs a paid plan for this file",
    403: "refused it", 404: "has no upload", 405: "has no upload", 409: "saw a different file than was sent", 411: "did not accept the request",
    413: "says the file is too large", 415: "does not take this kind of file", 429: "has had too many uploads just now", 503: "is not taking uploads just now" };
  const reasonOf = r => { let x = ""; try { x = (r.headers.get("x-reason") || "").replace(/\s+/g, " ").trim().slice(0, 140); } catch (e) {}
    return x ? (WHY[r.status] ? WHY[r.status] + " (" + x + ")" : x) : WHY[r.status] || "answered " + r.status; };
  const failWhy = e => e && e.name === "AbortError" ? "did not answer in time" : "could not be reached";
  async function timed(url, init, ms) {
    const ac = new AbortController(), t = setTimeout(() => ac.abort(), ms);
    try { return await fetch(url, { ...init, signal: ac.signal }); } finally { clearTimeout(t); }
  }
  const EXT = { "application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg" };
  // one file to one server: {ok, url} or {ok: false, why}. The server is asked first (HEAD /upload, BUD-06); one
  // that does not answer that question is sent the file anyway. A server whose answer names another SHA-256
  // did not store this exact file, so it does not count.
  async function uploadOne(srv, f, auth) {
    try {
      const r = await timed(srv + "/upload", { method: "HEAD", headers: { Authorization: auth, "X-SHA-256": f.sha, "X-Content-Type": f.type, "X-Content-Length": String(f.bytes.length) } }, 15000);
      if (!r.ok && ![404, 405, 501].includes(r.status)) return { ok: false, why: reasonOf(r) };
    } catch (e) { return { ok: false, why: failWhy(e) }; }
    try {
      const r = await timed(srv + "/upload", { method: "PUT", headers: { Authorization: auth, "Content-Type": f.type, "X-SHA-256": f.sha }, body: f.bytes }, 180000);
      if (!r.ok) return { ok: false, why: reasonOf(r) };
      let d = null; try { d = await r.json(); } catch (e) {}
      if (!d || String(d.sha256 || "").toLowerCase() !== f.sha) return { ok: false, why: "stored something other than this exact file" };
      return { ok: true, url: typeof d.url === "string" && /^https:\/\/[^\s]+$/.test(d.url) && d.url.includes(f.sha) ? d.url : srv + "/" + f.sha + (EXT[f.type] || "") };
    } catch (e) { return { ok: false, why: failWhy(e) }; }
  }

  // ---- making a stamp public ----
  // o = {pubHex, payload, docHash, relays, sign: async template -> signed event, send: async event -> {saved, failed},
  //      record: true, blossom: bool, files: [{name, bytes, type, label}], own: url or null, after: the earlier record's
  //      created_at, keep: copies already public (listed after the new ones),
  //      progress(step, what): "list", "auth", "upload", "record", "serverlist"}
  // -> {copies: [{name, type, sha, size, servers, urls, refused: [{server, why}]}], record: {saved, failed} or {error},
  //     list: "published" | "kept" | null, listSaved}
  async function publish(o) {
    const out = { copies: [], record: null, list: null };
    let tried = [];
    if (o.blossom && o.files && o.files.length) {
      if (o.progress) o.progress("list");
      const sl = await serverList(o.relays, o.pubHex), known = sl.servers;
      tried = [...new Set([o.own, ...(known || DEFAULT_SERVERS)].map(server).filter(Boolean))];
      // a list is published only when a relay answered that the key has none: never over one nobody could see
      out.list = known ? "kept" : sl.known ? null : "unknown";
      const files = [];
      for (const f of o.files) files.push({ ...f, sha: hex(await sha256(f.bytes)) });
      if (o.progress) o.progress("auth");
      const auth = authHeader(await o.sign(authTemplate(o.pubHex, files.map(f => f.sha))));
      for (const f of files) {
        if (o.progress) o.progress("upload", f.label);
        const c = { name: f.name, label: f.label, type: f.type, sha: f.sha, size: f.bytes.length, servers: [], urls: [], refused: [] };
        const res = await Promise.all(tried.map(s => uploadOne(s, f, auth)));
        res.forEach((r, i) => { if (r.ok) { c.servers.push(tried[i]); c.urls.push(r.url); } else c.refused.push({ server: tried[i], why: r.why }); });
        out.copies.push(c);
      }
    }
    if (o.progress) o.progress("record");
    const fresh = out.copies.filter(c => c.servers.length);
    const keep = (o.keep || []).filter(k => !fresh.some(c => c.sha === k.sha));
    // a newer record replaces the older one only if its time is later (NIP-01), so it is at least a second after
    const rec = await o.sign(await recordTemplate(o.pubHex, o.payload, o.docHash, [...fresh, ...keep], Math.max(now(), (o.after || 0) + 1)));
    out.record = await o.send(rec);
    out.recordEvent = rec;
    // the key's server list, the first time a copy was stored (never over a list the key already has)
    if (o.blossom && !out.list && fresh.length) {
      const used = tried.filter(s => fresh.some(c => c.servers.includes(s)));
      if (o.progress) o.progress("serverlist");
      try { const ev = await o.sign(listTemplate(o.pubHex, used)); const r = await o.send(ev); out.list = r.saved.length ? "published" : null; out.listSaved = r; }
      catch (e) { out.listError = e.message; }
    }
    return out;
  }

  // ---- the place a photo was taken ----
  // A JPEG's EXIF (APP1) or a PNG's eXIf chunk: the GPS block (tag 0x8825) holding a latitude or longitude;
  // or XMP text naming one. Read only; nothing is changed.
  function tiffGps(b, t, end) {
    if (t + 8 > end) return false;
    const le = b[t] === 0x49 && b[t + 1] === 0x49; if (!le && !(b[t] === 0x4d && b[t + 1] === 0x4d)) return false;
    const u16 = k => le ? b[k] | (b[k + 1] << 8) : (b[k] << 8) | b[k + 1];
    const u32 = k => (le ? (b[k] | (b[k + 1] << 8) | (b[k + 2] << 16) | (b[k + 3] << 24)) : ((b[k] << 24) | (b[k + 1] << 16) | (b[k + 2] << 8) | b[k + 3])) >>> 0;
    const entries = ifd => { const out = []; if (ifd + 2 > end) return out; for (let e = 0, n = u16(ifd); e < n && ifd + 14 + 12 * e <= end; e++) out.push(ifd + 2 + 12 * e); return out; };
    for (const q of entries(t + u32(t + 4))) {
      if (u16(q) !== 0x8825) continue;
      return entries(t + u32(q + 8)).some(g => u16(g) === 0x0002 || u16(g) === 0x0004);   // GPSLatitude, GPSLongitude
    }
    return false;
  }
  const latin = (b, s, e) => { let t = ""; for (let i = s; i < e; i++) t += String.fromCharCode(b[i]); return t; };
  const xmpGps = s => /GPS(Latitude|Longitude)/.test(s);
  function hasLocation(b) {
    try {
      if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
        let i = 2;
        while (i + 4 <= b.length) {
          if (b[i] !== 0xff) break;
          const m = b[i + 1];
          if (m === 0xff) { i++; continue; }
          if (m === 0x01 || (m >= 0xd0 && m <= 0xd8)) { i += 2; continue; }
          const len = ((b[i + 2] << 8) | b[i + 3]) + 2;
          if (m === 0xda || len < 4 || i + len > b.length) break;
          if (m === 0xe1) {
            const p = i + 4;
            if (latin(b, p, p + 6) === "Exif\0\0" && tiffGps(b, p + 6, i + len)) return true;
            if (latin(b, p, p + 28) === "http://ns.adobe.com/xap/1.0/" && xmpGps(latin(b, p, i + len))) return true;
          }
          i += len;
        }
        return false;
      }
      if (b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
        let i = 8;
        while (i + 12 <= b.length) {
          const len = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0, type = latin(b, i + 4, i + 8), s = i + 8, e = Math.min(b.length, s + len);
          if (type === "eXIf" && tiffGps(b, s, e)) return true;
          if ((type === "iTXt" || type === "tEXt") && /XML:com\.adobe\.xmp/.test(latin(b, s, Math.min(e, s + 40))) && xmpGps(latin(b, s, e))) return true;
          if (type === "IEND") break;
          i += 12 + len;
        }
      }
    } catch (e) {}
    return false;
  }

  return { RELEASE, DEFAULT_SERVERS, server, host, recordTemplate, authTemplate, listTemplate, authHeader, b64url, query, serverList, existingRecord,
           uploadOne, publish, hasLocation, profile, profileTemplate };
})();
if (typeof module !== "undefined" && module.exports) module.exports = DHP;

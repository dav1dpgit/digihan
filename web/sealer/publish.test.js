// Public records and public copies (run: node web/sealer/publish.test.js; SPEC.md section 13, release 0.7.0).
// The record's checks (verify.js), the Blossom upload against a stand-in server (fetch), the whole publishing
// with stand-in relays (WebSocket), and the photo-location check, on hand-made EXIF, XMP and PNG bytes.
const assert = require("assert");
global.DHV = require("../scanner/verify.js");
globalThis.hashwasm = require("./vendor/argon2.umd.min.js");
global.DHS = require("./dhseal.js");
const DHP = require("./publish.js");
const h = DHV.hex, u = DHV.unhex, enc = new TextEncoder();
const signWith = sk => async t => { const id = await DHV.eventId(t); return { ...t, id: h(id), sig: h(await DHS.schnorrSign(id, sk, new Uint8Array(32))) }; };

// a stand-in Blossom server: fetch(url, init) -> Response-like
function blossom(rules) {
  const stored = new Map(), log = [];
  const res = (status, body, headers = {}) => ({ ok: status >= 200 && status < 300, status, headers: { get: k => headers[k.toLowerCase()] || null }, json: async () => JSON.parse(body), arrayBuffer: async () => body });
  const f = async (url, init = {}) => {
    const m = /^(https:\/\/[^/]+)\/(upload|[0-9a-f]{64})/.exec(url), srv = m && m[1], r = rules[srv] || {};
    log.push((init.method || "GET") + " " + url);
    if (!m || r.down) throw new TypeError("Failed to fetch");
    const auth = init.headers && init.headers.Authorization;
    if (m[2] === "upload" && init.method === "HEAD") {
      if (r.noHead) return res(405, "");
      if (r.refuse) return res(r.refuse, "", r.reason ? { "x-reason": r.reason } : {});
      return res(200, "");
    }
    if (m[2] === "upload" && init.method === "PUT") {
      const ev = JSON.parse(Buffer.from(auth.slice(6).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
      const sha = h(await DHV.sha256(init.body));
      if (ev.kind !== 24242 || !(await DHV.eventValid(ev)) || !ev.tags.some(t => t[0] === "x" && t[1] === sha)) return res(401, "");
      if (r.refuse) return res(r.refuse, "");
      const got = r.alter ? h(await DHV.sha256(enc.encode("changed"))) : sha;
      stored.set(srv + "/" + got, init.body);
      return res(201, JSON.stringify({ url: srv + "/" + got + ".pdf", sha256: got, size: init.body.length, type: init.headers["Content-Type"], uploaded: 1 }));
    }
    const b = stored.get(srv + "/" + m[2]);
    return b ? res(200, b.buffer.slice(b.byteOffset, b.byteOffset + b.length)) : res(404, "");
  };
  return { f, stored, log };
}
// stand-in relays: a WebSocket that answers REQ from a store and stores EVENTs
function relays(store) {
  return class {
    constructor(url) { this.url = url; setTimeout(() => this.onopen && this.onopen(), 1); }
    send(raw) {
      const d = JSON.parse(raw);
      const back = m => setTimeout(() => this.onmessage && this.onmessage({ data: JSON.stringify(m) }), 1);
      if (d[0] === "REQ") {
        const f = d[2], hit = ev => (!f.kinds || f.kinds.includes(ev.kind)) && (!f.authors || f.authors.includes(ev.pubkey))
          && Object.keys(f).filter(k => k[0] === "#").every(k => ev.tags.some(t => t[0] === k[1] && f[k].includes(t[1])));
        for (const ev of store.values()) if (hit(ev)) back(["EVENT", d[1], ev]);
        back(["EOSE", d[1]]);
      } else if (d[0] === "EVENT") { store.set(d[1].id, d[1]); back(["OK", d[1].id, true, ""]); }
    }
    close() {}
  };
}

(async () => {
  let n = 0;
  const sk = u("11".repeat(32)), pub = DHS.pubFromSecret(sk), pk = h(pub), sign = signWith(sk);
  const docHash = await DHV.sha256(enc.encode("a document")), payload = await DHS.sealPayload(sk, pub, docHash, 1795000000, null, null);

  // 1. the record: made, signed, read back; every check refuses a broken one
  const copies = [{ sha: "ab".repeat(32), type: "application/pdf", size: 1234, servers: ["https://one.example", "https://two.example"] },
                  { sha: "cd".repeat(32), type: "image/png", size: 9, servers: [] }];          // not stored anywhere: left out
  const rec = await sign(await DHP.recordTemplate(pk, payload, docHash, copies, 1795000100));
  assert.strictEqual(DHV.tag(rec, "d"), "digihan-record:" + h(await DHV.sha256(payload))); n++;
  assert.strictEqual(DHV.tag(rec, "f"), null); n++;                                        // never crowds the key's registration lookup
  assert.ok(DHV.isRecord(rec) && !DHV.isStampEvent(rec)); n++;
  const r = await DHV.readRecord(rec);
  assert.ok(r && h(r.payload) === h(payload) && h(r.x) === h(docHash)); n++;
  assert.deepStrictEqual(r.copies, [{ sha: "ab".repeat(32), type: "application/pdf", size: 1234, servers: ["https://one.example", "https://two.example"] }]); n++;
  const broken = async (mut) => { const t = JSON.parse(JSON.stringify(await DHP.recordTemplate(pk, payload, docHash, copies, 1795000100))); mut(t); return DHV.readRecord(await sign(t)); };
  assert.strictEqual(await broken(t => { t.tags[0][1] = "digihan-record:" + "00".repeat(32); }), null); n++;                 // d not the payload's
  const other = new Uint8Array(payload); other[1] ^= 1;
  assert.strictEqual(await broken(t => { t.tags[0][1] = "digihan-record:" + "x"; }), null); n++;
  assert.strictEqual(await DHV.readRecord({ ...rec, sig: "00".repeat(64) }), null); n++;                                 // bad signature
  const otherKey = DHS.pubFromSecret(u("22".repeat(32)));
  const t2 = await DHP.recordTemplate(h(otherKey), payload, docHash, [], 1795000100);
  assert.strictEqual(await DHV.readRecord(await signWith(u("22".repeat(32)))(t2)), null); n++;                            // the payload's key id is not this key's
  const t3 = await DHP.recordTemplate(pk, payload, docHash, [{ sha: "ef".repeat(32), type: "x", size: 1, servers: ["http://plain.example", "https://ok.example/"] }], 1);
  assert.deepStrictEqual((await DHV.readRecord(await sign(t3))).copies[0].servers, ["https://ok.example"]); n++;          // https only
  // a record is never taken as a key registration
  const reg = await DHS.registration(sk, pub, enc.encode("png"));
  const ok1 = await DHV.checkSeal(payload, pub, docHash, [rec, reg], null);
  assert.ok(ok1.ok); n++;

  // 2. the upload permission (BUD-11) and its header (base64url, no padding)
  const auth = await sign(DHP.authTemplate(pk, ["ab".repeat(32), "cd".repeat(32)]));
  assert.ok(auth.created_at < Math.floor(Date.now() / 1000) && +DHV.tag(auth, "expiration") > Math.floor(Date.now() / 1000) + 600); n++;
  assert.deepStrictEqual(auth.tags.filter(t => t[0] === "x").map(t => t[1]), ["ab".repeat(32), "cd".repeat(32)]); n++;
  const hd = DHP.authHeader(auth);
  assert.ok(/^Nostr [A-Za-z0-9_-]+$/.test(hd)); n++;
  assert.deepStrictEqual(JSON.parse(Buffer.from(hd.slice(6), "base64url").toString()), auth); n++;

  // 3. servers typed by a person
  assert.strictEqual(DHP.server("blossom.example.com/"), "https://blossom.example.com"); n++;
  assert.strictEqual(DHP.server(" https://cdn.example.org "), "https://cdn.example.org"); n++;
  assert.strictEqual(DHP.server("http://cdn.example.org"), null); n++;
  assert.strictEqual(DHP.server("not a server"), null); n++;
  assert.strictEqual(DHP.server(""), null); n++;

  // 4. one file to one server
  const file = { name: "x_stamped.pdf", label: "the stamped PDF", type: "application/pdf", bytes: enc.encode("%PDF-1.7 a stamped file") };
  file.sha = h(await DHV.sha256(file.bytes));
  const B = blossom({ "https://paid.example": { refuse: 402 }, "https://types.example": { refuse: 415, reason: "PDF needs a plan" },
                      "https://nohead.example": { noHead: true }, "https://alter.example": { alter: true }, "https://down.example": { down: true } });
  global.fetch = B.f;
  const ah = DHP.authHeader(await sign(DHP.authTemplate(pk, [file.sha])));
  const up = await DHP.uploadOne("https://ok.example", file, ah);
  assert.ok(up.ok && up.url === "https://ok.example/" + file.sha + ".pdf"); n++;
  assert.deepStrictEqual(await DHP.uploadOne("https://paid.example", file, ah), { ok: false, why: "needs a paid plan for this file" }); n++;
  assert.deepStrictEqual(await DHP.uploadOne("https://types.example", file, ah), { ok: false, why: "does not take this kind of file (PDF needs a plan)" }); n++;
  assert.ok((await DHP.uploadOne("https://nohead.example", file, ah)).ok); n++;                   // no answer to the question: the upload is tried
  assert.deepStrictEqual(await DHP.uploadOne("https://alter.example", file, ah), { ok: false, why: "stored something other than this exact file" }); n++;
  assert.deepStrictEqual(await DHP.uploadOne("https://down.example", file, ah), { ok: false, why: "could not be reached" }); n++;

  // 5. the whole publishing: record only; then record and copies; then the finished file (step 3)
  const store = new Map(); global.WebSocket = relays(store);
  const RL = ["wss://r1.example", "wss://r2.example"];
  const send = async ev => { for (const s of [store]) s.set(ev.id, ev); return { saved: RL, failed: [] }; };
  const payloadA = await DHS.sealPayload(sk, pub, docHash, 1795000001, null, null);           // another stamp of the same file
  const a = await DHP.publish({ pubHex: pk, payload: payloadA, docHash, relays: RL, sign, send, record: true, blossom: false, files: [] });
  assert.strictEqual(a.copies.length, 0); assert.strictEqual(DHV.tag(a.recordEvent, "x"), h(docHash)); n++;
  assert.ok(![...store.values()].some(e => e.kind === 10063 || e.kind === 24242)); n++;           // no list, no upload permission
  const steps = [];
  const pic = { name: "x_stamped.png", label: "the stamped picture", type: "image/png", bytes: enc.encode("a stamped picture") };
  const b = await DHP.publish({ pubHex: pk, payload, docHash, relays: RL, sign, send, record: true, blossom: true, files: [file, pic],
                                own: "mine.example", progress: s => steps.push(s) });
  assert.deepStrictEqual(steps, ["list", "auth", "upload", "upload", "record", "serverlist"]); n++;
  assert.deepStrictEqual(b.copies.map(c => c.servers), [["https://mine.example", "https://blossom.primal.net", "https://blossom.band"],
                                                       ["https://mine.example", "https://blossom.primal.net", "https://blossom.band"]]); n++;
  const rb = await DHV.readRecord(b.recordEvent);
  assert.deepStrictEqual(rb.copies.map(c => c.sha), [file.sha, h(await DHV.sha256(pic.bytes))]); n++;
  assert.strictEqual(b.list, "published"); n++;
  const lists = [...store.values()].filter(e => e.kind === 10063);
  assert.deepStrictEqual(lists[0].tags, [["server", "https://mine.example"], ["server", "https://blossom.primal.net"], ["server", "https://blossom.band"]]); n++;
  // the record found again, as step 3 does, and the finished file published with the earlier copies kept after it
  const old = await DHP.existingRecord(RL, pk, payload);
  assert.ok(old && old.copies.length === 2); n++;
  const fin = { name: "x_finished.pdf", label: "the finished PDF", type: "application/pdf", bytes: enc.encode("%PDF-1.7 finished") };
  B.stored.clear();
  const c2 = await DHP.publish({ pubHex: pk, payload, docHash, relays: RL, sign, send, record: true, blossom: true, files: [fin], keep: old.copies, after: old.at });
  assert.ok(c2.recordEvent.created_at > old.at); n++;                                             // later, so it replaces the earlier record
  // the key now has a server list, so it is used and left as it is
  assert.strictEqual(c2.list, "kept"); n++;
  assert.deepStrictEqual(c2.copies[0].servers, ["https://mine.example", "https://blossom.primal.net", "https://blossom.band"]); n++;
  const rc = await DHV.readRecord(c2.recordEvent);
  assert.deepStrictEqual(rc.copies.map(c => c.sha), [h(await DHV.sha256(fin.bytes)), file.sha, h(await DHV.sha256(pic.bytes))]); n++;
  assert.strictEqual([...store.values()].filter(e => e.kind === 10063).length, 1); n++;
  // no server takes it: the record is still published, without a copy, and no list is made
  const store2 = new Map(); global.WebSocket = relays(store2);
  global.fetch = blossom({ "https://blossom.primal.net": { refuse: 402 }, "https://blossom.band": { refuse: 415 } }).f;
  const d = await DHP.publish({ pubHex: pk, payload, docHash, relays: RL, sign, send: async ev => { store2.set(ev.id, ev); return { saved: RL, failed: [] }; },
                                record: true, blossom: true, files: [file] });
  assert.deepStrictEqual(d.copies[0].servers, []); assert.strictEqual(d.list, null); n++;
  assert.deepStrictEqual(d.copies[0].refused.map(x => x.why), ["needs a paid plan for this file", "does not take this kind of file"]); n++;
  assert.strictEqual((await DHV.readRecord(d.recordEvent)).copies.length, 0); n++;
  assert.ok(![...store2.values()].some(e => e.kind === 10063)); n++;

  // relays that never answer: the copies go up, the record is sent, and no server list is published over one nobody could see
  global.WebSocket = class { constructor() { setTimeout(() => this.onopen && this.onopen(), 1); } send() {} close() {} };
  global.fetch = blossom({}).f;
  const e = await DHP.publish({ pubHex: pk, payload, docHash, relays: RL, sign, send: async () => ({ saved: [], failed: [] }), record: true, blossom: true, files: [file] });
  assert.strictEqual(e.list, "unknown"); assert.deepStrictEqual(e.copies[0].servers, ["https://blossom.primal.net", "https://blossom.band"]); n++;

  // 6. the place a photo was taken
  const tiff = (gps) => {                                  // little-endian TIFF: IFD0 with Orientation and (optionally) a GPS pointer
    const ent = [[0x0112, 3, 1, 1], ...(gps ? [[0x8825, 4, 1, 38]] : [])];
    const b = [0x49, 0x49, 0x2a, 0x00, 8, 0, 0, 0, ent.length, 0];
    for (const [tg, ty, c, v] of ent) b.push(tg & 255, tg >> 8, ty, 0, c, 0, 0, 0, v & 255, v >> 8, 0, 0);
    b.push(0, 0, 0, 0);
    while (b.length < 38) b.push(0);
    if (gps) { b.push(gps.length, 0); for (const tg of gps) b.push(tg & 255, tg >> 8, 5, 0, 3, 0, 0, 0, 0, 0, 0, 0); b.push(0, 0, 0, 0); }
    return b;
  };
  const jpeg = segs => { const out = [0xff, 0xd8]; for (const [m, d] of segs) out.push(0xff, m, (d.length + 2) >> 8, (d.length + 2) & 255, ...d); out.push(0xff, 0xda, 0, 2, 1, 2, 3, 0xff, 0xd9); return Uint8Array.from(out); };
  const exif = t => [..."Exif"].map(c => c.charCodeAt(0)).concat([0, 0], t);
  assert.strictEqual(DHP.hasLocation(jpeg([[0xe1, exif(tiff([0x0001, 0x0002, 0x0003, 0x0004]))]])), true); n++;
  assert.strictEqual(DHP.hasLocation(jpeg([[0xe1, exif(tiff([0x0000]))]])), false); n++;          // a GPS block with only its version: no place
  assert.strictEqual(DHP.hasLocation(jpeg([[0xe1, exif(tiff(null))]])), false); n++;
  assert.strictEqual(DHP.hasLocation(jpeg([[0xe0, [..."JFIF"].map(c => c.charCodeAt(0))]])), false); n++;
  const xmp = [..."http://ns.adobe.com/xap/1.0/\0<x:xmpmeta><rdf:Description exif:GPSLatitude=\"47,1.5N\"/></x:xmpmeta>"].map(c => c.charCodeAt(0));
  assert.strictEqual(DHP.hasLocation(jpeg([[0xe1, xmp]])), true); n++;
  const png = chunks => { const out = [137, 80, 78, 71, 13, 10, 26, 10]; for (const [t, d] of chunks) { out.push(0, 0, d.length >> 8, d.length & 255, ...[...t].map(c => c.charCodeAt(0)), ...d, 0, 0, 0, 0); } return Uint8Array.from(out); };
  assert.strictEqual(DHP.hasLocation(png([["IHDR", new Array(13).fill(0)], ["eXIf", tiff([0x0002, 0x0004])], ["IEND", []]])), true); n++;
  assert.strictEqual(DHP.hasLocation(png([["IHDR", new Array(13).fill(0)], ["IEND", []]])), false); n++;
  assert.strictEqual(DHP.hasLocation(enc.encode("%PDF-1.7")), false); n++;
  assert.strictEqual(DHP.RELEASE, "0.7.0"); n++;
  console.log("publish.test.js: all " + n + " checks passed");
})().catch(e => { console.error(e); process.exit(1); });

// The sealing core against Python and BIP340 (run: node web/sealer/dhseal.test.js)
const fs = require("fs"), path = require("path"), assert = require("assert");
global.DHV = require("../scanner/verify.js");
globalThis.hashwasm = require("./vendor/argon2.umd.min.js");     // v2: Argon2id for key files
const DHS = require("./dhseal.js");
const h2b = h => Uint8Array.from(Buffer.from(h, "hex")), b2h = b => Buffer.from(b).toString("hex");
(async () => {
  let n = 0;
  // 1. the ring's bit stream equals python/digihan.py build_stream (Reed-Solomon parity included)
  for (const v of JSON.parse(fs.readFileSync(path.join(__dirname, "stream_vectors.json"))).vectors) {
    const bits = DHS.buildStream(h2b(v.payload)), packed = new Uint8Array(Math.ceil(bits.length / 8));
    bits.forEach((b, i) => { if (b) packed[i >> 3] |= 0x80 >> (i & 7); });
    assert.strictEqual(bits.length, v.nbits); assert.strictEqual(b2h(packed), v.stream); n++;
  }
  assert.deepStrictEqual(DHS.GEOM.cells, [188, 195, 202, 210, 217]); n++;
  // 2. BIP340 signing: the official vectors that carry a secret key
  const rows = fs.readFileSync(path.join(__dirname, "..", "..", "python", "tests", "bip340_test_vectors.csv"), "utf8").trim().split(/\r?\n/).slice(1).map(l => l.split(","));
  for (const [idx, sk, pk, aux, msg, sig] of rows) {
    if (!sk) continue;
    assert.strictEqual(b2h(DHS.pubFromSecret(h2b(sk))).toUpperCase(), pk, "pubkey " + idx);
    assert.strictEqual(b2h(await DHS.schnorrSign(h2b(msg), h2b(sk), h2b(aux))).toUpperCase(), sig, "sig " + idx); n++;
  }
  // 3. a seal made here checks with the scanner's verifier; plain, center-committed and anchored
  const sk = DHS.newSecret(), pub = DHS.pubFromSecret(sk), png = new Uint8Array([137, 80, 78, 71, 1, 2, 3]);
  const reg = await DHS.registration(sk, pub, png);
  assert.ok(await DHV.eventValid(reg)); n++;
  const doc = await DHV.sha256(new TextEncoder().encode("contract"));
  const ch = await DHV.sha256(png);
  const p1 = await DHS.sealPayload(sk, pub, doc, 1795390000, ch, null);
  assert.ok((await DHV.checkSeal(p1, pub, doc, [reg])).ok); n++;
  const anchor = { height: 977124, hash: h2b("00000000000000000000663048004362a4cf48f3610e365efd19f07d5dc69ff9") };
  const p2 = await DHS.sealPayload(sk, pub, doc, 0, ch, anchor);
  assert.strictEqual(p2[0], 0x15); n++;
  assert.ok((await DHV.checkSeal(p2, pub, doc, [reg], async h => h === 977124 ? anchor.hash : null)).ok); n++;
  assert.ok(!(await DHV.checkSeal(p2, pub, doc, [reg], async () => new Uint8Array(32))).ok); n++;
  // 4. the key file: the right password opens it, a wrong one does not
  const kf = await DHS.lockKey(sk, pub, "correct horse battery", png, reg);
  assert.strictEqual(b2h(await DHS.unlockKey(kf, "correct horse battery")), b2h(sk)); n++;
  await assert.rejects(DHS.unlockKey(kf, "wrong password"), /Wrong password/); n++;
  // 3b. v2 key files: Argon2id; an older PBKDF2 file still opens and is flagged for re-encryption
  assert.strictEqual(kf.kdf, "argon2id"); assert.deepStrictEqual([kf.memory_cost, kf.time_cost, kf.parallelism], [65536, 3, 1]);
  assert.strictEqual(DHS.needsUpgrade(kf), false); n++;
  const oldSalt = crypto.getRandomValues(new Uint8Array(16)), oldNonce = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode("correct horse battery"), "PBKDF2", false, ["deriveKey"]);
  const oldK = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: oldSalt, iterations: 600000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const oldCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: oldNonce, additionalData: pub }, oldK, sk));
  const oldKf = { format: "digihan-keyfile-v1", kdf: "pbkdf2-sha256", iterations: 600000, cipher: "aes-256-gcm", salt: b2h(oldSalt),
                  nonce: b2h(oldNonce), ciphertext: b2h(oldCt), pubkey: b2h(pub), center_png: DHS.b64(png), registration: reg };
  assert.strictEqual(DHS.needsUpgrade(oldKf), true);
  const sk2 = await DHS.unlockKey(oldKf, "correct horse battery"); assert.strictEqual(b2h(sk2), b2h(sk)); n++;
  await assert.rejects(DHS.unlockKey(oldKf, "wrong password"), /Wrong password/); n++;
  const newKf = await DHS.lockKey(sk2, pub, "correct horse battery", png, reg);      // what the page does after the unlock
  assert.strictEqual(newKf.kdf, "argon2id"); assert.strictEqual(newKf.pubkey, oldKf.pubkey);
  assert.strictEqual(newKf.center_png, oldKf.center_png); assert.deepStrictEqual(newKf.registration, oldKf.registration);
  assert.strictEqual(b2h(await DHS.unlockKey(newKf, "correct horse battery")), b2h(sk)); n++;
  // 3c. the fixed Argon2id key file that python/tests opens too
  const vec = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "python", "tests", "web_keyfile_argon2id.json")));
  const vsk = await DHS.unlockKey(vec.keyfile, vec.password);
  assert.strictEqual(b2h(DHS.pubFromSecret(vsk)), vec.keyfile.pubkey); n++;
  // 5. a key kept offline: the page drafts, someone else signs, the page assembles and checks
  const d = await DHS.draftRegistration(pub, png);
  const reg2 = await DHS.finishRegistration(d, await DHS.schnorrSign(d.id, sk, new Uint8Array(32)));
  assert.ok(await DHV.eventValid(reg2)); n++;
  await assert.rejects(DHS.finishRegistration(d, new Uint8Array(64)), /does not match/); n++;
  const msg = await DHS.sealMessage(pub, doc, 0, ch, anchor);
  const p3 = await DHS.assemble(pub, msg, await DHS.schnorrSign(msg.m, sk, new Uint8Array(32)));
  assert.ok((await DHV.checkSeal(p3, pub, doc, [reg2], async h => h === 977124 ? anchor.hash : null)).ok); n++;
  await assert.rejects(DHS.assemble(pub, msg, new Uint8Array(64)), /does not match/); n++;
  assert.strictEqual(b2h(DHS.readPublicKey(DHS.npubEncode(pub))), b2h(pub)); n++;
  assert.strictEqual(b2h(DHS.readPublicKey(b2h(pub).toUpperCase())), b2h(pub)); n++;
  assert.strictEqual(DHS.readPublicKey("npub1notakey"), null); n++;
  // 5b. base64 of a big picture (a photo as the artwork): no "Maximum call stack size exceeded"
  const big = crypto.getRandomValues(new Uint8Array(65536)), bigger = new Uint8Array(65536 * 31); for (let i = 0; i < bigger.length; i += 65536) bigger.set(big, i);
  assert.strictEqual(DHS.b64(bigger), Buffer.from(bigger).toString("base64")); n++;
  assert.strictEqual(b2h(DHS.unb64(DHS.b64(bigger))), b2h(bigger)); n++;
  const kfBig = await DHS.lockKey(sk, pub, "correct horse battery", bigger, reg);
  assert.strictEqual(b2h(DHS.unb64(kfBig.center_png)), b2h(bigger)); n++;
  // 5c (release 0.6.2): base64 from a table, every length near the 3-byte groups and the 3072-byte pieces;
  // and no bytes handed to a function as arguments, at any size (no spread, no apply)
  for (const len of [0, 1, 2, 3, 4, 5, 6, 3069, 3070, 3071, 3072, 3073, 3074, 6143, 6144, 6145, 700001]) {
    const u = crypto.getRandomValues(new Uint8Array(Math.min(len, 65536))), v = new Uint8Array(len); for (let i = 0; i < len; i += u.length || 1) v.set(u.subarray(0, Math.min(u.length, len - i)), i);
    assert.strictEqual(DHS.b64(v), Buffer.from(v).toString("base64"), "base64, " + len + " bytes"); n++;
  }
  const src = require("fs").readFileSync(__dirname + "/dhseal.js", "utf8").replace(/\/\/.*$/gm, "");
  assert.ok(!/fromCharCode\s*\(\s*\.\.\.|fromCharCode\.apply/.test(src), "dhseal.js hands bytes to fromCharCode as arguments"); n++;
  assert.strictEqual(DHS.RELEASE, "0.6.3"); n++;
  // 6. payload version 2 (format v0.5): the stamp event. The fixed vector is checked by python/tests too.
  const V = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "python", "tests", "stamp_event_vector.json")));
  const vsk2 = h2b(V.secret_key), vpub = DHS.pubFromSecret(vsk2), vdoc = await DHV.sha256(new TextEncoder().encode(V.document_text));
  const vpng = h2b(V.center_png_hex), vch = await DHV.sha256(vpng);
  const vreg = await DHS.registration(vsk2, vpub, vpng, V.registration_created_at);
  for (const c of V.cases) {
    const anc = c.anchor ? { height: c.anchor.height, hash: h2b(c.anchor.hash), time: c.anchor.time } : null;
    const m2 = await DHS.sealMessage(vpub, vdoc, c.ts, vch, anc, 2);
    assert.strictEqual(JSON.stringify([0, m2.event.pubkey, m2.event.created_at, m2.event.kind, m2.event.tags, m2.event.content]), c.serialized, c.name); n++;
    assert.strictEqual(b2h(m2.m), c.event_id, c.name); n++;
    const pv = await DHS.assemble(vpub, m2, await DHS.schnorrSign(m2.m, vsk2, h2b(V.aux)));
    assert.strictEqual(b2h(pv), c.payload, c.name); n++;
    const at = async h => anc && h === anc.height ? { hash: anc.hash, time: anc.time } : null;
    assert.ok((await DHV.checkSeal(pv, vpub, vdoc, [vreg], at)).ok, c.name); n++;
    // the signed stamp event is a valid Nostr event, and is never taken as a key record
    const se = DHS.signedStamp(m2, pv.slice(14));
    assert.ok(await DHV.eventValid(se)); assert.ok(DHV.isStampEvent(se)); n++;
    assert.ok(!(await DHV.checkSeal(pv, vpub, vdoc, [se], at)).ok); n++;
    // a changed document, a changed time or (anchored) a wrong block time fails
    assert.ok(!(await DHV.checkSeal(pv, vpub, await DHV.sha256(new Uint8Array([1])), [vreg], at)).ok); n++;
    if (anc) { assert.ok(!(await DHV.checkSeal(pv, vpub, vdoc, [vreg], async () => ({ hash: anc.hash, time: anc.time + 1 }))).ok); n++;
               assert.ok(!(await DHV.checkSeal(pv, vpub, vdoc, [vreg], async () => anc.hash)).ok); n++; }   // no time: cannot check
  }
  if (process.env.SEAL_OUT) fs.writeFileSync(process.env.SEAL_OUT, JSON.stringify({ kf, password: "correct horse battery", p1: b2h(p1), p2: b2h(p2), sk: b2h(sk) }));
  console.log(`dhseal.test.js: ${n} checks passed`);
})().catch(e => { console.error("FAIL", e); process.exit(1); });

// The sealing core against Python and BIP340 (run: node web/sealer/dhseal.test.js)
const fs = require("fs"), path = require("path"), assert = require("assert");
global.DHV = require("../scanner/verify.js");
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
  if (process.env.SEAL_OUT) fs.writeFileSync(process.env.SEAL_OUT, JSON.stringify({ kf, password: "correct horse battery", p1: b2h(p1), p2: b2h(p2), sk: b2h(sk) }));
  console.log(`dhseal.test.js: ${n} checks passed`);
})().catch(e => { console.error("FAIL", e); process.exit(1); });

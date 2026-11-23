// The phone's OpenTimestamps reader against the same proofs as python/tests (run: node web/scanner/ots.test.js)
const fs = require("fs"), path = require("path"), assert = require("assert");
const DHO = require("./ots.js");
const D = path.join(__dirname, "..", "..", "python", "tests", "ots");
const rd = (...p) => new Uint8Array(fs.readFileSync(path.join(D, ...p)));
const HELLO_ROOT = "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00";
(async () => {
  let n = 0;
  const h = await DHO.parse(rd("hello-world.txt.ots"));
  assert.deepStrictEqual(h.bitcoin, [{ height: 358391, root: HELLO_ROOT }]); n++;
  const t = await DHO.parse(rd("two-calendars.txt.ots"));
  assert.deepStrictEqual(t.bitcoin, []);
  assert.deepStrictEqual(t.pending, ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org"]); n++;
  const e = await DHO.parse(rd("different-blockchains.txt.ots"));
  assert.deepStrictEqual(e.bitcoin, [{ height: 455605, root: "2a19192cf00fb1baeea516b69b3a62195849589b4caafeb6ad6ebba58b9ae69a" }]); n++;
  for (const bad of ["bad-major-version.ots", "exceeds-max-msg-length.ots"])
    await assert.rejects(DHO.parse(rd("invalid", bad))), n++;
  await assert.rejects(DHO.parse(rd("hello-world.txt.ots").slice(0, -3))); n++;
  const data = rd("hello-world.txt");
  assert.deepStrictEqual(await DHO.verify(rd("hello-world.txt.ots"), data, async x => x === 358391 ? { root: HELLO_ROOT, time: 1 } : null), { height: 358391, time: 1 }); n++;
  await assert.rejects(DHO.verify(rd("hello-world.txt.ots"), data, async () => ({ root: "00".repeat(32), time: 0 })), /does not match/); n++;
  await assert.rejects(DHO.verify(rd("hello-world.txt.ots"), new Uint8Array([1, 2]), async () => null), /different seal/); n++;
  await assert.rejects(DHO.verify(rd("two-calendars.txt.ots"), rd("two-calendars.txt"), async () => null), /pending/); n++;
  assert.ok(DHO.isProof(rd("hello-world.txt.ots")) && !DHO.isProof(data)); n++;
  const r160 = s => Buffer.from(DHO.ripemd160(new TextEncoder().encode(s))).toString("hex");
  assert.strictEqual(r160(""), "9c1185a5c5e9fc54612808977ee8f548b2258d31"); n++;
  assert.strictEqual(r160("abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"); n++;
  // writing: every example proof read and written back is byte-identical
  for (const f of ["hello-world.txt.ots", "two-calendars.txt.ots", "different-blockchains.txt.ots"]) {
    const b = rd(f); assert.strictEqual(Buffer.compare(Buffer.from(DHO.write(await DHO.load(b))), Buffer.from(b)), 0, f); n++;
  }
  // stamping and upgrading through a simulated calendar (pool hands the digest to alice, as the real ones do)
  const cat = (...a) => Buffer.concat(a.map(x => Buffer.from(x)));
  const vb = b => cat([b.length], b);                                   // lengths < 128 here
  const pool = "https://a.pool.opentimestamps.org", alice = "https://alice.btc.calendar.opentimestamps.org";
  const payload = new Uint8Array(78).map((_, i) => i * 7 % 256), t4 = Buffer.from([0x6a, 0xb0, 0x00, 0x01]);
  const digest = require("crypto").createHash("sha256").update(payload).digest();
  const leaf = cat(t4, digest), sha = b => require("crypto").createHash("sha256").update(b).digest();
  const root = sha(sha(sha(leaf)));
  const fake = async (url, init) => {
    const ok = body => ({ ok: true, arrayBuffer: async () => Uint8Array.from(body).buffer });
    if (url === pool + "/digest" && init.method === "POST") return ok(cat([0xf1], vb(t4), [0x00], Buffer.from("83dfe30d2ef90c8e", "hex"), vb(vb(Buffer.from(alice)))));
    if (url === alice + "/timestamp/" + leaf.toString("hex")) return ok(cat([0x08, 0x08, 0x08, 0x00], Buffer.from("0588960d73d71901", "hex"), vb([0xd0, 0xe1, 0x38])));  // height 930000
    return { ok: false };
  };
  const st = await DHO.stamp(payload, { fetch: fake, calendars: [pool], need: 1 });
  const pend = await DHO.parse(st.bytes);
  assert.deepStrictEqual([pend.bitcoin, pend.pending], [[], [alice]]); n++;
  const up = await DHO.upgrade(st.bytes, { fetch: fake });
  assert.strictEqual(up.added, 1); n++;
  const done = await DHO.parse(up.bytes);
  assert.deepStrictEqual(done.bitcoin, [{ height: 930000, root: Buffer.from(root).reverse().toString("hex") }]); n++;
  assert.deepStrictEqual(await DHO.verify(up.bytes, payload, async h => h === 930000 ? { root: Buffer.from(root).reverse().toString("hex"), time: 5 } : null), { height: 930000, time: 5 }); n++;
  await assert.rejects(DHO.stamp(payload, { fetch: fake, calendars: [pool], need: 2 }), /Only 1/); n++;
  if (process.env.OTS_OUT) fs.writeFileSync(process.env.OTS_OUT, up.bytes);
  console.log(`ots.test.js: ${n} checks passed`);
})().catch(e => { console.error("FAIL", e); process.exit(1); });

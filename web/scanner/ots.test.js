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
  console.log(`ots.test.js: ${n} checks passed`);
})().catch(e => { console.error("FAIL", e); process.exit(1); });

// Nostr signer support (run: node web/sealer/nostrsign.test.js). NIP-44 against a fixed vector (made with this code
// and confirmed against the official NIP-44 test vectors and nostr-tools 2.26.1 when it was written), and the
// checks the page makes on what a signer returns.
const fs = require("fs"), path = require("path"), assert = require("assert");
global.DHV = require("../scanner/verify.js");
globalThis.hashwasm = require("./vendor/argon2.umd.min.js");
global.DHS = require("./dhseal.js");
const DHN = require("./nostrsign.js");
const h = DHV.hex, u = DHV.unhex;
(async () => {
  let n = 0;
  // 1. NIP-44 version 2
  const V = JSON.parse(fs.readFileSync(path.join(__dirname, "nip44_vector.json")));
  const ck = await DHN.nip44.conversationKey(u(V.sk1), V.pub2);
  assert.strictEqual(h(ck), V.conversation_key); n++;
  const ck2 = await DHN.nip44.conversationKey(u(V.sk2), h(DHS.pubFromSecret(u(V.sk1))));
  assert.strictEqual(h(ck2), V.conversation_key); n++;                       // the same key from both sides
  for (const c of V.cases) {
    assert.strictEqual(await DHN.nip44.encrypt(ck, c.plaintext, u(V.nonce)), c.payload); n++;
    assert.strictEqual(await DHN.nip44.decrypt(ck, c.payload), c.plaintext); n++;
  }
  const bad = V.cases[1].payload.slice(0, 20) + (V.cases[1].payload[20] === "A" ? "B" : "A") + V.cases[1].payload.slice(21);
  await assert.rejects(DHN.nip44.decrypt(ck, bad)); n++;
  assert.deepStrictEqual([1, 32, 33, 37, 65, 100, 256, 257, 1000].map(DHN.nip44.padLen), [32, 32, 64, 64, 96, 128, 256, 320, 1024]); n++;
  // 2. bunker links
  const pk = "a".repeat(64);
  assert.deepStrictEqual(DHN.parseBunker("bunker://" + pk + "?relay=wss%3A%2F%2Frelay.example.com&relay=wss://r2.example&secret=xyz"),
    { remote: pk, relays: ["wss://relay.example.com", "wss://r2.example"], secret: "xyz" }); n++;
  assert.strictEqual(DHN.parseBunker("bunker://" + pk), null); n++;           // no relay: cannot connect
  assert.strictEqual(DHN.parseBunker("nostrconnect://" + pk + "?relay=wss://x"), null); n++;
  // 3. what a signer returns must be exactly the stamp event asked for
  const sk = DHS.newSecret(), pub = DHS.pubFromSecret(sk), doc = await DHV.sha256(new Uint8Array([7]));
  const msg = await DHS.sealMessage(pub, doc, 1795390000, await DHV.sha256(new Uint8Array([1])), null, 2);
  const signWith = async (ev, key) => { const id = await DHV.eventId(ev); return { ...ev, id: h(id), sig: h(await DHS.schnorrSign(id, key, new Uint8Array(32))) }; };
  const good = await signWith(msg.event, sk);
  const sig = await DHN.checkSigned(msg.event, JSON.stringify(good), h(pub));
  assert.ok(await DHV.schnorrVerify(msg.m, pub, sig)); n++;
  await assert.rejects(DHN.checkSigned(msg.event, await signWith({ ...msg.event, tags: [...msg.event.tags, ["client", "x"]] }, sk), h(pub)), /changed the record/); n++;
  await assert.rejects(DHN.checkSigned(msg.event, await signWith({ ...msg.event, created_at: msg.event.created_at + 1 }, sk), h(pub)), /changed the record/); n++;
  const other = DHS.newSecret();
  await assert.rejects(DHN.checkSigned(msg.event, await signWith({ ...msg.event, pubkey: h(DHS.pubFromSecret(other)) }, other), h(pub)), /different key/); n++;
  await assert.rejects(DHN.checkSigned(msg.event, { ...good, sig: "00".repeat(64) }, h(pub)), /does not check/); n++;
  console.log(`nostrsign.test.js: ${n} checks passed`);
})().catch(e => { console.error("FAIL", e); process.exit(1); });

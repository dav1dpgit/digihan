// The signer's name (run: node web/sealer/name.test.js; release 0.7.2). The name is a NIP-05 name in the public
// key's Nostr profile; it counts only when its domain lists that public key. verify.js reads and checks it (the
// scanner), publish.js builds the profile (the stamping page). The domain is a stand-in fetch here.
const assert = require("assert");
global.DHV = require("../scanner/verify.js");
globalThis.hashwasm = require("./vendor/argon2.umd.min.js");
global.DHS = require("./dhseal.js");
const DHP = require("./publish.js");
const h = DHV.hex;
const signWith = sk => async t => { const id = await DHV.eventId(t); return { ...t, id: h(id), sig: h(await DHS.schnorrSign(id, sk, new Uint8Array(32))) }; };

// a stand-in web server: fetch(url, init) -> Response-like; site(url, init) returns {status, body} or throws
function web(site) {
  const log = [];
  const f = async (url, init = {}) => {
    log.push({ url, init });
    const r = await site(url, init);
    return { ok: r.status >= 200 && r.status < 300, status: r.status, text: async () => r.body };
  };
  return { f, log };
}

(async () => {
  let n = 0; const ok = (c, what) => { assert.ok(c, what); n++; };

  // 1. names
  ok(DHV.parseName("dp@plotzwerks.com").text === "dp@plotzwerks.com", "a plain name");
  ok(DHV.parseName("  DP@PlotzWerks.COM ").text === "dp@plotzwerks.com", "case and spaces do not count");
  const und = DHV.parseName("_@digihan.org");
  ok(und.text === "digihan.org" && und.local === "_" && und.domain === "digihan.org", "_@domain shows as the domain");
  ok(DHV.parseName("a.b-c_d@sub.example.co.jp").domain === "sub.example.co.jp", "dots, dashes and subdomains");
  for (const bad of ["dp", "dp@", "@x.com", "dp@localhost", "a b@x.com", "dp@x.c", "dp@-x.com", "dp@x-.com", "dp@@x.com", "dp@x.com/path", 42, null, undefined, ""])
    ok(DHV.parseName(bad) === null, "not a name: " + JSON.stringify(bad));

  // 2. the newest valid profile of the key
  const sk = DHS.newSecret(), pub = h(DHS.pubFromSecret(sk)), sign = signWith(sk);
  const sk2 = DHS.newSecret(), pub2 = h(DHS.pubFromSecret(sk2)), sign2 = signWith(sk2);
  const prof = (at, content, s = sign, p = pub) => s({ pubkey: p, created_at: at, kind: 0, tags: [], content: JSON.stringify(content) });
  const p1 = await prof(100, { nip05: "old@example.com" }), p2 = await prof(200, { nip05: "dp@example.com" });
  const other = await prof(300, { nip05: "dp@example.com" }, sign2, pub2);
  const forged = { ...(await prof(400, { nip05: "x@example.com" })), sig: p1.sig };
  const wrongKind = await sign({ pubkey: pub, created_at: 500, kind: 1, tags: [], content: "{\"nip05\":\"y@example.com\"}" });
  ok((await DHV.newestProfile([p1, p2, other, forged, wrongKind], pub)).id === p2.id, "the newest valid profile of this public key");
  const t1 = await prof(600, { nip05: "a@example.com" }), t2 = await prof(600, { nip05: "b@example.com" });
  ok((await DHV.newestProfile([t1, t2], pub)).id === (t1.id < t2.id ? t1.id : t2.id), "same time: the lower id (NIP-01)");
  ok((await DHV.newestProfile([], pub)) === null && (await DHV.newestProfile([other], pub)) === null, "no profile of this public key");
  ok(DHV.profileName(p2) === "dp@example.com", "the profile's name");
  ok(DHV.profileName({ content: "not json" }) === null && DHV.profileName({ content: "{\"name\":\"x\"}" }) === null
     && DHV.profileName({ content: "{\"nip05\":\"  \"}" }) === null && DHV.profileName({ content: "{\"nip05\":7}" }) === null, "no name");

  // 3. asking the domain
  const list = names => ({ status: 200, body: JSON.stringify({ names }) });
  let w = web(() => list({ dp: pub }));
  let r = await DHV.checkName("dp@example.com", pub, w.f);
  ok(r.status === "confirmed" && r.name === "dp@example.com" && r.domain === "example.com", "the domain lists this public key: confirmed");
  ok(w.log[0].url === "https://example.com/.well-known/nostr.json?name=dp", "asks https://domain/.well-known/nostr.json?name=local");
  ok(w.log[0].init.redirect === "error" && w.log[0].init.credentials === "omit", "follows no redirect, sends no cookies");
  ok((await DHV.checkName("DP@Example.com", pub, web(() => list({ dp: pub.toUpperCase() })).f)).status === "confirmed", "case of the name and the hex do not count");
  ok((await DHV.checkName("_@example.com", pub, web(() => list({ _: pub })).f)).name === "example.com", "_@domain");
  ok((await DHV.checkName("dp@example.com", pub, web(() => list({ dp: pub2 })).f)).status === "other", "the name lists another public key: other");
  ok((await DHV.checkName("dp@example.com", pub, web(() => list({ david: pub })).f)).status === "unlisted", "the name is not listed: unlisted");
  ok((await DHV.checkName("dp@example.com", pub, web(() => ({ status: 200, body: "{}" })).f)).status === "unlisted", "no names at all: unlisted");
  ok((await DHV.checkName("dp@example.com", pub, web(() => ({ status: 404, body: "" })).f)).status === "unlisted", "no file (404): unlisted");
  ok((await DHV.checkName("dp@example.com", pub, web(() => ({ status: 200, body: "<!doctype html><title>Home</title>" })).f)).status === "unlisted", "a web page instead of the file: unlisted");
  ok((await DHV.checkName("dp@example.com", pub, web(() => ({ status: 500, body: "" })).f)).status === "unreachable", "a server error: unreachable");
  ok((await DHV.checkName("dp@example.com", pub, web(() => { throw new TypeError("Failed to fetch"); }).f)).status === "unreachable", "no answer, or not allowed to read it (CORS): unreachable");
  ok((await DHV.checkName("dp@example.com", pub, web((u, init) => { if (init.redirect === "error") throw new TypeError("redirect"); return list({ dp: pub }); }).f)).status === "unreachable", "a redirect: unreachable, never followed");
  const t0 = Date.now();
  r = await DHV.checkName("dp@example.com", pub, web((u, init) => new Promise((res, rej) => init.signal.addEventListener("abort", () => rej(new Error("aborted"))))).f, 300);
  ok(r.status === "unreachable" && Date.now() - t0 < 2000, "no answer in time: unreachable");
  w = web(() => list({ dp: pub }));
  ok((await DHV.checkName("not a name", pub, w.f)).status === "invalid" && w.log.length === 0, "not a name: nothing is asked");

  // 4. the profile the stamping page publishes
  let t = DHP.profileTemplate(pub, null, "dp@example.com", 1000);
  ok(t.kind === 0 && t.pubkey === pub && t.created_at === 1000 && JSON.parse(t.content).nip05 === "dp@example.com" && t.tags.length === 0, "a new profile holds the name");
  const full = await sign({ pubkey: pub, created_at: 5000, kind: 0, tags: [["i", "github:dp", "x"]], content: JSON.stringify({ name: "David", picture: "https://x/p.png", nip05: "old@example.com", lud16: "dp@example.com" }) });
  t = DHP.profileTemplate(pub, full, "dp@plotzwerks.com", 1000);
  const c = JSON.parse(t.content);
  ok(c.name === "David" && c.picture === "https://x/p.png" && c.lud16 === "dp@example.com" && c.nip05 === "dp@plotzwerks.com", "everything else in the profile is kept");
  ok(t.created_at === 5001 && t.tags.length === 1 && t.tags[0][0] === "i", "it replaces the newer profile; its tags are kept");
  for (const bad of ["not json", "[1,2]", "null", "\"text\""])
    assert.throws(() => DHP.profileTemplate(pub, { ...full, content: bad }, "dp@example.com", 1000), /could not be read/), n++;
  const signed = await sign(DHP.profileTemplate(pub, full, "dp@plotzwerks.com", 1000));
  ok(await DHV.eventValid(signed) && DHV.profileName(signed) === "dp@plotzwerks.com", "signed, it reads back");

  // 5. the profile from stand-in relays (the newest of what they hold; known only if one answered)
  class FakeWS {
    constructor(url) { this.url = url; setTimeout(() => this.onopen && this.onopen(), 1); }
    send(m) { const [, sub, filter] = JSON.parse(m);
      if (FakeWS.dead.includes(this.url)) return;
      const evs = (FakeWS.held[this.url] || []).filter(e => filter.kinds.includes(e.kind) && (!filter.authors || filter.authors.includes(e.pubkey)));
      setTimeout(() => { for (const e of evs) this.onmessage({ data: JSON.stringify(["EVENT", sub, e]) }); this.onmessage({ data: JSON.stringify(["EOSE", sub]) }); }, 2); }
    close() {}
  }
  global.WebSocket = FakeWS;
  const R = ["wss://a", "wss://b"];
  FakeWS.held = { "wss://a": [p1], "wss://b": [p2, other] }; FakeWS.dead = [];
  let got = await DHP.profile(R, pub);
  ok(got.known && got.ev.id === p2.id, "the newest profile across relays");
  FakeWS.held = {}; got = await DHP.profile(R, pub);
  ok(got.known && got.ev === null, "relays answered: no profile");
  FakeWS.dead = R; got = await DHP.profile(R, pub);
  ok(!got.known && got.ev === null, "no relay answered: not known (the page then publishes nothing)");

  console.log("name checks: " + n + " passed");
})().catch(e => { console.error(e); process.exit(1); });

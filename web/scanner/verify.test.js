// node web/scanner/verify.test.js  — BIP340 vectors, npub round trip, and a Python-made seal
const fs = require('fs'), path = require('path'), V = require('./verify.js');
(async () => {
  const rows = fs.readFileSync(path.join(__dirname, '..', '..', 'python', 'tests', 'bip340_test_vectors.csv'), 'utf8').trim().split('\n').slice(1);
  let ok = 0;
  for (const line of rows) {
    const c = line.split(',');           // index,secret key,public key,aux_rand,message,signature,verification result,comment
    const got = await V.schnorrVerify(V.unhex(c[4]), V.unhex(c[2]), V.unhex(c[5]));
    if (got === (c[6] === 'TRUE')) ok++; else console.log('vector', c[0], 'MISMATCH');
  }
  console.log(`BIP340 official vectors: ${ok}/${rows.length}`);
  const pk = V.unhex('b4f5c9c4e7f3f9fb1f1d6a7a2f2e9b7a4c6e1b2a3d4c5b6a7980716253443526');
  console.log('npub round trip:', V.hex(V.npubDecode(V.npubEncode(pk)) || []) === V.hex(pk) ? 'OK' : 'FAILED');
  if (process.argv[2]) {                  // a JSON case made by python: {payload, pubkey, doc_sha256, registration}
    const k = JSON.parse(fs.readFileSync(process.argv[2]));
    const good = await V.checkSeal(V.unhex(k.payload), V.unhex(k.pubkey), V.unhex(k.doc_sha256), [k.registration]);
    const bad = await V.checkSeal(V.unhex(k.payload), V.unhex(k.pubkey), V.unhex(k.doc_sha256.replace(/^./, c => c === '0' ? '1' : '0')), [k.registration]);
    console.log('python-made seal: valid =', good.ok, '| with a changed document: valid =', bad.ok, '-', bad.reason);
    process.exit(ok === rows.length && good.ok && !bad.ok ? 0 : 1);
  }
  process.exit(ok === rows.length ? 0 : 1);
})();

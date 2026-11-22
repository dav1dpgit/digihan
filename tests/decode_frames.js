// Decode the stress frames with the phone decoder (web/scanner/digihan.js) and print a table.
// Usage (from tests/, after make_frames.py):  node decode_frames.js          (the camera path)
//                                             node decode_frames.js photo    (the photo path)
//   after make_screens.py:                    node decode_frames.js photo screens
const fs = require('fs'), path = require('path');
const src = fs.readFileSync(path.join(__dirname, '..', 'web', 'scanner', 'digihan.js'), 'utf8');
const mod = { exports: {} };
(new Function('module', 'exports', src + ';module.exports.I={decodeGray,decodePhoto};'))(mod, mod.exports);
const rows = JSON.parse(fs.readFileSync(path.join('frames', (process.argv[3] || 'manifest') + '.json')));
const decode = process.argv[2] === 'photo' ? mod.exports.I.decodePhoto : mod.exports.I.decodeGray;
const by = new Map();
for (const r of rows) {
  const d = decode(new Uint8Array(fs.readFileSync(r.f)), r.w, r.h);
  const ok = !!d && Buffer.from(d.data).toString('hex') === r.payload;
  if (!by.has(r.cond)) by.set(r.cond, [0, 0]);
  const v = by.get(r.cond); v[0] += ok ? 1 : 0; v[1]++;
}
let a = 0, n = 0;
for (const [c, [k, m]] of by) { console.log(c.padEnd(34), `${k}/${m}`); a += k; n += m; }
console.log('TOTAL'.padEnd(34), `${a}/${n}`);

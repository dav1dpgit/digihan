// DigiHan ring decoder, format v0.4 (the ring is unchanged since v0.3) — self-contained JS port of digihan.py
// 2026-11-24 (release 0.6.2): a seal inside a seal — the outermost ring wins (see outermost(), below)
// 2026-11-24 (release 0.6.4): a stamped picture's seal is also found by its white disc (see sealPlates(), below)
// 2026-11-24 (release 0.6.5): a seal with a transparent background is read by its ink's colour (see inkGray(), below)
// Payload: 78 bytes = ver(4b)|flags(4b)|fingerprint(64b)|timestamp(40b)|sig(512b)
// Stream: 28-bit sync 0xE769C57 || RS(123,78) codeword bits, track-major from the innermost
// track; bit 0 starts at 12 o'clock under the key bridge and the stream runs clockwise.
"use strict";
const DECODER_RELEASE = "0.6.5";     // the scanner page compares this with its own release (an older copy shows up)

// v0.2: 28-bit sync 0xE769C57 (low cyclic autocorrelation, runs <= 3).
// 28 + 8*(78+45) === 1012 === ring capacity: no blank arc, spare capacity
// spent on parity. RS(123,78) corrects 22 byte errors (was 16).
const SYNC_BITS = [1,1,1,0,0,1,1,1, 0,1,1,0,1,0,0,1,
                   1,1,0,0,0,1,0,1, 0,1,1,1];
const PAYLOAD_BYTES = 78, NSYM = 45;
// v0.3 (format freeze): bit 0 starts at 12 o'clock under the key bridge and runs clockwise;
// the guard band between the center art and the locator ring is 1.2 mm (2 modules).
const START = -Math.PI / 2, GUARD_MM = 1.2;

// ---------------- GF(256) + Reed-Solomon decode (reedsolo port) ----------------
const GF_EXP = new Uint8Array(512), GF_LOG = new Uint8Array(256);
(function () {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x; GF_LOG[x] = i;
    x <<= 1; if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();
const gmul = (a, b) => (a && b) ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0;
const gdiv = (a, b) => a ? GF_EXP[(GF_LOG[a] - GF_LOG[b] + 255) % 255] : 0;
const gpow = (a, p) => GF_EXP[(GF_LOG[a] * p % 255 + 255) % 255];
const ginv = a => GF_EXP[255 - GF_LOG[a]];
function polyMul(p, q) {
  const r = new Array(p.length + q.length - 1).fill(0);
  for (let j = 0; j < q.length; j++)
    for (let i = 0; i < p.length; i++)
      r[i + j] ^= gmul(p[i], q[j]);
  return r;
}
function polyEval(p, x) {          // p in descending powers
  let y = p[0];
  for (let i = 1; i < p.length; i++) y = gmul(y, x) ^ p[i];
  return y;
}
function calcSyndromes(msg) {      // reedsolo: [0, s0..s_{nsym-1}]
  const s = [0];
  for (let i = 0; i < NSYM; i++) s.push(polyEval(msg, gpow(2, i)));
  return s;
}
function findErrorLocator(synd) {  // BM; returns descending-order locator
  let errLoc = [1], oldLoc = [1];
  const syndShift = synd.length - NSYM;
  for (let i = 0; i < NSYM; i++) {
    const K = i + syndShift;
    let delta = synd[K];
    for (let j = 1; j < errLoc.length; j++)
      delta ^= gmul(errLoc[errLoc.length - 1 - j], synd[K - j]);
    oldLoc.push(0);
    if (delta !== 0) {
      if (oldLoc.length > errLoc.length) {
        const newLoc = oldLoc.map(v => gmul(v, delta));
        oldLoc = errLoc.map(v => gdiv(v, delta));
        errLoc = newLoc;
      }
      const scaled = oldLoc.map(v => gmul(v, delta));
      const off = errLoc.length - scaled.length;
      for (let j = 0; j < scaled.length; j++) errLoc[off + j] ^= scaled[j];
    }
  }
  while (errLoc.length && errLoc[0] === 0) errLoc.shift();
  const errs = errLoc.length - 1;
  if (errs * 2 > NSYM) return null;
  return errLoc;
}
function findErrors(errLoc, nmess) {   // errLoc reversed (ascending)
  const pos = [];
  for (let i = 0; i < nmess; i++)
    if (polyEval(errLoc, gpow(2, i)) === 0) pos.push(nmess - 1 - i);
  return pos.length === errLoc.length - 1 ? pos : null;
}
function correctErrata(msg, synd, errPos) {
  const coefPos = errPos.map(p => msg.length - 1 - p);
  // errata locator, descending coeffs: prod (2^cp * x + 1)
  let errLoc = [1];
  for (const cp of coefPos) errLoc = polyMul(errLoc, [gpow(2, cp), 1]);
  // error evaluator: (synd_reversed * errLoc) mod x^(len)
  const syndRev = synd.slice().reverse();
  let errEval = polyMul(syndRev, errLoc);
  errEval = errEval.slice(errEval.length - (errLoc.length));  // last terms
  const X = coefPos.map(cp => gpow(2, cp));
  const out = Uint8Array.from(msg);
  for (let i = 0; i < X.length; i++) {
    const Xi = X[i], XiInv = ginv(Xi);
    let locPrime = 1;
    for (let j = 0; j < X.length; j++)
      if (j !== i) locPrime = gmul(locPrime, 1 ^ gmul(XiInv, X[j]));
    if (locPrime === 0) return null;
    let y = polyEval(errEval, XiInv);
    y = gmul(gpow(Xi, 1), y);
    out[errPos[i]] ^= gdiv(y, locPrime);
  }
  return out;
}
function rsDecode(cw) {           // cw: Uint8Array(123) -> {data, corrected}|null
  const synd = calcSyndromes(cw);
  if (Math.max(...synd) === 0)
    return { data: cw.slice(0, cw.length - NSYM), corrected: 0 };
  const errLoc = findErrorLocator(synd.slice(1));
  if (!errLoc) return null;
  const errPos = findErrors(errLoc.slice().reverse(), cw.length);
  if (!errPos) return null;
  const out = correctErrata(cw, synd, errPos);
  if (!out) return null;
  const check = calcSyndromes(out);
  if (Math.max(...check) !== 0) return null;
  return { data: out.slice(0, cw.length - NSYM), corrected: errPos.length };
}

// ---------------- geometry ----------------
function Geometry(d, nTracks, module, square) {
  const g = { d, square: !!square, frameGap: 0.5, frameW: 1.1 };
  g.squareSide = d + 2 * (g.frameGap + g.frameW);
  const R = d / 2;
  g.rRimOut = R; g.rRimIn = R - 0.9; g.rBandOut = g.rRimIn - 0.5;
  g.nTracks = nTracks; g.module = module; g.trackH = module * 1.15;
  g.rBandIn = g.rBandOut - nTracks * g.trackH;
  g.rLocOut = g.rBandIn - 0.4; g.rLocator = g.rLocOut - 0.7;
  g.rCenter = g.rLocator - GUARD_MM;
  g.trackR = []; g.cells = [];
  for (let i = 0; i < nTracks; i++) {
    const r = g.rBandIn + (i + 0.5) * g.trackH;
    g.trackR.push(r);
    g.cells.push(Math.floor(2 * Math.PI * r / module));
  }
  return g;
}
// v0.3 defines one size: 45 mm, 5 tracks, 0.6 mm modules (round or square).
const PROFILES = [Geometry(45, 5, 0.6, false), Geometry(45, 5, 0.6, true)];
const BRIDGE_ANGLES = Array.from({length: 8}, (_, j) => (-90 + 45*j) * Math.PI/180);

// ---------------- small linear algebra ----------------
function jacobiEig(Ain, nDim) {                 // symmetric nxn -> {vals, vecs}
  const n = nDim, A = Ain.map(r => r.slice());
  let V = Array.from({length: n}, (_, i) =>
    Array.from({length: n}, (_, j) => (i === j ? 1 : 0)));
  for (let sweep = 0; sweep < 30; sweep++) {
    let off = 0;
    for (let p = 0; p < n; p++) for (let q = p+1; q < n; q++) off += A[p][q]*A[p][q];
    if (off < 1e-18) break;
    for (let p = 0; p < n; p++) for (let q = p + 1; q < n; q++) {
      if (Math.abs(A[p][q]) < 1e-15) continue;
      const theta = (A[q][q] - A[p][p]) / (2 * A[p][q]);
      const t = Math.sign(theta || 1) / (Math.abs(theta) + Math.sqrt(theta*theta + 1));
      const c = 1 / Math.sqrt(t*t + 1), s = t * c;
      for (let k = 0; k < n; k++) {
        const akp = A[k][p], akq = A[k][q];
        A[k][p] = c*akp - s*akq; A[k][q] = s*akp + c*akq;
      }
      for (let k = 0; k < n; k++) {
        const apk = A[p][k], aqk = A[q][k];
        A[p][k] = c*apk - s*aqk; A[q][k] = s*apk + c*aqk;
      }
      for (let k = 0; k < n; k++) {
        const vkp = V[k][p], vkq = V[k][q];
        V[k][p] = c*vkp - s*vkq; V[k][q] = s*vkp + c*vkq;
      }
    }
  }
  return { vals: A.map((r, i) => r[i]), vecs: V };
}

function fitEllipse(pts) {        // -> {ctr:[x,y], M:[[a,b],[c,d]]} | null
  const n = pts.length;
  let mx = 0, my = 0, sd = 0;
  for (const [x, y] of pts) { mx += x; my += y; }
  mx /= n; my /= n;
  for (const [x, y] of pts) sd += (x-mx)*(x-mx) + (y-my)*(y-my);
  const s = Math.sqrt(sd / (2 * n)) || 1;
  // D columns: x2 xy y2 x y 1 (normalized); accumulate DtD 6x6
  const DtD = Array.from({length: 6}, () => new Array(6).fill(0));
  for (const [px, py] of pts) {
    const x = (px - mx)/s, y = (py - my)/s;
    const row = [x*x, x*y, y*y, x, y, 1];
    for (let i = 0; i < 6; i++) for (let j = i; j < 6; j++)
      DtD[i][j] += row[i]*row[j];
  }
  for (let i = 0; i < 6; i++) for (let j = 0; j < i; j++) DtD[i][j] = DtD[j][i];
  const { vals, vecs } = jacobiEig(DtD, 6);
  let mi = 0;
  for (let i = 1; i < 6; i++) if (vals[i] < vals[mi]) mi = i;
  const [a, b, c2, d, e, f] = vecs.map(r => r[mi]);
  const det = a*c2 - (b/2)*(b/2);
  if (Math.abs(det) < 1e-12) return null;
  const cx = (-(d/2)*c2 + (e/2)*(b/2)) / det;
  const cy = (-(e/2)*a + (d/2)*(b/2)) / det;
  const gsc = -(a*cx*cx + b*cx*cy + c2*cy*cy + d*cx + e*cy + f);
  if (Math.abs(gsc) < 1e-12) return null;
  const Q = [[a/gsc, (b/2)/gsc], [(b/2)/gsc, c2/gsc]];
  const eg = jacobiEig(Q, 2);
  if (eg.vals[0] <= 0 || eg.vals[1] <= 0) return null;
  const l1 = 1/Math.sqrt(eg.vals[0]), l2 = 1/Math.sqrt(eg.vals[1]);
  const v = eg.vecs;
  const M = [
    [v[0][0]*l1*v[0][0] + v[0][1]*l2*v[0][1], v[0][0]*l1*v[1][0] + v[0][1]*l2*v[1][1]],
    [v[1][0]*l1*v[0][0] + v[1][1]*l2*v[0][1], v[1][0]*l1*v[1][0] + v[1][1]*l2*v[1][1]],
  ];
  return { ctr: [cx*s + mx, cy*s + my], M: M.map(r => r.map(vv => vv*s)) };
}

// ---------------- image access ----------------
function otsu(gray) {
  const hist = new Float64Array(256);
  const step = Math.max(1, (gray.length / 60000) | 0);
  let n = 0;
  for (let i = 0; i < gray.length; i += step) { hist[gray[i]]++; n++; }
  let sum = 0;
  for (let t = 0; t < 256; t++) sum += t * hist[t];
  let sumB = 0, wB = 0, best = 0, th = 127;
  for (let t = 0; t < 256; t++) {
    wB += hist[t];
    if (wB === 0) continue;
    const wF = n - wB;
    if (wF === 0) break;
    sumB += t * hist[t];
    const mB = sumB / wB, mF = (sum - sumB) / wF;
    const between = wB * wF * (mB - mF) * (mB - mF);
    if (between > best) { best = between; th = t; }
  }
  return th;
}
function makeImg(gray, w, h) {
  const th = otsu(gray);
  const bin = new Uint8Array(w * h);
  for (let i = 0; i < w*h; i++) bin[i] = gray[i] < th ? 1 : 0;
  return { g: gray, bin, w, h, th };
}
function bil(im, x, y) {
  x = Math.min(Math.max(x, 0), im.w - 1.001);
  y = Math.min(Math.max(y, 0), im.h - 1.001);
  const x0 = x | 0, y0 = y | 0, fx = x - x0, fy = y - y0;
  const i = y0 * im.w + x0;
  return im.g[i]*(1-fx)*(1-fy) + im.g[i+1]*fx*(1-fy) +
         im.g[i+im.w]*(1-fx)*fy + im.g[i+im.w+1]*fx*fy;
}
function samplePts(im, xy, patch) {
  const out = new Float32Array(xy.length / 2);
  for (let k = 0; k < out.length; k++) {
    const x = xy[2*k], y = xy[2*k+1];
    let v = bil(im, x, y);
    if (patch > 0) {
      v += bil(im, x+patch, y) + bil(im, x-patch, y) +
           bil(im, x, y+patch) + bil(im, x, y-patch);
      v /= 5;
    }
    out[k] = v;
  }
  return out;
}
function bandThreshold(v) {
  const s = Float32Array.from(v).sort();
  const lo = s[Math.floor(0.08 * (s.length-1))];
  const hi = s[Math.floor(0.92 * (s.length-1))];
  return (lo + hi) / 2;
}

// ---------------- detection ----------------
function inkCentroid(im) {
  let sx = 0, sy = 0, n = 0;
  for (let y = 0; y < im.h; y += 2) for (let x = 0; x < im.w; x += 2)
    if (im.bin[y*im.w + x]) { sx += x; sy += y; n++; }
  return n < 50 ? null : [sx/n, sy/n, n];
}
function edgePoints(im, cx, cy, rmax, skipFrame) {
  const MINRUN = 3, MINGAP = 2;                 // px debounce vs noise specks
  const pts = [];
  for (let ai = 0; ai < 720; ai++) {
    const t = ai * Math.PI / 360, ct = Math.cos(t), st = Math.sin(t);
    // states: 0 seek first run, 1 inside first run, 2 seek gap-confirmed,
    //         3 seek second run (skipFrame only)
    let state = 0, run = 0, gap = 0, found = null, runStart = null;
    for (let r = rmax; r > rmax * 0.25; r -= 1.0) {
      const x = cx + r*ct, y = cy + r*st;
      if (x < 0 || y < 0 || x >= im.w-1 || y >= im.h-1) continue;
      const ink = im.bin[(y|0)*im.w + (x|0)];
      if (!skipFrame) {
        if (ink) { run++; if (runStart === null) runStart = [x, y];
                   if (run >= 2) { found = runStart; break; } }
        else { run = 0; runStart = null; }
      } else {
        if (state === 0) {
          if (ink) { run++; if (run >= MINRUN) { state = 1; gap = 0; } }
          else run = 0;
        } else if (state === 1) {
          if (!ink) { gap++; if (gap >= MINGAP) { state = 3; run = 0; runStart = null; } }
          else gap = 0;
        } else if (state === 3) {
          if (ink) { run++; if (runStart === null) runStart = [x, y];
                     if (run >= 2) { found = runStart; break; } }
          else { run = 0; runStart = null; }
        }
      }
    }
    if (found) pts.push(found);
  }
  return pts;
}

function inv2(M) {
  const det = M[0][0]*M[1][1] - M[0][1]*M[1][0];
  if (Math.abs(det) < 1e-9) return null;
  return [[ M[1][1]/det, -M[0][1]/det], [-M[1][0]/det, M[0][0]/det]];
}
function fitEllipseRobust(pts) {
  let fit = fitEllipse(pts);
  if (!fit) return null;
  for (let iter = 0; iter < 2; iter++) {
    const Minv = inv2(fit.M);
    if (!Minv) return fit;
    const dev = pts.map(([x, y]) => {
      const dx = x - fit.ctr[0], dy = y - fit.ctr[1];
      const u = Minv[0][0]*dx + Minv[0][1]*dy;
      const v = Minv[1][0]*dx + Minv[1][1]*dy;
      return Math.abs(Math.hypot(u, v) - 1);
    });
    const sorted = dev.slice().sort((a, b) => a - b);
    const med = sorted[sorted.length >> 1];
    const mad = sorted.map(d => Math.abs(d - med)).sort((a, b) => a - b)[sorted.length >> 1];
    const lim = med + Math.max(3 * mad, 0.01);
    const kept = pts.filter((_, i) => dev[i] <= lim);
    if (kept.length < pts.length * 0.5 || kept.length < 60) return fit;
    if (kept.length === pts.length) return fit;
    const nf = fitEllipse(kept);
    if (!nf) return fit;
    fit = nf; pts = kept;
  }
  return fit;
}

function findRimRound(im) {
  const c0 = inkCentroid(im);
  if (!c0) return null;
  let ctr = [c0[0], c0[1]], M = null;
  for (let it = 0; it < 4; it++) {
    const rmax = M ? Math.sqrt(Math.abs(M[0][0]*M[1][1]-M[0][1]*M[1][0]))*1.15
                   : Math.min(im.w, im.h)/2;
    const P = edgePoints(im, ctr[0], ctr[1], rmax, false);
    if (P.length < 300) return null;
    const fit = fitEllipseRobust(P);
    if (!fit) return null;
    const moved = Math.hypot(fit.ctr[0]-ctr[0], fit.ctr[1]-ctr[1]);
    ctr = fit.ctr; M = fit.M;
    if (moved < 0.3) break;
  }
  return { ctr, M };
}
function findSquareBox(im) {
  const c0 = inkCentroid(im);
  if (!c0) return null;
  let ctr = [c0[0], c0[1]];
  let box = null;
  const modeSide = (vals, approx, half) => {
    // mode of a 2px histogram in a +/-8% window around the approx side
    const win = Math.max(10, 0.08 * half);
    const hist = new Map();
    for (const v of vals) {
      if (Math.abs(v - approx) <= win) {
        const b = Math.round(v / 2) * 2;
        hist.set(b, (hist.get(b) || 0) + 1);
      }
    }
    let bb = approx, bc = 0;
    for (const [b, n] of hist) if (n > bc) { bc = n; bb = b; }
    return bc >= 8 ? bb : approx;
  };
  for (let it = 0; it < 3; it++) {
    const P = edgePoints(im, ctr[0], ctr[1], Math.hypot(im.w, im.h)/2, false);
    if (P.length < 200) return null;
    let best = null;
    for (let pd = 0; pd < 90; pd += 1) {
      const phi = pd * Math.PI/180, cp = Math.cos(phi), sp = Math.sin(phi);
      const u = [], v = [];
      for (const [x, y] of P) {
        u.push((x-ctr[0])*cp + (y-ctr[1])*sp);
        v.push(-(x-ctr[0])*sp + (y-ctr[1])*cp);
      }
      const us = u.slice().sort((a,b)=>a-b), vs = v.slice().sort((a,b)=>a-b);
      const q = (arr, f) => arr[Math.min(arr.length-1, Math.max(0, Math.round(f*(arr.length-1))))];
      const u0 = q(us,.025), u1 = q(us,.975), v0 = q(vs,.025), v1 = q(vs,.975);
      const area = (u1-u0)*(v1-v0);
      if (!best || area < best.area)
        best = { area, phi, u, v, u0, u1, v0, v1 };
    }
    const halfApprox = ((best.u1-best.u0)+(best.v1-best.v0))/4;
    const u1r = modeSide(best.u, best.u1, halfApprox);
    const u0r = modeSide(best.u, best.u0, halfApprox);
    const v1r = modeSide(best.v, best.v1, halfApprox);
    const v0r = modeSide(best.v, best.v0, halfApprox);
    const half = ((u1r-u0r)+(v1r-v0r))/4;
    const midU = (u1r+u0r)/2, midV = (v1r+v0r)/2;
    const cp = Math.cos(best.phi), sp = Math.sin(best.phi);
    const nctr = [ ctr[0] + midU*cp - midV*sp, ctr[1] + midU*sp + midV*cp ];
    const moved = Math.hypot(nctr[0]-ctr[0], nctr[1]-ctr[1]);
    ctr = nctr;
    box = { ctr, half, phi: best.phi };
    if (moved < 1.0) break;
  }
  return box;
}

function findRimSquare(im, g) {
  const box = findSquareBox(im);
  if (!box) return null;
  const kStart = (g.squareSide/2 - g.frameW*0.2) / (g.squareSide/2);
  let ctr = box.ctr, M = null;
  let rExp = box.half * (g.rRimOut / (g.squareSide/2));
  for (let it = 0; it < 4; it++) {
    const pts = [];
    for (let ai = 0; ai < 720; ai++) {
      const t = ai * Math.PI/360, ct = Math.cos(t), st = Math.sin(t);
      const rel = t - box.phi;
      const den = Math.max(Math.abs(Math.cos(rel)), Math.abs(Math.sin(rel)));
      const dEdge = box.half / Math.max(den, 1e-6);
      let run = 0, runStart = null, runR = 0, bestPt = null, bestD = 1e9;
      for (let r = kStart * dEdge; r > box.half * 0.55; r -= 1.0) {
        const x = ctr[0] + r*ct, y = ctr[1] + r*st;
        if (x < 0 || y < 0 || x >= im.w-1 || y >= im.h-1) { run = 0; runStart = null; continue; }
        if (im.bin[(y|0)*im.w + (x|0)]) {
          run++;
          if (runStart === null) { runStart = [x, y]; runR = r; }
          if (run === 2) {
            const d = Math.abs(runR - rExp);
            if (d < bestD) { bestD = d; bestPt = runStart; }
          }
        } else { run = 0; runStart = null; }
      }
      if (bestPt && bestD < rExp * 0.12) pts.push(bestPt);
    }
    if (pts.length < 200) return null;
    const fit = fitEllipseRobust(pts);
    if (!fit) return null;
    const moved = Math.hypot(fit.ctr[0]-ctr[0], fit.ctr[1]-ctr[1]);
    ctr = fit.ctr; M = fit.M;
    rExp = Math.sqrt(Math.abs(M[0][0]*M[1][1] - M[0][1]*M[1][0]));
    if (moved < 0.3) break;
  }
  return { ctr, M };
}
function findLocator(im, rim, g) {
  const rhoHi = (g.rBandIn - 0.05) / g.rRimOut;
  const rhoLo = (g.rCenter + 0.1) / g.rRimOut;
  const expW = (g.rLocOut - g.rLocator) / g.rRimOut;
  const pts = [];
  for (let k = 0; k < 360; k++) {
    const al = 2*Math.PI*k/360, u = [Math.cos(al), Math.sin(al)];
    const Mu = [rim.M[0][0]*u[0] + rim.M[0][1]*u[1],
                rim.M[1][0]*u[0] + rim.M[1][1]*u[1]];
    const prof = [], coords = [];
    for (let s = 0; s < 48; s++) {
      const rho = rhoHi + (rhoLo - rhoHi) * s / 47;
      const x = rim.ctr[0] + rho*Mu[0], y = rim.ctr[1] + rho*Mu[1];
      coords.push([x, y]); prof.push(bil(im, x, y));
    }
    let mn = 1e9, mx = -1e9;
    for (const v of prof) { if (v < mn) mn = v; if (v > mx) mx = v; }
    if (mx - mn < 40) continue;
    const th = (mn + mx)/2;
    let i = 0;
    while (i < 48 && prof[i] >= th) i++;
    if (i >= 48) continue;
    let j = i;
    while (j < 48 && prof[j] < th) j++;
    const w = Math.abs((rhoHi + (rhoLo-rhoHi)*Math.min(j,47)/47) -
                       (rhoHi + (rhoLo-rhoHi)*i/47));
    if (w > expW * 3.5) continue;
    pts.push(coords[i]);
  }
  if (pts.length < 90) return null;
  return fitEllipse(pts);
}

// ---------------- sampling in seal frame ----------------
function ringXY(anch, g, rMm, angArr) {
  const [rim, loc] = anch;
  const f = (rMm - g.rLocOut) / (g.rRimOut - g.rLocOut);
  const xy = new Float32Array(angArr.length * 2);
  for (let k = 0; k < angArr.length; k++) {
    const u0 = Math.cos(angArr[k]), u1 = Math.sin(angArr[k]);
    const pr0 = rim.ctr[0] + rim.M[0][0]*u0 + rim.M[0][1]*u1;
    const pr1 = rim.ctr[1] + rim.M[1][0]*u0 + rim.M[1][1]*u1;
    const pl0 = loc.ctr[0] + loc.M[0][0]*u0 + loc.M[0][1]*u1;
    const pl1 = loc.ctr[1] + loc.M[1][0]*u0 + loc.M[1][1]*u1;
    xy[2*k] = pl0 + f*(pr0 - pl0);
    xy[2*k+1] = pl1 + f*(pr1 - pl1);
  }
  return xy;
}
const mod2pi = a => ((a % (2*Math.PI)) + 2*Math.PI) % (2*Math.PI);
const wrapPi = a => mod2pi(a + Math.PI) - Math.PI;
function applyCal(angArr, cal) {
  if (!cal) return angArr;
  const { na, nd } = cal;
  return angArr.map(a => {
    const aa = mod2pi(a - na[0]) + na[0];
    let i = 0;
    while (i < na.length && !(aa >= na[i] && aa <= (i+1 < na.length ? na[i+1] : na[0] + 2*Math.PI))) i++;
    if (i >= na.length) i = na.length - 1;
    const a0 = na[i], a1 = (i+1 < na.length ? na[i+1] : na[0] + 2*Math.PI);
    const d0 = nd[i], d1 = (i+1 < na.length ? nd[i+1] : nd[0]);
    const t = a1 > a0 ? (aa - a0) / (a1 - a0) : 0;
    return a + d0 + t*(d1 - d0);
  });
}

function findBridgesBlind(im, anch, g, patch) {
  const rG = (g.rCenter + g.rLocator)/2, N = 1440;
  const ang = Array.from({length: N}, (_, i) => i * 2*Math.PI/N);
  const v = samplePts(im, ringXY(anch, g, rG, ang), patch);
  const th = bandThreshold(v);
  const ink = Array.from(v, x => x < th ? 1 : 0);
  let tot = ink.reduce((a,b)=>a+b,0);
  if (tot < 8 || tot > N/3) return null;
  let gap = ink.indexOf(0);
  if (gap < 0) return null;
  const runs = [];
  let i = 0;
  while (i < N) {
    const ii = (i + gap) % N;
    if (ink[ii]) {
      let j = i, wsum = 0, csum = 0;
      while (j < N && ink[(j + gap) % N]) {
        const w = Math.max(th - v[(j + gap) % N], 0);
        wsum += w; csum += j * w; j++;
      }
      runs.push({ ang: mod2pi(((csum/Math.max(wsum,1e-9)) + gap) * 2*Math.PI/N),
                  len: j - i });
      i = j;
    } else i++;
  }
  const cand = runs.filter(r => r.len >= 2 && r.len <= N*10/360);
  if (cand.length < 6) return null;
  cand.sort((a, b) => b.len - a.len);
  if (cand.length > 1 && cand[0].len < cand[1].len * 1.25) return null;
  const theta0 = mod2pi(cand[0].ang - BRIDGE_ANGLES[0]);
  const best = new Map();                         // slot -> {bd, exp, d}: one reading per slot
  for (const r of cand.slice(0, 12)) {
    let bj = 0, bd = 1e9;
    for (let j = 0; j < 8; j++) {
      const rel = Math.abs(wrapPi(r.ang - theta0 - BRIDGE_ANGLES[j]));
      if (rel < bd) { bd = rel; bj = j; }
    }
    if (bd < 12 * Math.PI/180 && (!best.has(bj) || bd < best.get(bj).bd)) {
      const exp = mod2pi(BRIDGE_ANGLES[bj] + theta0);
      best.set(bj, { bd, exp, d: wrapPi(r.ang - exp) });
    }
  }
  // v0.3: keep readings within 2.5 deg of the median offset. A real bridge sits within
  // ~2 deg of its slot; a stray ink run (often a signature stroke) sits 4-11 deg off.
  const all = [...best.values()];
  if (!all.length) return null;
  const ds = all.map(x => x.d).sort((a, b) => a - b);
  const med = ds.length % 2 ? ds[(ds.length - 1) / 2] : (ds[ds.length / 2 - 1] + ds[ds.length / 2]) / 2;
  const keep = all.filter(x => Math.abs(x.d - med) <= 2.5 * Math.PI / 180);
  if (keep.length < 5) return null;
  keep.sort((a, b) => a.exp - b.exp);
  return { theta0, cal: { na: keep.map(x => x.exp), nd: keep.map(x => x.d) } };
}

// ---------------- decode ----------------
function bitsToPayload(bits) {
  const total = (PAYLOAD_BYTES + NSYM) * 8;
  const body = bits.slice(SYNC_BITS.length, SYNC_BITS.length + total);
  const cw = new Uint8Array(PAYLOAD_BYTES + NSYM);
  for (let i = 0; i < cw.length; i++) {
    let b = 0;
    for (let k = 0; k < 8; k++) b = (b << 1) | body[i*8 + k];
    cw[i] = b;
  }
  // 0.6.5: version 0 is never a seal (SPEC section 5: versions 1 and 2). An all-zero codeword passes the
  // error correction trivially, and an even, dark area read through the inverted search can give one; it was
  // reported as a seal of zeros, and stopped the reading by colour from being tried
  const r = rsDecode(cw);
  return r && (r.data[0] >> 4) !== 0 ? r : null;
}

function decodeWithGeom(im, g) {
  const rim = g.square ? findRimSquare(im, g) : findRimRound(im);
  if (!rim) return null;
  let loc = findLocator(im, rim, g);
  if (!loc) loc = { ctr: rim.ctr,
                    M: rim.M.map(r => r.map(v => v * g.rLocOut / g.rRimOut)) };
  const anch = [rim, loc];
  const scale = Math.sqrt(Math.abs(rim.M[0][0]*rim.M[1][1] -
                                   rim.M[0][1]*rim.M[1][0])) / g.rRimOut;
  if (scale * g.module < 2.5) return null;      // below camera floor
  const patch = g.module * scale * 0.22;
  const C0 = g.cells[0], pitch = 2*Math.PI/C0, L = SYNC_BITS.length;

  const sampleTrack0 = (angArr, cal) =>
    samplePts(im, ringXY(anch, g, g.trackR[0], applyCal(angArr, cal)), patch);

  function fracRefine(base, cal) {
    let bs = -1e18, bf = 0;
    for (let fi = 0; fi <= 60; fi++) {
      const frac = -1.5 + 3.0 * fi / 60;
      const ang = Array.from({length: L}, (_, k) => base + (frac + k + 0.43)*pitch);
      const v = sampleTrack0(ang, cal);
      const th = bandThreshold(v);
      let s = 0;
      for (let k = 0; k < L; k++) s += (th - v[k]) * (SYNC_BITS[k] ? 1 : -1);
      if (s > bs) { bs = s; bf = frac; }
    }
    return base + bf * pitch;
  }
  function syncScore(theta, cal) {
    const ang = Array.from({length: L}, (_, k) => theta + (k + 0.43)*pitch);
    const v = sampleTrack0(ang, cal);
    const th = bandThreshold(v);
    let m = 0;
    for (let k = 0; k < L; k++) m += ((v[k] < th) ? 1 : 0) === SYNC_BITS[k] ? 1 : 0;
    return m;
  }
  const candidates = [];
  const blind = findBridgesBlind(im, anch, g, patch);
  if (blind) {
    const t = fracRefine(blind.theta0 + START, blind.cal);   // v0.3: bit 0 starts under the key bridge
    if (syncScore(t, blind.cal) >= L - 4) candidates.push([t, blind.cal]);
  }
  { // coarse sync search at 1/3-cell steps
    const SUB = 3;
    const subAng = Array.from({length: C0*SUB}, (_, i) => (i/SUB + 0.43)*pitch);
    const v = sampleTrack0(subAng, null);
    const th = bandThreshold(v);
    const b = Array.from(v, x => x < th ? 1 : 0);
    let bb = -1, bo = 0;
    for (let off = 0; off < C0*SUB; off++) {
      let m = 0;
      for (let k = 0; k < L; k++)
        m += b[(off + k*SUB) % (C0*SUB)] === SYNC_BITS[k] ? 1 : 0;
      if (m > bb) { bb = m; bo = off; }
    }
    if (bb >= L - 4) {
      let t0 = fracRefine((bo/SUB) * pitch, null);
      // cal at t0 via targeted bridge measurement (reuse blind cal machinery
      // by shifting: cheap approach — reuse blind if it exists, else none)
      const cal = blind ? blind.cal : null;
      t0 = cal ? fracRefine(t0, cal) : t0;
      const dup = candidates.length &&
        Math.abs(wrapPi(t0 - candidates[0][0])) < 0.25 * pitch;
      if (!dup) candidates.push([t0, cal]);
    }
  }
  if (!candidates.length) return null;
  const attempts = [[patch,0,0],[0,0,0],[patch,-8,0],[patch,8,0],
                    [0,-12,0],[0,12,0],[patch,0,0.15],[patch,0,-0.15]];
  for (const [thetaC, cal] of candidates) {
    for (const useCal of (cal ? [true, false] : [false])) {
      // v0.3: the no-calibration retry refines its own start angle
      const theta0 = useCal ? thetaC : fracRefine(thetaC, null);
      for (const [p, tb, dr] of attempts) {
        const bits = [];
        for (let t = 0; t < g.nTracks; t++) {
          const C = g.cells[t];
          const rMm = g.trackR[t] + dr * g.module;
          let ang = Array.from({length: C}, (_, i) => theta0 + (i + 0.43)*2*Math.PI/C);
          if (useCal) ang = applyCal(ang, cal);
          const v = samplePts(im, ringXY(anch, g, rMm, ang), p);
          const th = bandThreshold(v) + tb;
          for (let i = 0; i < C; i++) bits.push(v[i] < th ? 1 : 0);
        }
        const res = bitsToPayload(bits);
        // cx, cy, rimPx: where the ring was found (its rim's centre and outer radius, in this image's pixels),
        // so a ring found inside another seal's artwork can be told from that seal (see outermost below)
        if (res) return { ...res, geom: g, scale, cx: rim.ctr[0], cy: rim.ctr[1], rimPx: scale * g.rRimOut };
      }
    }
  }
  return null;
}

function parsePayload(p) {
  const ver = p[0] >> 4, flags = p[0] & 0xf;
  const fp = Array.from(p.slice(1, 9), b => b.toString(16).padStart(2, "0")).join("");
  let ts = 0;
  for (let i = 9; i < 14; i++) ts = ts * 256 + p[i];
  const sig = Array.from(p.slice(14), b => b.toString(16).padStart(2, "0")).join("");
  return { ver, flags, fp, ts, sig };
}

function cropCenter(gray, w, h, frac) {
  const s = Math.round(Math.min(w, h) * frac);
  const x0 = (w - s) >> 1, y0 = (h - s) >> 1;
  const out = new Uint8Array(s * s);
  for (let y = 0; y < s; y++)
    out.set(gray.subarray((y0 + y) * w + x0, (y0 + y) * w + x0 + s), y * s);
  return { g: out, w: s, h: s };
}

// ---------------- a seal inside a seal: the outermost ring wins (2026-11-24) ----------------
// A seal's artwork can itself be a picture of a seal, ring and all. That inner ring is readable, and it is
// a real seal's data, but it is not the seal being looked at: it is artwork. Every search below can find it
// first (the tight centre crop holds only the inner ring), so a ring that is read is not the answer until
// the larger crops have been tried too; a larger ring that encloses it is the seal. Enclosing: the inner
// ring lies inside the outer seal's centre circle (rCenter / rRimOut = 0.68 of the rim; 0.8 allows for a
// tilted photo). Positions are in the pixels of the whole picture; shift() moves a crop's result there.
const shift = (r, x0, y0) => r && { ...r, cx: r.cx + x0, cy: r.cy + y0 };
function encloses(o, r) {
  return o.rimPx > r.rimPx * 1.2 && Math.hypot(o.cx - r.cx, o.cy - r.cy) + r.rimPx <= o.rimPx * 0.8;
}
function outermost(best, r) {
  if (!r) return best;
  if (!best) return r;
  return encloses(r, best) ? r : best;
}

function decodeGray(gray, w, h) {
  // crop ladder: user centers the seal in the reticle, so try tight first;
  // each crop gets its own Otsu threshold (handles gradients + desk clutter)
  // 0.9 x min-dimension primary region,
  // NO downscale (px-per-module is the load-bearing variable). Tighter and
  // full-frame rungs follow for clutter/framing variance.
  // 2026-11-24: after a ring is read, the larger crops are still tried; a ring there that encloses it wins
  // (a seal inside a seal). A frame where nothing is read costs the same as before.
  const crops = [0.72, 0.9, -1];               // -1 = full uncropped frame
  let best = null;
  for (const fc of crops) {
    let im, x0 = 0, y0 = 0;
    if (fc < 0) im = makeImg(gray, w, h);
    else {
      const c = cropCenter(gray, w, h, fc);
      im = makeImg(c.g, c.w, c.h); x0 = (w - c.w) >> 1; y0 = (h - c.h) >> 1;
    }
    for (const g of PROFILES) {
      const r = decodeWithGeom(im, g);
      if (r) { best = outermost(best, shift(r, x0, y0)); break; }
    }
  }
  return best;
}

// ---------------- photos: find the seal by its outline first ----------------
// A photo or screenshot can hold a lot besides the seal: text, a phone's toolbar (dark in dark mode),
// the seal off center or filling the width. The crop ladder above assumes a centered seal, and a large
// dark block drags the ink centroid away from it. So for photos, find hollow, roughly round (or square)
// ink outlines — the seal's rim or frame — and read the ring inside each one.
function sealOutlines(gray, w, h) {
  const S = 2, W = Math.ceil(w / S), H = Math.ceil(h / S);      // label on a half-size ink mask
  const th = otsu(gray), bin = new Uint8Array(W * H);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++)
    if (gray[y*w + x] < th) bin[((y / S) | 0) * W + ((x / S) | 0)] = 1;
  const lab = new Int32Array(W * H), stack = new Int32Array(W * H), out = [];
  let next = 0;
  for (let s = 0; s < W * H; s++) {
    if (!bin[s] || lab[s]) continue;
    next++;
    let sp = 0, n = 0, x0 = W, y0 = H, x1 = 0, y1 = 0, sx = 0, sy = 0;
    stack[sp++] = s; lab[s] = next;
    while (sp) {
      const p = stack[--sp], px = p % W, py = (p / W) | 0;
      n++; sx += px; sy += py;
      if (px < x0) x0 = px; if (px > x1) x1 = px; if (py < y0) y0 = py; if (py > y1) y1 = py;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        const qx = px + dx, qy = py + dy;
        if (qx < 0 || qy < 0 || qx >= W || qy >= H) continue;
        const q = qy * W + qx;
        if (bin[q] && !lab[q]) { lab[q] = next; stack[sp++] = q; }
      }
    }
    const bw = x1 - x0 + 1, bh = y1 - y0 + 1;
    if (Math.min(bw, bh) * S < 100) continue;                    // smaller than any readable seal
    if (bw / bh > 1.6 || bh / bw > 1.6) continue;                // not round or square, even tilted
    if (n / (bw * bh) > 0.45) continue;                          // a solid block (a toolbar), not an outline
    const mx = (x0 + x1) / 2, my = (y0 + y1) / 2;
    if (Math.abs(sx / n - mx) > 0.12 * bw || Math.abs(sy / n - my) > 0.12 * bh) continue;  // lopsided
    if (lab[(my | 0) * W + (mx | 0)] === next) continue;         // not hollow
    out.push({ cx: mx * S + S / 2, cy: my * S + S / 2, side: Math.max(bw, bh) * S, area: bw * bh });
  }
  out.sort((a, b) => b.area - a.area);
  return out.slice(0, 4);
}
function cropBox(gray, w, h, cx, cy, side) {
  const x0 = Math.max(0, Math.round(cx - side / 2)), y0 = Math.max(0, Math.round(cy - side / 2));
  const x1 = Math.min(w, Math.round(cx + side / 2)), y1 = Math.min(h, Math.round(cy + side / 2));
  const cw = x1 - x0, ch = y1 - y0, out = new Uint8Array(cw * ch);
  for (let y = 0; y < ch; y++) out.set(gray.subarray((y0 + y) * w + x0, (y0 + y) * w + x1), y * cw);
  return { g: out, w: cw, h: ch };
}
function decodeOutlines(gray, w, h) {
  // largest outline first, so an outer seal is tried before any seal drawn in its artwork; every outline is
  // still tried, and only a ring that encloses the one already read replaces it
  let best = null;
  for (const o of sealOutlines(gray, w, h)) {
    const side = o.side * 1.22;                                   // the rim plus a quiet margin
    const x0 = Math.max(0, Math.round(o.cx - side / 2)), y0 = Math.max(0, Math.round(o.cy - side / 2));   // as cropBox
    const c = cropBox(gray, w, h, o.cx, o.cy, side);
    const im = makeImg(c.g, c.w, c.h);
    for (const g of PROFILES) {
      const r = decodeWithGeom(im, g);
      if (r) { best = outermost(best, shift(r, x0, y0)); break; }
    }
  }
  return best;
}
// For a still picture: the camera's ladder first, then the outline search; each also inverted, for a
// seal shown light on dark.
// A seal in a corner of a larger picture (the stamping page's "picture with the seal in a corner"): the
// outline search above ranks a busy photo's own shapes first, so each corner is also tried as a square
// crop, read like a camera frame. The stamping page puts the seal, on a white disc, 3% from the edges.
function decodeCorners(gray, w, h) {
  const s = Math.min(w, h), SIZES = [0.36, 0.46, 0.58, 0.28, 0.72, 0.9];   // larger crops last: a seal filling most of a small picture
  const at = (f, k) => {                                      // corner k (0..3) as a square crop of side s*f, or null
    const side = Math.round(s * f);
    if (side < 100) return null;
    const [cx, cy] = [[w - side / 2, h - side / 2], [side / 2, h - side / 2], [w - side / 2, side / 2], [side / 2, side / 2]][k];
    const c = cropBox(gray, w, h, cx, cy, side);
    return shift(decodeGray(c.g, c.w, c.h), Math.max(0, Math.round(cx - side / 2)), Math.max(0, Math.round(cy - side / 2)));
  };
  for (const f of SIZES) for (let k = 0; k < 4; k++) {
    let r = at(f, k);
    if (!r) continue;
    // the larger crops of the same corner: a seal around this one (a seal inside a seal) wins
    for (const f2 of SIZES) if (f2 > f) r = outermost(r, at(f2, k));
    return r;
  }
  return null;
}
// 0.6.4: a stamped picture's seal sits on a white disc (the stamping page's plate, 1.2 x the seal), in a corner,
// or raised above a corner by the website label under it. On a dark or busy photo one threshold for the whole
// picture can miss the seal's own outline, and a corner crop misses a raised seal; so the disc itself is
// looked for: near-white, roughly round, hollow (the seal is inside it), at least 100 px across. Each disc
// found is cropped and read like a camera frame, with its own threshold.
function sealPlates(gray, w, h) {
  const S = 2, W = Math.ceil(w / S), H = Math.ceil(h / S), bin = new Uint8Array(W * H);
  for (let y = 0; y < h; y += S) for (let x = 0; x < w; x += S) if (gray[y * w + x] >= 235) bin[(y / S) * W + x / S] = 1;
  const lab = new Int32Array(W * H), stack = new Int32Array(W * H), out = [];
  let next = 0;
  for (let s = 0; s < W * H; s++) {
    if (!bin[s] || lab[s]) continue;
    next++;
    let sp = 0, n = 0, x0 = W, y0 = H, x1 = 0, y1 = 0;
    stack[sp++] = s; lab[s] = next;
    while (sp) {
      const p = stack[--sp], px = p % W, py = (p / W) | 0;
      n++; if (px < x0) x0 = px; if (px > x1) x1 = px; if (py < y0) y0 = py; if (py > y1) y1 = py;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        const qx = px + dx, qy = py + dy;
        if (qx < 0 || qy < 0 || qx >= W || qy >= H) continue;
        const q = qy * W + qx;
        if (bin[q] && !lab[q]) { lab[q] = next; stack[sp++] = q; }
      }
    }
    const bw = x1 - x0 + 1, bh = y1 - y0 + 1;
    if (Math.min(bw, bh) * S < 100 || bw / bh > 1.3 || bh / bw > 1.3) continue;      // too small, or not round
    if (n / (bw * bh) > 0.7) continue;                                              // a solid bright area, not a disc around a seal
    const mx = (x0 + x1) / 2, my = (y0 + y1) / 2;
    if (lab[(my | 0) * W + (mx | 0)] === next) continue;                           // not hollow: no seal inside
    out.push({ cx: mx * S + S / 2, cy: my * S + S / 2, side: Math.max(bw, bh) * S, area: bw * bh });
  }
  out.sort((a, b) => b.area - a.area);
  return out.slice(0, 4);
}
function decodePlates(gray, w, h) {
  let best = null;
  for (const o of sealPlates(gray, w, h)) {
    const side = o.side * 1.06, x0 = Math.max(0, Math.round(o.cx - side / 2)), y0 = Math.max(0, Math.round(o.cy - side / 2));
    const c = cropBox(gray, w, h, o.cx, o.cy, side);
    best = outermost(best, shift(decodeGray(c.g, c.w, c.h), x0, y0));
  }
  return best;
}
function decodePhoto(gray, w, h) {
  // the centre crops, then the outlines (each tried even after a ring is read, for a seal around it); when
  // neither read anything, the white discs (0.6.4), then the corners
  let r = outermost(decodeGray(gray, w, h), decodeOutlines(gray, w, h)) || decodePlates(gray, w, h) || decodeCorners(gray, w, h);
  if (r) return r;
  const inv = new Uint8Array(gray.length);
  for (let i = 0; i < gray.length; i++) inv[i] = 255 - gray[i];
  return outermost(decodeGray(inv, w, h), decodeOutlines(inv, w, h));
}

// ---------------- 0.6.5: a seal with a transparent background ----------------
// The stamping page can draw the seal on a picture with no white disc behind it, so the picture shows between
// its dots. In plain grey the picture's own dark parts then look like ink. The ring's ink is vermilion
// (178, 56, 44), so a second grey picture is made from colour: dark where a pixel is red to orange (hue about
// -20 to +35 degrees) by how much colour it has (the largest of r, g, b minus the smallest), white
// everywhere else, so the picture's black, grey and white parts all become paper.
function inkGray(rgba, w, h) {
  const out = new Uint8Array(w * h);
  for (let i = 0, j = 0; j < out.length; i += 4, j++) {
    const r = rgba[i], g = rgba[i + 1], b = rgba[i + 2], c = r - (g < b ? g : b);
    let v = 255;
    if (r >= g && r >= b && c > 20) { const hue = (g - b) / c; if (hue > -0.35 && hue < 0.6) v = c >= 128 ? 0 : 255 - 2 * c; }
    out[j] = v;
  }
  return out;
}
// a still picture (RGBA, as a canvas gives it): read in grey first, then by the ink's colour
function decodePicture(rgba, w, h) {
  const gray = new Uint8Array(w * h);
  for (let i = 0, j = 0; j < gray.length; i += 4, j++) gray[j] = (rgba[i] * 299 + rgba[i + 1] * 587 + rgba[i + 2] * 114) / 1000 | 0;
  return decodePhoto(gray, w, h) || decodeInk(inkGray(rgba, w, h), w, h);
}
// a camera frame read by the ink's colour: the centre crops, and the outlines (the picture around the seal can
// have red or orange next to it, which the centre crops take in; the rim's outline is found apart from it)
function decodeInkFrame(ink, w, h) {
  return outermost(decodeGray(ink, w, h), decodeOutlines(ink, w, h));
}
// the ink-colour picture: as decodePhoto, but never inverted (in it the ink is always the dark part)
function decodeInk(ink, w, h) {
  return outermost(decodeGray(ink, w, h), decodeOutlines(ink, w, h)) || decodePlates(ink, w, h) || decodeCorners(ink, w, h);
}

if (typeof module !== "undefined") {
  module.exports = { DECODER_RELEASE, decodeGray, decodePhoto, decodePicture, decodeInk, decodeInkFrame, inkGray, decodeCorners, decodePlates, sealPlates, sealOutlines, decodeWithGeom, makeImg, Geometry, PROFILES,
                     parsePayload, rsDecode };
}

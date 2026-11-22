"""Camera-stress frames for the phone decoder: 11 conditions x 20 frames, fixed random draws.
Usage (from tests/):  python make_frames.py [--art ../python/sample_center.png] [--n 20]
Writes frames/*.gray (8-bit raw) and frames/manifest.json; then run:  node decode_frames.js"""
import argparse, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))
import numpy as np
from multiprocessing import Pool
from PIL import Image
import digihan as dh
from battery import degrade, CONDITIONS

G = dh.Geometry(45, 5, 0.6); DPMM = 15.0
ap = argparse.ArgumentParser()
ap.add_argument("--art", default=os.path.join(HERE, "..", "python", "sample_center.png"))
ap.add_argument("--n", type=int, default=20)
A = ap.parse_args()
ART = Image.open(A.art).convert("RGBA")


def seal(payload):
    ring = dh.render(G, dh.build_stream(payload, 45), DPMM, "empty", cell="dot")
    a = np.asarray(ring); rgb = np.full(a.shape + (3,), 255, np.uint8); rgb[a < 128] = (178, 56, 44)
    S = a.shape[0]; c = S / 2; r_art = (G.r_center - 0.4) * DPMM
    w, h = ART.size; sc = 2 * r_art / np.hypot(w, h)
    a2 = ART.resize((max(1, int(w * sc)), max(1, int(h * sc))), Image.LANCZOS)
    lay = Image.new("RGBA", (S, S), (0, 0, 0, 0)); lay.paste(a2, (int(c - a2.width / 2), int(c - a2.height / 2)))
    yy, xx = np.mgrid[0:S, 0:S]; clip = ((xx - c) ** 2 + (yy - c) ** 2) <= ((G.r_center - 0.2) * DPMM) ** 2
    la = np.asarray(lay).copy(); la[..., 3] = la[..., 3] * clip
    im = Image.fromarray(rgb).convert("RGBA"); im.alpha_composite(Image.fromarray(la)); im = im.convert("L")
    F = int(S / 0.6); fr = Image.new("L", (F, F), 255); fr.paste(im, ((F - S) // 2, (F - S) // 2))   # seal fills 60%
    return fr


def job(args):
    ci, t = args
    name, ppm, blur, noise, jpeg, ig, tilt, pap = CONDITIONS[ci]
    payload = np.random.default_rng(1000 * ci + t).integers(0, 256, 78, dtype=np.uint8).tobytes()
    img = degrade(seal(payload), np.random.default_rng(50000 + 1000 * ci + t), ppm, G, DPMM, blur, noise, jpeg, True, ig, tilt, pap)
    a = np.asarray(img.convert("L"), np.uint8); fn = os.path.join("frames", f"{ci}_{t}.gray"); a.tofile(fn)
    return {"ci": ci, "cond": name, "t": t, "f": fn, "w": int(a.shape[1]), "h": int(a.shape[0]), "payload": payload.hex()}


if __name__ == "__main__":
    os.makedirs("frames", exist_ok=True)
    with Pool() as p:
        rows = p.map(job, [(ci, t) for ci in range(len(CONDITIONS)) for t in range(A.n)], chunksize=4)
    json.dump(rows, open(os.path.join("frames", "manifest.json"), "w")); print("frames", len(rows))

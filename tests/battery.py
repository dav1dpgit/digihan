"""DigiHan camera-damage battery: rotation, scale, tilt, blur, noise, JPEG, ink spread, paper."""
import io, sys
import numpy as np
from PIL import Image, ImageFilter
from digihan import Geometry, build_stream, render, decode, PAYLOAD_BYTES

NSYM = 45
N_TRIALS = 25

def _persp_coeffs(src, dst):
    A = []
    for (x, y), (u, v) in zip(src, dst):
        A.append([x, y, 1, 0, 0, 0, -u*x, -u*y])
        A.append([0, 0, 0, x, y, 1, -v*x, -v*y])
    b = np.array(dst).reshape(8)
    return np.linalg.solve(np.array(A, dtype=float), b)

def perspective(img, rng, tilt_deg):
    """Simulate a camera tilt: foreshorten one axis by cos(tilt) + keystone."""
    w, h = img.size
    t = np.deg2rad(tilt_deg)
    fore = np.cos(t)
    # physically honest keystone: seal half-width s at distance D=20cm
    key = 2 * 22.5 * np.sin(t) / 200.0
    theta = rng.uniform(0, np.pi)           # tilt axis direction
    # destination corners: shrink along tilt axis + asymmetric keystone
    corners = np.array([[0,0],[w,0],[w,h],[0,h]], float)
    c = corners - [w/2, h/2]
    R = np.array([[np.cos(theta), -np.sin(theta)],[np.sin(theta), np.cos(theta)]])
    cr = c @ R.T
    cr[:,1] *= fore
    cr[:,0] *= (1 + key * np.sign(cr[:,1]) * abs(cr[:,1])/(h/2))
    dst = cr @ R + [w/2, h/2]
    # PIL wants map dst->src
    coeffs = _persp_coeffs(dst.tolist(), corners.tolist())
    return img.transform((w, h), Image.PERSPECTIVE, coeffs,
                         resample=Image.BICUBIC, fillcolor=255)

def paper(img, rng, mottle=0.10, grain=6.0):
    """Multiplicative low-frequency mottle + additive fine grain."""
    a = np.asarray(img, dtype=np.float32)
    small = rng.normal(1.0, mottle, (max(2, a.shape[0]//40),
                                     max(2, a.shape[1]//40)))
    field = np.asarray(Image.fromarray(
        np.clip(small*127, 0, 255).astype(np.uint8)).resize(
        (a.shape[1], a.shape[0]), Image.BICUBIC), np.float32) / 127.0
    a = 255 - (255 - a) * np.clip(field, 0.75, 1.25)   # mottle affects ink
    a = a * np.clip(field, 0.9, 1.1)                    # and paper brightness
    a = a + rng.normal(0, grain, a.shape)
    return Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))

def degrade(img, rng, px_per_module, geom, dpmm, blur=0.0, noise=0.0,
            jpeg=None, rot=True, ink_gain=0, tilt=0.0, paper_sim=False):
    if rot:
        img = img.rotate(rng.uniform(0, 360), resample=Image.BICUBIC,
                         expand=True, fillcolor=255)
    if tilt > 0:
        img = perspective(img, rng, tilt)
    if ink_gain > 0:
        img = img.filter(ImageFilter.MinFilter(ink_gain * 2 + 1))  # ink spread
    elif ink_gain < 0:
        img = img.filter(ImageFilter.MaxFilter(-ink_gain * 2 + 1)) # ink loss
    # camera resolution sim: rescale so one module = px_per_module pixels
    cur = geom.module * dpmm
    f = px_per_module / cur
    img = img.resize((max(32, int(img.width * f)),) * 2, Image.LANCZOS)
    if paper_sim:
        img = paper(img, rng)
    if blur > 0:
        img = img.filter(ImageFilter.GaussianBlur(blur))
    a = np.asarray(img, dtype=np.float32)
    if noise > 0:
        a = a + rng.normal(0, noise, a.shape)
    a = np.clip(a, 0, 255).astype(np.uint8)
    img = Image.fromarray(a)
    if jpeg:
        buf = io.BytesIO()
        img.convert("RGB").save(buf, "JPEG", quality=jpeg)
        img = Image.open(io.BytesIO(buf.getvalue())).convert("L")
    return img

CONDITIONS = [
    # name,                          ppm, blur, noise, jpeg, ink, tilt, paper
    ("rotation only, 6 px/module",     6, 0.0,   0,  None,  0,    0, False),
    ("4 px/module",                    4, 0.0,   0,  None,  0,    0, False),
    ("tilt 10 deg",                    6, 0.0,   0,  None,  0,   10, False),
    ("tilt 20 deg",                    6, 0.0,   0,  None,  0,   20, False),
    ("tilt 30 deg",                    6, 0.0,   0,  None,  0,   30, False),
    ("paper texture",                  6, 0.0,   0,  None,  0,    0, True),
    ("paper + tilt 15",                6, 0.0,   0,  None,  0,   15, True),
    ("6 ppm + ink spread 1px",         6, 0.0,   0,  None,  1,    0, False),
    ("6 ppm + ink loss 1px",           6, 0.0,   0,  None, -1,    0, False),
    ("phone-ish: 5ppm b.7 n8 q70 t8",  5, 0.7,   8,    70,  0,    8, True),
    ("hostile: 4ppm b1 n12 q55 t15",   4, 1.0,  12,    55,  0,   15, True),
]

def run(geoms, centers=("dense",)):
    rng = np.random.default_rng(1)
    print(f"{'geometry':<18} {'center':<6} {'condition':<30} {'ok':>5} {'avg corr':>9}")
    for (d, nt, m) in geoms:
        g = Geometry(d, nt, m)
        dpmm = 15.0
        for cmode in centers:
            for (name, ppm, blur, noise, jpeg, ig, tilt, pap) in CONDITIONS:
                ok, corr = 0, []
                for _ in range(N_TRIALS):
                    payload = rng.integers(0, 256, PAYLOAD_BYTES,
                                           dtype=np.uint8).tobytes()
                    img = render(g, build_stream(payload, NSYM), dpmm, cmode)
                    img = degrade(img, rng, ppm, g, dpmm, blur, noise, jpeg,
                                  True, ig, tilt, pap)
                    try:
                        out, ne = decode(img, g, NSYM)
                        if out == payload:
                            ok += 1
                            corr.append(ne)
                    except Exception:
                        pass
                ac = f"{np.mean(corr):.1f}" if corr else "-"
                print(f"{d}mm/{nt}t/{m}mm{'':<4} {cmode:<6} {name:<30} "
                      f"{ok:>2}/{N_TRIALS} {ac:>9}")

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "main"
    if which == "main":
        run([(45, 5, 0.6)], centers=("dense", "empty", "text"))
    elif which == "geo":
        run([(40, 5, 0.5), (45, 6, 0.7)])

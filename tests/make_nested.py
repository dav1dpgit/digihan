"""A seal inside a seal (2026-11-24): frames where the seal's artwork is itself a picture of another seal, ring
and all, the way the stamping page draws an uploaded picture (cropped to a square, filling the centre
circle). The inner ring is readable; the decoder must read the OUTER ring, which is the seal. The manifest's
payload is the outer seal's, so decode_frames.js counts a frame read as the inner seal as a failure.
Layouts: the inner seal filling the centre; a smaller inner seal off centre; three deep (the inner seal holds
another). Each under three camera conditions with the seal filling 60%, 80% and 95% of the frame (the
tighter, the more the centre crops hold only the inner ring), plus a phone screenshot of each.
Usage (from tests/):  python make_nested.py && node decode_frames.js camera nested && node decode_frames.js photo nested"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))
import numpy as np
from PIL import Image, ImageDraw
import digihan as dh
from battery import degrade

G = dh.Geometry(45, 5, 0.6); DPMM = 15.0
CONDS = [("clean, 6 px/module", 6, 0.0, 0, None, 0, 0, False),
         ("tilt 20 deg", 6, 0.0, 0, None, 0, 20, False),
         ("phone-ish: 5ppm b.7 n8 q70 t8", 5, 0.7, 8, 70, 0, 8, True)]
FILLS = (0.6, 0.8, 0.95)     # how much of the frame the outer seal fills: held close, its rim nears the edge


def seal_rgb(payload, art):
    """The seal alone, tight to its rim (like the stamping page's seal picture), vermilion on white;
    art (RGB or None) cropped to a square and drawn filling the centre circle."""
    ring = dh.render(G, dh.build_stream(payload, 45), DPMM, "empty", cell="dot")
    a = np.asarray(ring); S = a.shape[0]
    rgb = np.full(a.shape + (3,), 255, np.uint8); rgb[a < 128] = (178, 56, 44)
    im = Image.fromarray(rgb)
    if art is not None:
        c = S / 2; r = G.r_center * DPMM; side = int(round(2 * r))
        s = min(art.size); sq = art.crop(((art.width - s) // 2, (art.height - s) // 2, (art.width - s) // 2 + s, (art.height - s) // 2 + s))
        sq = sq.resize((side, side), Image.LANCZOS)
        mask = Image.new("L", (side, side), 0); ImageDraw.Draw(mask).ellipse([0, 0, side - 1, side - 1], fill=255)
        im.paste(sq, (int(c - side / 2), int(c - side / 2)), mask)
    return im


def lettered():
    """Plain artwork for the innermost seal: a vermilion disc with a white bar (no ring)."""
    im = Image.new("RGB", (600, 600), (255, 255, 255)); d = ImageDraw.Draw(im)
    d.ellipse([0, 0, 599, 599], fill=(178, 56, 44)); d.rectangle([170, 270, 430, 330], fill=(255, 255, 255))
    return im


def off_centre(inner):
    """A picture holding the inner seal small and off centre (a photo of a stamped page, say)."""
    pic = Image.new("RGB", (1000, 1000), (250, 248, 242)); d = ImageDraw.Draw(pic)
    for k in range(9): d.rectangle([80, 80 + 60 * k, 900, 100 + 60 * k], fill=(90, 90, 90))
    s = inner.resize((430, 430), Image.LANCZOS); pic.paste(s, (500, 520))
    return pic


def framed(im):
    """The seal filling 60% of a white square (a camera frame)."""
    g = im.convert("L"); F = int(g.width / 0.6); fr = Image.new("L", (F, F), 255); fr.paste(g, ((F - g.width) // 2, (F - g.height) // 2))
    return fr


def screen(im):
    """A phone screenshot: the seal across most of the width, a caption and a dark toolbar."""
    W, H = 1242, 2688; side = int(W * 0.9)
    page = Image.new("L", (W, H), 242); page.paste(im.convert("L").resize((side, side), Image.LANCZOS), ((W - side) // 2, int(H * 0.42) - side // 2))
    d = ImageDraw.Draw(page)
    for i in range(5): d.text((60, int(H * 0.79) + 30 * i), "key id 44d8 4690 7e91 c4d0  stamped 2026-11-24 03:40 UTC " * 2, fill=60)
    d.rectangle([0, int(H * 0.86), W, H], fill=84)
    page = page.resize((int(W * 1400 / H), 1400), Image.LANCZOS)     # as the scanner scales a picture
    return page


if __name__ == "__main__":
    os.makedirs("frames", exist_ok=True)
    rng = np.random.default_rng(7); rows = []
    pay = lambda: rng.integers(0, 256, 78, dtype=np.uint8).tobytes()
    for t in range(5):
        p1, p2, p3 = pay(), pay(), pay()
        inner = seal_rgb(p1, lettered())
        layouts = {"inner seal fills the centre": seal_rgb(p2, inner),
                   "small inner seal off centre": seal_rgb(p2, off_centre(inner)),
                   "three deep": seal_rgb(p3, seal_rgb(p2, inner))}
        outer_pay = {"inner seal fills the centre": p2, "small inner seal off centre": p2, "three deep": p3}
        for lay, im in layouts.items():
            for ci, (name, ppm, blur, noise, jpeg, ig, tilt, pap) in enumerate(CONDS):
                img = degrade(framed(im), np.random.default_rng(900 + 100 * t + ci), ppm, G, DPMM, blur, noise, jpeg, True, ig, tilt, pap)
                D = 2 * G.r_rim_out / G.module * ppm                  # the seal's width in this frame, px
                for fill in FILLS:
                    side = min(img.width, img.height, int(D / fill)); cx, cy = img.width // 2, img.height // 2
                    fr = img.crop((cx - side // 2, cy - side // 2, cx - side // 2 + side, cy - side // 2 + side))
                    a = np.asarray(fr.convert("L"), np.uint8); fn = os.path.join("frames", f"nest_{t}_{lay[:5]}_{ci}_{int(fill * 100)}.gray"); a.tofile(fn)
                    rows.append({"cond": f"{lay[:16]}, fills {int(fill * 100)}%: {name[:12]}", "f": fn, "w": int(a.shape[1]), "h": int(a.shape[0]), "payload": outer_pay[lay].hex()})
            a = np.asarray(screen(im), np.uint8); fn = os.path.join("frames", f"nest_{t}_{lay[:5]}_screen.gray"); a.tofile(fn)
            rows.append({"cond": f"{lay[:16]}: phone screenshot", "f": fn, "w": int(a.shape[1]), "h": int(a.shape[0]), "payload": outer_pay[lay].hex()})
    json.dump(rows, open(os.path.join("frames", "nested.json"), "w")); print("frames", len(rows))

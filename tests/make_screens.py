"""Phone-screenshot frames for the photo path: a seal on a light page with a caption, a red logo and a
dark-mode browser toolbar along the bottom, in three layouts (full width above the middle, off center,
small and low). 20 payloads x 3 layouts, scaled the way the scanner scales a picture (longest side 1400).
Usage (from tests/):  python make_screens.py && node decode_frames.js photo screens"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))
import numpy as np
from PIL import Image, ImageDraw
sys.argv = [sys.argv[0]]
from make_frames import seal, G   # noqa: E402  (same seal drawing as the camera frames)

LAYOUTS = {"full width, dark toolbar": (0.94, 0.50, 0.45), "off center": (0.70, 0.40, 0.30),
           "small, low": (0.45, 0.62, 0.62)}


def screen(payload, layout):
    frac, fx, fy = LAYOUTS[layout]
    W, H = 1242, 2688
    s = seal(payload)                                   # the seal fills 60% of this square
    s = s.crop((int(s.width * 0.2), int(s.height * 0.2), int(s.width * 0.8), int(s.height * 0.8)))
    side = int(W * frac); s = s.resize((side, side), Image.LANCZOS)
    page = Image.new("L", (W, H), 242)
    page.paste(s, (int(W * fx) - side // 2, int(H * fy) - side // 2))
    d = ImageDraw.Draw(page)
    d.rectangle([40, 140, 110, 210], fill=91)                                   # red logo
    for i in range(6):
        d.text((60, int(H * 0.79) + 30 * i), "key id 44d8 4690 7e91 c4d0  sealed 2026-10-18 20:40 UTC " * 2, fill=60)
    d.rectangle([0, int(H * 0.86), W, H], fill=84)                               # dark toolbar
    d.rounded_rectangle([60, int(H * 0.875), W - 60, int(H * 0.915)], 40, fill=115)
    return page.resize((647, 1400), Image.BILINEAR)


if __name__ == "__main__":
    os.makedirs(os.path.join("frames", "screens"), exist_ok=True)
    rows = []
    for t in range(20):
        payload = np.random.default_rng(77000 + t).integers(0, 256, 78, dtype=np.uint8).tobytes()
        payload = bytes([0x10 | (payload[0] & 0x0F)]) + payload[1:]  # payload version 1 (a reader refuses version 0, release 0.6.5)
        for k, layout in enumerate(LAYOUTS):
            a = np.asarray(screen(payload, layout), np.uint8)
            fn = os.path.join("frames", "screens", f"{k}_{t}.gray"); a.tofile(fn)
            rows.append({"cond": layout, "t": t, "f": fn, "w": int(a.shape[1]), "h": int(a.shape[0]),
                         "payload": payload.hex()})
    json.dump(rows, open(os.path.join("frames", "screens.json"), "w")); print("screens", len(rows))

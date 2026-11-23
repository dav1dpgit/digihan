"""DigiHan — stamp any PDF.

Usage:
  python sign_pdf.py INPUT.pdf [OUTDIR] --key key_NAME [--page N] [--mode auto|overlay|cover]

Signs the PDF's exact original bytes (document tier 1, byte-exact), places a
45 mm round seal with the registered signature in the center on a clear part
of the chosen page (default: last page), embeds the original bytes and the
78-byte payload, then re-verifies the result from scratch and runs tamper tests.
"""
import argparse, getpass, hashlib, io, json, os, sys, time
import numpy as np
from PIL import Image
from pypdf import PdfReader, PdfWriter, Transformation
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib.units import mm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import digihan as dh          # noqa: E402  (format v0.4)
import dhsign                 # noqa: E402

NSYM, DPMM = 45, 24.0
ANCHOR = None   # (block_height, block_hash_bytes) when sealing with --anchor (format v0.4)
REG_NAME = "digihan-registration.json"   # the signer's public registration record, attached so a verifier
                                         # (the phone scanner, verify_pdf.py) needs no separate file
BLOCK = lambda h: ANCHOR[1] if ANCHOR and h == ANCHOR[0] else None
GEOM = dh.Geometry(45, 5, 0.6, square=False)
SEAL_MM = 45.0
VERMILLION = (178, 56, 44)


def unique(path):
    """Never overwrite: add _2, _3 ... if the file already exists."""
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{stem}_{i}{ext}"):
        i += 1
    return f"{stem}_{i}{ext}"


# ------------------------------------------------------------------ seal ---
def render_seal(payload: bytes, art: Image.Image) -> Image.Image:
    ring = dh.render(GEOM, dh.build_stream(payload, NSYM), DPMM, "empty", cell="dot")
    a = np.asarray(ring)
    rgb = np.full(a.shape + (3,), 255, np.uint8)
    rgb[a < 128] = VERMILLION
    S = a.shape[0]; c = S / 2.0
    r_art = (GEOM.r_center - 0.4) * DPMM
    w, h = art.size
    sc = 2 * r_art / np.hypot(w, h)
    art_s = art.resize((max(1, int(w * sc)), max(1, int(h * sc))), Image.LANCZOS)
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    layer.paste(art_s, (int(c - art_s.width / 2), int(c - art_s.height / 2)))
    yy, xx = np.mgrid[0:S, 0:S]
    clip = ((xx - c) ** 2 + (yy - c) ** 2) <= ((GEOM.r_center - 0.2) * DPMM) ** 2
    la = np.asarray(layer).copy(); la[..., 3] = la[..., 3] * clip
    out = Image.fromarray(rgb).convert("RGBA")
    out.alpha_composite(Image.fromarray(la))
    return out.convert("RGB")


# ------------------------------------------------------------- placement ---
def rasterize(pdf_path, page_no, dpi, prefix=None):
    import pypdfium2 as pdfium
    pdf = pdfium.PdfDocument(pdf_path)
    try:
        return pdf[page_no].render(scale=dpi / 72).to_pil().convert("L")
    finally:
        pdf.close()


def find_clear_spot(page_img: Image.Image, dpi: int, page_w_mm, page_h_mm):
    """Find a spot for the 45 mm seal with the widest clear margin around it.
    Returns (x_mm_from_left, y_mm_from_top, quiet_zone_mm) of the seal's
    top-left corner, or None. Prefers the bottom-right, the usual seal place."""
    a = np.asarray(page_img) < 200                     # ink
    px = dpi / 25.4
    H, W = a.shape
    ii = np.pad(a.cumsum(0).cumsum(1), ((1, 0), (1, 0)))
    def ink(x0, y0, x1, y1):
        x0, y0 = max(0, x0), max(0, y0); x1, y1 = min(W, x1), min(H, y1)
        return ii[y1, x1] - ii[y0, x1] - ii[y1, x0] + ii[y0, x0]
    seal = int(SEAL_MM * px)
    edge = int(8 * px)                                 # keep 8 mm off the paper edge
    for qz_mm in (15, 10, 6, 3):                       # spec minimum: >= 3 mm
        q = int(qz_mm * px)
        e = max(edge, q)                               # the clear margin must be ON the paper
        best = None
        step = max(1, int(2 * px))
        for y in range(e, H - e - seal, step):
            for x in range(e, W - e - seal, step):
                if ink(x - q, y - q, x + seal + q, y + seal + q) == 0:
                    score = x + y                      # bottom-right preferred
                    if best is None or score > best[0]:
                        best = (score, x, y)
        if best:
            return best[1] / px, best[2] / px, qz_mm
    return None


# ------------------------------------------------------------- the seal ---
def seal_pdf(in_path, out_dir, page_no, kf, password, art_path, reg):
    os.makedirs(out_dir, exist_ok=True)
    log = []
    say = lambda s="": (print(s), log.append(s))
    original = open(in_path, "rb").read()
    base = os.path.splitext(os.path.basename(in_path))[0]

    r = PdfReader(io.BytesIO(original))
    if r.is_encrypted:
        raise SystemExit("PDF is password-protected; it cannot be stamped as-is.")
    n_pages = len(r.pages)
    page_no = (n_pages - 1) if page_no is None else page_no
    page = r.pages[page_no]
    mb = page.mediabox
    w_pt, h_pt = float(mb.width), float(mb.height)
    rot = int(page.get("/Rotate", 0) or 0) % 360
    sig_fields = []
    af = r.trailer["/Root"].get("/AcroForm")
    if af is not None:
        for f in (af.get_object().get("/Fields") or []):
            fo = f.get_object()
            if fo.get("/FT") == "/Sig":
                sig_fields.append(fo.get("/T"))
    say(f"input: {os.path.basename(in_path)} — {len(original):,} bytes, {n_pages} page(s)")
    say(f"seal page: {page_no + 1} of {n_pages}, {w_pt/72*25.4:.0f} x {h_pt/72*25.4:.0f} mm, rotation {rot}")
    if sig_fields:
        say(f"WARNING: the PDF already carries digital signature field(s) {sig_fields}; "
            "adding the seal overlay will show as a change to those signatures.")
    if rot:
        say("WARNING: page is rotated; placement is computed on the rendered page.")

    # 1. sign the original bytes -------------------------------------------
    pk = bytes.fromhex(kf["pubkey"])
    art_bytes = open(art_path, "rb").read()
    center_hash = hashlib.sha256(art_bytes).digest()
    assert reg["tags"][1][1] == center_hash.hex(), "artwork does not match registration"
    ts = int(time.time())
    sk = dhsign.unlock_key(kf, password)
    payload = dhsign.seal_payload(sk, pk, original, ts, center_hash, anchor=ANCHOR)
    del sk
    say(f"document sha256 (what was signed): {hashlib.sha256(original).hexdigest()}")
    say(f"signer: {dhsign.bech32('npub', pk)}  fingerprint {dhsign.fingerprint(pk).hex()}")

    # 2. seal image, self-checked optically --------------------------------
    seal = render_seal(payload, Image.open(art_path).convert("RGBA"))
    seal_path = unique(os.path.join(out_dir, f"{base}_seal.png"))
    seal.save(seal_path)
    got, _ = dh.decode(Image.open(seal_path), GEOM, NSYM)
    assert got == payload, "seal image failed its own optical read"

    # 3. place it on a clear spot ------------------------------------------
    page_img = rasterize(in_path, page_no, 100)
    W_mm, H_mm = page_img.width / 100 * 25.4, page_img.height / 100 * 25.4
    spot = find_clear_spot(page_img, 100, W_mm, H_mm)
    if spot is None:
        raise SystemExit("No clear 45 mm area with even a 3 mm margin on this page. "
                         "Pick another page with --page, or add a blank page.")
    x_mm, y_mm, qz = spot
    say(f"placement: {x_mm:.0f} mm from left, {y_mm:.0f} mm from top, "
        f"clear margin {qz} mm on every side")
    if rot:
        raise SystemExit("Rotated pages are not handled yet.")

    ov = io.BytesIO()
    c = canvas.Canvas(ov, pagesize=(w_pt, h_pt))
    c.drawImage(ImageReader(seal_path), x_mm * mm, h_pt - (y_mm + SEAL_MM) * mm,
                width=SEAL_MM * mm, height=SEAL_MM * mm)
    c.save()
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(original)))
    w.pages[page_no].merge_transformed_page(
        PdfReader(io.BytesIO(ov.getvalue())).pages[0],
        Transformation().translate(float(mb.left), float(mb.bottom)))
    w.add_attachment("original.pdf", original)
    w.add_attachment(REG_NAME, json.dumps(reg).encode())
    w.add_metadata({"/DigiHanPayload": payload.hex(), "/DigiHanRegistration": REG_NAME,
                    "/DigiHanSealPage": str(page_no + 1),
                    "/DigiHanSealBox": f"{x_mm:.2f},{y_mm:.2f},{SEAL_MM:.1f},{qz}",
                    "/DigiHanFormat": "DigiHan format v0.4, doc tier 1 (byte-exact)"})
    buf = io.BytesIO(); w.write(buf)
    sealed_path = unique(os.path.join(out_dir, f"{base}_sealed.pdf"))
    open(sealed_path, "wb").write(buf.getvalue())
    return dict(log=log, say=say, payload=payload, pk=pk, ts=ts, original=original,
                sealed_path=sealed_path, seal_path=seal_path, page_no=page_no,
                x_mm=x_mm, y_mm=y_mm, qz=qz, h_pt=h_pt, base=base)


# ------------------------------------------------- cover sheet (e-signed) ---
def seal_cover(in_path, out_dir, kf, password, art_path, reg, sig_fields):
    """For PDFs that already carry an e-signature: never touch the file. Seal its
    exact bytes on a new cover page and attach the file unchanged."""
    os.makedirs(out_dir, exist_ok=True)
    log = []
    say = lambda s="": (print(s), log.append(s))
    original = open(in_path, "rb").read()
    name = os.path.basename(in_path)
    base = os.path.splitext(name)[0]
    r = PdfReader(io.BytesIO(original))
    mb = r.pages[0].mediabox
    w_pt, h_pt = float(mb.width), float(mb.height)
    say(f"input: {name} — {len(original):,} bytes, {len(r.pages)} page(s)")
    say(f"existing e-signature field(s): {', '.join(str(s) for s in sig_fields)} "
        f"-> cover-sheet mode: the file is attached unchanged")
    say(f"e-signature check before stamping: {esig_status(original)}")

    pk = bytes.fromhex(kf["pubkey"])
    art_bytes = open(art_path, "rb").read()
    center_hash = hashlib.sha256(art_bytes).digest()
    assert reg["tags"][1][1] == center_hash.hex(), "artwork does not match registration"
    ts = int(time.time())
    sk = dhsign.unlock_key(kf, password)
    payload = dhsign.seal_payload(sk, pk, original, ts, center_hash, anchor=ANCHOR)
    del sk
    say(f"document sha256 (what was signed): {hashlib.sha256(original).hexdigest()}")
    say(f"signer: {dhsign.bech32('npub', pk)}  fingerprint {dhsign.fingerprint(pk).hex()}")

    seal = render_seal(payload, Image.open(art_path).convert("RGBA"))
    seal_path = unique(os.path.join(out_dir, f"{base}_seal.png"))
    seal.save(seal_path)
    got, _ = dh.decode(Image.open(seal_path), GEOM, NSYM)
    assert got == payload, "seal image failed its own optical read"

    # cover page, same size as the document's first page; seal centred low with
    # at least 15 mm of clear paper on every side
    x_mm = (w_pt / 72 * 25.4 - SEAL_MM) / 2
    y_mm = h_pt / 72 * 25.4 - 30 - SEAL_MM - 15
    b = io.BytesIO(); c = canvas.Canvas(b, pagesize=(w_pt, h_pt))
    c.setFont("Helvetica-Bold", 15); c.drawString(25 * mm, h_pt - 28 * mm, "DigiHan seal — cover sheet")
    c.setFont("Helvetica", 9.5)
    when = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ts))
    lines = [f"Original file, attached unchanged: {name}",
             f"Size: {len(original):,} bytes",
             f"SHA-256: {hashlib.sha256(original).hexdigest()}",
             f"Stamped (time stated by the signer): {when}   Key id: {dhsign.fingerprint(pk).hex()}",
             "",
             "The seal below is calculated from the attached file's exact bytes.",
             "The attached file and its own electronic signatures are not modified.",
             "To check: scan the seal, open the attachment, and confirm its SHA-256 matches.",
             "",
             "DigiHan format v0.4. It proves which key signed these exact bytes; it is not a notarization."]
    for i, t in enumerate(lines):
        c.drawString(25 * mm, h_pt - 40 * mm - i * 5.2 * mm, t)
    c.drawImage(ImageReader(seal_path), x_mm * mm, h_pt - (y_mm + SEAL_MM) * mm,
                width=SEAL_MM * mm, height=SEAL_MM * mm)
    c.save()
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(b.getvalue())))
    w.add_attachment(name, original)
    w.add_attachment(REG_NAME, json.dumps(reg).encode())
    w.add_metadata({"/DigiHanPayload": payload.hex(), "/DigiHanSealedFile": name, "/DigiHanRegistration": REG_NAME,
                    "/DigiHanSealPage": "1",
                    "/DigiHanSealBox": f"{x_mm:.2f},{y_mm:.2f},{SEAL_MM:.1f},15",
                    "/DigiHanFormat": "DigiHan format v0.4, cover sheet, doc tier 1 (byte-exact)"})
    out = io.BytesIO(); w.write(out)
    sealed_path = unique(os.path.join(out_dir, f"{base}_DigiHan_cover.pdf"))
    open(sealed_path, "wb").write(out.getvalue())
    say(f"cover sheet: seal at {x_mm:.0f} mm from left, {y_mm:.0f} mm from top, "
        f"15 mm clear margin; original attached as '{name}'")
    return dict(log=log, say=say, payload=payload, pk=pk, ts=ts, original=original,
                sealed_path=sealed_path, seal_path=seal_path, page_no=0, x_mm=x_mm,
                y_mm=y_mm, qz=15, h_pt=h_pt, base=base, mode="cover", name=name)


def esig_status(pdf_bytes):
    """Integrity of an existing e-signature, as pyHanko computes it. Trust in the
    signer's certificate chain is not checked here (Adobe's roots are not loaded)."""
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext
    except ImportError:
        return "pyHanko not installed; skipped"
    import logging
    for lg in ("pyhanko", "pyhanko_certvalidator"):
        logging.getLogger(lg).setLevel(logging.CRITICAL)
    rr = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
    if not rr.embedded_signatures:
        return "no e-signature found"
    parts = []
    for es in rr.embedded_signatures:
        try:
            s = validate_pdf_signature(es, ValidationContext(allow_fetching=False))
            mod = getattr(s, "modification_level", None)
            parts.append(f"'{es.field_name}': bytes intact={s.intact}, "
                         f"coverage={s.coverage.name}, "
                         f"changes after signing={mod.name if mod else 'n/a'}")
        except Exception as e:
            parts.append(f"'{es.field_name}': could not evaluate ({type(e).__name__})")
    return "; ".join(parts)


# ---------------------------------------------------------- verification ---
def verify_from_scratch(st, reg, out_dir):
    say = st["say"]
    sealed = open(st["sealed_path"], "rb").read()
    r = PdfReader(io.BytesIO(sealed))
    payload_meta = bytes.fromhex(r.metadata["/DigiHanPayload"])
    original = r.attachments[st.get("name", "original.pdf") if st.get("mode") == "cover"
                             else "original.pdf"][0]
    pk = bytes.fromhex(reg["pubkey"])
    keyring = {dhsign.fingerprint(pk).hex(): pk}

    # read the seal optically from the sealed PDF as printed, at 600 dpi
    page = rasterize(st["sealed_path"], st["page_no"], 600)
    px = 600 / 25.4
    cx, cy = (st["x_mm"] + SEAL_MM / 2) * px, (st["y_mm"] + SEAL_MM / 2) * px
    half = (SEAL_MM / 2 + st["qz"]) * px             # the seal plus its clear margin
    box = [int(cx - half), int(cy - half), int(cx + half), int(cy + half)]
    assert box[0] >= 0 and box[1] >= 0 and box[2] <= page.width and box[3] <= page.height, \
        "verification frame would leave the paper"
    frame = page.crop(box)
    payload_optical, ncorr = dh.decode(frame, GEOM, NSYM)

    say(); say("=== VERIFICATION (from the delivered file, as a stranger would) ===")
    say(f"seal read from the printed page (600 dpi): "
        f"{'OK' if payload_optical == st['payload'] else 'MISMATCH'}, {ncorr} byte(s) repaired")
    say(f"seal == payload stored in the file: {payload_optical == payload_meta}")
    say(f"embedded original == your input file, byte for byte: {original == st['original']}")
    ok, lines, _ = dhsign.verify_payload(payload_optical, original, keyring, [reg], block_hash_at=BLOCK)
    for l in lines:
        say("  " + l)

    say(); say("=== TAMPER TESTS — each must fail ===")
    def t(name, doc, p=payload_optical, regs=(reg,)):
        res = dhsign.verify_payload(p, doc, keyring, list(regs), block_hash_at=BLOCK)[0]
        say(f"  {'FAIL as required ' if not res else 'PASSED (DEFECT)  '}  {name}")
        return not res
    flips = [len(original) // 3, len(original) // 2, len(original) - 10]
    allgood = True
    for pos in flips:
        d = bytearray(original); d[pos] ^= 1
        allgood &= t(f"one bit flipped at byte {pos:,} of the document", bytes(d))
    allgood &= t("a different file (the stamped PDF itself) offered as the document", sealed)
    back = payload_optical[:9] + (st["ts"] - 86400 * 30).to_bytes(5, "big") + payload_optical[14:]
    allgood &= t("timestamp in the seal backdated 30 days", original, p=back)
    if st.get("mode") == "cover":
        say(); say("=== YOUR E-SIGNATURE, INSIDE THE ATTACHED FILE ===")
        say(f"  attached file is byte-identical to your input: {original == st['original']}")
        say(f"  e-signature check after stamping: {esig_status(original)}")
    return ok and allgood and payload_optical == payload_meta and original == st["original"]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("input"); ap.add_argument("outdir", nargs="?", default="sealed")
    ap.add_argument("--page", type=int, default=None, help="1-based page number")
    ap.add_argument("--mode", choices=["auto", "overlay", "cover"], default="auto",
                    help="auto: cover sheet if the PDF already has an e-signature")
    ap.add_argument("--key", required=True,
                    help="folder made by make_key.py (keyfile.json, registration.json, center_art.png), "
                         "or a key file saved from the stamping page")
    ap.add_argument("--anchor", default=None, metavar="auto|node|HEIGHT:HASH",
                    help="prove the seal was made no earlier than a Bitcoin block: 'auto' asks two block "
                         "explorers, 'node' asks your bitcoin-cli, or give HEIGHT:HASH")
    ap.add_argument("--stamp", action="store_true",
                    help="prove the seal was made no later than a Bitcoin block: send its hash to the "
                         "OpenTimestamps calendars (finish later with timestamp.py upgrade)")
    ap.add_argument("--password", default=None, help=argparse.SUPPRESS)   # tests only
    a = ap.parse_args()
    if a.anchor:
        import anchor as _anchor
        ANCHOR = _anchor.parse_anchor_arg(a.anchor)
        print(f"Anchoring to Bitcoin block {ANCHOR[0]} ({ANCHOR[1].hex()[:16]}...): the seal will prove it was "
              f"made no earlier than this block.")
    if os.path.isfile(a.key):                    # one key file from the sealing page: key, artwork and record
        import base64, tempfile
        kf = json.load(open(a.key))
        reg = kf["registration"]
        art = tempfile.NamedTemporaryFile(suffix=".png", delete=False).name
        open(art, "wb").write(base64.b64decode(kf["center_png"]))
    else:
        kf = json.load(open(os.path.join(a.key, "keyfile.json")))
        reg = json.load(open(os.path.join(a.key, "registration.json")))
        art = os.path.join(a.key, "center_art.png")
        if not os.path.exists(art):
            art = os.path.join(HERE, "sample_center.png")
    a.art = art
    pw = a.password or getpass.getpass("Key password (typing is hidden): ")
    try:
        dhsign.unlock_key(kf, pw)
    except Exception:
        raise SystemExit("Wrong password for this key.")
    rr = PdfReader(a.input)
    sig_fields = []
    af = rr.trailer["/Root"].get("/AcroForm")
    if af is not None:
        for f in (af.get_object().get("/Fields") or []):
            fo = f.get_object()
            if fo.get("/FT") == "/Sig" and fo.get("/V") is not None:
                sig_fields.append(fo.get("/T"))
    mode = a.mode if a.mode != "auto" else ("cover" if sig_fields else "overlay")
    if mode == "cover":
        st = seal_cover(a.input, a.outdir, kf, pw, a.art, reg, sig_fields or ["(none)"])
    else:
        if sig_fields:
            print("WARNING: overlay mode on an e-signed PDF will break or flag that signature.")
        st = seal_pdf(a.input, a.outdir, None if a.page is None else a.page - 1,
                      kf, pw, a.art, reg)
    passed = verify_from_scratch(st, reg, a.outdir)
    f = dhsign.parse_payload(st["payload"])
    st["say"](); st["say"]("=== PHONE CHECK — the scanner (web/scanner, digihan.org/scan) should show ===")
    st["say"](f"  digest      {hashlib.sha256(st['payload']).hexdigest()[:8]}")
    st["say"](f"  frame       round · jitsuin 45mm")
    st["say"](f"  version     1 (flags {f['flags']})")
    st["say"](f"  fingerprint {f['fp'].hex()}")
    if f["flags"] & dhsign.FLAG_ANCHOR:
        st["say"](f"  anchored    no earlier than Bitcoin block {f['ts']}")
    else:
        st["say"](f"  timestamp   {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(f['ts']))}")
    st["say"](); st["say"](f"RESULT: {'ALL CHECKS PASSED' if passed else 'A CHECK FAILED — see above'}")
    # the 78-byte seal data, for an OpenTimestamps proof ("no later than")
    pay = unique(os.path.join(a.outdir, f"{st['base']}_seal_payload.bin"))
    open(pay, "wb").write(st["payload"])
    stamped = None
    if a.stamp:
        import ots
        try:
            proof, cals = ots.stamp(st["payload"])
            stamped = pay + ".ots"
            open(stamped, "xb").write(proof.to_bytes())
        except Exception as e:
            print(f"Time proof not started: {e}. Try later: python timestamp.py stamp \"{pay}\"")
    rpt = unique(os.path.join(a.outdir, f"{st['base']}_verification_report.txt"))
    open(rpt, "w").write("\n".join(st["log"]) + "\n")
    print()
    print(f"Stamped PDF:  {os.path.abspath(st['sealed_path'])}")
    print(f"Report:       {os.path.abspath(rpt)}")
    print(f"Seal data:    {os.path.abspath(pay)}")
    if stamped:
        print(f"Time proof:   {os.path.abspath(stamped)}   (pending; in a few hours run:")
        print(f'              python timestamp.py upgrade "{stamped}"')
        print(f'              python timestamp.py attach "{st["sealed_path"]}" "{stamped}")')
    else:
        print(f'For a "no later than" time proof: python timestamp.py stamp "{pay}"')
    print("To check it independently, run:")
    print(f'  .\\.venv\\Scripts\\python.exe verify_pdf.py "{st["sealed_path"]}" --save-original'
          if os.name == "nt" else
          f'  python verify_pdf.py "{st["sealed_path"]}" --save-original')
    print("(the signer's registration record is attached to the stamped PDF, so no other file is needed)")

"""DigiHan — check a sealed PDF. Needs no secret. The signer's public registration record is
attached to PDFs sealed by sign_pdf.py v0.4.3 and later; for older ones, give registration.json.

Usage:
  python verify_pdf.py SEALED.pdf [REGISTRATION.json] [--save-original]

Checks, in order:
  1. the registration record is signed by the key it names
  2. the seal printed on the page is read optically and matches the data in the file
  3. the signature in the seal matches the attached original's exact bytes, the
     stated time, the signer's key, and the registered center art
--save-original writes the attached, signed original next to the sealed file so
you can open and read exactly what was signed.
"""
import argparse, hashlib, io, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pypdf import PdfReader  # noqa: E402
import digihan as dh         # noqa: E402
import dhsign                # noqa: E402
import sign_pdf              # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("sealed")
ap.add_argument("registration", nargs="?", default=None,
                help="the signer's registration.json (not needed when the PDF carries it)")
ap.add_argument("--save-original", action="store_true")
ap.add_argument("--node", action="store_true", help="take Bitcoin block data from your own bitcoin-cli "
                "(otherwise two block explorers are asked: mempool.space and blockstream.info)")
ap.add_argument("--block-hash", default=None, help="for an anchored seal: the anchored block's hash "
                "(from your own node: bitcoin-cli getblockhash HEIGHT)")
ap.add_argument("--ots", default=None, help="an OpenTimestamps proof (.ots) for this seal, if it is not "
                "attached to the PDF")
a = ap.parse_args()

problems = []
r = PdfReader(a.sealed)
md = r.metadata or {}
if a.registration:
    reg = json.load(open(a.registration))
    print(f"Signer (from {os.path.basename(a.registration)}): {dhsign.bech32('npub', bytes.fromhex(reg['pubkey']))}")
else:
    reg_name = md.get("/DigiHanRegistration") or sign_pdf.REG_NAME
    if reg_name not in r.attachments:
        raise SystemExit("This PDF does not carry the signer's registration record; give registration.json "
                         "after the PDF's name.")
    reg = json.loads(r.attachments[reg_name][0])
    print(f"Signer (from the registration attached to this PDF): {dhsign.bech32('npub', bytes.fromhex(reg['pubkey']))}")
if not dhsign.check_registration(reg):
    problems.append("the registration record's own signature is not valid")
    print("  registration record: NOT VALID")
else:
    print("  registration record: valid (signed by the key it names)")
pk = bytes.fromhex(reg["pubkey"])
keyring = {dhsign.fingerprint(pk).hex(): pk}

if "/DigiHanPayload" not in md:
    raise SystemExit("No DigiHan seal data found in this PDF.")
payload_meta = bytes.fromhex(md["/DigiHanPayload"])
name = md.get("/DigiHanSealedFile") or "original.pdf"
mode = "cover sheet" if "/DigiHanSealedFile" in md else "seal on page"
if name not in r.attachments:
    raise SystemExit(f"The signed original ('{name}') is not attached to this PDF.")
original = r.attachments[name][0]
print(f"Layout: {mode}; signed file attached as '{name}' "
      f"({len(original):,} bytes, sha256 {hashlib.sha256(original).hexdigest()[:16]}...)")

# optical read of the printed seal
page_no = int(md.get("/DigiHanSealPage", "1")) - 1
x_mm, y_mm, size_mm, qz = (float(v) for v in md["/DigiHanSealBox"].split(","))
page = sign_pdf.rasterize(a.sealed, page_no, 600)
px = 600 / 25.4
cx, cy = (x_mm + size_mm / 2) * px, (y_mm + size_mm / 2) * px
half = (size_mm / 2 + min(qz, 15)) * px
frame = page.crop((max(0, int(cx - half)), max(0, int(cy - half)),
                   min(page.width, int(cx + half)), min(page.height, int(cy + half))))
try:
    payload_seal, repaired = dh.decode(frame, sign_pdf.GEOM, sign_pdf.NSYM)
    print(f"Seal on page {page_no + 1}: read OK ({repaired} byte(s) repaired by error correction)")
    if payload_seal != payload_meta:
        problems.append("the printed seal and the data stored in the file disagree")
except Exception as e:
    payload_seal = None
    problems.append(f"the printed seal could not be read ({type(e).__name__})")
    print("Seal on page: could not be read")

payload = payload_seal or payload_meta
def block_at(h):
    if a.block_hash:
        return dhsign.block_hash_bytes(a.block_hash)
    import anchor
    if a.node:
        return anchor.node_hash_at(h)
    b = anchor.explorer_hash_at(h)
    if b is not None:
        print(f"  block {h}: hash from mempool.space and blockstream.info ({b.hex()[:16]}...). For full "
              f"independence, compare it with your own node: bitcoin-cli getblockhash {h}")
    return b
ok, lines, _ = dhsign.verify_payload(payload, original, keyring, [reg], block_hash_at=block_at)
for l in lines:
    print("  " + l)
seal_fp = dhsign.parse_payload(payload)["fp"].hex()
if not ok and seal_fp not in keyring:
    problems.append(f"this seal was made by a different key (fingerprint {seal_fp}) "
                    f"than the registration you supplied ({dhsign.fingerprint(pk).hex()})")
elif not ok:
    problems.append("the signature does not match the attached file, time, key or center art")

# no later than: an OpenTimestamps proof, attached as seal.ots or given with --ots
import ots, timestamp     # noqa: E402
proof_bytes = open(a.ots, "rb").read() if a.ots else None
if proof_bytes is None:
    for nm in [ots.attach_name()] + [n for n in r.attachments if n != ots.attach_name()]:
        if nm in r.attachments and ots.is_proof(r.attachments[nm][0]):
            proof_bytes = r.attachments[nm][0]
            break
later = None
if proof_bytes is None:
    print("  TIME (no later than): no OpenTimestamps proof attached")
elif ok:
    try:
        later = timestamp.check(ots.Proof.from_bytes(proof_bytes), payload, a.node, say=lambda m: print("  " + m))
    except ots.ProofError as e:
        print(f"  TIME (no later than): the attached proof cannot be read — {e}")

if later and dhsign.parse_payload(payload)["flags"] & dhsign.FLAG_ANCHOR and later[0] < dhsign.parse_payload(payload)["ts"]:
    problems.append(f"the time proofs contradict each other: anchored to block {dhsign.parse_payload(payload)['ts']}, "
                    f"but timestamped at the lower block number {later[0]}")

if mode == "cover sheet":
    print(f"E-signature inside the attached file: {sign_pdf.esig_status(original)}")

if a.save_original:
    out = os.path.splitext(a.sealed)[0] + "_signed_original.pdf"
    if os.path.exists(out):
        print(f"(not saved: {out} already exists)")
    else:
        open(out, "wb").write(original)
        print(f"Saved what was signed: {out}")

print()
if problems:
    print("RESULT: NOT VALID")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)
f = dhsign.parse_payload(payload)
print("RESULT: VALID — the attached file is exactly what this key sealed.")
when = lambda t: time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(t))
if f["flags"] & dhsign.FLAG_ANCHOR and later:          # a bookended seal: both ends proven
    print(f"        Sometime between and including Block {f['ts']:,} and Block {later[0]:,} (Bitcoin), both proven:")
    print(f"        the block anchor for Block {f['ts']:,}, OpenTimestamps for Block {later[0]:,} (mined {when(later[1])}).")
elif f["flags"] & dhsign.FLAG_ANCHOR:
    print(f"        Made no earlier than Bitcoin block {f['ts']:,} (proven: the block's hash is signed).")
else:
    print(f"        Time stated by the signer: {when(f['ts'])} (not proven).")
if later and not f["flags"] & dhsign.FLAG_ANCHOR:
    print(f"        Made no later than Bitcoin block {later[0]:,}, mined {when(later[1])} (proven: OpenTimestamps).")
print("        Read the attached file: it is exactly what was sealed.")

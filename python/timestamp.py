"""Prove a seal was made NO LATER THAN a Bitcoin block, with OpenTimestamps (see docs/TIME-PROOF.md).

  python timestamp.py stamp   sealed/x_seal_payload.bin       # sends the seal's hash to the calendars
  python timestamp.py upgrade sealed/x_seal_payload.bin.ots   # a few hours later: fetches the Bitcoin part
  python timestamp.py attach  sealed/x_sealed.pdf sealed/x_seal_payload.bin.ots
  python timestamp.py verify  sealed/x_seal_payload.bin.ots [--node]

`stamp` also takes a sealed PDF (it reads the seal data from it). `attach` writes a new PDF
(x_sealed_timestamped.pdf) with the proof attached as seal.ots; the original file is not changed.
The .ots files are standard: `ots verify x_seal_payload.bin.ots` (opentimestamps-client) checks them too.
"""
import argparse, os, shutil, sys, time

import anchor
import ots


def _payload_from(path):
    b = open(path, "rb").read()
    if b[:5] == b"%PDF-":
        from pypdf import PdfReader
        md = PdfReader(path).metadata or {}
        if "/DigiHanPayload" not in md:
            raise SystemExit("No DigiHan seal data found in this PDF.")
        return bytes.fromhex(md["/DigiHanPayload"])
    if len(b) != 78:
        raise SystemExit("A seal's data is 78 bytes; this file is not one (use the _seal_payload.bin file).")
    return b


def _payload_for_proof(proof_path):
    base = proof_path[:-4] if proof_path.endswith(".ots") else proof_path
    if not os.path.exists(base):
        raise SystemExit(f"Need the seal data next to the proof: {base}")
    return _payload_from(base)


def _when(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t))


def cmd_stamp(a):
    payload = _payload_from(a.file)
    out = (os.path.splitext(a.file)[0] + "_seal_payload.bin" if a.file.lower().endswith(".pdf") else a.file) + ".ots"
    if os.path.exists(out):
        raise SystemExit(f"{out} already exists; use upgrade.")
    if a.file.lower().endswith(".pdf"):
        open(out[:-4], "xb").write(payload)          # keep the seal data next to its proof
    proof, cals = ots.stamp(payload)
    open(out, "xb").write(proof.to_bytes())
    print(f"Sent the seal's hash to {len(cals)} calendars: {', '.join(cals)}")
    print(f"Pending proof: {out}")
    print("In a few hours (once a calendar's transaction is in a Bitcoin block), run:")
    print(f'  python timestamp.py upgrade "{out}"')


def cmd_upgrade(a):
    raw = open(a.proof, "rb").read()
    proof = ots.Proof.from_bytes(raw)
    if proof.bitcoin():
        print(f"Already complete: Bitcoin block {proof.bitcoin()[0][0]}.")
        return
    n = ots.upgrade(proof)
    if not n:
        print("Not ready yet: no calendar has its transaction in a Bitcoin block. Try again later.")
        sys.exit(2)
    bak = a.proof + ".bak"
    if not os.path.exists(bak):
        shutil.copyfile(a.proof, bak)                # the pending proof is kept
    open(a.proof, "wb").write(proof.to_bytes())
    print(f"Complete: the proof now reaches Bitcoin block {proof.bitcoin()[0][0]} ({a.proof}; "
          f"the pending version is kept as {bak}).")
    print("Attach it to the sealed PDF with:")
    print(f'  python timestamp.py attach SEALED.pdf "{a.proof}"')


def cmd_attach(a):
    from pypdf import PdfReader, PdfWriter
    proof_bytes = open(a.proof, "rb").read()
    proof = ots.Proof.from_bytes(proof_bytes)
    payload = _payload_from(a.sealed)
    if proof.digest != ots.payload_digest(payload):
        raise SystemExit("This proof is for a different seal than the one in this PDF.")
    r = PdfReader(a.sealed)
    if ots.attach_name() in r.attachments:
        raise SystemExit(f"This PDF already has a {ots.attach_name()} attachment.")
    w = PdfWriter(clone_from=r)
    w.add_attachment(ots.attach_name(), proof_bytes)
    if r.metadata:
        w.add_metadata(dict(r.metadata))
    out = os.path.splitext(a.sealed)[0] + "_timestamped.pdf"
    with open(out, "xb") as fh:
        w.write(fh)
    state = f"reaches Bitcoin block {proof.bitcoin()[0][0]}" if proof.bitcoin() else "still pending"
    print(f"Wrote {out} with the proof attached as {ots.attach_name()} ({state}).")


def check(proof, payload, use_node=False, say=print):
    """Verify a proof against a seal; returns (height, block_time) or None. Prints what it did."""
    src = "your node (bitcoin-cli)" if use_node else "mempool.space and blockstream.info"
    try:
        h, t = ots.verify(proof, payload, anchor.node_merkle_at if use_node else anchor.explorer_merkle_at)
    except ots.ProofError as e:
        say(f"TIME (no later than): not proven — {e}")
        return None
    say(f"TIME (no later than): the seal existed when Bitcoin block {h} was mined ({_when(t)}); "
        f"block data from {src}")
    return h, t


def cmd_verify(a):
    proof = ots.Proof.from_bytes(open(a.proof, "rb").read())
    payload = _payload_for_proof(a.proof) if not a.payload else _payload_from(a.payload)
    sys.exit(0 if check(proof, payload, a.node) else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stamp"); s.add_argument("file"); s.set_defaults(fn=cmd_stamp)
    s = sub.add_parser("upgrade"); s.add_argument("proof"); s.set_defaults(fn=cmd_upgrade)
    s = sub.add_parser("attach"); s.add_argument("sealed"); s.add_argument("proof"); s.set_defaults(fn=cmd_attach)
    s = sub.add_parser("verify"); s.add_argument("proof"); s.add_argument("--payload")
    s.add_argument("--node", action="store_true", help="take block data from your own bitcoin-cli")
    s.set_defaults(fn=cmd_verify)
    a = ap.parse_args()
    a.fn(a)

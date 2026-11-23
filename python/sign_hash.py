"""Sign a code from the DigiHan stamping page with a key you keep offline.

The stamping page (digihan.org/seal) can work with only your public key. When it needs a signature it shows
a 64-character code: a SHA-256 hash (32 bytes) of your seal's registration record, or of what a document's
seal signs. Sign it
here, on the computer that holds your key, and paste the 128-character signature back into the page.

  python sign_hash.py CODE --key key_alice                     (a folder made by make_key.py)
  python sign_hash.py CODE --key digihan-key-0d698fd9.json     (a key file saved from the stamping page)

Sign only codes the stamping page shows you: a signature over a code is a signature over whatever made it.
"""
import argparse, getpass, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340  # noqa: E402
import dhsign  # noqa: E402


def load_keyfile(path):
    if os.path.isdir(path):
        path = os.path.join(path, "keyfile.json")
    return json.load(open(path))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("code", help="the 64-character code the stamping page shows")
    ap.add_argument("--key", required=True, help="a key folder (make_key.py) or a key file from the stamping page")
    ap.add_argument("--password", default=None, help=argparse.SUPPRESS)   # tests only
    a = ap.parse_args(argv)
    code = a.code.strip().lower()
    if len(code) != 64 or any(c not in "0123456789abcdef" for c in code):
        raise SystemExit("The code is 64 characters, 0-9 and a-f. Copy it again from the page.")
    kf = load_keyfile(a.key)
    pw = a.password or getpass.getpass("Key password (typing is hidden): ")
    try:
        sk = dhsign.unlock_key(kf, pw)
    except Exception:
        raise SystemExit("Wrong password for this key.")
    msg, pk = bytes.fromhex(code), bytes.fromhex(kf["pubkey"])
    sig = bip340.sign(msg, sk, os.urandom(32))
    del sk
    assert bip340.verify(msg, pk, sig)
    print(f"Key: {dhsign.bech32('npub', pk)}")
    print("Signature (paste this into the page):")
    print(sig.hex())
    return sig.hex()


if __name__ == "__main__":
    main()

"""DigiHan — make a new key on this computer.

The signing code is pure Python and not constant-time: fine for trying DigiHan,
not yet for a key that guards anything valuable.

Usage:
  python make_key.py NAME [--art PATH_TO_CENTER_PNG]

Creates the folder key_NAME holding:
  keyfile.json       the secret key, locked with your password (scrypt + ChaCha20-Poly1305)
  registration.json  the public record: your public key and the hash of your center art,
                     signed by the new key (give this to anyone who should verify you)
  center_art.png     the artwork registered as your seal's center
Never overwrites: refuses if the folder already exists.
"""
import argparse, getpass, hashlib, json, os, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dhsign  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("name")
ap.add_argument("--art", default=os.path.join(HERE, "sample_center.png"),
                help="PNG of your signature or seal design (transparent background)")
ap.add_argument("--password", default=None, help=argparse.SUPPRESS)   # tests only
a = ap.parse_args()

folder = os.path.join(HERE, f"key_{a.name}")
if os.path.exists(folder):
    raise SystemExit(f"{folder} already exists — choose another name. Nothing was changed.")
if a.password:
    pw = a.password
else:
    pw = getpass.getpass("Choose a password for this key (typing is hidden): ")
    if getpass.getpass("Type it again: ") != pw:
        raise SystemExit("The two passwords did not match. Nothing was created.")
if len(pw) < 10:
    raise SystemExit("Use at least 10 characters. Nothing was created.")

art = open(a.art, "rb").read()
sk, pk = dhsign.new_key()
kf = dhsign.lock_key(sk, pk, pw)
kf["format"] = "digihan-keyfile-v1"
reg = dhsign.register_center(sk, pk, art)
del sk

os.makedirs(folder)
json.dump(kf, open(os.path.join(folder, "keyfile.json"), "w"), indent=1)
json.dump(reg, open(os.path.join(folder, "registration.json"), "w"), indent=1)
shutil.copyfile(a.art, os.path.join(folder, "center_art.png"))

assert dhsign.check_registration(reg)
assert dhsign.unlock_key(kf, pw) is not None
print(f"Created {folder}")
print(f"  public key (npub): {dhsign.bech32('npub', pk)}")
print(f"  fingerprint:       {dhsign.fingerprint(pk).hex()}   (this appears in every seal)")
print(f"  center art hash:   {hashlib.sha256(art).hexdigest()[:16]}...")
print("Keep keyfile.json and your password private. registration.json is public.")

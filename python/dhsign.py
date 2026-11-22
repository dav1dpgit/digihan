"""DigiHan signing and verification layer (format v0.3). See SPEC.md.

  payload (78 B) = ver/flags (1) | key_fingerprint (8) | timestamp (5) | sig (64)
  m = TaggedHash("DigiHan/v1", doc_hash || timestamp || key_fingerprint [|| center_hash])
The password only encrypts the private key at rest; it never enters the seal.
"""
import hashlib, json, os, time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import bip340

VERSION = 1
FLAG_CENTER = 0b0100            # flags bit 2: center committed
TAG = "DigiHan/v1"              # BIP340 tagged-hash tag for the signed message


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def fingerprint(pubkey: bytes) -> bytes:
    return sha256(pubkey)[:8]


# ---------------------------------------------------------------- keys ---
def new_key():
    while True:
        sk = os.urandom(32)
        try:
            return sk, bip340.pubkey_gen(sk)
        except ValueError:
            continue


def lock_key(sk: bytes, pubkey: bytes, password: str) -> dict:
    """Encrypt the private key with a password (scrypt -> ChaCha20-Poly1305)."""
    salt, nonce = os.urandom(16), os.urandom(12)
    k = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1,
                       maxmem=64 * 1024 * 1024, dklen=32)
    ct = ChaCha20Poly1305(k).encrypt(nonce, sk, pubkey)   # pubkey as AAD
    return {"format": "digihan-keyfile-v1", "kdf": "scrypt",
            "n": 2**15, "r": 8, "p": 1, "salt": salt.hex(), "nonce": nonce.hex(),
            "ciphertext": ct.hex(), "pubkey": pubkey.hex()}


def unlock_key(kf: dict, password: str) -> bytes:
    k = hashlib.scrypt(password.encode(), salt=bytes.fromhex(kf["salt"]),
                       n=kf["n"], r=kf["r"], p=kf["p"],
                       maxmem=64 * 1024 * 1024, dklen=32)
    return ChaCha20Poly1305(k).decrypt(bytes.fromhex(kf["nonce"]),
                                       bytes.fromhex(kf["ciphertext"]),
                                       bytes.fromhex(kf["pubkey"]))


# ------------------------------------------------------------- npub -----
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32(hrp: str, data: bytes) -> str:
    acc = bits = 0
    five = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append((acc << (5 - bits)) & 31)
    hx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(hx + five + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CH[d] for d in five + chk)


# ------------------------------------------------- center registration ---
def nostr_event_id(ev: dict) -> bytes:
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"],
                      ev["tags"], ev["content"]],
                     separators=(",", ":"), ensure_ascii=False)
    return sha256(ser.encode("utf-8"))


def register_center(sk: bytes, pubkey: bytes, art_bytes: bytes) -> dict:
    """Seal registration: a signed Nostr event binding key -> center artwork.
    Kind 30078 (NIP-78 application data). d-tag carries the center hash so each
    artwork is its own record and old seals keep verifying after art changes."""
    ch = sha256(art_bytes).hex()
    ev = {"pubkey": pubkey.hex(), "created_at": int(time.time()), "kind": 30078,
          "tags": [["d", "digihan-center:" + ch], ["center_hash", ch]],
          "content": json.dumps({"app": "DigiHan", "format": "v0.3",
                                 "center_hash": ch})}
    eid = nostr_event_id(ev)
    ev["id"] = eid.hex()
    ev["sig"] = bip340.sign(eid, sk, os.urandom(32)).hex()
    return ev


def check_registration(ev: dict) -> bool:
    eid = nostr_event_id(ev)
    return (eid.hex() == ev["id"] and
            bip340.verify(eid, bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])))


# ------------------------------------------------------- sign / payload ---
def signed_message(doc_hash: bytes, ts: int, fp: bytes, center_hash=None) -> bytes:
    body = doc_hash + ts.to_bytes(5, "big") + fp
    if center_hash is not None:
        body += center_hash
    return bip340.tagged_hash(TAG, body)


def seal_payload(sk: bytes, pubkey: bytes, doc_bytes: bytes, ts: int,
                 center_hash=None, aux=None) -> bytes:
    fp = fingerprint(pubkey)
    m = signed_message(sha256(doc_bytes), ts, fp, center_hash)
    sig = bip340.sign(m, sk, aux if aux is not None else os.urandom(32))
    flags = FLAG_CENTER if center_hash is not None else 0
    p = bytes([(VERSION << 4) | flags]) + fp + ts.to_bytes(5, "big") + sig
    assert len(p) == 78
    return p


def parse_payload(p: bytes) -> dict:
    return {"version": p[0] >> 4, "flags": p[0] & 0xF, "fp": p[1:9],
            "ts": int.from_bytes(p[9:14], "big"), "sig": p[14:78]}


def verify_payload(p: bytes, doc_bytes: bytes, keyring: dict, registrations: list):
    """Returns (ok, report_lines, matched_registration). See SPEC.md, section 8."""
    lines = []
    f = parse_payload(p)
    lines.append(f"version {f['version']}, flags {f['flags']:04b}, "
                 f"fingerprint {f['fp'].hex()}, asserted time "
                 f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(f['ts']))}")
    if f["version"] != VERSION or f["flags"] & ~FLAG_CENTER & 0xF:
        lines.append("FORMAT: unknown version or reserved flag set -> reject (SPEC.md, section 5)")
        return False, lines, None
    pk = keyring.get(f["fp"].hex())
    if pk is None:
        lines.append("KEY: no key for this fingerprint on this device -> cannot verify")
        return False, lines, None
    if fingerprint(pk) != f["fp"]:
        lines.append("KEY: keyring entry does not hash to the fingerprint -> reject")
        return False, lines, None
    lines.append(f"KEY: resolved fingerprint to public key {pk.hex()[:16]}...")
    dh = sha256(doc_bytes)
    lines.append(f"DOCUMENT: sha256 {dh.hex()[:16]}... ({len(doc_bytes):,} bytes)")
    candidates = [None]
    if f["flags"] & FLAG_CENTER:
        candidates = [r for r in registrations
                      if r["pubkey"] == pk.hex() and check_registration(r)]
        if not candidates:
            lines.append("CENTER: seal is center-committed but no valid registration "
                         "for this key is available -> cannot verify")
            return False, lines, None
    for reg in candidates:
        ch = bytes.fromhex(reg["tags"][1][1]) if reg else None
        m = signed_message(dh, f["ts"], f["fp"], ch)
        if bip340.verify(m, pk, f["sig"]):
            if reg:
                lines.append(f"CENTER: signed under registered artwork "
                             f"{reg['tags'][1][1][:16]}... (registration event "
                             f"{reg['id'][:12]}... signature valid) -> show this "
                             f"artwork beside the scanned seal for comparison")
            lines.append("SIGNATURE: VALID — document unmodified since signing; "
                         "produced by the holder of this key; signer bound to the "
                         "asserted time")
            return True, lines, reg
    lines.append("SIGNATURE: FAIL — document, time, key or center does not match "
                 "what was signed")
    return False, lines, None

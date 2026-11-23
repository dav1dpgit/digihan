"""DigiHan signing and verification layer (format v0.5: payload versions 1 and 2). See SPEC.md.

  payload (78 B) = ver/flags (1) | key_fingerprint (8) | timestamp (5) | sig (64)
  m = TaggedHash("DigiHan/v1", doc_hash || timestamp || key_fingerprint [|| center_hash] [|| block_hash])
The password only encrypts the private key at rest; it never enters the seal.
"""
import hashlib, json, os, time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import bip340

VERSION = 1
VERSIONS = (1, 2)                 # format v0.5: version 2 signs a stamp event (SPEC.md, section 6.2)
FLAG_CENTER = 0b0100            # flags bit 2: center committed
FLAG_ANCHOR = 0b0001            # flags bit 0 (format v0.4): the time field holds a Bitcoin block height and
                                # the signed message ends with that block's hash -> "made no earlier than"
KNOWN_FLAGS = FLAG_CENTER | FLAG_ANCHOR
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
    if kf.get("kdf") == "argon2id":                 # a key file made by the sealing page (web/sealer v4 on)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            from argon2.low_level import hash_secret_raw, Type
        except ImportError:
            raise SystemExit("This key file uses Argon2id. Install it first: pip install argon2-cffi")
        k = hash_secret_raw(password.encode(), bytes.fromhex(kf["salt"]), time_cost=int(kf["time_cost"]),
                            memory_cost=int(kf["memory_cost"]), parallelism=int(kf["parallelism"]),
                            hash_len=32, type=Type.ID)
        return AESGCM(k).decrypt(bytes.fromhex(kf["nonce"]), bytes.fromhex(kf["ciphertext"]),
                                 bytes.fromhex(kf["pubkey"]))
    if kf.get("kdf") == "pbkdf2-sha256":            # a key file made by the sealing page before v4
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        k = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(kf["salt"]), int(kf["iterations"]), 32)
        return AESGCM(k).decrypt(bytes.fromhex(kf["nonce"]), bytes.fromhex(kf["ciphertext"]),
                                 bytes.fromhex(kf["pubkey"]))
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


def register_center(sk: bytes, pubkey: bytes, art_bytes: bytes, image_url: str = None) -> dict:
    """Seal registration: a signed Nostr event binding key -> center artwork (see nip/NIP-DIGIHAN.md).
    Kind 30078. The d tag carries the center hash, so each artwork is its own record and old seals keep
    verifying after the artwork changes. The f tag carries the 8-byte key id, so a verifier holding only
    a scanned seal can ask relays for the record ({"kinds": [30078], "#f": [key_id]})."""
    ch = sha256(art_bytes).hex()
    tags = [["d", "digihan-center:" + ch], ["center_hash", ch], ["f", fingerprint(pubkey).hex()],
            ["alt", "DigiHan seal: artwork registration"]]
    if image_url:
        tags.append(["image", image_url])
    ev = {"pubkey": pubkey.hex(), "created_at": int(time.time()), "kind": 30078, "tags": tags,
          "content": json.dumps({"app": "DigiHan", "format": "v0.3", "center_hash": ch})}
    eid = nostr_event_id(ev)
    ev["id"] = eid.hex()
    ev["sig"] = bip340.sign(eid, sk, os.urandom(32)).hex()
    return ev


def reg_tag(ev: dict, name: str):
    for t in ev.get("tags", []):
        if t and t[0] == name and len(t) > 1:
            return t[1]
    return None


def check_registration(ev: dict) -> bool:
    eid = nostr_event_id(ev)
    return (eid.hex() == ev["id"] and
            bip340.verify(eid, bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])))


# ------------------------------------------------------- sign / payload ---
def signed_message(doc_hash: bytes, ts: int, fp: bytes, center_hash=None, block_hash=None) -> bytes:
    body = doc_hash + ts.to_bytes(5, "big") + fp
    if center_hash is not None:
        body += center_hash
    if block_hash is not None:                  # anchored seal (v0.4): 32 bytes, in the usual display order
        body += block_hash
    return bip340.tagged_hash(TAG, body)


def stamp_event(pubkey: bytes, doc_hash: bytes, field: int, fp: bytes, center_hash=None, block=None) -> dict:
    """Payload version 2 (SPEC.md, section 6.2): the stamp event, a Nostr event built from the seal's parts.
    field = the 5-byte timestamp field (time, or block height A); block = (height, hash 32 bytes, header time)."""
    dh = doc_hash.hex()
    tags = [["d", f"digihan-stamp:{dh}:{field}"], ["x", dh], ["f", fp.hex()]]
    if center_hash is not None:
        tags.append(["center_hash", center_hash.hex()])
    if block is not None:
        tags.append(["block", str(block[0]), block[1].hex()])
    tags.append(["alt", "DigiHan stamp: a seal on a document"])
    content = f"DigiHan stamp. Document SHA-256: {dh}." + (f" No earlier than Bitcoin block {block[0]}." if block else "")
    return {"pubkey": pubkey.hex(), "created_at": int(block[2]) if block else field, "kind": 30078,
            "tags": tags, "content": content}


def is_stamp_event(ev: dict) -> bool:
    return (reg_tag(ev, "d") or "").startswith("digihan-stamp:")


def block_hash_bytes(display_hex: str) -> bytes:
    """A block hash as printed by bitcoin-cli getblockhash or a block explorer -> 32 bytes, same order."""
    b = bytes.fromhex(display_hex.strip())
    if len(b) != 32:
        raise ValueError("a block hash is 64 hex characters")
    return b


def seal_payload(sk: bytes, pubkey: bytes, doc_bytes: bytes, ts: int,
                 center_hash=None, aux=None, anchor=None) -> bytes:
    """anchor = (block_height, block_hash_bytes) seals "no earlier than that block" (format v0.4):
    the time field then holds the height, and the block's hash is signed with the document."""
    fp = fingerprint(pubkey)
    block_hash = None
    if anchor is not None:
        ts, block_hash = int(anchor[0]), anchor[1]
        assert len(block_hash) == 32 and 0 <= ts < 2 ** 40
    m = signed_message(sha256(doc_bytes), ts, fp, center_hash, block_hash)
    sig = bip340.sign(m, sk, aux if aux is not None else os.urandom(32))
    flags = (FLAG_CENTER if center_hash is not None else 0) | (FLAG_ANCHOR if anchor is not None else 0)
    p = bytes([(VERSION << 4) | flags]) + fp + ts.to_bytes(5, "big") + sig
    assert len(p) == 78
    return p


def parse_payload(p: bytes) -> dict:
    return {"version": p[0] >> 4, "flags": p[0] & 0xF, "fp": p[1:9],
            "ts": int.from_bytes(p[9:14], "big"), "sig": p[14:78]}


def verify_payload(p: bytes, doc_bytes: bytes, keyring: dict, registrations: list, block_hash_at=None,
                   block_time_at=None):
    """Returns (ok, report_lines, matched_registration). See SPEC.md, section 8.
    block_hash_at(height) -> 32 bytes or None: needed only for anchored seals (format v0.4).
    block_time_at(height) -> the block header's time or None: needed only for anchored version 2 seals."""
    lines = []
    f = parse_payload(p)
    anchored = bool(f["flags"] & FLAG_ANCHOR)
    when = (f"anchored: no earlier than Bitcoin block {f['ts']}" if anchored else "time stated by the signer "
            + time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(f['ts'])))
    lines.append(f"version {f['version']}, flags {f['flags']:04b}, fingerprint {f['fp'].hex()}, {when}")
    if f["version"] not in VERSIONS or f["flags"] & ~KNOWN_FLAGS & 0xF:
        lines.append("FORMAT: unknown version or reserved flag set -> reject (SPEC.md, section 5)")
        return False, lines, None
    block_hash = None
    if anchored:
        block_hash = block_hash_at(f["ts"]) if block_hash_at else None
        if block_hash is None:
            lines.append(f"TIME: this seal is anchored to Bitcoin block {f['ts']}; its block hash is needed to "
                         f"check it (from your own node: bitcoin-cli getblockhash {f['ts']})")
            return False, lines, None
    block_time = None
    if anchored and f["version"] == 2:
        block_time = block_time_at(f["ts"]) if block_time_at else None
        if block_time is None:
            lines.append(f"TIME: this version 2 seal is anchored to Bitcoin block {f['ts']}; its block header time is "
                         f"needed to check it (from your own node: bitcoin-cli getblockheader $(bitcoin-cli getblockhash {f['ts']}))")
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
                      if r["pubkey"] == pk.hex() and not is_stamp_event(r) and check_registration(r)]
        if not candidates:
            lines.append("CENTER: seal is center-committed but no valid registration "
                         "for this key is available -> cannot verify")
            return False, lines, None
    for reg in candidates:
        ch = bytes.fromhex(reg_tag(reg, "center_hash")) if reg else None
        if f["version"] == 2:
            ev = stamp_event(pk, dh, f["ts"], f["fp"], ch, (f["ts"], block_hash, block_time) if anchored else None)
            m = nostr_event_id(ev)
        else:
            m = signed_message(dh, f["ts"], f["fp"], ch, block_hash)
        if bip340.verify(m, pk, f["sig"]):
            if reg:
                lines.append(f"CENTER: signed under registered artwork "
                             f"{reg_tag(reg, 'center_hash')[:16]}... (registration event "
                             f"{reg['id'][:12]}... signature valid) -> show this "
                             f"artwork beside the scanned seal for comparison")
            if anchored:
                lines.append(f"TIME: made no earlier than Bitcoin block {f['ts']} (hash {block_hash.hex()[:16]}...), "
                             "because that block's hash is part of what was signed")
            if f["version"] == 2:
                lines.append(f"FORMAT: version 2, signed over the stamp event {m.hex()[:16]}... (SPEC.md, section 6.2)")
            lines.append("SIGNATURE: VALID — document unmodified since signing; "
                         "produced by the holder of this key; "
                         + ("time proven by the block anchor" if anchored else "signer bound to the asserted time"))
            return True, lines, reg
    lines.append("SIGNATURE: FAIL — document, time, key or center does not match "
                 "what was signed")
    return False, lines, None

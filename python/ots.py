"""OpenTimestamps proofs for DigiHan seals: "this seal existed no later than Bitcoin block H".

The proof is over SHA-256 of the seal's 78-byte payload (the data in the ring). The payload holds the
signature, so a proof that the payload existed when block H was mined proves the seal was made by then.

Reads and writes the standard .ots format (opentimestamps.org): the usual `ots` client verifies these
proofs (`ots verify x_seal_payload.bin.ots`), and this code reads proofs the `ots` client made.
Pure Python, standard library only. See docs/TIME-PROOF.md.
"""
import hashlib, json, re, urllib.request

HEADER_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAJOR_VERSION = 1
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
OP_APPEND, OP_PREPEND, OP_REVERSE, OP_HEXLIFY = 0xF0, 0xF1, 0xF2, 0xF3
OP_SHA1, OP_RIPEMD160, OP_SHA256, OP_KECCAK256 = 0x02, 0x03, 0x08, 0x67
MAX_LEN, MAX_PAYLOAD, MAX_URI, MAX_DEPTH = 4096, 8192, 1000, 256
URI_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")
# Calendars that accept a digest and later serve the Bitcoin part of the proof (the `ots` client's defaults).
CALENDARS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
             "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"]
HTTP_HEADERS = {"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "digihan-ots/0.4"}
# The pools above hand the digest to calendars such as alice.btc.calendar.opentimestamps.org; a pending
# proof names those. upgrade() asks only calendars on this list (the `ots` client's whitelist, plus the pools).
CALENDAR_OK = re.compile(r"^https://([a-z0-9-]+\.)*(calendar\.opentimestamps\.org|calendar\.eternitywall\.com|"
                         r"calendar\.catallaxy\.com|pool\.opentimestamps\.org|pool\.eternitywall\.com|"
                         r"btc\.catallaxy\.com)/?$")


class ProofError(ValueError):
    pass


# ---------------------------------------------------------------- bytes ---
class _Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def bytes(self, n):
        if self.i + n > len(self.b):
            raise ProofError("proof ends early")
        r = self.b[self.i:self.i + n]
        self.i += n
        return r

    def varuint(self):
        v = shift = 0
        for _ in range(9):
            c = self.bytes(1)[0]
            v |= (c & 0x7F) << shift
            if not c & 0x80:
                return v
            shift += 7
        raise ProofError("number too long")

    def varbytes(self, maxlen, minlen=0):
        n = self.varuint()
        if n > maxlen or n < minlen:
            raise ProofError("field length out of range")
        return self.bytes(n)


def _varuint(v):
    out = bytearray()
    while True:
        c = v & 0x7F
        v >>= 7
        out.append(c | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _varbytes(b):
    return _varuint(len(b)) + b


# ------------------------------------------------------------- operations ---
def apply_op(op, msg):
    """op = (tag, arg). Returns the result, or raises ProofError."""
    tag, arg = op
    if len(msg) > MAX_LEN:
        raise ProofError("message too long")
    if tag == OP_APPEND:
        r = msg + arg
    elif tag == OP_PREPEND:
        r = arg + msg
    elif tag == OP_REVERSE:
        r = msg[::-1]
    elif tag == OP_HEXLIFY:
        r = msg.hex().encode()
    elif tag == OP_SHA256:
        r = hashlib.sha256(msg).digest()
    elif tag == OP_SHA1:
        r = hashlib.sha1(msg).digest()
    elif tag == OP_RIPEMD160:
        try:
            r = hashlib.new("ripemd160", msg).digest()
        except ValueError:
            raise ProofError("ripemd160 is not available in this Python")
    else:
        raise ProofError(f"unknown operation 0x{tag:02x}")
    if len(r) > MAX_LEN:
        raise ProofError("result too long")
    return r


def _read_op(rd, tag):
    if tag in (OP_APPEND, OP_PREPEND):
        return (tag, rd.varbytes(MAX_LEN, 1))
    if tag in (OP_REVERSE, OP_HEXLIFY, OP_SHA1, OP_RIPEMD160, OP_SHA256, OP_KECCAK256):
        return (tag, b"")
    raise ProofError(f"unknown operation 0x{tag:02x}")


def _write_op(op):
    tag, arg = op
    return bytes([tag]) + (_varbytes(arg) if tag in (OP_APPEND, OP_PREPEND) else b"")


# ----------------------------------------------------------- attestations ---
def _read_att(rd):
    tag = rd.bytes(8)
    payload = rd.varbytes(MAX_PAYLOAD)
    p = _Reader(payload)
    if tag == TAG_PENDING:
        uri = p.varbytes(MAX_URI)
        if not set(uri) <= URI_CHARS:
            raise ProofError("calendar address has characters that are not allowed")
        att = ("pending", uri.decode())
    elif tag == TAG_BITCOIN:
        att = ("bitcoin", p.varuint())
    else:
        return ("other", tag, payload)
    if p.i != len(payload):
        raise ProofError("attestation has extra bytes")
    return att


def _att_tag(att):
    return {"pending": TAG_PENDING, "bitcoin": TAG_BITCOIN}.get(att[0]) or att[1]


def _write_att(att):
    if att[0] == "pending":
        payload = _varbytes(att[1].encode())
    elif att[0] == "bitcoin":
        payload = _varuint(att[1])
    else:
        payload = att[2]
    return _att_tag(att) + _varbytes(payload)


def _att_key(att):
    # the reference client's order: by tag, then calendar address / block height / payload
    return (_att_tag(att), att[1] if att[0] != "other" else att[2])


# --------------------------------------------------------------- the tree ---
class Timestamp:
    """One message in the proof tree, the attestations made on it, and the operations leading on."""

    def __init__(self, msg):
        self.msg = msg
        self.atts = []          # ("pending", uri) | ("bitcoin", height) | ("other", tag, payload)
        self.ops = {}           # (tag, arg) -> Timestamp

    @classmethod
    def read(cls, rd, msg, depth=MAX_DEPTH):
        if depth <= 0:
            raise ProofError("proof is nested too deeply")
        self = cls(msg)

        def one(tag):
            if tag == 0x00:
                a = _read_att(rd)
                if a not in self.atts:
                    self.atts.append(a)
            else:
                op = _read_op(rd, tag)
                # keccak256 appears only on Ethereum branches, ripemd160 on none of today's calendars:
                # such a branch is kept (and written back) but not evaluated
                if msg is None or op[0] == OP_KECCAK256:
                    nxt = None
                elif op[0] == OP_RIPEMD160 and "ripemd160" not in hashlib.algorithms_available:
                    nxt = None
                else:
                    nxt = apply_op(op, msg)
                self.ops[op] = Timestamp.read(rd, nxt, depth - 1)

        tag = rd.bytes(1)[0]
        while tag == 0xFF:
            one(rd.bytes(1)[0])
            tag = rd.bytes(1)[0]
        one(tag)
        return self

    def write(self):
        atts = sorted(self.atts, key=_att_key)
        ops = sorted(self.ops.items(), key=lambda kv: kv[0])
        if not atts and not ops:
            raise ProofError("empty timestamp")
        out = b""
        for a in atts[:-1]:
            out += b"\xff\x00" + _write_att(a)
        if not ops:
            return out + b"\x00" + _write_att(atts[-1])
        if atts:
            out += b"\xff\x00" + _write_att(atts[-1])
        for op, st in ops[:-1]:
            out += b"\xff" + _write_op(op) + st.write()
        op, st = ops[-1]
        return out + _write_op(op) + st.write()

    def merge(self, other):
        if other.msg != self.msg:
            raise ProofError("cannot merge proofs of different messages")
        for a in other.atts:
            if a not in self.atts:
                self.atts.append(a)
        for op, st in other.ops.items():
            if op in self.ops:
                self.ops[op].merge(st)
            else:
                self.ops[op] = st

    def walk(self):
        """Yields (msg, attestation) for every attestation in the tree."""
        for a in self.atts:
            yield self.msg, a
        for st in self.ops.values():
            yield from st.walk()

    def leaves(self):
        """Yields every Timestamp node that carries an attestation."""
        if self.atts:
            yield self
        for st in self.ops.values():
            yield from st.leaves()


class Proof:
    """A detached .ots proof: the file's hash and the timestamp tree that starts from it."""
    HASH_LEN = {OP_SHA256: 32, OP_SHA1: 20, OP_RIPEMD160: 20, OP_KECCAK256: 32}

    def __init__(self, digest, timestamp=None, hash_op=OP_SHA256):
        self.hash_op, self.digest = hash_op, digest
        self.timestamp = timestamp or Timestamp(digest)

    @classmethod
    def from_bytes(cls, b):
        rd = _Reader(b)
        if rd.bytes(len(HEADER_MAGIC)) != HEADER_MAGIC:
            raise ProofError("not an OpenTimestamps proof")
        if rd.varuint() != MAJOR_VERSION:
            raise ProofError("unknown proof version")
        hop = rd.bytes(1)[0]
        if hop not in cls.HASH_LEN:
            raise ProofError("unknown file hash")
        digest = rd.bytes(cls.HASH_LEN[hop])
        ts = Timestamp.read(rd, digest)
        if rd.i != len(b):
            raise ProofError("extra bytes after the proof")
        return cls(digest, ts, hop)

    def to_bytes(self):
        return HEADER_MAGIC + _varuint(MAJOR_VERSION) + bytes([self.hash_op]) + self.digest + self.timestamp.write()

    def bitcoin(self):
        """[(height, merkle_root_display_hex)] claimed by the proof, lowest block number first."""
        out = {(a[1], m[::-1].hex()) for m, a in self.timestamp.walk()
               if a[0] == "bitcoin" and m is not None and len(m) == 32}
        return sorted(out)

    def pending(self):
        return sorted({a[1] for _, a in self.timestamp.walk() if a[0] == "pending"})


def is_proof(b):
    return b[:len(HEADER_MAGIC)] == HEADER_MAGIC


def payload_digest(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


# --------------------------------------------------------------- network ---
def _http(url, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, headers=HTTP_HEADERS, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(10000)


def stamp(payload: bytes, calendars=None, need=2, http=_http):
    """Send SHA-256(payload) to OpenTimestamps calendars. Returns (Proof, [calendars that answered]).
    The proof is pending until a calendar's transaction is in a Bitcoin block (usually a few hours);
    then upgrade() fetches the Bitcoin part. No nonce is added: the seal is public anyway."""
    d = payload_digest(payload)
    proof, ok = Proof(d), []
    for cal in calendars or CALENDARS:
        try:
            body = http(cal.rstrip("/") + "/digest", data=d)
            proof.timestamp.merge(Timestamp.read(_Reader(body), d))
            ok.append(cal)
        except Exception:
            continue
    if len(ok) < need:
        raise ProofError(f"only {len(ok)} of the calendars answered (need {need})")
    return proof, ok


def upgrade(proof: Proof, http=_http):
    """Ask each calendar for the Bitcoin part of a pending proof. Returns the number of parts added.
    Only known https calendars are asked (CALENDAR_OK), because the proof file names the address."""
    added = 0
    for node in list(proof.timestamp.leaves()):
        if node.msg is None:
            continue
        for a in list(node.atts):
            if a[0] != "pending" or not CALENDAR_OK.match(a[1]):
                continue
            try:
                body = http(a[1].rstrip("/") + "/timestamp/" + node.msg.hex())
            except Exception:
                continue                       # not ready yet (404) or unreachable
            got = Timestamp.read(_Reader(body), node.msg)
            if any(x[0] == "bitcoin" for _, x in got.walk()):
                node.merge(got)
                added += 1
    return added


# --------------------------------------------------------------- verify ---
def verify(proof: Proof, payload: bytes, merkle_root_at):
    """Check a proof against a seal's payload.
    merkle_root_at(height) -> (merkle_root_display_hex, block_time_unix) or None.
    Returns (height, block_time) of the lowest block number that attests, or raises ProofError."""
    if proof.hash_op != OP_SHA256 or proof.digest != payload_digest(payload):
        raise ProofError("this proof is for different data, not this seal")
    claims = proof.bitcoin()
    if not claims:
        raise ProofError("the proof is still pending: no Bitcoin block yet" if proof.pending()
                         else "the proof has no Bitcoin attestation")
    errors = []
    for height, root in claims:
        got = merkle_root_at(height)
        if got is None:
            errors.append(f"block {height}: block data could not be fetched")
            continue
        if got[0].lower() == root:
            return height, got[1]
        errors.append(f"block {height}: the proof does not match that block")
    raise ProofError("; ".join(errors))


def attach_name():
    return "seal.ots"


if __name__ == "__main__":
    import sys
    p = Proof.from_bytes(open(sys.argv[1], "rb").read())
    print(json.dumps({"digest": p.digest.hex(), "bitcoin": p.bitcoin(), "pending": p.pending()}, indent=1))

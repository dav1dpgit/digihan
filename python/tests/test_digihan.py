"""DigiHan format v0.4 tests. Run from the python/ folder:  python -m pytest tests"""
import csv, hashlib, json, os, sys
import numpy as np
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bip340, dhsign, digihan as dh  # noqa: E402

G = dh.Geometry(45, 5, 0.6)
GS = dh.Geometry(45, 5, 0.6, square=True)


def test_bip340_official_vectors():
    n = 0
    for row in csv.DictReader(open(os.path.join(HERE, "bip340_test_vectors.csv"))):
        n += 1
        pk, msg, sig = (bytes.fromhex(row[k]) for k in ("public key", "message", "signature"))
        assert bip340.verify(msg, pk, sig) == (row["verification result"] == "TRUE"), row["index"]
        if row["secret key"]:
            sk, aux = bytes.fromhex(row["secret key"]), bytes.fromhex(row["aux_rand"])
            assert bip340.pubkey_gen(sk) == pk and bip340.sign(msg, sk, aux) == sig
    assert n == 19


def test_geometry_v03():
    assert G.cells == [188, 195, 202, 210, 217]
    assert G.capacity_bits == 1012 == len(dh.SYNC_BITS) + 8 * (dh.PAYLOAD_BYTES + dh.NSYM_DEFAULT)
    assert abs((G.r_locator - G.r_center) - 1.2) < 1e-9          # guard band
    assert abs(dh.START_ANGLE + np.pi / 2) < 1e-12                 # bit 0 at 12 o'clock


@pytest.mark.parametrize("geom", [G, GS], ids=["round", "square"])
@pytest.mark.parametrize("cell", ["dot", "arc"])
def test_round_trip(geom, cell):
    p = np.random.default_rng(7).integers(0, 256, 78, dtype=np.uint8).tobytes()
    img = dh.render(geom, dh.build_stream(p, 45), 15.0, "text", cell=cell)
    got, n = dh.decode(img, geom, 45)
    assert got == p and n == 0


def test_bit0_under_key_bridge():
    s = np.zeros(1012, np.uint8); s[0] = 1
    a = np.asarray(dh.render(G, s, 15.0, "empty", cell="dot"))
    S = a.shape[0]; c = S / 2
    yy, xx = np.mgrid[0:S, 0:S]; r = np.hypot(xx - c, yy - c) / 15.0
    ys, xs = np.nonzero((a < 128) & (r > G.r_band_in) & (r < G.r_band_out))
    ang = np.degrees(np.arctan2(ys.mean() - c, xs.mean() - c))
    assert abs(ang - (-90 + 360 * 0.43 / G.cells[0])) < 0.5


def test_sign_verify_and_tamper():
    sk, pk = dhsign.new_key()
    art = b"center-art-bytes"
    reg = dhsign.register_center(sk, pk, art)
    assert dhsign.check_registration(reg)
    doc, ts = b"an exact document", 1767225600
    ch = hashlib.sha256(art).digest()
    p = dhsign.seal_payload(sk, pk, doc, ts, ch)
    assert len(p) == 78 and p[0] >> 4 == 1 and p[0] & 0x04
    keyring = {dhsign.fingerprint(pk).hex(): pk}
    ok, _, _ = dhsign.verify_payload(p, doc, keyring, [reg])
    assert ok
    assert not dhsign.verify_payload(p, doc + b" ", keyring, [reg])[0]           # one byte changed
    q = bytearray(p); q[9:14] = (ts - 3600).to_bytes(5, "big")                   # time edited
    assert not dhsign.verify_payload(bytes(q), doc, keyring, [reg])[0]


def test_signed_message_tag():
    m = dhsign.signed_message(b"\0" * 32, 0, b"\0" * 8)
    assert m == bip340.tagged_hash("DigiHan/v1", b"\0" * 45)


# ---- v0.4: "no earlier than" block anchor ----
GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"   # Bitcoin block 0


def test_anchor_no_earlier_than_block():
    sk, pk = dhsign.new_key()
    doc = b"anchored document"
    bh = dhsign.block_hash_bytes(GENESIS)
    p = dhsign.seal_payload(sk, pk, doc, 0, anchor=(0, bh))
    f = dhsign.parse_payload(p)
    assert f["flags"] & dhsign.FLAG_ANCHOR and f["ts"] == 0
    keyring = {dhsign.fingerprint(pk).hex(): pk}
    ok, lines, _ = dhsign.verify_payload(p, doc, keyring, [], block_hash_at=lambda h: bh if h == 0 else None)
    assert ok and any("no earlier than Bitcoin block 0" in l for l in lines)
    wrong = bytes(32)                                         # a different chain or a made-up block
    assert not dhsign.verify_payload(p, doc, keyring, [], block_hash_at=lambda h: wrong)[0]
    assert not dhsign.verify_payload(p, doc, keyring, [])[0]  # no block hash available: cannot pass


def test_anchor_with_center_and_tamper():
    sk, pk = dhsign.new_key()
    art = b"art"; reg = dhsign.register_center(sk, pk, art)
    bh = dhsign.block_hash_bytes(GENESIS)
    p = dhsign.seal_payload(sk, pk, b"doc", 0, hashlib.sha256(art).digest(), anchor=(0, bh))
    kr = {dhsign.fingerprint(pk).hex(): pk}
    assert dhsign.verify_payload(p, b"doc", kr, [reg], block_hash_at=lambda h: bh)[0]
    q = bytearray(p); q[9:14] = (1).to_bytes(5, "big")       # claim a higher block number
    assert not dhsign.verify_payload(bytes(q), b"doc", kr, [reg], block_hash_at=lambda h: bh)[0]


# ------------------------------------------------ OpenTimestamps (no later than) ---
import ots  # noqa: E402

OTSD = os.path.join(HERE, "ots")
HELLO_ROOT = "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00"   # block 358391


def _read(*p):
    return open(os.path.join(OTSD, *p), "rb").read()


def test_ots_reads_and_writes_standard_proofs():
    for name, btc, pend in [("hello-world.txt", [(358391, HELLO_ROOT)], []),
                            ("two-calendars.txt", [], ["https://alice.btc.calendar.opentimestamps.org",
                                                       "https://bob.btc.calendar.opentimestamps.org"]),
                            ("different-blockchains.txt", [(455605, "2a19192cf00fb1baeea516b69b3a62195849589b4caafeb6ad6ebba58b9ae69a")], None)]:
        raw = _read(name + ".ots")
        p = ots.Proof.from_bytes(raw)
        assert p.digest == hashlib.sha256(_read(name)).digest()
        assert p.bitcoin() == btc
        if pend is not None:
            assert p.pending() == pend
        assert p.to_bytes() == raw                      # byte-identical round trip
    for bad in ("bad-major-version.ots", "exceeds-max-msg-length.ots"):
        with pytest.raises(ots.ProofError):
            ots.Proof.from_bytes(_read("invalid", bad))
    with pytest.raises(ots.ProofError):
        ots.Proof.from_bytes(_read("hello-world.txt.ots")[:-3])      # cut short


def test_ots_verify_against_block():
    p, data = ots.Proof.from_bytes(_read("hello-world.txt.ots")), _read("hello-world.txt")
    assert ots.verify(p, data, lambda h: (HELLO_ROOT, 1_432_800_000) if h == 358391 else None) == (358391, 1_432_800_000)
    with pytest.raises(ots.ProofError, match="does not match"):
        ots.verify(p, data, lambda h: ("00" * 32, 0))
    with pytest.raises(ots.ProofError, match="different data"):
        ots.verify(p, data + b"x", lambda h: (HELLO_ROOT, 0))
    with pytest.raises(ots.ProofError, match="could not be fetched"):
        ots.verify(p, data, lambda h: None)


def test_ots_stamp_upgrade_verify_a_seal():
    """A seal's payload through a simulated calendar: stamp -> pending -> upgrade -> Bitcoin -> verify."""
    sk, pk = dhsign.new_key()
    payload = dhsign.seal_payload(sk, pk, b"contract", 1_790_000_000)
    d = ots.payload_digest(payload)
    t4 = (1_790_000_100).to_bytes(4, "big")
    pool, cal = "https://a.pool.opentimestamps.org", "https://alice.btc.calendar.opentimestamps.org"
    leaf = t4 + d                                          # the calendar prepends its time
    tx_prefix, tx_suffix = b"\x01" * 40, b"\x02" * 12      # stand-ins for the calendar's transaction
    inner = hashlib.sha256(hashlib.sha256(tx_prefix + hashlib.sha256(leaf).digest() + tx_suffix).digest()).digest()
    root = hashlib.sha256(hashlib.sha256(inner + b"\x03" * 32).digest()).digest()

    def http(url, data=None):
        if url == pool + "/digest":
            assert data == d
            return bytes([0xF1]) + ots._varbytes(t4) + b"\x00" + ots._write_att(("pending", cal))
        if url == cal + "/timestamp/" + leaf.hex():
            body = bytes([0x08, 0xF1]) + ots._varbytes(tx_prefix) + bytes([0xF0]) + ots._varbytes(tx_suffix)
            body += bytes([0x08, 0x08, 0xF0]) + ots._varbytes(b"\x03" * 32) + bytes([0x08, 0x08])
            return body + b"\x00" + ots._write_att(("bitcoin", 930000))
        raise OSError("404")

    proof, ok = ots.stamp(payload, calendars=[pool], need=1, http=http)
    assert ok == [pool] and proof.pending() == [cal] and proof.bitcoin() == []
    pending = ots.Proof.from_bytes(proof.to_bytes())
    with pytest.raises(ots.ProofError, match="pending"):
        ots.verify(pending, payload, lambda h: None)
    assert ots.upgrade(pending, http=http) == 1
    assert not ots.CALENDAR_OK.match("https://evil.example.com") and not ots.CALENDAR_OK.match("http://alice.btc.calendar.opentimestamps.org")
    done = ots.Proof.from_bytes(pending.to_bytes())
    assert done.bitcoin() == [(930000, root[::-1].hex())]
    assert ots.verify(done, payload, lambda h: (root[::-1].hex(), 1_790_003_000)) == (930000, 1_790_003_000)
    other = dhsign.seal_payload(sk, pk, b"contract", 1_790_000_001)
    with pytest.raises(ots.ProofError, match="different data"):
        ots.verify(done, other, lambda h: (root[::-1].hex(), 0))


@pytest.mark.online
def test_ots_online_block_358391():
    """Needs the internet: the example proof's root against two block explorers."""
    import anchor
    got = anchor.explorer_merkle_at(358391)
    assert got is not None and got[0] == HELLO_ROOT
    assert ots.verify(ots.Proof.from_bytes(_read("hello-world.txt.ots")), _read("hello-world.txt"),
                      anchor.explorer_merkle_at)[0] == 358391


def test_sign_hash_for_an_offline_key(tmp_path, capsys):
    """sign_hash.py signs a sealing-page code with a key folder; the signature checks against the key."""
    import sign_hash, bip340
    sk, pk = dhsign.new_key()
    d = tmp_path / "key_t"; d.mkdir()
    (d / "keyfile.json").write_text(json.dumps(dhsign.lock_key(sk, pk, "pw-for-tests")))
    code = hashlib.sha256(b"a code from the page").hexdigest()
    sig = sign_hash.main([code, "--key", str(d), "--password", "pw-for-tests"])
    assert bip340.verify(bytes.fromhex(code), pk, bytes.fromhex(sig))
    with pytest.raises(SystemExit):
        sign_hash.main(["xyz", "--key", str(d), "--password", "pw-for-tests"])

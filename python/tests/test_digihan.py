"""DigiHan format v0.3 tests. Run from the python/ folder:  python -m pytest tests"""
import csv, hashlib, os, sys
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

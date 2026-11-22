"""DigiHan — confirm this computer's install works.
Runs the 19 official BIP340 test vectors and a seal encode/decode round trip."""
import csv, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numpy as np  # noqa: E402
import bip340, digihan as dh  # noqa: E402

ok = n = 0
for row in csv.DictReader(open(os.path.join(HERE, "tests", "bip340_test_vectors.csv"))):
    n += 1
    pk = bytes.fromhex(row["public key"]); msg = bytes.fromhex(row["message"])
    sig = bytes.fromhex(row["signature"]); want = row["verification result"] == "TRUE"
    good = bip340.verify(msg, pk, sig) == want
    if row["secret key"]:
        sk = bytes.fromhex(row["secret key"]); aux = bytes.fromhex(row["aux_rand"])
        good &= bip340.pubkey_gen(sk) == pk and bip340.sign(msg, sk, aux) == sig
    ok += good
print(f"BIP340 official test vectors: {ok}/{n}")

g = dh.Geometry(45, 5, 0.6)
p = np.random.default_rng(1).integers(0, 256, 78, dtype=np.uint8).tobytes()
out, _ = dh.decode(dh.render(g, dh.build_stream(p, 45), 15.0, "text", cell="dot"), g, 45)
print(f"Seal encode/decode round trip: {'OK' if out == p else 'FAILED'}")
print("SELF-TEST PASSED" if ok == n and out == p else "SELF-TEST FAILED")

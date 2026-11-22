"""BIP340 Schnorr signatures over secp256k1 — pure Python, following the
algorithm in the BIP340 specification (bitcoin/bips, bip-0340.mediawiki).
For proof-of-concept use only: not constant-time, not for production keys.
"""
import hashlib

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def _add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] == P2[0] and P1[1] != P2[1]:
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    return (x3, (lam * (P1[0] - x3) - P1[1]) % p)


def _mul(P, k):
    R = None
    for i in range(256):
        if (k >> i) & 1:
            R = _add(R, P)
        P = _add(P, P)
    return R


def _b(i: int) -> bytes:
    return i.to_bytes(32, "big")


def _i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _lift_x(x: int):
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y % 2 == 0 else p - y)


def pubkey_gen(seckey: bytes) -> bytes:
    d0 = _i(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError("secret key out of range")
    return _b(_mul(G, d0)[0])


def sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    d0 = _i(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError("secret key out of range")
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    P = _mul(G, d0)
    d = d0 if P[1] % 2 == 0 else n - d0
    t = bytes(a ^ b for a, b in zip(_b(d), tagged_hash("BIP0340/aux", aux_rand)))
    k0 = _i(tagged_hash("BIP0340/nonce", t + _b(P[0]) + msg)) % n
    if k0 == 0:
        raise RuntimeError("nonce is zero")
    R = _mul(G, k0)
    k = k0 if R[1] % 2 == 0 else n - k0
    e = _i(tagged_hash("BIP0340/challenge", _b(R[0]) + _b(P[0]) + msg)) % n
    sig = _b(R[0]) + _b((k + e * d) % n)
    if not verify(msg, _b(P[0]), sig):
        raise RuntimeError("produced signature failed self-check")
    return sig


def verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    P = _lift_x(_i(pubkey))
    r, s = _i(sig[:32]), _i(sig[32:])
    if P is None or r >= p or s >= n:
        return False
    e = _i(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg)) % n
    R = _add(_mul(G, s), _mul(P, n - e))
    if R is None or R[1] % 2 != 0 or R[0] != r:
        return False
    return True

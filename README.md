# DigiHan

DigiHan is a digital version of the Japanese hanko seal. The ring of dots around the seal holds a
signature of the exact document plus the time the signer stated, made with the signer's key.
Anyone can point a phone camera at the seal and check it against the signer's published key, with
no account and no company in the middle.

The center of the seal is free artwork (a signature, lettering, a crest, anything). Only the ring
follows the format, so a seal can look like its owner and still be read by any camera.

## Status: format v0.3 (frozen), November 2026

| Works today | Not yet |
|---|---|
| The seal format, frozen as v0.3 ([SPEC.md](SPEC.md)) | Proof of **when** a seal was made (the time is the signer's statement; see below) |
| Python codec: draw and read seals, round or square | Signature check on the phone (the scanner reads the ring; checking needs the key and document) |
| Keys: BIP340 Schnorr, published as Nostr keys (npub) | A Nostr NIP for the center registration (draft in progress) |
| Seal any PDF, including PDFs already e-signed (cover sheet, file left unchanged) | Document tiers beyond byte-exact |
| Check a sealed PDF with only the signer's public record | |
| Phone scanner (static web page): [digihan.org/scan](https://digihan.org/scan) | |

### What a valid seal proves

It proves which **key** sealed the document, that the document's bytes have not changed by even one
byte, and that the stated time cannot be changed afterward. It does **not** prove who holds the key
(a notary's job), and it does **not** prove when the seal was made: the signer chooses the time. Time
anchors that prove a window between two Bitcoin blocks are planned ([SPEC.md, section 11](SPEC.md#11-planned-not-in-v03)).

## Layout

```
SPEC.md               the format, v0.3 (public domain)
python/               reference code
  digihan.py          ring codec: draw and read seals
  dhsign.py           payload, signing, verification, key files, center registration
  bip340.py           BIP340 Schnorr signatures (pure Python)
  make_key.py         make a key, locked with your password
  sign_pdf.py         seal a PDF, then re-check the result from scratch
  verify_pdf.py       check a sealed PDF with only the signer's registration.json
  selftest.py         confirm an install works
  sample_center.png   a neutral center image for trying it out
  tests/              pytest suite and the official BIP340 test vectors
web/scanner/          the phone scanner: index.html + digihan.js (no build step, no server code)
tests/                camera-stress rig for the phone decoder
```

## Try it

Python 3.10 or newer.

```
cd python
pip install -r requirements.txt
python selftest.py
python make_key.py alice --art sample_center.png
python sign_pdf.py ../some.pdf sealed --key key_alice
python verify_pdf.py sealed/some_sealed.pdf key_alice/registration.json --save-original
```

`make_key.py` writes `key_alice/`: `keyfile.json` (the secret key, encrypted with your password:
scrypt + ChaCha20-Poly1305), `registration.json` (public: your key and your center artwork's hash,
signed by your key) and `center_art.png`. Keep the key file and password private; share
`registration.json` and sealed files freely. The password never goes into a seal.

`sign_pdf.py` never overwrites a file. If the PDF already has an electronic signature (Adobe Sign,
DocuSign), it does not touch that file: it makes a cover page with the seal and attaches the signed
file unchanged, so the existing signature stays valid.

**Scanner.** `web/scanner/` is two static files. Serve them over HTTPS (phones only open the camera on
HTTPS) and open the page on a phone. It reads the ring and shows the version, key id, stated time and
a short digest of the payload.

## Tests

```
cd python && python -m pytest tests          # 9 tests: BIP340 vectors, round trips, signing, tamper checks
cd tests && python make_frames.py && node decode_frames.js
```

The stress rig draws 220 frames (11 camera conditions x 20) and reads them with the phone decoder.
With `sample_center.png` in the center, v0.3 reads **214/220**. Against v0.2, on identical frames with a
handwritten signature in the center, v0.3 reads 216/220 where v0.2 read 196/220; the gains are at
20-30 degree tilt and in the hostile condition, where v0.2 took stray signature strokes for bridges.

## Security notes

* `bip340.py` is pure Python and not constant-time. It is fine for trying DigiHan, not yet for a key
  that guards anything valuable.
* Report security problems to dp@modulo.network (see [SECURITY.md](SECURITY.md)).

## License

Code: Apache License 2.0 ([LICENSE](LICENSE)). The format in [SPEC.md](SPEC.md) is public domain
(CC0 1.0): anyone may implement it without asking.

# DigiHan

A seal you can check with a phone camera.

DigiHan is a digital version of the Japanese hanko seal. The ring of dots around the seal holds a
signature of the exact document, made with the signer's key. Point a phone at the seal and it tells you
whether that key sealed that document. There is no account and no company in the middle. The center of
the seal is free artwork (a signature, lettering, a crest); only the ring follows the format.

**Try it:** open [digihan.org/scan](https://digihan.org/scan) on a phone and point it at any seal on
[digihan.org](https://digihan.org). It should say **Signature valid**.

## What a seal proves

| Proves | Does not prove |
|---|---|
| Which **key** sealed the document | **Who** holds the key |
| The document has not changed by even one byte | **When** the seal was made, unless it carries a time proof (below) |
| The stated time cannot be changed afterward | |

**Time.** In a plain seal the time is the signer's statement. Two proofs place a seal between two
Bitcoin blocks: an *anchored* seal was made **no earlier than** block A (the block's hash is signed), and
an OpenTimestamps proof shows it existed **no later than** block B. With both (a bookended seal) the
phone says "Sometime between and including Block A and Block B". See [docs/TIME-PROOF.md](docs/TIME-PROOF.md).

## Status

Format v0.4 is frozen ([SPEC.md](SPEC.md)).

| Works | In progress |
|---|---|
| Draw and read seals, round or square (Python) | Nostr NIP for the seal registration: [draft](nip/NIP-DIGIHAN.md) |
| Seal a PDF; check a sealed PDF (Python) | Carrying a time proof for a seal outside a PDF or a site |
| Phone scanner: reads the ring (camera or photo, including screenshots) **and checks the signature** | Document tiers beyond exact bytes |
| Keys are Nostr keys (npub); the phone can find a key on Nostr relays from the seal's key id, once the signer has published their registration | |
| Time proofs, Python and phone: "no earlier than" (block anchor) and "no later than" (OpenTimestamps) | |

## Check a seal on a phone

1. Open the scanner and point it at the seal, or use the photo button.
2. The scanner reads the ring and looks up the signer's key: keys saved on the phone, the site's sample
   list, then Nostr relays (it sends only the 8-byte key id).
3. It needs the document, because the signature covers the document. For the sample seals the documents
   are published. For anything else, tap **Check against a document…** and pick the file. It is hashed on
   the phone and not uploaded. A sealed PDF works too: the scanner finds the original attached inside it.
4. The answer is **Signature valid**, **Signature does NOT match**, or what is still missing. The
   *time proof* line shows the proven window, if the seal has one. A sealed PDF carries its proof
   inside; a separate `.ots` proof file can be picked the same way as a document.

## Seal and check PDFs (Python 3.10+)

```
cd python
pip install -r requirements.txt
python selftest.py
python make_key.py alice --art sample_center.png
python sign_pdf.py ../some.pdf sealed --key key_alice
python verify_pdf.py sealed/some_sealed.pdf key_alice/registration.json --save-original
```

With time proofs (needs the internet; `--anchor node` and `--node` use your own bitcoin-cli instead):

```
python sign_pdf.py ../some.pdf sealed --key key_alice --anchor auto --stamp
python timestamp.py upgrade sealed/some_seal_payload.bin.ots          # a few hours later
python timestamp.py attach sealed/some_sealed.pdf sealed/some_seal_payload.bin.ots
python verify_pdf.py sealed/some_sealed_timestamped.pdf key_alice/registration.json
```

* `make_key.py` makes `key_alice/`: `keyfile.json` (your secret key, encrypted with your password),
  `registration.json` (public: your key and your artwork's hash, signed by your key, ready to publish
  on Nostr) and `center_art.png`. Keep the key file and password private. The password never goes into a seal.
* `sign_pdf.py` never overwrites a file. If the PDF already has an electronic signature (Adobe Sign,
  DocuSign) it leaves that file untouched: it adds a cover page with the seal and attaches the signed
  file unchanged.
* `--anchor` makes an anchored seal (no earlier than a block); `--stamp` starts the OpenTimestamps proof
  (no later than a block), which `timestamp.py` finishes and attaches.

## Repository

```
SPEC.md              the format (public domain)
docs/TIME-PROOF.md   proving when a seal was made: block anchors and OpenTimestamps
nip/NIP-DIGIHAN.md   draft Nostr NIP for the seal registration
python/              codec, signing, keys, PDF tools, time proofs (anchor.py, ots.py, timestamp.py), tests
web/scanner/         the phone scanner: index.html, digihan.js (reads rings), verify.js (checks signatures),
                     ots.js (checks time proofs)
tests/               camera-stress and screenshot rigs for the phone decoder
```

## Tests

```
cd python && python -m pytest tests     # BIP340 vectors, round trips, signing, tampering, anchors, OpenTimestamps
cd python && python -m pytest tests -m online   # the example proof against two live block explorers
node web/scanner/verify.test.js         # the phone's signature check against the BIP340 vectors
node web/scanner/ots.test.js            # the phone's OpenTimestamps reader
cd tests && python make_frames.py && node decode_frames.js          # 220 camera-damaged frames
cd tests && python make_screens.py && node decode_frames.js photo screens   # 60 phone screenshots
```

The phone decoder reads 214 of 220 camera-damaged frames (rotation, scale, 10-30 degree tilt, blur,
noise, JPEG, ink spread, paper), 217 through the photo path, and all 60 screenshots (a seal off center,
small, or above a dark browser toolbar). GitHub runs these tests on every push.

## Security

* `python/bip340.py` is pure Python and not constant-time: fine for trying DigiHan, not yet for a key
  that guards anything valuable.
* Report security problems to dp@modulo.network ([SECURITY.md](SECURITY.md)).

## License

Code: Apache License 2.0 ([LICENSE](LICENSE)). The format ([SPEC.md](SPEC.md)) is public domain (CC0 1.0).

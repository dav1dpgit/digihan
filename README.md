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
| Which **key** sealed the document | **Who** holds the key (that is a separate step, such as a notary) |
| The document has not changed by even one byte | **When** the seal was made, unless it is anchored (below) |
| The stated time cannot be changed afterward | |

**Time.** In a normal seal the time is the signer's statement. An *anchored* seal (draft) proves it was
made **no earlier than** a given Bitcoin block. Proof of **no later than** is next. See
[docs/TIME-PROOF.md](docs/TIME-PROOF.md).

## Status

Format v0.3 is frozen ([SPEC.md](SPEC.md)).

| Works | In progress |
|---|---|
| Draw and read seals, round or square (Python) | Time proof "no later than" (OpenTimestamps) |
| Seal a PDF; check a sealed PDF (Python) | Nostr NIP for the seal registration: [draft](nip/NIP-DIGIHAN.md) |
| Phone scanner: reads the ring **and checks the signature** | Time anchors on the phone are a draft (they need a block hash from mempool.space) |
| Keys are Nostr keys (npub); the phone can find a key on Nostr relays from the seal's key id, once the signer has published their registration | Document tiers beyond exact bytes |
| Anchored seals, "no earlier than a block" (draft v0.4) | |

## Check a seal on a phone

1. Open the scanner and point it at the seal, or use the photo button.
2. The scanner reads the ring and looks up the signer's key: keys saved on the phone, the site's sample
   list, then Nostr relays (it sends only the 8-byte key id).
3. It needs the document, because the signature covers the document. For the sample seals the documents
   are published. For anything else, tap **Check against a document…** and pick the file. It is hashed on
   the phone and not uploaded. A sealed PDF works too: the scanner finds the original attached inside it.
4. The answer is **Signature valid**, **Signature does NOT match**, or what is still missing.

## Seal and check PDFs (Python 3.10+)

```
cd python
pip install -r requirements.txt
python selftest.py
python make_key.py alice --art sample_center.png
python sign_pdf.py ../some.pdf sealed --key key_alice
python verify_pdf.py sealed/some_sealed.pdf key_alice/registration.json --save-original
```

* `make_key.py` makes `key_alice/`: `keyfile.json` (your secret key, encrypted with your password),
  `registration.json` (public: your key and your artwork's hash, signed by your key, ready to publish
  on Nostr) and `center_art.png`. Keep the key file and password private. The password never goes into a seal.
* `sign_pdf.py` never overwrites a file. If the PDF already has an electronic signature (Adobe Sign,
  DocuSign) it leaves that file untouched: it adds a cover page with the seal and attaches the signed
  file unchanged. Add `--anchor auto` (or `--anchor HEIGHT:HASH` from your own node) for an anchored seal.

## Repository

```
SPEC.md              the format (public domain)
docs/TIME-PROOF.md   the plan and status for proving when a seal was made
nip/NIP-DIGIHAN.md   draft Nostr NIP for the seal registration
python/              codec, signing, keys, PDF tools, anchors, tests
web/scanner/         the phone scanner: index.html, digihan.js (reads rings), verify.js (checks signatures)
tests/               camera-stress rig for the phone decoder
```

## Tests

```
cd python && python -m pytest tests     # BIP340 vectors, round trips, signing, tampering, anchors
node web/scanner/verify.test.js         # the phone's signature check against the BIP340 vectors
cd tests && python make_frames.py && node decode_frames.js   # 220 camera-damaged frames
```

The phone decoder reads 214 of 220 camera-damaged frames (rotation, scale, 10-30 degree tilt, blur,
noise, JPEG, ink spread, paper).

## Security

* `python/bip340.py` is pure Python and not constant-time: fine for trying DigiHan, not yet for a key
  that guards anything valuable.
* Report security problems to dp@modulo.network ([SECURITY.md](SECURITY.md)).

## License

Code: Apache License 2.0 ([LICENSE](LICENSE)). The format ([SPEC.md](SPEC.md)) is public domain (CC0 1.0).

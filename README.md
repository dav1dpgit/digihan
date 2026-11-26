# DigiHan

A seal you can check with a phone camera.

DigiHan is a digital version of the Japanese hanko seal. The ring of dots around the seal holds a
signature of the exact document, made with the signer's private key. Point a phone at the seal and it tells you
whether the private key of that public key signed that document, and who the signer is when the phone has a
reason to know. There is no account and no company in the middle. The center of
the seal is free artwork (a signature, lettering, a crest); only the ring follows the format.

**Try it:** open [digihan.org/scan](https://digihan.org/scan) on a phone and point it at any seal on
[digihan.org](https://digihan.org). It should say **Signature valid**, signed by a digihan.org sample seal. To make your own seal and stamp a
document, open [digihan.org/seal](https://digihan.org/seal): it works in any browser, phone or computer.

## What a seal proves

| Proves | Does not prove |
|---|---|
| Which **public key**'s private key signed the document | **Who** holds that private key, unless the phone knows the public key (below) |
| The document has not changed by even one byte | **When** the seal was made, unless it carries a time proof (below) |
| The stated time cannot be changed afterward | |

**Time.** In a plain seal the time is the signer's statement. Two proofs place a seal between two
Bitcoin blocks: an *anchored* seal was made **no earlier than** block A (the block's hash is signed), and
an OpenTimestamps proof shows it existed **no later than** block B. With both (a bookended seal) the
phone says "Sometime between and including Block A and Block B". See [docs/TIME-PROOF.md](docs/TIME-PROOF.md).

## Status

Format v0.5 is frozen ([SPEC.md](SPEC.md)). It has two payload versions: version 1, and version 2, the
Nostr stamp event, which any Nostr signer app can sign.

| Works | In progress |
|---|---|
| Draw and read seals, round or square (Python) | Nostr NIP for the seal registration: [draft](nip/NIP-DIGIHAN.md) |
| Stamp a PDF; check a stamped PDF (Python) | Carrying a time proof for a seal outside a PDF or a site |
| Phone scanner: reads the ring (camera or photo, including screenshots and seals with a transparent background) **and checks the signature**; a seal drawn inside another seal's artwork is never taken for the seal | Document tiers beyond exact bytes |
| Keys are Nostr keys (the public key is an npub); the stamping page sends each seal's registration to Nostr relays, and the phone finds the public key there from the seal's public key id | |
| Time proofs, Python and phone: "no earlier than" (block anchor) and "no later than" (OpenTimestamps) | |
| Stamping page: make a seal and stamp any file in a browser, bookended; finish the proof later. A PNG or JPEG picture also gets a stamped copy with the seal in a corner (turned up to 15° either way, on a white disc or with a transparent background, the website under it if you choose) | |
| Up to 21 seals on one device; private key files encrypted with Argon2id; the pages work offline once opened | |
| Who signed: the phone shows the signer as known only for a public key you saved on it, a sample seal, or a name its own domain confirms (NIP-05); any other public key is shown as unknown, in full | |
| Private keys kept elsewhere: a Nostr signer (browser extension or app browser, NIP-07; bunker link or nostrconnect, NIP-46), a second device by QR code, or `sign_hash.py` | |
| Optional, off by default: a public record of a stamp on Nostr, and a public copy of the stamped file on Blossom servers; the scanner finds them from a seal alone, or from the original | |

## Check a seal on a phone

1. Open the scanner and point it at the seal, or use the photo button.
2. The scanner reads the ring and looks up the signer's public key: the registration inside a stamped file you
   opened, public keys saved on the phone, the site's sample list, then Nostr relays (it sends only the 8-byte
   public key id).
3. It needs the document, because the signature covers the document. For the sample seals the documents
   are published. For anything else, tap **Check against a document…** and pick the file. It is hashed on
   the phone and not uploaded. A stamped PDF or stamped picture works too: the scanner finds the original
   carried inside it.
   If the signer made the stamp public, the scanner finds its public record on Nostr and downloads the public
   copy of the stamped file from a Blossom server, so the seal alone (on paper, say) is enough. A file with no
   seal in it can be looked up by its SHA-256 with **Look up a public record for this file**.
4. The answer is **Signature valid**, **Signature does NOT match**, or what is still missing. The
   *time proof* line shows the proven window, if the seal has one. A stamped PDF carries the signer's
   registration record and its time proof inside, so picking it is all the phone needs; a separate
   `.ots` proof file can be picked the same way as a document.
5. **The result** is one line per check. Each line names the item and where it came from, and what it is checked
   against and where that came from, then the result (Match, No match, or Not checked, and why), marked ✓, ✗,
   ! (not known), – (none) or … (waiting):
   * the signature in the seal's ring against the SHA-256 hash of the document file;
   * the public key (from the registration inside the stamped file, a Nostr relay, this phone or the sample list)
     against the public keys saved on this phone and on digihan.org's sample list;
   * the name in the public key's Nostr profile against the name file on that name's website;
   * the artwork registered for the public key against the center of the seal (by eye);
   * the Bitcoin block hash signed in the seal against that block at mempool.space and blockstream.info;
   * the OpenTimestamps proof against the Bitcoin block at mempool.space and blockstream.info.
6. **Who signed.** A valid signature shows only that the private key of this public key signed. A public key
   that came with the seal (inside the stamped file, on Nostr, in a public record) was put there by whoever made
   the seal: anyone can make a seal with the same artwork and a private key of their own. So the scanner shows the
   signer as known only when:
   * you saved the public key on the phone (**Save this public key on this phone**, or **Add a signer's public
     key…**);
   * it is one of the sample seals on digihan.org; or
   * the public key's Nostr profile gives a name such as `dp@example.com` and `example.com` itself lists that
     public key under that name, at `/.well-known/nostr.json` (NIP-05).

   Otherwise it says **Signature valid · signer unknown** and shows the full public key, to check with the signer.
   A name the domain does not confirm gives **Name NOT confirmed**, in red. See SPEC.md, section 14.

## Stamp a document in a browser

[digihan.org/seal](https://digihan.org/seal) (`web/sealer/`) does everything on the device: nothing is uploaded
unless you tick the two publishing boxes in step 2.

1. **Your seal.** Type up to four characters for the center, or pick an image, and choose a password. The
   page makes your key pair (a private key that signs and its public key), signs a registration record for your
   artwork, sends that record to Nostr relays, and keeps the private key file on the device, encrypted with the
   password (Argon2id). Save the private key file to stamp on another device. One device keeps up to 21 seals;
   pick the one to use.
   **Your name (optional).** Give a name such as `you@yourdomain.com` and the private key password: the page puts
   the name in your public key's Nostr profile (keeping anything else the profile holds) and shows the small file
   your website must serve at `https://yourdomain.com/.well-known/nostr.json`, with the header
   `Access-Control-Allow-Origin: *`. **Check my name** asks your domain, as a scanner will. With a private key in a
   Nostr signer, set the name in your Nostr app's profile instead.
   **Or keep your private key elsewhere.** The private key never touches the page:
   * **A Nostr signer.** Connect a browser extension or the browser inside a Nostr app (NIP-07), paste a
     `bunker://` link from a signer app, or let the app open the page's `nostrconnect://` link or QR code
     (NIP-46). The signer signs the seal's record, then each stamp, with your private key; it shows you what it
     signs. Seals made
     this way are payload version 2: the signature is over a Nostr stamp event (SPEC.md, section 6.2).
   * **A second device.** A phone or computer that holds the private key (made or opened on this page) signs for
     this one: this page shows a QR code with what to sign; on the other device tap **Sign for another
     device**, scan it, check what it is, enter the password and sign; scan its answer back. It works with
     the other device offline.
   * **Your own computer.** The page shows a 64-character code; sign it with your private key (`python
     sign_hash.py CODE --key YOUR_KEY`, or any BIP340 signer that signs the 32 bytes as given) and paste the
     signature back.
2. **Your document.** Any file. The page anchors the seal to a recent Bitcoin block (two block explorers
   must agree), signs, draws the seal and reads it back, starts the OpenTimestamps proof, and gives you a
   PDF: a cover page with the seal, then the document's own pages if it is a PDF, with the file attached
   unchanged, the registration record, the artwork and the pending proof. For a PNG or JPEG picture you
   also get a stamped picture: the picture with the seal in a corner you choose, turned up to 15° either way,
   on a white disc or with a transparent background (the page reads it back first, and falls back to a
   frosted or white disc where the picture behind the seal is too busy). It carries the original inside it.
   Ticking "Add the website below the seal" puts https://digihan.org under the seal.
   **Optional, off for each document:** "Publish a public record of this stamped file on Nostr" (this public
   key's private key stamped a file with this hash, and when), and under it "Also put a public copy of the
   stamped file on Blossom" (the stamped PDF and stamped picture, uploaded to blossom.primal.net, blossom.band and your own
   server if you give one; the record names where they went). A stamped file carries the original, so a
   public copy makes the original public. A photo that carries the place it was taken gets a warning first.
3. **Finish the time proof.** A few hours later, pick that PDF again. The page fetches the Bitcoin part of
   the proof and gives you the finished PDF: "Sometime between and including Block A and Block B". If the
   file was put on Blossom, the page puts the finished file there too and publishes the record again with it
   first (it asks for the private key password, or the signer, to sign them).

The scanner and `verify_pdf.py` check these PDFs with nothing else needed. `sign_pdf.py --key` also takes
a private key file saved from the page.

## Stamp and check PDFs (Python 3.10+)

```
cd python
pip install -r requirements.txt
python selftest.py
python make_key.py alice --art sample_center.png
python sign_pdf.py ../some.pdf sealed --key key_alice
python verify_pdf.py sealed/some_sealed.pdf --save-original
```

With time proofs (needs the internet; `--anchor node` and `--node` use your own bitcoin-cli instead):

```
python sign_pdf.py ../some.pdf sealed --key key_alice --anchor auto --stamp
python timestamp.py upgrade sealed/some_seal_payload.bin.ots          # a few hours later
python timestamp.py attach sealed/some_sealed.pdf sealed/some_seal_payload.bin.ots
python verify_pdf.py sealed/some_sealed_timestamped.pdf
```

* `make_key.py` makes `key_alice/`: `keyfile.json` (your private key, encrypted with your password),
  `registration.json` (public: your public key and your artwork's hash, signed with your private key, ready to
  publish on Nostr) and `center_art.png`. Keep the private key file and password private. The password never
  goes into a seal.
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
python/              codec, signing, key pairs, PDF tools, time proofs (anchor.py, ots.py, timestamp.py),
                     sign_hash.py (signs the stamping page's codes with a private key kept offline), tests
web/scanner/         the phone scanner: index.html, digihan.js (reads rings), verify.js (checks signatures and
                     signers' names), ots.js (time proofs: checks, starts and finishes them)
web/sealer/          the stamping page: index.html, dhseal.js (draws rings, signs, private key files),
                     nostrsign.js (Nostr signers), publish.js (public records, Blossom copies, the signer's
                     name in the profile), vendor/
tests/               camera-stress, screenshot and seal-inside-a-seal rigs for the phone decoder
```

## Tests

```
cd python && python -m pytest tests     # BIP340 vectors, round trips, signing, tampering, anchors, OpenTimestamps
cd python && python -m pytest tests -m online   # the example proof against two live block explorers
node web/scanner/verify.test.js         # the phone's signature check against the BIP340 vectors
node web/scanner/ots.test.js            # the OpenTimestamps code: reading, writing, stamping, finishing
node web/sealer/dhseal.test.js          # the stamping page's rings (vs Python), signing (BIP340 vectors), private key files
node web/sealer/nostrsign.test.js       # NIP-44 encryption and the checks on what a Nostr signer returns
node web/sealer/publish.test.js         # public records, Blossom uploads, the photo-location check
node web/sealer/name.test.js            # the signer's name: reading the profile, asking the domain, publishing it
cd tests && python make_frames.py && node decode_frames.js          # 220 camera-damaged frames
cd tests && python make_screens.py && node decode_frames.js photo screens   # 60 phone screenshots
cd tests && python make_nested.py && node decode_frames.js photo nested     # 150 seals inside seals
```

The phone decoder reads 217 of 220 camera-damaged frames (rotation, scale, 10-30 degree tilt, blur,
noise, JPEG, ink spread, paper), 219 through the photo path, all 60 screenshots (a seal off center,
small, or above a dark browser toolbar), and all 150 seals inside seals, always as the outer seal. GitHub
runs the Python tests, the phone tests, the screenshots and the seals inside seals on every push, and
publishes each release from CHANGELOG.md.

## Security

* `python/bip340.py` is pure Python and not constant-time: fine for trying DigiHan, not yet for a private key
  that guards anything valuable.
* A seal's artwork can be copied by anyone. Only the public key tells two seals apart, and only a public key you
  saved, or a name its domain confirms, tells you who holds the private key.
* Report security problems to dp@modulo.network ([SECURITY.md](SECURITY.md)).

## License

Code: Apache License 2.0 ([LICENSE](LICENSE)). The format ([SPEC.md](SPEC.md)) is public domain (CC0 1.0).

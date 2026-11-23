# Changelog

## v0.5.3 (2026-11-23): one meaning for "fingerprint"

* "Fingerprint" now means only the key id: the first 8 bytes of the SHA-256 hash of the public key, as
  in SPEC.md. The sealing page and sign_hash.py called 32-byte SHA-256 hashes "fingerprints" too; they
  now say "SHA-256 hash (32 bytes)".

## v0.5.2 (2026-11-23): straight to the camera

* Scanner v13: no start screen. The camera opens as the scanner opens; a photo is one tap on the photo
  button in the camera view. If the browser will not open the camera (no permission, no camera), a small
  notice in the viewfinder offers "Start camera" and the photo button stays. "Stop" is now "Close" (back
  to where the scanner was opened); "Scan another" and returning to the app reopen the camera.
* The site menu lists How it works first; "Open the scanner" is now "Open scanner".

## v0.5.1 (2026-11-23): keep your key offline

* Sealing page v2: step 1 can take only a public key (npub or hex) for a key kept offline. The page shows
  a 64-character code for the artwork record and for each seal; the signature is made elsewhere and
  pasted back, and checked before it is used. The page then keeps only public parts on the device.
* `python/sign_hash.py`: signs those codes with a key folder from `make_key.py` or a key file from the page.
* `dhseal.js` splits signing into prepare (`sealMessage`, `draftRegistration`) and finish (`assemble`,
  `finishRegistration`); tests cover both, and a pasted signature that does not match.
* The sealing page has the site's menu (a small seal, top right).

## v0.5.0 (2026-11-23): seal in a browser

* The sealing page (`web/sealer/`, digihan.org/seal): make a seal (key and center artwork) on the device,
  seal any file, bookended by default (block anchor plus an OpenTimestamps proof started at once), and
  finish the proof a few hours later. Nothing is uploaded; the key file is encrypted with a password
  (PBKDF2-SHA256 and AES-256-GCM, WebCrypto). Every drawn seal is read back before it is used.
* `web/sealer/dhseal.js`: the ring's bit stream (checked against Python on 12 payloads), the seal drawing,
  BIP340 signing (checked against the official vectors), payloads, registration records, key files.
* `web/scanner/ots.js` now also writes proofs (byte-identical to Python on every example and sample proof),
  starts them with the timestamp servers that accept web pages, and finishes them.
* Python: `dhsign.unlock_key` and `sign_pdf.py --key` read key files saved from the sealing page.
* Scanner v12: shows the artwork attached to a sealed PDF; reads attached files whose type contains the
  word "stream" (it missed them before).
* PDFs from the sealing page attach the artwork as `digihan-center.png` (SPEC section 9).

## v0.4.3 (2026-11-23): the sealed PDF carries the signer's key

* `sign_pdf.py` attaches the signer's registration record to the sealed PDF
  (`digihan-registration.json`, both layouts). `verify_pdf.py` uses it, so the registration file is no
  longer needed on the command line (it is still accepted, for older PDFs).
* Phone scanner v11: picking a sealed PDF also gives the scanner the signer's key, so a seal can be
  checked with no pasting. The key is used for that check only, when its record's signature is valid
  and its key matches the seal's key id; it is not saved on the phone. A picked `registration.json`
  works the same way.

## v0.4.2 (2026-11-23): shorter results

* The phone scanner (v10) and `verify_pdf.py` no longer add "Who holds the key is a separate question"
  to their results. README and SPEC keep the one factual line in their lists of what a seal proves.

## v0.4.1 (2026-11-23): wording for bookended seals

* A seal with both time proofs (bookended) is now reported as "Sometime between and including Block A
  and Block B", followed by the dates the blocks were mined: phone scanner v9 and `verify_pdf.py`.
  SPEC.md section 11.2 recommends the wording.
* GitHub workflows moved to the current action versions (the old ones ran on Node.js 20, which GitHub
  is retiring).

## v0.4.0 (2026-11-22): time proofs, no earlier than and no later than

* Format v0.4 (frozen): flag bit 0 defined. An anchored seal signs a Bitcoin block's hash and so was made
  **no earlier than** that block. An OpenTimestamps proof over the seal's 78 bytes shows it existed
  **no later than** a block. Plain v0.3 seals are unchanged and still valid (SPEC.md, sections 10-11).
* Python: `ots.py` reads and writes standard `.ots` proofs (checked against the reference library on
  its example proofs, byte for byte); `timestamp.py` stamps, upgrades, attaches (`seal.ots` in a new
  PDF) and verifies; `sign_pdf.py --stamp` and `--anchor node`; `verify_pdf.py` checks an attached proof
  and reports the window; contradicting proofs fail.
* Block data comes from your own node (`--node`) or from two block explorers (mempool.space and
  blockstream.info), refused when they disagree.
* Phone scanner v8: checks both proofs and shows "sealed after block A and before block B"; finds the
  proof inside a sealed PDF, as a picked `.ots` file, or next to the scanner (`ots/<seal digest>.ots`).
* Phone scanner v7: photos and screenshots are searched for the seal's outline first. A screenshot taken
  in dark mode (a dark browser toolbar along the bottom) or a seal off center no longer fails:
  60/60 test screenshots (was 2/60).
* GitHub now tags each release and publishes it (`.github/workflows/tag-release.yml`) and runs the
  tests on every push (`.github/workflows/tests.yml`).

## v0.3.1 (2026-11-22): the phone checks signatures

* Scanner v6 checks the BIP340 signature on the phone (`web/scanner/verify.js`, tested on the 19 official
  vectors). It finds the key from the seal's key id (keys saved on the phone, a published sample list, or
  Nostr relays), takes the document (published, or a file picked on the phone and hashed there; a sealed
  PDF's attached original is found), and answers Signature valid / does NOT match / what is missing.
* Photo upload fixed: pictures with transparent backgrounds came out inverted and did not read; uploads
  that do not read are tried once inverted (a seal on a dark screen).
* Registration records gain `["f", key id]` and `alt` tags; draft Nostr NIP in `nip/NIP-DIGIHAN.md`.
* Time proof started (draft v0.4): anchored seals prove "made no earlier than Bitcoin block H"
  (`sign_pdf.py --anchor`, `verify_pdf.py --block-hash`, `python/anchor.py`; the phone fetches the block
  hash). `sign_pdf.py` writes the seal data for an OpenTimestamps proof. Plan: `docs/TIME-PROOF.md`.
* README rewritten.

## v0.3.0 (2026-11-22): first public release, format frozen

* Format v0.3 frozen (see SPEC.md, section 10 for changes from v0.2):
  signing tag "DigiHan/v1"; bit 0 at 12 o'clock under the key bridge; guard band 1.2 mm;
  one size (45 mm, 0.6 mm modules).
* Decoders (Python and phone): keep only plausible bridge readings; re-refine the start angle
  when retrying without the bridge calibration. Phone decoder: 196/220 -> 216/220 on the stress rig.
* Verifier rejects unknown versions and reserved flags.
* Released under Apache-2.0; SPEC.md in the public domain (CC0 1.0).

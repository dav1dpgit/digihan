# Changelog

## v0.5.10 (2026-11-23): steady layout, the key on this device, progress you can see; scanner resets

* Stamping page v8: one column at every width (wider on a desktop). "Make a key here" and "Use a key I
  keep offline" are two equal buttons, and switching between them no longer changes the box's size. A
  panel says what this device keeps (the encrypted key file and its method, or only the public parts) and
  erases it with a second tap. The stamping steps show a checkmark when done and moving dots on the step
  in progress. Fixed: picking a new document while the previous one was loaded, then tapping Stamp
  quickly, could sign the previous document; and picking another file during a stamp could mix the two.
* Scanner v18: every result is cleared when the scanner is opened, closed, or come back to from another
  app (not while a file is being picked). After the ring is read and before a document is loaded, the
  scanner shows "Seal read" and a next step with its own button, instead of a yellow warning.

## v0.5.9 (2026-11-23): one header everywhere; the stamping page uses a wide screen

* Stamping page v7: the site's shared header (logo and menu, full width), so the logo and the menu sit in
  exactly the same place as on the front page and How it works, on phones and desktops. On a screen
  1,100 px or wider, the steps sit side by side: your seal and the time proof on the left, stamping on
  the right.

## v0.5.8 (2026-11-23): a picture with the seal in a corner

* Stamping page v6: for a PNG file, an option makes a copy of the picture with the seal in a chosen
  corner, on a white disc, besides the PDF. The copy carries the original picture's exact bytes, the
  registration, the artwork and the time proof inside its own file (SPEC section 9: `dhFl` chunks and a
  `DigiHanPayload` text chunk). The seal's size follows the picture (28% of the shorter side, never so
  small that the scanner cannot read it after shrinking the picture to 1,400 px); the page reads the seal
  back from the finished picture before offering it, and says so if the picture is too small (under
  about 450 px on its shorter side). Step 3 finishes the time proof inside a stamped picture too.
* Scanner v17: the photo button reads a stamped picture's seal from its corner and its original from
  inside, so one picture is enough to check. "Check against a document…" accepts a stamped picture.
  Fixed: a PNG stamped into a PDF was taken for the artwork only and never checked as the document.
* digihan.js: decodePhoto also tries square crops at each corner (decodeCorners).

## v0.5.7 (2026-11-23): "seal" is the noun; "stamp" and "sign" are the verbs

* Everywhere people read (stamping page v5, scanner v16, the PDF cover text, the Python tools' messages,
  README, SPEC prose, TIME-PROOF): the person **stamps** a document with their seal; the key **signs**.
  "Seal a document" is "Stamp a document", the button is "Stamp", and the browser's PDF is
  `<name>_stamped.pdf`. The Python tools still write `<name>_sealed.pdf` into a `sealed/` folder, and code
  names (web/sealer/, seal_payload, ...) are unchanged.

## v0.5.6 (2026-11-23): Argon2id key files; DH logo

* Sealing page v4: new key files are encrypted with Argon2id (64 MiB, 3 passes, 1 lane), then AES-256-GCM.
  Argon2id makes every password guess cost memory as well as time. Older key files (PBKDF2-SHA256) still
  open, and are re-encrypted with Argon2id the first time they are unlocked to seal; the page then asks
  for the key file to be saved again. The Argon2 code is hash-wasm 4.12.0 (MIT), in web/sealer/vendor/.
* Python: dhsign.unlock_key opens the new key files (needs argon2-cffi, now in requirements.txt).
* Logo: the 判 box is now a carved-hanko DH (D and H overlapped by 70%), also the browser-tab icon; the
  logo links back to the front page, and "Sample seals" is gone from the menu. Footer credit: a Plotzwerks
  project (plotzwerks.com). Scanner v15: the same tab icon.

## v0.5.5 (2026-11-23): menu without sub-text

* Sealing page: the seal menu lists the page names only (no description under each).

## v0.5.4 (2026-11-23): works offline; a warning for keys that share a key id

* Sealing page v3: with no internet connection, the two Bitcoin proof boxes are turned off with a plain
  note, so a seal can still be made; the note says step 3 can add the "no later than" proof once online.
  The same happens when the Bitcoin block sites do not answer although the phone says it is online.
  They turn back on when the connection returns (unless the person changed them). Messages no longer
  say "block explorers".
* Scanner v14: if different full keys with the seal's key id are found (the 8 bytes match, the keys do
  not), the result says "Signature valid — check the signer", names the key that signed and where it came
  from, and the other key(s). No format change.
* Both pages ask the browser to save them for offline use where the site provides `sw.js` (digihan.org
  does), and link the site's app manifest and icon. Served elsewhere, both steps fail quietly.

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

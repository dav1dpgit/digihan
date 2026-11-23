# Changelog

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

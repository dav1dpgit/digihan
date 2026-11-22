# DigiHan seal format, v0.3

Status: **frozen**. Payload version 1. This document is placed in the public domain (CC0 1.0);
anyone may implement it without asking. The reference code in this repository is Apache-2.0.

A DigiHan seal is a round (or square) printed or on-screen mark. Its outer ring of dots carries a
BIP340 Schnorr signature over the SHA-256 of an exact document, a timestamp and, optionally, the hash
of the seal's center artwork. Anyone with a camera and the signer's public key can check it. The
center artwork is free: drawn, lettered or computer-made. Only the ring follows this format.

Keywords MUST, SHOULD and MAY are used as in RFC 2119.

## 1. What a valid seal proves

A seal that verifies proves three things:

1. the holder of the key with the stated fingerprint signed it;
2. the document's bytes are exactly the bytes that were signed (one changed byte fails);
3. the time in the seal is the time the signer stated, and nobody can change it afterward.

It does **not** prove who holds the key (that is a separate step, such as a notary), and it does
**not** prove when the seal was made: the signer chooses the time. Time anchors that prove a window
(no earlier than one Bitcoin block, no later than another) are planned as a future extension (section 11).

## 2. Geometry

One size is defined: 45 mm diameter, 5 data tracks, 0.6 mm modules. All radii in millimetres from the center.

| Element | Inner radius | Outer radius | Notes |
|---|---|---|---|
| Center artwork | 0 | 15.35 | free zone; MUST stay inside 15.35 |
| Guard band | 15.35 | 16.55 | 1.2 mm (2 modules); only the 8 bridges cross it |
| Locator ring | 16.55 | 17.25 | solid |
| Inner quiet gap | 17.25 | 17.65 | empty |
| Data band | 17.65 | 21.10 | 5 tracks, each 0.69 mm (1.15 modules) tall |
| Outer quiet gap | 21.10 | 21.60 | empty |
| Rim | 21.60 | 22.50 | solid |

Track `t` (0 = innermost) is centred at `r_t = 17.65 + (t + 0.5) × 0.69`:
17.995, 18.685, 19.375, 20.065, 20.755 mm. It holds `C_t = floor(2π r_t / 0.6)` cells:
**188, 195, 202, 210, 217** (1012 in all).

**Bridges (kissōtai).** Eight tabs join the center to the locator ring, from radius 15.15 to 16.85,
at 45° steps starting at 12 o'clock. The 12 o'clock bridge (the key bridge) is 1.6 mm wide; the
other seven are 0.8 mm. A bridge MAY be a rectangle or a triangle pointing in or out (triangle base
twice the rectangle width). The key bridge marks orientation; the sync word (section 3) remains the
authority, so a damaged bridge slows reading but does not prevent it.

**Square variant (organizational seals).** The same ring inside a square frame: 0.5 mm gap outside
the rim, then a 1.1 mm frame. Outside side 48.2 mm.

**Quiet zone.** At least 3 mm (5 modules) of clear paper or screen around the seal; 15 mm is recommended.

**Ink.** A dark cell is a 1, an empty cell is a 0. Ink colour is free if it contrasts with the paper
(vermillion is customary). A cell MAY be drawn as an arc segment or a dot; a dot has diameter about
0.52 mm and is centred on the cell's sample point.

## 3. Bit layout

Angles are measured on the seal as seen from the front, clockwise, from 12 o'clock.

Cell `i` of track `t` spans `[360°·i / C_t, 360°·(i + 0.86) / C_t)` from 12 o'clock; its **sample
point** is at `360°·(i + 0.43) / C_t` on radius `r_t`. Bit 0 is cell 0 of track 0, just clockwise of
the key bridge.

The 1012-bit stream is laid **track-major**: all of track 0 (cells 0 … 187), then track 1, and so on
out to track 4.

Stream = sync word (28 bits) ‖ Reed–Solomon codeword (123 bytes, most significant bit of each byte first).
28 + 8 × 123 = 1012 = ring capacity: every cell carries data.

* Sync word: `1110 0111 0110 1001 1100 0101 0111` (0xE769C57). Low cyclic autocorrelation, no run longer than 3.
* Reed–Solomon: RS(123, 78) over GF(2⁸), primitive polynomial 0x11D, generator α = 2, first consecutive
  root α⁰, 45 parity bytes appended to the 78 payload bytes (systematic). Corrects up to 22 byte errors.

## 4. Payload (78 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version (high 4 bits) and flags (low 4 bits) |
| 1 | 8 | key fingerprint = first 8 bytes of SHA-256(public key) |
| 9 | 5 | timestamp, Unix seconds, big-endian (signer-stated) |
| 14 | 64 | BIP340 Schnorr signature |

## 5. Version and flags

* Version MUST be 1. A verifier MUST reject any other version.
* Flag bit 2 (value 4): the center artwork is committed (section 6). Bits 0, 1 and 3 are reserved,
  MUST be 0, and a verifier MUST reject a seal with a reserved bit set.

## 6. Signed message

```
doc_hash    = SHA-256(document bytes)                       32 bytes
center_hash = SHA-256(center artwork file bytes)            32 bytes, only if flag bit 2 is set
m = TaggedHash("DigiHan/v1", doc_hash ‖ timestamp(5) ‖ fingerprint(8) [‖ center_hash])
signature = BIP340-Sign(secret key, m)
```

`TaggedHash(tag, x) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ x)`, as defined in BIP340.

Because the timestamp and fingerprint are inside `m`, changing either breaks the signature, and the
same document sealed twice gives two different rings.

## 7. Keys and the center registration

* The signer's key is a BIP340 x-only public key (32 bytes). It is published as a Nostr public key:
  `npub` = bech32("npub", public key), as in NIP-19.
* A seal that commits its center has a **registration**: a Nostr event (NIP-01), signed by the same key:
  * `kind`: 30078 (application data, NIP-78)
  * `tags`: `["d", "digihan-center:<center_hash hex>"]`, `["center_hash", "<center_hash hex>"]`
  * `content`: `{"app": "DigiHan", "format": "v0.3", "center_hash": "<hex>"}`

  Each artwork gets its own record (the `d` tag carries the hash), so old seals keep verifying after
  a signer changes artwork. A Nostr NIP for this record is being drafted.

## 8. Verification

1. Read the ring (section 3) and correct it with Reed–Solomon. If it cannot be corrected, the seal is unreadable.
2. Check version and flags (section 5).
3. Find the public key whose fingerprint matches. The fingerprint is only an index: confirm
   SHA-256(public key)[0:8] equals it.
4. Compute `doc_hash` over the exact document bytes the verifier will show the reader.
5. If flag bit 2 is set, take `center_hash` from a registration for this key whose own signature is valid.
6. Build `m` (section 6) and check the BIP340 signature with the public key.
7. If valid, show the reader: the key, the signer-stated time, and, if committed, the registered
   artwork beside the scanned seal so a person can compare them.

A verifier MUST present the document it checked (for a PDF, the attached original), never a different
rendering of it. This defeats files that look different in different viewers.

## 9. Documents (tier 1, byte-exact)

v0.3 defines tier 1: `doc_hash` is over the exact bytes of the file. The reference PDF tool
(`python/sign_pdf.py`) embeds what a verifier needs:

* **Seal on the page.** The seal is drawn in a clear area; the exact original is attached as
  `original.pdf`. Metadata: `/DigiHanPayload` (payload, hex), `/DigiHanSealPage` (1-based),
  `/DigiHanSealBox` ("x_mm,y_mm,size_mm,quiet_zone_mm" from the top left), `/DigiHanFormat`.
* **Cover sheet.** If the PDF already carries an electronic signature, it is not modified: a cover
  page holds the seal and the signed file is attached unchanged. `/DigiHanSealedFile` names the attachment.

Later tiers (canonical content, printed canonical string) are not yet defined.

## 10. Changes from v0.2

* Signing tag renamed from "RingSeal/v1" to "DigiHan/v1".
* Bit 0 moved from 3 o'clock to 12 o'clock, under the key bridge.
* Guard band widened from 0.9 mm to 1.2 mm (center radius 15.65 → 15.35 mm).
* Decoders keep only plausible bridge readings (within 2.5° of the median offset) and refine the
  start angle separately when retrying without the bridge calibration.
* One size only (45 mm / 0.6 mm); the 40 mm test profile is dropped.

## 11. Planned (not in v0.3)

* **Time anchors.** No later than: an OpenTimestamps proof that a hash of the seal was in a Bitcoin
  block. No earlier than: a recent block hash inside the signed message. Together they prove a window.
  This will use a reserved flag and a new tag, so v0.3 seals stay valid.
* **Signature check on the phone** (the scanner reads the ring today; checking the signature needs the key and document).
* **Nostr NIP** for the center registration.

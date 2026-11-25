# DigiHan seal format, v0.5

Status: **frozen**. Payload versions 1 and 2. v0.5 adds payload version 2, the **stamp event** (section
6.2): the same ring, with the signature made over a Nostr event, so any Nostr signer app can make it.
Every v0.4 seal is a valid v0.5 seal. v0.4 added time proofs (section 11) to v0.3. Section 13 (2026-11-25) adds optional
public records and public copies; it changes nothing in the ring. This document is placed in the public domain (CC0 1.0);
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
3. the time in the seal cannot be changed afterward.

It does **not** prove who holds the key. On its own the time
is the signer's statement. Two time proofs (section 11) prove a window instead: an **anchored** seal was
made no earlier than a given Bitcoin block, and an **OpenTimestamps proof** shows it existed no later
than a given block.

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
| 9 | 5 | timestamp, Unix seconds, big-endian (signer-stated); for an anchored seal, a Bitcoin block height |
| 14 | 64 | BIP340 Schnorr signature |

## 5. Version and flags

* Version MUST be 1 or 2. A verifier MUST reject any other version. Version 1 signs the message of
  section 6.1; version 2 signs the stamp event of section 6.2. Both use the same fields and flags.
  A reader SHOULD treat a decoded payload of version 0 as no seal and keep looking: an all-zero codeword
  passes the Reed–Solomon check trivially, and an even, dark area can read as one.
* Flag bit 2 (value 4): the center artwork is committed (section 6).
* Flag bit 0 (value 1): the seal is **anchored** (section 11.1). The timestamp field holds a Bitcoin block
  height instead of a time.
* Bits 1 and 3 are reserved, MUST be 0, and a verifier MUST reject a seal with a reserved bit set.

## 6. Signed message

### 6.1 Payload version 1

```
doc_hash    = SHA-256(document bytes)                       32 bytes
center_hash = SHA-256(center artwork file bytes)            32 bytes, only if flag bit 2 is set
block_hash  = hash of the anchored block, display order     32 bytes, only if flag bit 0 is set
m = TaggedHash("DigiHan/v1", doc_hash ‖ timestamp(5) ‖ fingerprint(8) [‖ center_hash] [‖ block_hash])
signature = BIP340-Sign(secret key, m)
```

`TaggedHash(tag, x) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ x)`, as defined in BIP340.

Because the timestamp and fingerprint are inside `m`, changing either breaks the signature, and the
same document stamped twice gives two different rings.

### 6.2 Payload version 2: the stamp event

The signature is a Nostr event signature (NIP-01) over a **stamp event** built from the same parts. A
Nostr signer (NIP-07 browser extension or in-app browser, NIP-46 remote signer, NIP-55 Android signer)
only signs whole events, never a bare 32-byte message; version 2 lets any of them stamp, and the signer
app shows the person what is being signed.

```
F  = the payload's 5-byte timestamp field (Unix seconds; for an anchored seal, the block height A)
T  = F, or for an anchored seal the time in block A's header (Unix seconds)
event = {
  "pubkey":     hex(public key),
  "created_at": T,
  "kind":       30078,
  "tags": [
    ["d", "digihan-stamp:" + hex(doc_hash) + ":" + dec(F)],
    ["x", hex(doc_hash)],
    ["f", hex(fingerprint)],
    ["center_hash", hex(center_hash)],              only if flag bit 2 is set
    ["block", dec(A), hex(block_hash)],             only if flag bit 0 is set
    ["alt", "DigiHan stamp: a seal on a document"]
  ],
  "content": "DigiHan stamp. Document SHA-256: " + hex(doc_hash) + "."
             + (" No earlier than Bitcoin block " + dec(A) + ".", only if flag bit 0 is set)
}
m = event id = SHA-256(UTF-8 of [0, pubkey, created_at, kind, tags, content] serialized as in NIP-01)
signature = BIP340-Sign(secret key, m)
```

`hex` is lowercase hexadecimal; `dec` is base 10 with no leading zeros or separators. The tags are in
exactly this order. Every value comes from the ring, the document, the key record and the Bitcoin block,
so a verifier rebuilds the event and checks the signature over its id; the event itself never has to be
stored or published.

* For an anchored seal the event's time is block A's header time, because a Nostr event needs a real
  time and the ring's field holds the block height. A verifier gets it from the same sources as the
  block's hash (section 11.3). A stamp made before block A was mined cannot carry that time.
* A signing client MUST compare the event the signer returns with the event it asked for, field by
  field, and refuse it if anything differs (a signer that adds a tag or changes the time makes a
  signature no verifier can rebuild).
* The signed stamp event is a valid Nostr event. Anyone holding the document, the seal and the key record
  can rebuild it and publish it to relays; it then says, publicly, that this key stamped a file with this
  hash at this time. The `d` tag is unique to each stamp (the document hash and the timestamp field), so
  one stamp never replaces another.
* A stamped PDF of version 2 SHOULD attach the signed event as `digihan-stamp.json`. A verifier does not
  need it.
* Kind 30078 is shared with the key record (section 7). A verifier MUST NOT take an event whose `d` tag
  starts with `digihan-stamp:` as a key record.

## 7. Keys and the center registration

* The signer's key is a BIP340 x-only public key (32 bytes). It is published as a Nostr public key:
  `npub` = bech32("npub", public key), as in NIP-19.
* A seal that commits its center has a **registration**: a Nostr event (NIP-01), signed by the same key:
  * `kind`: 30078 (application data, NIP-78)
  * `tags`: `["d", "digihan-center:<center_hash hex>"]`, `["center_hash", "<center_hash hex>"]`
  * `content`: `{"app": "DigiHan", "format": "v0.3", "center_hash": "<hex>"}`

  Each artwork gets its own record (the `d` tag carries the hash), so old seals keep verifying after
  a signer changes artwork. Records also carry `["f", "<key id>"]` and an `alt` tag; the draft NIP
  ([nip/NIP-DIGIHAN.md](nip/NIP-DIGIHAN.md)) defines the full record.
* The stamping page sends the registration to Nostr relays (`wss://relay.damus.io`, `wss://nos.lol`,
  `wss://relay.primal.net`) when a seal is made, and again when the signer asks. A relay's `OK` answer
  (or `duplicate:`) counts as saved. A verifier holding only a scanned seal asks relays for
  `{"kinds": [30078], "#f": ["<key id>"]}`. Nothing about any document is sent.

## 8. Verification

1. Read the ring (section 3) and correct it with Reed–Solomon. If it cannot be corrected, the seal is unreadable.
   The seal is the outermost ring. The center artwork may itself show a seal, ring and all (a picture of
   a seal used as artwork); a ring inside another seal's center artwork is artwork, and a reader MUST NOT
   take it as the seal. A reader that reads a ring SHOULD look for a larger ring around it and, if one
   encloses it, read that one instead.
2. Check version and flags (section 5).
3. Find the public key whose fingerprint matches. The fingerprint is only an index: confirm
   SHA-256(public key)[0:8] equals it.
4. Compute `doc_hash` over the exact document bytes the verifier will show the reader.
5. If flag bit 2 is set, take `center_hash` from a registration for this key whose own signature is valid.
6. If flag bit 0 is set, get the anchored block's hash (section 11.3).
7. Build `m` (section 6.1 for version 1; for version 2, the stamp event's id, section 6.2, which needs
   block A's header time for an anchored seal) and check the BIP340 signature with the public key.
8. If an OpenTimestamps proof for this seal is available, check it (section 11.2).
9. If valid, show the reader: the key; the time (the signer's statement, or the proven window); and, if
   committed, the registered artwork beside the scanned seal so a person can compare them.

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

* **Registration record.** The signer's registration record (section 7) MAY be attached as
  `digihan-registration.json`, named by `/DigiHanRegistration`, so a verifier needs no separate file. A
  verifier uses it only if its own signature is valid and its key matches the seal's key id.
* **Center artwork.** The registered artwork MAY be attached as `digihan-center.png` (its exact bytes,
  so a verifier can show it beside the scanned seal after checking its hash against the registration).
* **Time proof.** An OpenTimestamps proof (section 11.2) MAY be attached as `seal.ots`. The reference
  tool writes it into a new file (`python/timestamp.py attach`); the stamped PDF is not changed.

**A stamped picture (PNG).** For a PNG file, the stamping page can also write a copy of the picture with
the seal drawn in one corner, on a white disc, 3% of the shorter side from the edges (in a bottom corner,
above the website line, if the stamping page was asked to show one under the seal). The seal signs the
ORIGINAL picture's bytes; the copy's own bytes are not what was signed. The copy carries what a verifier
needs inside its own file, before `IEND`:

* `tEXt` chunk `DigiHanPayload`: the payload, hex. `tEXt` chunk `DigiHanFormat`: a description.
* One private chunk `dhFl` per file: 1 byte version (1), the file name in UTF-8, a 0 byte, then the
  file's exact bytes. The files are the original picture, and MAY include `digihan-registration.json`,
  `digihan-center.png` and `seal.ots`, with the same meaning as the PDF attachments above.

**The seal's look in a stamped picture.** The seal MAY be turned (the stamping page allows -15° to +15°;
readers find the start of the ring by its sync pattern and key bridge at any angle). It MAY be drawn with
no white disc and no paper behind it (a transparent background), or on a partly see-through white disc.
On a picture, the ring's ink (vermilion, 178/56/44) is then not always darker than what is behind it, so
a reader that finds no seal in grey SHOULD read the picture again by the ink's colour: dark where a pixel
is red to orange, by how much colour it has, and white elsewhere. The stamping page reads every stamped
picture back this way before offering it.

**A stamped picture (JPEG).** For a JPEG file, the copy is a JPEG and carries the same things in APP10
segments (marker `FF EA`), placed after the picture's own leading APP segments. Each segment's data starts
with `DigiHan` and a 0 byte, then one kind byte:

* Kind 1, text: the key, a 0 byte, the value (`DigiHanPayload`, `DigiHanFormat`, as for PNG).
* Kind 2, a part of a file: the file's number (1 byte), the part's number and the number of parts (2 bytes
  each, big-endian), then the part. A file's parts joined in order hold what a PNG's `dhFl` chunk holds.

The copy is drawn upright: if the original carries an EXIF orientation, the copy is turned by it and
carries none. The original inside is unchanged.

**Location in a photo.** A JPEG or PNG original may carry the place it was taken (EXIF GPS, or XMP). The seal
signs the original's exact bytes, so the location cannot be removed without breaking the seal: the stamped
PDF and the stamped picture carry it, and so does any public copy (section 13). A stamping client SHOULD
say so before stamping such a file.

A verifier reads the seal from the picture's pixels, then checks it against the original found inside.
Programs that rewrite pictures (most messaging and social apps) drop these chunks and segments; the
original is then needed separately.

Later tiers (canonical content, printed canonical string) are not yet defined.

## 10. Changes

**v0.5 (from v0.4).** Payload version 2, the stamp event (section 6.2): the signature is made over a
Nostr event built from the same parts, so Nostr signer apps can stamp. The ring, the payload layout, the
flags and the time proofs are unchanged; version 1 seals are unchanged. Clarified 2026-11-24: the seal is
the outermost ring, and a ring drawn in the center artwork is artwork (section 8, step 1); the format is
unchanged. Added 2026-11-24: the stamped JPEG picture (section 9); the ring and payload are unchanged. Added 2026-11-25: public records and public
copies (section 13, optional) and the note on location in a photo (section 9); the ring, payload and
signatures are unchanged.

**v0.4 (from v0.3).** Flag bit 0 defined: anchored seals, "made no earlier than block A" (section 11.1).
OpenTimestamps proofs over the payload, "existed no later than block B" (section 11.2). Block data from a
node or from two sources that agree (section 11.3). The ring, the payload layout and plain seals are
unchanged.

**v0.3 (from v0.2).**

* Signing tag renamed from "RingSeal/v1" to "DigiHan/v1".
* Bit 0 moved from 3 o'clock to 12 o'clock, under the key bridge.
* Guard band widened from 0.9 mm to 1.2 mm (center radius 15.65 → 15.35 mm).
* Decoders keep only plausible bridge readings (within 2.5° of the median offset) and refine the
  start angle separately when retrying without the bridge calibration.
* One size only (45 mm / 0.6 mm); the 40 mm test profile is dropped.

## 11. Time proofs

### 11.1 No earlier than: the block anchor

Flag bit 0 (value 1) marks an anchored seal. The 5-byte timestamp field holds a Bitcoin block height A
(big-endian), and the signed message ends with block A's 32-byte hash in display order (as
`bitcoin-cli getblockhash A` prints it):

```
m = TaggedHash("DigiHan/v1", doc_hash ‖ A(5) ‖ fingerprint(8) [‖ center_hash] ‖ block_hash)
```

A verifier gets block A's hash (section 11.3) and checks the signature with it. If it verifies, the seal
was made after block A was mined. For payload version 2, block A's height and hash are in the stamp
event's `block` tag and block A's header time is the event's time (section 6.2). A signer SHOULD anchor at least two blocks below the chain tip. A v0.3
verifier rejects an anchored seal, because bit 0 is reserved in v0.3.

### 11.2 No later than: OpenTimestamps

The proof is an OpenTimestamps detached proof (the standard `.ots` file format, opentimestamps.org) whose
file hash is SHA-256 over the seal's 78-byte payload. A verifier:

1. computes SHA-256 of the payload read from the ring and requires it to equal the proof's file hash;
2. follows the proof's operations to each Bitcoin block attestation (height B, message = a merkle root);
3. gets block B's merkle root (section 11.3) and compares; the lowest block number that matches is the
   bound: the seal existed no later than block B;
4. if the seal is also anchored at block A, requires A ≤ B; otherwise the seal is reported as not valid.
   A seal with both proofs is **bookended**; a verifier SHOULD state its window as "Sometime between and
   including Block A and Block B".

Pending attestations (calendar addresses) prove nothing until completed. Where proofs are kept:

* in a stamped PDF, as an attached file named `seal.ots` (a verifier MAY accept any attached file that
  starts with the OpenTimestamps file header);
* beside the seal data file, as `<name>.ots`;
* published by a site at `ots/<hex SHA-256 of the payload>.ots`, relative to its scanner.

### 11.3 Block data

The verifier's own Bitcoin node needs no trust. Otherwise a verifier SHOULD ask at least two independent
sources and MUST refuse an answer they disagree on. Block times can be off by up to about two hours;
block numbers are exact.

See [docs/TIME-PROOF.md](docs/TIME-PROOF.md).

## 12. Also planned

* The center registration as a Nostr NIP: draft in [nip/NIP-DIGIHAN.md](nip/NIP-DIGIHAN.md). It adds an
  `f` tag (the key id) so a verifier holding only a scanned seal can find the key on relays.
* A way to carry a time proof for a seal that is neither in a PDF nor on a site (for example a Nostr event).

## 13. Public records and public copies (optional)

Everything above works with nothing published. A signer MAY publish a stamp, in two parts:

* a **public record** on Nostr relays: this key stamped a file with this SHA-256 hash, and the ring's payload;
* **public copies** of the stamped PDF or stamped picture on Blossom servers (BUD-01, BUD-02), named in the
  record. A stamped file carries the original, so a public copy makes the original public too.

Neither changes the ring, the payload or the signature. A record proves only that its key published it; a
reader still checks the seal (section 8) against the original.

### 13.1 The public record

An addressable Nostr event (NIP-01), signed by the seal's key:

```
kind       30078
created_at the time it was published (not the stamp's time)
tags       ["d", "digihan-record:" + hex(SHA-256(payload))]
           ["x", hex(doc_hash)]                          the original's SHA-256, as signed (section 6)
           ["payload", hex(payload)]                      the ring's 78 bytes
           ["copy", hex(SHA-256(file)), mime, dec(size), server, ...]   one per public copy, OPTIONAL
           ["alt", "DigiHan stamp record: a seal on a document, made public"]
content    "DigiHan stamp. Document SHA-256: " + hex(doc_hash) + "."
```

* `d` is unique to the seal, so a newer record for the same seal replaces the older one on relays (kind 30078
  is addressable by kind, key and `d`).
* `copy` lists a stamped file's SHA-256 (its Blossom address), its type and size, then the base URLs of the
  servers that stored its exact bytes. The copy listed first is the one a reader SHOULD fetch first.
* The record carries no `f` tag, so a lookup of the key's registration by key id (section 7) never has to
  page through a signer's records.
* The sending client uses the same relays as the registration (section 7).

### 13.2 Public copies

* The client asks each server first (`HEAD /upload`, BUD-06), then uploads (`PUT /upload`, BUD-02) with an
  authorization event (kind 24242, BUD-11) signed by the seal's key: `["t", "upload"]`, an `expiration` a few
  minutes ahead, and one `x` tag per file. A server that refuses, or whose answer names a different SHA-256,
  is left out of the `copy` tag.
* A stamped file that is being made public carries `DigiHanPublish` = `blossom`: in a PDF's document
  information, in a PNG's `tEXt` chunk, or in a JPEG's DigiHan text segment (section 9). It is written before
  the file's SHA-256 is taken, so it is part of the public copy.
* When the time proof of such a file is finished (section 11.2), the finished file is a new file with a new
  SHA-256. The client uploads it the same way and publishes the record again with the finished copy listed
  first. The earlier copy stays where it was stored: a Blossom address cannot be withdrawn from every server.
* If a relay answers that the key has no Blossom server list (kind 10063, BUD-03), the client publishes one
  naming the servers that stored a copy. If the key has one, it is used and left as it is: the list is
  replaceable, and publishing a new one would replace a list the signer made elsewhere. If no relay answers,
  no list is published.

### 13.3 Finding a record

* **From a scanned seal.** Once the key is found (section 7), ask the relays for
  `{"kinds": [30078], "authors": ["<pubkey>"]}` and pick the record whose `d` matches; the relays learn the
  key, as they do for the registration. If the key is not known, or the answer may have been cut short by a
  relay's limit, `{"kinds": [30078], "#d": ["digihan-record:<hex>"]}` finds it directly; the relays then learn
  which seal is being checked.
* **From an original.** `{"kinds": [30078], "#x": ["<hex SHA-256 of the file>"]}`; the relays learn the file's hash.
* A reader MUST check that the record's signature is valid, that its `d` is `digihan-record:` and the SHA-256 of
  its `payload`, that the payload's key id is the record key's (`SHA-256(pubkey)[0:8]`), and, from a scanned
  seal, that the payload is the one read from the ring.
* A downloaded copy MUST have the SHA-256 named in its `copy` tag. It is then checked like any stamped file:
  its seal data must be the ring's payload, and the seal is checked against the original inside it.
* With no copy to download, a record still lets a reader check the signature against the record's `x` hash.
  That shows the key signed a file with that hash; it does not show which file the reader holds.

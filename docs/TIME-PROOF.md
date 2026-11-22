# Time proof

A v0.3 seal proves which key sealed a document and that the document has not changed. The time in it
is the signer's statement: the signer can write any time, earlier or later. This note is the plan to
prove **when** a seal was made, as a window between two Bitcoin blocks, and what is built so far.

## The window

| Bound | What it proves | How | Status |
|---|---|---|---|
| No earlier than | The seal was made after Bitcoin block H was mined | Block H's hash is part of what is signed. Nobody can know a block's hash before the block exists. | **Built, draft v0.4** |
| No later than | The seal existed before Bitcoin block K was mined | An OpenTimestamps proof that the seal's data was recorded in block K | Next |

Together they place the seal between two blocks: usually a window of one to three hours.

## No earlier than (built, draft v0.4)

* Payload flag bit 0 (value 1) marks an **anchored** seal. The 5-byte time field then holds the block
  height H instead of a time, and the signed message ends with block H's 32-byte hash, in the order it is
  usually printed (as `bitcoin-cli getblockhash H` shows it):

  `m = TaggedHash("DigiHan/v1", doc_hash ‖ H(5) ‖ key_id(8) [‖ center_hash] ‖ block_hash)`

* The ring is unchanged: same 78 bytes, same layout.
* A v0.3 verifier must reject a seal with a reserved flag set, so an anchored seal is refused by old
  verifiers rather than misread. That is by design.

**Sealing:** `python sign_pdf.py doc.pdf sealed --key key_alice --anchor auto` anchors two blocks below
the tip reported by mempool.space. For full independence give a block from your own node:
`--anchor HEIGHT:HASH` with `bitcoin-cli getblockcount` and `bitcoin-cli getblockhash HEIGHT`.

**Checking:** `python verify_pdf.py sealed/doc_sealed.pdf key_alice/registration.json` asks mempool.space
for block H's hash; `--block-hash HASH` uses one you got from your own node. The phone scanner fetches
the hash from mempool.space and says "made no earlier than Bitcoin block H".

**Limits.** A block's own time can be off by up to about two hours. The check trusts whichever source
gave the block hash; your own node is the only source that needs no trust.

## No later than (next)

1. `sign_pdf.py` already writes the seal's 78-byte data to `<name>_seal_payload.bin`. Its SHA-256 is the
   value the phone's digest is cut from, so the phone can recompute it from the ring alone.
2. Stamp it with the official OpenTimestamps client:
   ```
   pip install opentimestamps-client
   ots stamp doc_seal_payload.bin          # writes doc_seal_payload.bin.ots
   ots upgrade doc_seal_payload.bin.ots    # a few hours later, once a block includes it
   ots verify doc_seal_payload.bin.ots     # "Bitcoin block K attests existence as of ..."
   ```
3. To build: attach the upgraded `.ots` proof inside the sealed PDF; teach `verify_pdf.py` to check it;
   teach the phone to check it against block K's header (the proof's last step is block K's merkle root).
4. For seals outside PDFs, publish the proof beside the seal, for example as a Nostr event (compare NIP-03).

## Prior work

Linking timestamps into a hash chain is Haber and Stornetta (1991). OpenTimestamps (2016) anchors
hashes in Bitcoin. Two-sided ("not before, not after") Bitcoin timestamps are described in the
literature, including IACR ePrint 2019/644. DigiHan's part is fitting both bounds into a seal that a
phone camera can read.

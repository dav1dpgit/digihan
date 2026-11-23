# Time proof

A plain seal proves which key sealed a document and that the document has not changed. The time in it
is the signer's statement: the signer can write any time, earlier or later. Format v0.4 adds two proofs
that place the seal between two Bitcoin blocks. Both are built, in the Python tools and on the phone.

| Bound | What it proves | How |
|---|---|---|
| **No earlier than** | The seal was made after Bitcoin block A was mined | Block A's hash is part of what is signed. Nobody can know a block's hash before the block exists. |
| **No later than** | The seal existed when Bitcoin block B was mined | An OpenTimestamps proof that the seal's 78 bytes were recorded in block B |

A seal with both is **bookended**. The phone and `verify_pdf.py` then say:
*Sometime between and including Block A and Block B*, followed by the dates the blocks were mined.
"Including" because the seal can be made in the minutes right after block A, and the proof can be in
block B itself. The window is usually one to a few hours. Either proof can be used alone.

## No earlier than: the block anchor

* Payload flag bit 0 (value 1) marks an **anchored** seal. The 5-byte time field holds the block height A
  instead of a time, and the signed message ends with block A's 32-byte hash, in the order it is usually
  printed (as `bitcoin-cli getblockhash A` shows it):

  `m = TaggedHash("DigiHan/v1", doc_hash ‖ A(5) ‖ key_id(8) [‖ center_hash] ‖ block_hash)`

* The ring is unchanged: same 78 bytes, same layout. A v0.3 verifier rejects an anchored seal (bit 0 was
  reserved) instead of misreading it.
* The anchor is two blocks below the tip, so a short chain reorganization cannot remove it.

```
python sign_pdf.py doc.pdf sealed --key key_alice --anchor auto    # two block explorers
python sign_pdf.py doc.pdf sealed --key key_alice --anchor node    # your own bitcoin-cli
```

## No later than: OpenTimestamps

The proof is a standard OpenTimestamps file (`.ots`) over the SHA-256 of the seal's 78-byte payload,
the data in the ring. The payload holds the signature, so proving the payload existed at block B proves
the seal was made by then. The phone gets the payload from the ring, so it needs nothing else to know
which proof belongs to which seal.

```
python sign_pdf.py doc.pdf sealed --key key_alice --anchor auto --stamp       # seal and stamp at once
python timestamp.py upgrade sealed/doc_seal_payload.bin.ots                    # a few hours later
python timestamp.py attach  sealed/doc_sealed.pdf sealed/doc_seal_payload.bin.ots
python verify_pdf.py sealed/doc_sealed_timestamped.pdf key_alice/registration.json
```

* `--stamp` (or `python timestamp.py stamp sealed/doc_seal_payload.bin` later) sends the hash to the
  OpenTimestamps calendars and saves a pending proof. A calendar puts many hashes into one Bitcoin
  transaction, so the proof is complete once that transaction is in a block: usually a few hours.
* `upgrade` fetches the Bitcoin part. It keeps the pending version as `.bak`.
* `attach` writes a new PDF with the proof attached as `seal.ots`. The sealed PDF is not changed.
* The `.ots` files are standard: `ots verify doc_seal_payload.bin.ots` (opentimestamps-client) checks
  them too, and `timestamp.py` reads proofs the `ots` client made.

**Where a verifier finds the proof:** attached to the sealed PDF as `seal.ots`; as a file next to the
seal data (`<name>_seal_payload.bin.ots`), which the phone accepts through *Check against a document…*;
or published by a site at `ots/<seal digest>.ots`. The 21 sample seals on digihan.org have theirs there,
made and completed by a GitHub workflow.

## Block data

Both checks need facts about a block: its hash (anchor) or its merkle root (OpenTimestamps). Your own
node needs no trust: `--node` on `verify_pdf.py` and `timestamp.py verify` uses `bitcoin-cli`. Otherwise
the Python tools and the phone ask two block explorers, mempool.space and blockstream.info, and refuse an
answer the two disagree on.

## Limits

* A block's own time can be off by up to about two hours, so dates shown for blocks are approximate.
  The block numbers are exact.
* The calendars are not trusted for the proof: a complete proof checks against the block alone. They are
  needed only to get the proof finished, and a calendar that disappears before then means stamping again.
* If the two proofs contradict each other (the timestamp's block is below the anchor's), the seal is
  reported as not valid.
* A seal outside a PDF and outside a site needs its proof carried some other way, for example a Nostr
  event (compare NIP-03). That is not defined yet.

## Prior work

Linking timestamps into a hash chain is Haber and Stornetta (1991). OpenTimestamps (2016) anchors
hashes in Bitcoin. Two-sided ("not before, not after") Bitcoin timestamps are described in the
literature, including IACR ePrint 2019/644. DigiHan's part is fitting both bounds into a seal that a
phone camera can read.

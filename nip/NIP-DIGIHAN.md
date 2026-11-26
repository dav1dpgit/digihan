NIP-XX
======

DigiHan seal registration
-------------------------

`draft` `optional`

This NIP defines a signed record that binds a Nostr key to the artwork in the center of a
[DigiHan](https://github.com/dav1dpgit/digihan) seal, and lets anyone holding only a scanned seal
find the key that made it.

## Background

A DigiHan seal is a printed or on-screen mark. The ring of dots around it carries a 78-byte payload:
a BIP340 Schnorr signature over the SHA-256 of an exact document, a timestamp stated by the signer,
an 8-byte **key id**, and, when the artwork is committed, the SHA-256 of the seal's center artwork
(format: [SPEC.md](../SPEC.md)). The center artwork is free (a handwritten signature, lettering, a crest).

Signers use their Nostr key (the same secp256k1 x-only key). The ring has room for only the key id,
the first 8 bytes of SHA-256 of the 32-byte public key. A verifier therefore needs two things from
outside the ring: the full public key, and the hash of the artwork the seal was signed under. This
NIP puts both in one event that relays can find by the key id.

## Event

An addressable event of kind `30078` (NIP-78) with these tags:

| Tag | Value | |
|---|---|---|
| `d` | `digihan-center:<center_hash>` | REQUIRED. One record per artwork. |
| `center_hash` | 64 hex characters: SHA-256 of the artwork file's exact bytes | REQUIRED |
| `f` | 16 hex characters: the key id, `SHA-256(pubkey)[0:8]` | REQUIRED. Single letter so relays index it. |
| `alt` | `DigiHan seal: artwork registration` | RECOMMENDED (NIP-31) |
| `image` | URL of the artwork file whose SHA-256 is `center_hash` | OPTIONAL |

`content` is JSON: `{"app": "DigiHan", "format": "v0.3", "center_hash": "<hex>"}`.

The event is signed by the seal's key, as any Nostr event (NIP-01).

Because the `d` tag carries the artwork hash, a signer who changes artwork publishes a new event and
the old one stays: seals made under the old artwork keep verifying.

### Example

A real record for sample seal #1 on digihan.org (key id `44d846907e91c4d0`):

```json
{
  "pubkey": "db4a3ff738c8438a49f73eaae455ec3f26a26360989219736041e426b3abca81",
  "created_at": 1795362961,
  "kind": 30078,
  "tags": [
    [
      "d",
      "digihan-center:fc24fb9a20d21e1caac9bf77ac06db961e9de1e1ae456a4b1dddd92c70761eb4"
    ],
    [
      "center_hash",
      "fc24fb9a20d21e1caac9bf77ac06db961e9de1e1ae456a4b1dddd92c70761eb4"
    ],
    [
      "f",
      "44d846907e91c4d0"
    ],
    [
      "alt",
      "DigiHan seal: artwork registration"
    ],
    [
      "image",
      "https://digihan.org/centers/fc24fb9a20d21e1caac9bf77ac06db961e9de1e1ae456a4b1dddd92c70761eb4.png"
    ]
  ],
  "content": "{\"app\": \"DigiHan\", \"format\": \"v0.3\", \"center_hash\": \"fc24fb9a20d21e1caac9bf77ac06db961e9de1e1ae456a4b1dddd92c70761eb4\"}",
  "id": "7b1f8547e362ec826e7ccc747cbbe95e8f7932b74a5be73f72af3a1f7e4ee43f",
  "sig": "6ded25a0367122760f0688d00695c255e144106ff10fd52c781c74f6f0cf3aec2bd971a66ccc31ebfe111f388491ebaf0b233eaf2119c969e538d2e466ae6fee"
}
```

## Publishing

The signer's client sends the record (`["EVENT", <event>]`) to several relays when the key and artwork
are set up, and MAY send it again later; relays keep one copy of an event. The record holds nothing
about any document. The DigiHan stamping page sends it to `wss://relay.damus.io`, `wss://nos.lol` and
`wss://relay.primal.net`, the relays its scanner asks.

## Stamp event (seal payload version 2)

A seal of payload version 2 is signed over a second kind-`30078` event, the **stamp event**, defined in
[SPEC.md](../SPEC.md), section 6.2. Its `d` tag is `digihan-stamp:<document SHA-256>:<timestamp field>`,
and it carries `x` (the document's SHA-256), `f` (the key id), `center_hash`, `block` (for a seal
anchored to a Bitcoin block) and `alt` tags. This lets any NIP-07, NIP-46 or NIP-55 signer stamp a
document, and the signer shows the person what they sign. The event does not need to be published: a
verifier rebuilds it from the scanned ring, the document, this registration and the Bitcoin block, and
checks the signature over its id.

A client looking for registrations MUST ignore events whose `d` tag starts with `digihan-stamp:`.

## Public stamp record (optional)

A signer MAY make a stamp public with a third kind-`30078` event, the **public record**, defined in
[SPEC.md](../SPEC.md), section 13. Its `d` tag is `digihan-record:<SHA-256 of the 78-byte payload>`, and it
carries `x` (the original's SHA-256), `payload` (the ring's 78 bytes in hex), `copy` tags for copies of the
stamped file on Blossom servers (the file's SHA-256, its type, its size, then the servers), and `alt`. It has
no `f` tag, so the registration lookup below never pages through a signer's records. A reader finds it from a
scanned seal with `{"kinds": [30078], "authors": ["<pubkey>"]}`, or by its `d` tag, and from an original with
`{"kinds": [30078], "#x": ["<SHA-256>"]}`. The signer's Blossom server list (kind 10063, BUD-03) is published
only if the key has none.

A client looking for registrations MUST ignore events whose `d` tag starts with `digihan-record:`.

## Finding the key for a scanned seal

1. Read the ring and take the key id (payload bytes 1-8, as 16 hex characters).
2. Ask relays: `["REQ", <sub>, {"kinds": [30078], "#f": ["<key id>"]}]`.
3. For each event returned, the client MUST:
   * check the event id and signature (NIP-01);
   * check that the `f` tag equals the key id **and** that `SHA-256(pubkey)[0:8]` equals it: the key id
     is an index, not an identity;
   * take `center_hash` and check the seal's signature as in SPEC.md, section 8.
4. If several keys share a key id, try each. Only a key whose signature checks counts.
5. If an `image` tag is present, the client SHOULD show that image beside the scanned seal only when
   the downloaded file's SHA-256 equals `center_hash`, so a person can compare the two.

A seal that does not commit its artwork (payload flag bit 2 clear) needs only the public key; the
same query finds it.

## Security considerations

* **What a record proves.** The holder of the private key registered this artwork for its public key. It says
  nothing about who that is: anyone can register a copy of the same artwork for a public key of their own, and a
  stamped file carries whatever registration its maker put in it. Clients MUST NOT treat a signer as known from a
  registration. They MAY treat one as known from a public key the user saved, or name one from a NIP-05 name in the
  public key's profile (kind 0) that its domain confirms; a name the domain does not confirm MUST NOT be shown as the
  signer (SPEC.md, section 14). Binding a public key to a person by other means (for example, a notary's
  attestation) is out of scope and may be a separate NIP.
* **Withheld records.** A relay may not return a record. Clients SHOULD ask several relays and SHOULD
  let the user add a key or record by hand.
* **Key id collisions.** 8 bytes is enough to index, not to identify. Clients MUST confirm the full public key
  by checking the seal's signature, and SHOULD show the full public key wherever the signer is not known.
* **Deleting a record.** A deletion request (NIP-09) for a registration would stop old seals from
  verifying where relays honor it. Signers SHOULD NOT delete a record while seals made under it are in use.
* **Privacy.** A query by key id tells relays which signer's seal is being checked; a query for a public
  record by its `d` tag tells them which seal, and by `x`, which file. Confirming a name asks the relays for the
  public key's profile and tells the name's domain that someone is checking that name.

## Open questions

1. A dedicated addressable kind instead of the general-purpose `30078`.
2. Confirm the `f` tag letter is free of conflicting use.
3. Time proof: carrying an OpenTimestamps proof for a seal (compare NIP-03, kind 1040).

## Reference implementation

* Writing: `python/dhsign.py`, `register_center()`.
* Reading: `web/scanner/verify.js` and the relay query in `web/scanner/index.html`.

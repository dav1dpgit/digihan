# Changelog

## v0.7.7 (2026-11-26): "Signature valid for this file"

* Scanner v34: the headline says "Signature valid for this file" (and "· signer unknown" when the public key is
  not saved on the phone, not on the sample list and has no confirmed name). The first line names the public key
  as part of the check: "Signature in the seal's ring, checked with the public key, against the SHA-256 hash of
  the document file", and its result says what a match means: "Match: the signature was made with this public
  key's private key, over this exact file." The check itself is unchanged: the BIP340 signature check, which
  passes only for a signature made with the matching private key.
* Stamping page v28 (release number only). How it works v25 and the README use the same words. Offline copy v15.

## v0.7.6 (2026-11-26): a button back to the home page

* Scanner v33: "Return to the home page" under "Scan another" on the result. It stops the camera and opens the
  front page.
* The scanner's buttons now use the page's own font, at the size their style sets (14 px; 15 px for "Start
  camera"). Their style rule was written as "font: 600 14px/1 inherit", which browsers reject as a whole, so the
  buttons fell back to the browser's default font (measured in Chromium: Arial, 13.3 px), while the one link
  styled as a button ("Open the public copy") used the page's font at 15 px.
* Stamping page v27 (release number only). Offline copy v14.

## v0.7.5 (2026-11-26): each check names both items and where they came from

* Scanner v32: each line names the item and where it came from, and what it is checked against and where that
  came from. For example "Signature in the seal's ring against the SHA-256 hash of the document file", "Public key
  from the registration inside IMG_8075.jpeg against the public keys saved on this phone and on digihan.org's
  sample list", "Name dp@example.com in the public key's Nostr profile against the name file at
  https://example.com/.well-known/nostr.json", "Bitcoin block hash signed in the seal against block 977,604 at
  mempool.space and blockstream.info", "OpenTimestamps proof inside IMG_8075.jpeg against the Bitcoin block at
  mempool.space and blockstream.info".
* Each result starts with Match, No match or Not checked, then says why in full words, for example "No match: not
  saved on this phone and not on digihan.org's sample list", "No match. Document file: notes.md. It is not the
  file that was stamped, or it was changed after stamping."
* Stamping page v26 (release number only). How it works v24 and the README use the same words. Offline copy v13.

## v0.7.4 (2026-11-26): each check says what it checks against what

* Scanner v31: each line of the result names what is checked against what, above its result: "Signature against
  the document", "Public key against the public keys this phone knows", "Name against its website", "Artwork
  against the seal's center", "Earliest time against Bitcoin", "Latest time against Bitcoin (OpenTimestamps)".
  Lines not checked yet say so ("Not checked yet.", "No document yet.") instead of a dash.
* Stamping page v25 (release number only). How it works v23 and the README use the same names. Offline copy v12.

## v0.7.3 (2026-11-26): the result, one line per check

* Scanner v30: the result is one line per check, each with what was checked, a mark (✓ passed, ✗ failed, ! not
  known, – none, … waiting) and the result in a few words: Document (the signature matches this exact file),
  Public key (saved on this phone, a sample seal, or not known to this phone and where it was found, with the
  full public key), Name (the NIP-05 name and whether its domain lists this public key), Artwork (the registered
  artwork, to compare with the seal's center), Time and Time proof. The long sentences under the verdict and the
  "Signed by" box are gone; the digest moved down with the other details.
* No names are asked for: "Save this public key on this phone" and "Add a signer's public key…" save the public
  key alone.
* Stamping page v24 (release number only, and one line in "Check my name"). How it works v22, README, SPEC.md
  section 14 and the NIP draft say the same. Offline copy v11.

## v0.7.2 (2026-11-26): who signed

* A valid signature shows only that the private key of a public key signed the document. Until now the scanner
  showed the same green "Signature valid" for any public key that passed, wherever it came from: saved on the
  phone, the sample list, Nostr relays, or the registration carried inside the stamped file itself. The last
  two are written by whoever made the seal, so a seal made with someone else's artwork and a private key of the
  maker's own (re-stamping the same file, or editing a stamped file's seal and registration together) showed the
  same green, with only the npub in small type telling them apart. Seen in the scanner's code (showValid) and
  reproduced in a test: two seals with the same artwork on the same photo, made with two key pairs.
* Scanner v29. Green "Signature valid" now needs a public key the phone has a reason to know: one you saved
  on the phone under a name, a digihan.org sample seal, or a name its own domain confirms (below). Under the
  verdict a new "Signed by" line names the signer. Any other public key gives amber "Signature valid · signer
  unknown", the full public key (to check with the signer, letter for letter), where it was found, and "Save
  this public key on this phone" with a name. "Add a signer's public key…" also asks for a name. A saved
  public key can be removed from the phone from the result.
* The signer's name (NIP-05, optional). The scanner reads the public key's Nostr profile (kind 0) and, if it
  gives a name such as dp@example.com, asks https://example.com/.well-known/nostr.json?name=dp whether it lists
  this public key (no redirect followed). Listed: green, signed by dp@example.com. The domain lists another
  public key, or not the name, or has no file: red "Name NOT confirmed" (anyone can write a name into the
  profile of their own public key; only the domain can list a public key under it). The domain cannot be
  asked: the signer stays unknown, and the scanner says so.
* Stamping page v23, step 1: "Your name". For a private key kept on the device: type the name and the private
  key password, and the page publishes the public key's Nostr profile with it, keeping anything else an
  existing profile holds (nothing is published if no relay answers, since a new profile would replace one
  nobody could see). It shows the file your website must serve, and "Check my name" asks your domain as a
  scanner will. For a private key in a Nostr signer, the name is set in the Nostr app's profile.
* The artwork and digest lines say what they show: a matching artwork shows the center was not swapped onto
  the ring, not who signed (anyone can register a copy of any artwork); the digest names the seal.
* Wording: every "key" a reader sees on the scanner, the stamping page, How it works (v21), the front page
  captions and the README now says "public key" or "private key" (private key file, private key password,
  public key id).
* SPEC.md section 14 (who signed; the format is unchanged), section 1 and section 8 step 9; the NIP draft's
  security notes. New tests: web/sealer/name.test.js (49 checks). Offline copy v10.

## v0.7.1 (2026-11-25): step 1 stays in view when a seal is made

* Stamping page v22: after "Make my seal" (and when a seal is opened, picked, erased, connected through a
  signer, or "Make another seal" or "Back to your seals" is tapped), step 1 "Your seal" shows from its top,
  12 px below the top of the screen, if its top would otherwise be above the screen; if its top is on
  screen, nothing moves. Step 1 swaps its whole content when a seal is made. Seen in Chrome: in some runs
  the browser's scroll anchoring, having picked an element inside the form that was then hidden, moved the
  page to its very top; in others the page stayed the same distance down, which then showed the bottom of
  the new seal's details. What Safari did was not seen here (no Safari engine in the test machine). Step 1
  is now left out of scroll anchoring (overflow-anchor: none), and the page sets the position itself.
* README brought up to date: the stamped picture's options, up to 21 seals a device, Argon2id key files,
  offline use, the new code files and tests, and the decoder's current results (217/220 camera frames,
  219/220 through the photo path, 60/60 screenshots, 150/150 seals inside seals).
* Offline copy v9.

## v0.7.0 (2026-11-25): public records on Nostr and public copies on Blossom (optional)

* Stamping page v21, step 2: two tick boxes, off by default and off again for each new document.
  "Publish a public record of this stamped file on Nostr" (anyone can see that this key stamped a file with
  this hash, and when) and, under it, "Also put a public copy of the stamped file on Blossom" (anyone can
  download it or connect all publicly-announced copies made by this key). Ticking the second ticks the
  first. With Blossom ticked the rest happens on its own: the stamped PDF and the stamped picture are
  uploaded (each server is asked first, then sent the file with an upload permission signed by the seal's
  key; a server whose answer names another SHA-256 does not count), the record is signed and sent to the
  three relays, and the key's Blossom server list (kind 10063) is published the first time, never over a
  list the key already has (and not at all if no relay answers). The page shows one link per copy (tap to
  copy), the servers that refused and why, and, if none took a file, "Not uploaded: no server accepted the
  file." The downloads show before the publishing starts, and the stamp never depends on it. Servers: your own (optional, remembered on the device), then blossom.primal.net
  and blossom.band (the second takes PDFs only on a paid plan).
* Signing: with the page's key, the one password at stamping signs everything (the key is wiped once the
  record is signed). A Nostr signer is asked for the upload, the record and, once, the server list; signer
  connections now ask for those permissions (kinds 24242 and 10063). A seal that signs by code cannot
  publish from the page, and the page says so.
* Step 3: a stamped file that was made public says so inside itself (DigiHanPublish), so when its time
  proof is finished the page puts the finished file on Blossom too and publishes the record again with the
  finished copy first (the earlier copies stay listed after it). It asks for the password, or the signer.
* Location: a JPEG or PNG original that carries the place it was taken (EXIF GPS or XMP) gets a pause
  before stamping: "This photo carries the place it was taken. The stamped file keeps it, and so will any
  public copy." Stamp anyway, or Cancel. Nothing is removed: the seal signs the original's exact bytes.
* Scanner v28: from a seal alone (on paper, or a seal picture), when no document is at hand, the scanner
  asks the relays for the key's public records (by the key, as it already does for the registration;
  by the seal's record name only when the key is unknown or the answer may have been cut short), downloads the first public copy it can, checks
  its SHA-256 and that its seal data is the ring's, then checks the seal against the original inside it.
  With no copy to be had, a record lets it check the signature against the record's hash, and it says that
  this does not show which file you hold. A file with no seal in it can be looked up with "Look up a public
  record for this file" (it sends the file's SHA-256). "Open the public copy" opens it.
* SPEC.md section 13 (optional, the ring unchanged): the record (kind 30078, `d` = digihan-record: and the
  payload's SHA-256, `x`, `payload`, `copy`; no `f` tag, so a signer's records never crowd out the
  registration lookup), the uploads, the publish note, the lookups and the reader's checks. Section 9: the
  note on location in a photo. NIP draft: the record.
* Tests: web/sealer/publish.test.js (53 checks: the record and its refusals, the upload permission, a
  stand-in Blossom server, the whole publishing with stand-in relays, the location check on hand-made EXIF,
  XMP and PNG bytes). Page tests with stand-in servers and relays: the page's key, a Nostr signer, a code
  key, a refused upload, step 3, and the scanner from a seal alone and from the original.
* Offline copy v8 (keeps publish.js).

## v0.6.5 (2026-11-24): the seal's angle and a transparent background in stamped pictures

* Stamping page v20, stamped picture options: **Seal angle**, a slider from -15° to +15° (+ is clockwise;
  default 0); **Transparent background** (default off): no white disc and no paper behind the seal, so the
  picture shows between its dots. The page reads the picture back as the scanner would before offering it;
  where a transparent seal does not read (the picture behind it is busy or red there), it puts a frosted
  disc behind it (white at 55%, the picture still showing through), then the white disc, and says which.
  A transparent or frosted seal is tried at one size (a bigger seal rarely helps there, and each failed try
  costs seconds). Stamping now shows a step of its own for the stamped picture. On 22 real photos
  (scikit-image's samples, at both a bottom and a top corner, +10° and -15°): 14 kept the transparent seal,
  6 got the frosted disc, 2 (a red retina scan) the white disc; all 24 stamped pictures check valid, and the
  slowest took 11.5 seconds on the test machine.
* The phone's ring reader reads by the ink's colour (web/scanner/digihan.js, inkGray): dark where a pixel is
  red to orange by how much colour it has, white elsewhere, so a picture's black, grey and white parts all
  become paper. A still picture is read in grey first, then by colour (decodePicture). The camera reads
  every third frame by colour, with the centre crops and the outlines (scanner v27). Tested with the camera
  on transparent seals, and with transparent stamped pictures re-saved as an app would (1280 px, JPEG
  quality 70): the seal read in each.
* Fixed: the reader took an all-zero payload for a seal. An all-zero codeword passes the error correction
  trivially, and an even, dark area read through the inverted search can give one; on a dark photo it was
  reported as a seal of zeros, which stopped the reading by colour from being tried. Version 0 is now no
  seal (SPEC.md section 5; the same in python/digihan.py). The test frames now use payload version 1;
  before and after this release they read the same: 60/60 screenshots, 150/150 nested seals, 219/220 and
  217/220 camera frames.
* SPEC.md section 9: the seal's angle, the transparent and frosted backgrounds, and reading by colour.
* Offline copy v7.

## v0.6.4 (2026-11-24): the website under the seal (optional)

* Stamping page v19: a tick box, off by default, "Add the website below the seal". In the PDF,
  https://digihan.org goes under the seal on the first page as a link; its top is 6 mm below the seal, and
  the clear space recorded for readers (DigiHanSealBox) is then 5 mm instead of 15 (SPEC.md asks for at
  least 3). In the stamped picture it goes on a small white label under the seal's white disc; in a bottom
  corner the seal sits higher by the label. If the seal and the label do not fit a small picture, the
  stamped picture is made with the seal only and the page says so; the PDF still shows the website.
* Fixed: the message for a picture too small for its seal gave too low a size (it used an older size of
  the white disc, 1.07 of the seal instead of 1.2): a 300 x 300 picture now reads "at least about 400
  pixels" (was 350).
* The phone's ring reader also looks for a stamped picture's white disc and reads the seal inside it, with
  its own threshold (web/scanner/digihan.js, sealPlates). On a dark, busy photo the outline search can miss
  the seal, and the corner crops miss a seal raised by the label. Only tried when the centre crops and the
  outlines read nothing; the 60 screenshots, 150 nested-seal frames and 220 camera frames read as before.
* Offline copy v6.

## v0.6.3 (2026-11-24): photos upright; a stamped JPEG picture

* Fixed: a phone photo showed turned a quarter in the stamped PDF. A phone saves a photo as its sensor
  faced, with an EXIF Orientation tag saying how to turn it for showing (an upright iPhone photo is usually
  6). The stamping page put the JPEG's bytes into the PDF as stored, and PDF viewers do not read that tag.
  The page now reads the tag and draws the JPEG's own bytes turned upright (not re-saved), for all eight
  orientations. Tested with 16 pictures (each orientation, landscape and portrait), checked pixel by pixel.
* Stamping page v18: a JPEG photo also gets a stamped picture, as a JPEG: the photo upright, the seal in
  the chosen corner, and the original photo, the seal data, the key record, the artwork and the time proof
  inside the file, in APP10 segments (SPEC.md, section 9). The seal is read back after the JPEG compression
  before the picture is offered. A picture over 16 million pixels gets a smaller stamped copy (a phone's
  canvas limit); the original inside is unchanged. "Also make a stamped picture" now starts ticked for PNG
  and JPEG files, and the corner choice shows for both. Step 3 finishes the time proof of a stamped JPEG
  picture. Scanner v26 reads the files inside a stamped JPEG picture. A PNG still gives a PNG picture.
* Offline copy v5.

## v0.6.2 (2026-11-24): a seal inside a seal; base64 without arguments

* Fixed: a seal whose artwork is a picture of another seal, ring and all, was read as that inner seal.
  The phone's ring reader tries a tight centre crop first, and on a seal that fills the picture that crop
  holds only the inner ring. So a photo of the seal was reported as the inner seal's key, and the seal's
  own stamped PDF was refused ("the drawn seal and the file's seal data differ"). The reader
  (web/scanner/digihan.js) now keeps looking after a ring is read: the larger crops, the outlines and the
  larger corner crops are tried too, and a ring that encloses the one read wins. A ring is enclosed when it
  lies inside the other ring's centre circle. SPEC.md, section 8, step 1 now says it: the seal is the
  outermost ring; a ring in the centre artwork is artwork. The format is unchanged. The Python tools
  already read from the outside in and were not affected. New tests: tests/make_nested.py (150 frames:
  the inner seal filling the centre, small and off centre, three deep; held at 60%, 80% and 95% of the
  frame; phone screenshots). Before the fix, 13 were read as the inner seal; now none are, by either
  path. The 60 screenshots and 220 camera frames read exactly as before. A frame that reads now takes
  about 20 ms instead of 6 (once, on the frame that reads).
* Fixed, again: "Maximum call stack size exceeded" when making a seal with a photo as its artwork was
  still reported after v0.6.1. v0.6.1 passed the picture's bytes to a function 32 KB at a time, which
  still depends on the browser's limit on arguments (WebKit's is about 65,536, and less if the stack runs
  out first). Which copy of the code that phone ran was not seen. dhseal.js and nostrsign.js now make
  base64 from a table, with no bytes passed as arguments at any size; dhseal.test.js checks every length
  near the 3-byte and 3072-byte boundaries and that the code passes no bytes as arguments.
* Stamping page v17 and scanner v25 show their release (0.6.2) and the release of the code they loaded.
  A phone keeps a copy of the code for offline use, and an open tab keeps the code it opened with; an
  older copy is now named on the page, with "close this tab and open the page again", instead of failing
  later. The offline copy is renewed (digihan-offline-v4).

## v0.6.1 (2026-11-24): a photo as the seal's artwork

* Fixed: making a seal with a picture as its artwork could stop with "Maximum call stack size exceeded".
  The key file keeps the artwork as base64 text, and dhseal.js made that text by passing every byte of the
  picture to one function call as its own argument. A photo saved as the 600 x 600 artwork is about 700 KB,
  more arguments than a browser allows; lettered artwork is small, so it never showed. The text is now
  made in pieces of 32 KB. Tested with a 690 KB artwork (seal made, public record sent, stamped, checked)
  and a 2 MB round trip in dhseal.test.js.

## v0.6.0 (2026-11-23): Nostr signers, a second device, and the stamp event (format v0.5)

* Format v0.5 (SPEC.md, section 6.2): payload version 2, the **stamp event**. The ring, the 78-byte
  payload, the flags and the time proofs are unchanged; only what the signature covers differs. Version 2
  signs the id of a Nostr event (kind 30078, `d` tag `digihan-stamp:<document SHA-256>:<time field>`, with
  `x`, `f`, `center_hash`, `block` and `alt` tags) built from the same parts, because Nostr signer apps sign
  whole events only. A verifier rebuilds the event from the ring, the document, the key record and the
  Bitcoin block; for a seal anchored to a block, the event's time is that block's header time. Version 1
  seals are unchanged and still made by keys on the device, the Python tools and second devices. A shared
  test vector (python/tests/stamp_event_vector.json) is checked by both the JavaScript and Python code.
* Stamping page v16, "Use a key I keep elsewhere" (was "...offline"), three ways to sign:
  * **A Nostr signer.** "Connect a Nostr signer…": the signer in this browser (an extension, or the
    built-in browser of a Nostr app; NIP-07), a pasted `bunker://` link, or the page's own
    `nostrconnect://` link and QR code for a signer app (NIP-46, requests encrypted with NIP-44 v2). The
    signer signs the seal's public record, then each stamp (payload version 2), and shows what it signs.
    The page checks that the signed event is exactly the one it asked for, shows the signer's approval page
    when it asks for one, and offers "Ask again" and "Sign another way instead" (the code, version 1). The
    link to the signer is kept with the seal on the device, never in a saved seal file; "Disconnect the
    signer" removes it. The stamped PDF (and stamped picture) carries the signed stamp event as
    `digihan-stamp.json`.
  * **A second device, by QR code.** "Sign on another device…" shows a QR code with what to sign (for the
    seal's record, or a stamp: the document's name, size and SHA-256 hash, the time or block, the artwork's
    hash). On the device that holds the key, "Sign for another device…" reads it with the camera, a photo
    or pasted text, shows in words what it is about to sign, works the code out itself, asks for the
    password, and shows the signature as a QR code to scan back. It works with that device offline (the
    QR code libraries, jsQR 1.4.0 and qrcode-generator 1.4.4, are saved for offline use).
  * **Your own computer**, as before (sign_hash.py or any BIP340 signer that signs the 32 bytes as given).
* Scanner v24: checks version 2 seals (it also fetches the anchored block's header time); shows the version
  ("2 · a Nostr stamp event"); never takes a stamp event as a key record.
* Python: verify_pdf.py checks version 2 seals (`--block-time` for an anchored seal checked against your own
  block data). Fixed: verify_pdf.py stopped with an error after a valid result when the attached original
  was not a PDF (a text file or a picture stamped on the stamping page).
* nip/NIP-DIGIHAN.md describes the stamp event; How it works (site) lists the three ways to keep a key
  elsewhere. Offline copy of the site: v3 (saves nostrsign.js and the QR code libraries).

## v0.5.18 (2026-11-23): offline signing instructions say what is signed

* Stamping page v15, key kept offline. Setting up the seal: the instructions now say what the code is made
  from (the seal's public record: public key, time, key id, the artwork's SHA-256 hash; the code is also the
  record's Nostr id), that sign_hash.py asks for the key's password, that a BIP340 signer must sign the 32
  bytes exactly as given (a tool that hashes the code again, or Bitcoin's older signed-message method,
  gives a signature the page rejects), and to sign only codes the page shows. Stamping: the code's parts
  are listed fully (with the block proof, the block number takes the place of the time, and the block's
  hash is added), "key's fingerprint" is now "key id", the signature is said to go into the ring, and the
  sign_hash.py command is shown here too.
* How it works (site): with a key kept offline, a code is signed once when the seal is set up and once for
  each document.

## v0.5.17 (2026-11-23): larger logo

* Stamping page v14: the shared site header's DH logo is larger (38 px, was 24 px) and the name beside it
  21 px (was 17 px), the same on every page of the site. The logo and the menu button stay in the same
  place on every page.

## v0.5.16 (2026-11-23): the seal's public record goes to Nostr

* Stamping page v13: when a seal is made (here, or with a key kept offline), the page sends the seal's
  public record to three Nostr relays (relay.damus.io, nos.lol, relay.primal.net). The record is the
  registration the seal already has, signed by its key when it was made: the public key, the key id and
  the artwork's SHA-256 hash. Nothing about any document is sent, and no new signature is needed. Until
  now nothing sent it, so the scanner's lookup on Nostr by key id found nothing for seals made on the
  stamping page; now a scanned seal plus the original can be checked without the stamped PDF.
* Step 1 has an "On Nostr" panel: when the record was sent and which relays saved it, which did not and
  why, and a button to send it ("Send to Nostr" for a seal not sent from this device, such as one opened
  from a key file or made before this version; "Send again" otherwise). The note is kept with the seal on
  the device, and survives re-encryption of the key file.
* SPEC section 7 and the draft NIP describe the publishing.

## v0.5.15 (2026-11-23): each loaded file is checked by itself

* Scanner v23, fixed: after a stamped PDF or stamped picture was read, a file loaded with "Check against a
  document…" was never checked by itself. The scanner went down its list of files and stopped at the first
  match, which was the original carried inside the stamped PDF, so the result never named the loaded file,
  and a changed file loaded this way still showed "Signature valid". Now every loaded file gets its own
  result, named in the document row ("notes.md: matches", "notes.md: does NOT match", or for a stamped PDF
  or picture, "the original inside it matches"), and the verdict is about the file loaded last. A file that
  does not match says so: it is not the file that was stamped, or it was changed after stamping. The copy
  inside the stamped PDF the seal was read from answers only when no file has been loaded. Loading the same
  file again lists it once.

## v0.5.14 (2026-11-23): the stamped PDF shows the document

* Stamping page v12: for a file that is not a PDF, the stamped PDF now shows the document after the cover
  page, so it can be read on any phone: a text file (.md, .txt, .csv, .json and similar) as text, with a
  light reading of Markdown (headings, bullets, quotes, code), and a picture as a picture. Text in plain
  letters becomes real PDF text (small, sharp, searchable; up to 200 pages); text in other scripts
  (Japanese, for example) is drawn by the browser as page pictures (up to 30 pages). The original file
  stays attached unchanged and is what was signed; the cover page says which pages show it. Other files
  (spreadsheets, for example) are attached only, and the cover says so.
* Scanner v22: when a file is loaded, its name shows at once, even before the signer's key is found. A
  stamped PDF that cannot be read now says so instead of nothing happening. Of the seals drawn in a PDF,
  the one matching the stored seal data is used (a picture shown on a later page may contain another seal).

## v0.5.13 (2026-11-23): up to 21 seals on one device

* Stamping page v11: a device keeps up to 21 seals (each its encrypted key file, or the public parts of a
  key kept offline) in the browser's database storage (IndexedDB), listed at the top of step 1 ("Your seals
  on this device, n of 21"); tap one to use it. "Make another seal" and "Open a key file…" add to the
  list and never replace a seal; opening a key file already kept just selects it; at 21 the page asks for
  one to be erased first. "Erase from this device" erases the seal in use (second tap). The one seal kept
  by earlier versions (localStorage) moves into the list the first time the page opens.
  Fixed: "Open another key file…" silently replaced the seal kept on the device.
* Stamped picture: the white disc behind the seal is now 1.2 times the seal's width (was 1.07). With the
  narrower disc a busy photo next to it could stop the seal being found (seen in tests in one corner in
  every try); 72 stamped pictures in all four corners now read back every time.
* Scanner v21: if a file is loaded but the signer's key is not found (an original file does not carry the
  key), the scanner says so: "Seal read · file loaded", and asks for the stamped PDF or picture instead.

## v0.5.12 (2026-11-23): wording for the two files; a gentler tilt

* "Original" means the file as it was before stamping; the file you get back is "the stamped PDF" or
  "the stamped picture". The PDF cover text (stamping page and sign_pdf.py) now reads "Original file,
  attached unchanged"; the PNG option is "Also make a stamped picture"; the scanner's result names "the
  original inside" the stamped file and its button reads "Load the stamped PDF or picture…".
* Stamping page v10: the DH stamps for finished steps tilt by -2.5 to +2.5 degrees.

## v0.5.11 (2026-11-23): check a stamped PDF without the camera; DH stamps for finished steps

* Scanner v19: the photo button (now a picture and a folder) also takes a stamped PDF. The scanner reads
  the seal data the PDF stores (DigiHanPayload) and the seal drawn in it (from its picture, including
  PDFs made by sign_pdf.py), requires the two to match, and checks the signature against the signed file
  attached inside. A result row says where the seal was read from. If the drawn seal and the stored seal
  data differ: "The drawn seal and the file's seal data differ".
* Stamping page v9: each finished step is stamped with the DH logo, tilted at random between -7 and +7
  degrees.

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

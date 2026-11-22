# OpenTimestamps test proofs

Copied unchanged from the `examples/` folder of opentimestamps-client
(https://github.com/opentimestamps/opentimestamps-client, LGPL-3.0), used only as test data:

* `hello-world.txt.ots`: complete; Bitcoin block 358391.
* `two-calendars.txt.ots`: pending at two calendars.
* `different-blockchains.txt.ots`: Bitcoin block 455605 plus an Ethereum branch (kept, not evaluated).
* `invalid/`: proofs a reader must reject.

The merkle root the tests expect for block 358391 is the one the proof itself leads to; the online check
(`python -m pytest tests -m online`) compares it with mempool.space and blockstream.info.

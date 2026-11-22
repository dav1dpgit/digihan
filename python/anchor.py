"""Bitcoin block data for DigiHan time proofs (see docs/TIME-PROOF.md).

* No earlier than (block anchor): the seal's 5-byte time field holds block height H and the signed
  message ends with that block's hash. Nobody knows a block's hash before the block is mined, so a seal
  that verifies with it was made after block H.
* No later than (OpenTimestamps, ots.py): the proof ends at a block's merkle root; the verifier checks
  that root against the block.

Your own node is the source that needs no trust:
    bitcoin-cli getblockcount
    bitcoin-cli getblockhash <height>
    bitcoin-cli getblockheader <hash>
Otherwise these helpers ask two public block explorers (mempool.space and blockstream.info) and refuse
an answer the two disagree on.
"""
import json, subprocess, urllib.request

import dhsign

EXPLORERS = ["https://mempool.space/api", "https://blockstream.info/api"]
DEPTH = 2          # anchor two blocks below the tip, so a short chain reorganization cannot drop it


class BlockDataError(RuntimeError):
    pass


def _get(base: str, path: str) -> str:
    req = urllib.request.Request(base + path, headers={"User-Agent": "digihan/0.4"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read(100000).decode().strip()


def _agree(path: str, parse):
    """Ask every explorer; return the answer if those that answered agree, else raise."""
    got = {}
    for base in EXPLORERS:
        try:
            got[base] = parse(_get(base, path))
        except Exception:
            continue
    if not got:
        raise BlockDataError("no block explorer answered")
    vals = set(got.values())
    if len(vals) > 1:
        raise BlockDataError("the block explorers disagree: " + json.dumps({k: str(v) for k, v in got.items()}))
    return vals.pop()


# ------------------------------------------------------------ explorers ---
def explorer_tip_anchor():
    """(height, hash_bytes) DEPTH blocks below the tip."""
    h = max(_agree_tip()) - DEPTH
    return h, dhsign.block_hash_bytes(_agree(f"/block-height/{h}", lambda t: t.lower()))


def _agree_tip():
    tips = []
    for base in EXPLORERS:
        try:
            tips.append(int(_get(base, "/blocks/tip/height")))
        except Exception:
            continue
    if not tips:
        raise BlockDataError("no block explorer answered")
    return tips


def explorer_hash_at(height: int):
    try:
        return dhsign.block_hash_bytes(_agree(f"/block-height/{height}", lambda t: t.lower()))
    except Exception:
        return None


def explorer_merkle_at(height: int):
    """(merkle_root_display_hex, block_time) for an OpenTimestamps check, or None."""
    try:
        bh = _agree(f"/block-height/{height}", lambda t: t.lower())
        return _agree(f"/block/{bh}", lambda t: (json.loads(t)["merkle_root"].lower(), int(json.loads(t)["timestamp"])))
    except Exception:
        return None


# ------------------------------------------------------------ your node ---
def _cli(cli, *args):
    out = subprocess.run(list(cli) + list(args), capture_output=True, text=True, timeout=20)
    if out.returncode != 0:
        raise BlockDataError(out.stderr.strip() or "bitcoin-cli failed")
    return out.stdout.strip()


def node_hash_at(height: int, cli=("bitcoin-cli",)):
    try:
        return dhsign.block_hash_bytes(_cli(cli, "getblockhash", str(height)))
    except Exception:
        return None


def node_merkle_at(height: int, cli=("bitcoin-cli",)):
    try:
        hdr = json.loads(_cli(cli, "getblockheader", _cli(cli, "getblockhash", str(height))))
        return hdr["merkleroot"].lower(), int(hdr["time"])
    except Exception:
        return None


def node_tip_anchor(cli=("bitcoin-cli",)):
    h = int(_cli(cli, "getblockcount")) - DEPTH
    return h, dhsign.block_hash_bytes(_cli(cli, "getblockhash", str(h)))


def parse_anchor_arg(arg: str):
    """'auto' -> two explorers' tip minus DEPTH; 'node' -> your bitcoin-cli's tip minus DEPTH;
    'HEIGHT:HASH' -> that block."""
    if arg == "auto":
        return explorer_tip_anchor()
    if arg == "node":
        return node_tip_anchor()
    h, _, hx = arg.partition(":")
    return int(h), dhsign.block_hash_bytes(hx)

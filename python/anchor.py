"""Block anchors for DigiHan seals (draft v0.4): "made no earlier than Bitcoin block H".

The seal's 5-byte time field holds the block height H and the signed message ends with that block's
hash. Nobody can know a block's hash before the block is mined, so a seal that verifies with it was
made after block H. Get the block from your own node when you can:
    bitcoin-cli getblockcount
    bitcoin-cli getblockhash <height>
or let these helpers ask a public block explorer (mempool.space).
"""
import json, subprocess, urllib.request

import dhsign

EXPLORER = "https://mempool.space/api"
DEPTH = 2          # anchor two blocks below the tip, so a short chain reorganization cannot drop it


def _get(path: str) -> str:
    with urllib.request.urlopen(EXPLORER + path, timeout=15) as r:
        return r.read().decode().strip()


def explorer_tip_anchor():
    """(height, hash_bytes) DEPTH blocks below the explorer's tip."""
    h = int(_get("/blocks/tip/height")) - DEPTH
    return h, dhsign.block_hash_bytes(_get(f"/block-height/{h}"))


def explorer_hash_at(height: int):
    try:
        return dhsign.block_hash_bytes(_get(f"/block-height/{height}"))
    except Exception:
        return None


def node_hash_at(height: int, cli=("bitcoin-cli",)):
    try:
        out = subprocess.run(list(cli) + ["getblockhash", str(height)], capture_output=True, text=True, timeout=20)
        return dhsign.block_hash_bytes(out.stdout) if out.returncode == 0 else None
    except Exception:
        return None


def parse_anchor_arg(arg: str):
    """'auto' -> the explorer's tip minus DEPTH; 'HEIGHT:HASH' -> that block (e.g. from your own node)."""
    if arg == "auto":
        return explorer_tip_anchor()
    h, _, hx = arg.partition(":")
    return int(h), dhsign.block_hash_bytes(hx)

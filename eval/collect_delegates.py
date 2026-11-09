"""Sample real EIP-7702 authorizations from Ethereum mainnet (read-only).

Blocks are drawn uniformly at random, with a fixed seed, from the range between
Pectra activation and a pinned end block, so every number derived from the
output can be regenerated. Writes:

  data/auths_sample.csv      one row per authorization tuple seen in the sample
  data/sample_meta.json      the sampling parameters and how many blocks failed
  data/delegates_code.json   runtime bytecode of the most-authorized delegates
"""
import argparse
import csv
import json
import random
import sys
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from eth_keys import keys
from eth_utils import keccak
import rlp

PECTRA_BLOCK = 22431084  # first mainnet block after the Pectra fork (7 May 2025)
ZERO = "0x" + "00" * 20
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def rpc(url, method, params, tries=6):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(
                url, body, {"content-type": "application/json", "user-agent": "eip7702-study/1.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                out = json.load(resp)
            if "error" in out:
                raise RuntimeError(out["error"])
            return out["result"]
        except Exception as exc:  # public RPCs rate-limit; back off and retry
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{method} failed after {tries} tries: {last}")


def recover_authority(auth):
    """Recover the signer of an authorization tuple, or None if it is invalid."""
    chain_id, nonce = int(auth["chainId"], 16), int(auth["nonce"], 16)
    address = bytes.fromhex(auth["address"][2:])
    msg = keccak(b"\x05" + rlp.encode([chain_id, address, nonce]))
    r, s = int(auth["r"], 16), int(auth["s"], 16)
    y = int(auth.get("yParity", auth.get("v", "0x0")), 16)
    if s > SECP_N // 2 or y > 1 or not (0 < r < SECP_N) or s == 0:
        return None
    try:
        return keys.Signature(vrs=(y, r, s)).recover_public_key_from_msg_hash(msg).to_checksum_address().lower()
    except Exception:
        return None


def scan_block(url, number):
    block = rpc(url, "eth_getBlockByNumber", [hex(number), True])
    rows = []
    for tx in block["transactions"]:
        if tx.get("type") != "0x4":
            continue
        for auth in tx.get("authorizationList") or []:
            authority = recover_authority(auth)
            rows.append(
                {
                    "block": number,
                    "tx": tx["hash"],
                    "delegate": auth["address"].lower(),
                    "chain_id": int(auth["chainId"], 16),
                    "nonce": int(auth["nonce"], 16),
                    "valid_sig": authority is not None,
                    "self_sponsored": authority == tx["from"].lower(),
                    "authority": authority or "",
                }
            )
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", default="https://ethereum-rpc.publicnode.com")
    ap.add_argument("--from-block", type=int, default=PECTRA_BLOCK)
    ap.add_argument("--to-block", type=int, required=True, help="pinned end block")
    ap.add_argument("--samples", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=7702)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--top", type=int, default=40, help="fetch bytecode for this many delegates")
    ap.add_argument("--out", default="data")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    blocks = sorted(random.Random(args.seed).sample(range(args.from_block, args.to_block + 1), args.samples))

    rows, failed = [], []

    def work(n):
        try:
            return n, scan_block(args.rpc, n)
        except Exception as exc:
            return n, exc

    with ThreadPoolExecutor(args.workers) as pool:
        for i, (n, res) in enumerate(pool.map(work, blocks), 1):
            if isinstance(res, Exception):
                failed.append(n)
            else:
                rows.extend(res)
            if i % 100 == 0:
                print(f"{i}/{len(blocks)} blocks, {len(rows)} authorizations, {len(failed)} failed", flush=True)

    with open(out / "auths_sample.csv", "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, ["block", "tx", "delegate", "chain_id", "nonce", "valid_sig", "self_sponsored", "authority"]
        )
        writer.writeheader()
        writer.writerows(rows)

    top = [d for d, _ in Counter(r["delegate"] for r in rows if r["delegate"] != ZERO).most_common(args.top)]
    code = {d: rpc(args.rpc, "eth_getCode", [d, hex(args.to_block)]) for d in top}
    (out / "delegates_code.json").write_text(json.dumps(code, indent=1))

    meta = {
        "rpc": args.rpc,
        "from_block": args.from_block,
        "to_block": args.to_block,
        "samples": args.samples,
        "seed": args.seed,
        "failed_blocks": failed,
        "authorizations": len(rows),
    }
    (out / "sample_meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps({k: v for k, v in meta.items() if k != "failed_blocks"} | {"failed": len(failed)}, indent=1))
    return 1 if len(failed) > args.samples * 0.01 else 0


if __name__ == "__main__":
    sys.exit(main())

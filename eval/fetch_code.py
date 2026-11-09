"""Snapshot the bytecode the evaluation runs on, so it reproduces with no network.

Delegates are ranked by authorization count in data/auths_sample.csv. Ranks 1-40 are the development
set the rules were tuned on. Ranks 41-100 are a holdout, kept out of tuning.

Also records whether each address hard-coded in that bytecode has code on mainnet, which is what
separates a contract the wallet trusts from a single private key.
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scan7702 import evm  # noqa: E402
from scan7702.chain import Chain  # noqa: E402

ZERO = "0x" + "00" * 20
DEV_SIZE, TOTAL = 40, 100


def main():
    meta = json.loads((ROOT / "data" / "sample_meta.json").read_text())
    chain = Chain(meta["rpc"])
    # Deployed code does not change, and public RPCs refuse old-state queries, so read at a recent
    # block and record which one.
    block = chain.rpc("eth_blockNumber")
    with open(ROOT / "data" / "auths_sample.csv") as fh:
        counts = Counter(row["delegate"] for row in csv.DictReader(fh) if row["delegate"] != ZERO)
    ranked = counts.most_common(TOTAL)

    delegates = []
    for rank, (address, count) in enumerate(ranked, 1):
        delegates.append(
            {
                "rank": rank,
                "address": address,
                "authorizations": count,
                "split": "dev" if rank <= DEV_SIZE else "holdout",
                "code": "0x" + chain.code(address, block).hex(),
            }
        )
        print(rank, address, count, (len(delegates[-1]["code"]) - 2) // 2, flush=True)

    addresses = set()
    for item in delegates:
        addresses.update(evm.analyse(bytes.fromhex(item["code"][2:])).hardcoded)
    kinds = {address: bool(chain.code(address, block)) for address in sorted(addresses)}

    (ROOT / "data" / "delegates.json").write_text(json.dumps(delegates, indent=1))
    (ROOT / "data" / "hardcoded_is_contract.json").write_text(json.dumps(kinds, indent=1))
    meta["code_fetched_at_block"] = int(block, 16)
    (ROOT / "data" / "sample_meta.json").write_text(json.dumps(meta, indent=1))
    print(f"{len(delegates)} delegates, {len(kinds)} hard-coded addresses, {sum(kinds.values())} with code")


if __name__ == "__main__":
    main()

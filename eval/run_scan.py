"""Run the delegate scan over the bytecode snapshot in data/delegates.json.

Usage: run_scan.py dev|holdout
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scan7702.chain import LocalChain  # noqa: E402
from scan7702.probe import World, scan  # noqa: E402


def main():
    split = sys.argv[1]
    delegates = [d for d in json.loads((ROOT / "data" / "delegates.json").read_text()) if d["split"] == split]
    kinds = json.loads((ROOT / "data" / "hardcoded_is_contract.json").read_text())
    results = []
    with LocalChain() as chain:
        world = World(chain)
        for item in delegates:
            code = bytes.fromhex(item["code"][2:])
            started = time.time()
            if code:
                result = scan(chain, world, item["address"], code, kinds)
            else:
                result = {"delegate": item["address"], "verdict": "NO_CODE", "size": 0, "selectors": 0,
                          "hardcoded": [], "findings": []}
            result.update(rank=item["rank"], authorizations=item["authorizations"],
                          seconds=round(time.time() - started, 2))
            results.append(result)
            found = sorted({f["finding"] for f in result["findings"]})
            print(f"{item['rank']:>3} {item['address']} {result['verdict']:<10} {result['seconds']:>6}s {found}",
                  flush=True)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / f"scan_{split}.json").write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()

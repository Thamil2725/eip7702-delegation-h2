# H2: EIP-7702 delegation security analysis and tooling

**Work in progress. Not ready to submit.**

See [`docs/H2_REQUIREMENTS.md`](docs/H2_REQUIREMENTS.md) for what the brief requires, what is finished, what is still missing, and how to run what exists.

| Folder | Contents |
|---|---|
| `scan7702/` | The delegate analyser |
| `eval/` | Mainnet sampling and scan scripts |
| `data/` | Sampled authorizations and bytecode snapshots |
| `results/` | Scan output for the development set. The rules were tuned on it, so it is not an accuracy result. |
| `src/mocks/` | Mock tokens the analyser tests with |

Not in this repository: the delegation manager contract and exploit demonstrations, which have not been written yet.

# H2: what is required and what you need to write

Project H2 from `Blockchain_Web3_Project_Ideas_Final.pdf`: **EIP-7702 delegation: security analysis and tooling**. Hybrid, difficulty 2/3.

## 1. What the brief asks for

**What to build.** Tooling that analyses the risk surface EIP-7702 creates, covering three questions, plus a safe delegation manager:

1. What can a malicious or buggy delegate do to an EOA?
2. How does revocation work?
3. How does delegation interact with existing approvals?

**Deliverables.**

- An analysis of the attack surface, with concrete exploit demonstrations **on a testnet**.
- A delegation manager contract, with safety properties **you state and test**.

**Beyond the library.** The brief calls this new territory and says original analysis is valuable. You get no credit for wiring existing tools together without implementing the core mechanism yourself.

**Hybrid means both count.** Implementation is judged on what you built, and research is judged on how rigorous the evaluation is.

**Submission (Part 3 of the PDF).** Four things:

| # | Item | Requirement |
|---|---|---|
| 1 | Repository | Builds and runs from a clean checkout. The README says exactly how to reproduce every number in the report. |
| 2 | Report | Roughly 8 to 12 pages: problem, related work with correct citations, what you built, how you evaluated it, limitations. |
| 3 | Dependency justification | About half a page. For each external dependency: what it does, why it does not hollow out your contribution, and what you implemented instead. |
| 4 | Demonstration | Short. |

**How it is marked.** An honestly measured negative or partial result scores well. An evaluation that cannot support its claims is marked down however much was built, and the PDF names "a detector without a false-positive rate" as an example. The analyser is a detector, so it needs a measured false-positive rate.

**One correction to the brief.** It says an EOA "temporarily" delegates. The final EIP does not work that way: a delegation stays until the account signs a new one. The EIP's own description says it "permanently sets the code". Anything temporary has to be built by you, so say this in your report.

## 2. Where the project stands

| Part | Status |
|---|---|
| Mainnet sample (3,000 blocks, 23,434 authorizations) | Done: `eval/collect_delegates.py`, `data/` |
| Bytecode snapshot of the top 100 delegates | Done: `eval/fetch_code.py`, `data/delegates.json` |
| Delegate scan (question 1) | Working, but not yet evaluated: `scan7702/` |
| Scan of the 40-delegate development set | Done, but the rules were tuned on it: `results/scan_dev.json` |
| Labels and false-positive rate | **Not started** |
| Holdout scan (60 delegates) | **Not run** |
| `account` command (questions 2 and 3) | **Not started** |
| `auth` command (checks a signed authorization) | **Not started** |
| Command-line entry point | **Not started** |
| **Delegation manager contract and its tests** | **Not started: you write this (section 3)** |
| Exploit demonstrations on a testnet | **Not started: needs a funded Sepolia key (section 4)** |
| Report, dependency note, full README with reproduction steps, `requirements.txt`, demo | **Not started** (the current README is only a pointer to this file) |

`data/delegates_code.json` is an older output, replaced by `data/delegates.json`.

## 3. What you need to write: the delegation manager

This is the required contract. These are requirements and questions, not a design, because the design is the part you are marked on.

### 3.1 Write these down first

1. **What "manager" means in your project**, in one paragraph. Who calls it, what can they do, and what does the account owner gain compared with a plain delegate?
2. **Your threat model.** Who is the attacker (a stranger, a relayer, a previous delegate, a phishing site)? What do they control? What is out of scope?
3. **Your safety properties**, as a numbered list, using the template in 3.3.

### 3.2 What your design has to address

Each row comes from the EIP's Security Considerations or from the brief. Your report must say how you handle each one, or why you do not.

| Risk | Where it comes from | Question your design must answer |
|---|---|---|
| Access control | EIP: a poor delegate "can allow a malicious actor to take near complete control over a signer's EOA" | Who can make the account do anything? Can you prove a stranger cannot? |
| Signature pitfalls | EIP lists replay protection, `value`, `gas`, and `target`/`calldata` | If you accept signatures, what exactly is signed? Can one be reused, or used on another chain or account? |
| Front-running setup | EIP: initcode does not run on delegation, and setup calldata must be signed by the EOA's key | Do you need any setup? If so, how can an observer not take it over? |
| Storage collisions | EIP: storage survives a change of delegate, and it suggests ERC-7201 | What happens if a previous delegate left data in your slots? |
| Revocation | EIP: delegating to the zero address clears the code, and clearing storage is "not natively offered" | What is still live after a reset? What happens if the account delegates back to you later? |
| Approvals | Brief, question 3 | Can your contract create an approval that outlives the delegation? What about allowances other people gave this account? |
| Contract signatures | Permit2's `SignatureVerification.sol` calls `isValidSignature` when the signer has code | Once an EOA has code, who can "sign" for it? |
| `tx.origin` assumptions | EIP says this breaks `require(tx.origin == msg.sender)` guards | Does your contract rely on this anywhere? |
| Receiving assets | Many delegates in our scan reject plain ETH or safe ERC-721 transfers | Can the account still receive ETH and NFTs after delegating to you? |
| Limits of any delegate | The EOA key can always sign a new authorization | What can your contract never protect against? Say so plainly. |

### 3.3 Template for each safety property

```
P1. <One sentence that can be false.> Example: "A stranger cannot reduce the account's balance of any asset."
Why it matters: <the attack it stops>
Test: <test name, and whether it is a unit, fuzz or invariant test>
Limit: <when it does not hold>
```

A property you cannot write a failing test for is too vague.

### 3.4 How to test it

- Put the contract in `src/` and the tests in `test/`.
- Install the test library first: `forge install foundry-rs/forge-std` (not installed yet).
- Use all three kinds of test: unit tests for each rule, fuzz tests for random callers and calldata, and invariant tests for totals over long call sequences.
- Write tests for the limits too. A test showing what the contract does *not* protect is worth marks.
- Run the analyser on your own contract with `scan7702.probe.scan`. It should not come back `UNSAFE`, and you should explain anything it does report.
- Measure gas against a plain delegate, and report it.

## 4. Exploit demonstrations

The brief requires these on a testnet. Local runs alone do not meet it.

**Cover the three questions**: at least one malicious delegate case, one buggy delegate case, one revocation case and one approval case.

**For each demonstration, record:**

- which risk it shows and which source describes it
- balances and allowances before and after
- the transaction hashes, so anyone can check them on a block explorer
- whether your manager stops it, and if not, why not

**Ground rules:**

- Use only accounts you created for this, and mock tokens you deployed.
- Use a throwaway Sepolia key with only test ETH. **Never commit a key.** `.env` is already in `.gitignore`.
- Target nothing you do not own.

## 5. The evaluation still to do

1. **Label the delegates before reading the scan's verdicts.** Write the labelling rule down first. Good evidence: verified source code, vendor documentation and published indicator lists. Leave a delegate unlabelled rather than guessing, and report how many you left.
2. **Scan the holdout** with `eval/run_scan.py holdout`, with the rules frozen. Do not change rules after seeing it. If you must, say so and the holdout no longer counts.
3. **Report** precision, recall and false-positive rate with confidence intervals. The set is small, so the intervals will be wide; state them anyway.

**Known problems to resolve first:**

- Ranks 2 and 6 (`0x27dbd0e7…`, `0xc43b6c6a…`, 3,625 authorizations together) came back `NO_FINDING` and nobody knows why. They could be missed sweepers.
- Rating contract callers as `CAUTION` moved 6 delegates down from `UNSAFE`. Ranks 17, 20 and 21 move funds through a function using the `transfer` selector, which looks suspicious. This rule may be hiding real drainers.
- `NO_FINDING` does not mean safe. The scan tries a fixed set of argument shapes.
- Also state that the scan runs bytecode on a local chain, so a delegate that depends on other mainnet contracts may behave differently.

## 6. Report outline (8 to 12 pages)

| Section | Pages | Contents |
|---|---|---|
| Problem | 1 | What EIP-7702 changes, and the three questions |
| Background and related work | 1.5 | EIP mechanics and the sources below |
| Measurement | 1.5 | The mainnet sample, with confidence intervals |
| Attack surface | 2 to 3 | Each risk with its testnet demonstration |
| Analyser | 1.5 | How it works and what it cannot see |
| Delegation manager | 2 | Threat model, properties, design, gas |
| Evaluation | 1.5 | Holdout results and the false-positive rate |
| Limitations | 1 | Be blunt. This section scores well. |

### Numbers measured so far

Uniform random sample of 3,000 blocks, seed 7702, blocks 22,431,084 to 26,377,607, no failed blocks.

| Measure | Value |
|---|---|
| Authorization tuples | 23,434 in 6,612 transactions |
| Distinct signers | 21,298 |
| Distinct delegates | 418, plus the zero address |
| Most-used delegate | `0xe6b97a…43ed`, 4,657 tuples (19.9%) |
| Resets to the zero address | 340 (1.45%) |
| Paid for by the signer | 810 (3.46%) |
| `chain_id = 0` | 4 (0.02%) |

These count tuples included in transactions. Signatures were checked but nonces were not, and tuples with the wrong nonce are skipped on-chain, so they **overstate successful delegations**. Add confidence intervals before quoting them.

The development scan (21 `UNSAFE`, 10 `CAUTION`, 9 `NO_FINDING`) is **not** an accuracy result: the rules were tuned on those 40 delegates and they are not labelled.

### Sources

Checked to exist, with details confirmed from the page or file itself:

- EIP-7702, "Set Code for EOAs", Buterin, Wilson, Dietrichs, lightclient. Status: Final. https://eips.ethereum.org/EIPS/eip-7702
- Qi, Wang, Li, Zhu, Chen. "EIP-7702 Phishing Attack." arXiv:2512.12174, December 2025. https://arxiv.org/abs/2512.12174
- Huang, Liu, Yang, Wu, Wang. "Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem." USENIX Security 2026. https://www.usenix.org/conference/usenixsecurity26/presentation/huang-mingyuan
- Nethermind Research. "EIP-7702 attack surfaces: what developers should know." 8 April 2025. https://nethermind.io/blog/eip-7702-attack-surfaces-what-developers-should-know
- The Block on Wintermute's CrimeEnjoyor analysis, 1 June 2025. https://www.theblock.co/post/356481
- Uniswap Permit2, `SignatureVerification.sol`. https://github.com/Uniswap/permit2/blob/main/src/libraries/SignatureVerification.sol
- "CrimeEnjoyor: Hunting EIP-7702 Sweeper Contracts on Ethereum", by born, 30 June 2026. A blog post, so treat its list as one source. https://blag.nullteilerfrei.de/?p=6189

Read these yourself before citing them:

- "DelegProof: A Machine-Checked Security Analysis of EIP-7702 Delegation." ePrint 2026/2060. Only the title was seen; the PDF could not be opened. https://eprint.iacr.org/2026/2060.pdf
- All of the above: only summaries or abstracts were read, not full papers. Read any paper you cite.

The PDF's own H2 references are the EIP-7702 text and the Pectra specification page.

## 7. Dependency note: starting list

| Dependency | Used for |
|---|---|
| Foundry (`forge`, `anvil`) | Compiling, testing and the local chain |
| `eth-account` | Signing authorizations and type-4 transactions |
| `eth-abi`, `eth-utils` | Encoding calls and hashing |
| `eth-keys`, `rlp` | Recovering signers in the sampler |

`web3` is installed in the venv but the code does not import it directly, so leave it out of `requirements.txt` if the rest still installs without it. Add anything you bring in, such as `forge-std`. The analyser's probing and scoring logic is written for this project; say so in the note.

## 8. Running what exists

From a clean clone on Windows, with Foundry installed to `.tools\foundry` (see https://github.com/foundry-rs/foundry/releases/tag/v1.9.0):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install web3 eth-account
.\.tools\foundry\forge.exe build
.\.venv\Scripts\python.exe eval\run_scan.py dev
```

To regenerate the sample and the snapshot (needs network; the code snapshot will record a newer block):

```powershell
.\.venv\Scripts\python.exe eval\collect_delegates.py --to-block 26377607 --samples 3000 --out data
.\.venv\Scripts\python.exe eval\fetch_code.py
```

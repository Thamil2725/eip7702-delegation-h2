"""Find out what a delegate lets other people do to an account, by trying it on a local chain.

A funded test account delegates to the contract under test. Other addresses then call every function
found in the bytecode, using common argument shapes, and we check whether assets moved. Everything
happens on a throwaway chain, and all the assets are mock tokens.

A positive result is direct evidence, because the assets really moved in the simulation. A negative
result is not a proof of safety: the probe only tries a fixed set of argument shapes.
"""
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

from . import evm
from .chain import calldata

VICTIM_KEY = "0x" + "a1" * 32  # local test keys, never used on a real network
SPONSOR_KEY = "0x" + "a2" * 32
STRANGER = "0x" + "b0" * 20
ALICE = "0x" + "b1" * 20
OLD_SPENDER = "0x" + "b2" * 20
PAYER = "0x" + "b3" * 20

ETH_BALANCE = 10 * 10**18
TOKEN_BALANCE = 1000 * 10**18
INBOUND_ALLOWANCE = 500 * 10**18
NFT_ID = 1
SECOND_NFT_ID = 2
ONE = 10**18
UNKNOWN_SELECTOR = b"\xde\xad\xbe\xef"
ERC1271_MAGIC = bytes.fromhex("1626ba7e")
TOPIC_APPROVAL = keccak(text="Approval(address,address,uint256)").hex()
TOPIC_APPROVAL_ALL = keccak(text="ApprovalForAll(address,address,bool)").hex()

CRITICAL = "CRITICAL"
MEDIUM = "MEDIUM"
LOW = "LOW"
MAX_SELECTORS = 64
MAX_HARDCODED = 5
MAX_SEQUENCE_STARTS = 12
LOW_SLOT_LIMIT = 2**64  # hashed slots (mappings, ERC-7201) are astronomically larger than this


def word(value):
    return (int(value, 16) if isinstance(value, str) else value).to_bytes(32, "big")


def padded(data):
    return data + b"\0" * (-len(data) % 32)


def argument_shapes(token, recipient, balance):
    """Calldata bodies for the signatures that asset-moving functions usually have."""
    move = calldata("transfer(address,uint256)", recipient, balance)
    exec_move = word(0x60) + word(len(move)) + padded(move)
    batch_eth = word(0x20) + word(1) + word(0x20) + word(recipient) + word(ONE) + word(0x60) + word(0)
    batch_token = word(0x20) + word(1) + word(0x20) + word(token) + word(0) + exec_move
    erc7821 = encode(["(address,uint256,bytes)[]"], [[(token, 0, move)]])
    return {
        "()": b"",
        "(recipient)": word(recipient),
        "(token)": word(token),
        "(recipient,amount)": word(recipient) + word(ONE),
        "(token,recipient)": word(token) + word(recipient),
        "(recipient,token)": word(recipient) + word(token),
        "(token,recipient,amount)": word(token) + word(recipient) + word(balance),
        "(target,value,bytes):eth": word(recipient) + word(ONE) + word(0x60) + word(0),
        "(target,value,bytes):token": word(token) + word(0) + exec_move,
        "(target,bytes):token": word(token) + word(0x40) + word(len(move)) + padded(move),
        "(address[])": word(0x20) + word(1) + word(token),
        "(Call[]):eth": batch_eth,
        "(Call[]):token": batch_token,
        "erc7821": word(1 << 248) + word(0x40) + word(len(erc7821)) + padded(erc7821),
    }


class World:
    """One funded account with the kinds of asset and allowance a real account has."""

    def __init__(self, chain):
        self.chain = chain
        self.victim = Account.from_key(VICTIM_KEY).address.lower()
        self.sponsor = Account.from_key(SPONSOR_KEY).address.lower()
        self.token = chain.deploy("Tokens.sol", "MockERC20").lower()
        self.nft = chain.deploy("Tokens.sol", "MockERC721").lower()
        for who in (self.victim, self.sponsor, STRANGER, ALICE, OLD_SPENDER, PAYER):
            chain.set_balance(who, ETH_BALANCE)
        chain.send(PAYER, self.token, calldata("mint(address,uint256)", self.victim, TOKEN_BALANCE))
        chain.send(PAYER, self.token, calldata("mint(address,uint256)", ALICE, INBOUND_ALLOWANCE))
        chain.send(PAYER, self.nft, calldata("mint(address,uint256)", self.victim, NFT_ID))
        chain.send(PAYER, self.nft, calldata("mint(address,uint256)", PAYER, SECOND_NFT_ID))
        # Allowances that exist before delegation: one from the account, one to it.
        chain.send(self.victim, self.token, calldata("approve(address,uint256)", OLD_SPENDER, 100 * ONE))
        chain.send(ALICE, self.token, calldata("approve(address,uint256)", self.victim, INBOUND_ALLOWANCE))

    def assets(self):
        chain = self.chain
        return {
            "eth": chain.balance(self.victim),
            "erc20": chain.read(self.token, "balanceOf(address)", ["uint256"], self.victim),
            "inbound": chain.read(self.token, "balanceOf(address)", ["uint256"], ALICE),
            "nft": chain.read(self.nft, "ownerOf(uint256)", ["address"], NFT_ID),
        }


def asset_changes(before, after, receipt, world):
    """Which findings a successful call produced."""
    found = []
    if after["eth"] < before["eth"]:
        found.append("MOVES_ETH")
    if after["erc20"] < before["erc20"]:
        found.append("MOVES_ERC20")
    if after["inbound"] < before["inbound"]:
        found.append("SPENDS_INBOUND_ALLOWANCE")
    if after["nft"] != before["nft"]:
        found.append("MOVES_NFT")
    victim_topic = "0x" + "00" * 12 + world.victim[2:]
    for log in receipt["logs"]:
        topics = log["topics"]
        if len(topics) < 2 or topics[1] != victim_topic:
            continue
        kind = topics[0].removeprefix("0x")
        amount = int(log["data"], 16) if log["data"] != "0x" else 0
        erc721_approved = len(topics) == 4 and int(topics[2], 16) != 0
        if (kind in (TOPIC_APPROVAL, TOPIC_APPROVAL_ALL) and amount) or (kind == TOPIC_APPROVAL and erc721_approved):
            found.append("SETS_ALLOWANCE")
    return found


def storage_writes(chain, tx_hash):
    """Slots written by the delegate's own frame, read from the execution trace."""
    trace = chain.rpc("debug_traceTransaction", tx_hash, {"disableStorage": True, "disableMemory": True})
    return {
        int(step["stack"][-1], 16)
        for step in trace.get("structLogs", [])
        if step["op"] == "SSTORE" and step["depth"] == 1 and step.get("stack")
    }


def try_all(chain, world, caller, selectors):
    """Call each selector with each argument shape. Leaves chain state as it found it."""
    balance = chain.read(world.token, "balanceOf(address)", ["uint256"], world.victim) or 0
    shapes = argument_shapes(world.token, STRANGER, balance)
    hits, writers, slots = [], {}, set()
    base = chain.snapshot()
    for selector in selectors:
        for shape, body in shapes.items():
            data = selector + body
            if chain.raw_call(world.victim, data, sender=caller) is None:
                continue  # reverted, so a real transaction would change nothing either
            before = world.assets()
            receipt = chain.send(caller, world.victim, data)
            if int(receipt["status"], 16) == 1:
                written = storage_writes(chain, receipt["transactionHash"])
                slots |= written
                changes = asset_changes(before, world.assets(), receipt, world)
                for change in changes:
                    hits.append({"finding": change, "selector": selector.hex(), "shape": shape})
                if written and not changes and selector not in writers:
                    writers[selector] = data
            chain.revert(base)
            base = chain.snapshot()
    return hits, writers, slots


def inbound_checks(chain, world):
    """Does the account still receive assets normally? Leaves chain state as it found it."""
    found = []
    base = chain.snapshot()
    before = chain.balance(world.victim)
    receipt = chain.send(PAYER, world.victim, b"", value=ONE)
    if int(receipt["status"], 16) == 0:
        found.append((LOW, "REJECTS_ETH", "a plain ETH transfer to the account reverts"))
    elif chain.balance(world.victim) < before + ONE:
        found.append((CRITICAL, "FORWARDS_INBOUND_ETH", "ETH sent to the account does not stay in it"))
    chain.revert(base)
    base = chain.snapshot()
    data = calldata("safeTransferFrom(address,address,uint256)", PAYER, world.victim, SECOND_NFT_ID)
    if int(chain.send(PAYER, world.nft, data)["status"], 16) == 0:
        found.append((LOW, "REJECTS_ERC721", "a safe ERC-721 transfer to the account reverts"))
    chain.revert(base)
    return found


def scan(chain, world, delegate, code, hardcoded_is_contract=None):
    """Return findings for one delegate. Leaves chain state as it found it."""
    facts = evm.analyse(code)
    selectors = facts.selectors[:MAX_SELECTORS] + [UNKNOWN_SELECTOR]
    findings = []

    def add(severity, finding, detail):
        findings.append({"severity": severity, "finding": finding, "detail": detail})

    start = chain.snapshot()
    chain.set_code(delegate, code)
    chain.delegate(VICTIM_KEY, delegate, SPONSOR_KEY)

    # 1. Can a stranger move anything in a single call?
    hits, writers, slots = try_all(chain, world, STRANGER, selectors)
    for hit in hits:
        add(CRITICAL, hit["finding"], f"stranger calling 0x{hit['selector']} with {hit['shape']}")

    # 2. Does an open setup call let a stranger move assets on their next call?
    for selector, data in list(writers.items())[:MAX_SEQUENCE_STARTS]:
        base = chain.snapshot()
        chain.send(STRANGER, world.victim, data)
        second, _, _ = try_all(chain, world, STRANGER, selectors)
        for hit in second:
            add(CRITICAL, "TAKEOVER_SEQUENCE",
                f"stranger calls 0x{selector.hex()}, then 0x{hit['selector']} with {hit['shape']}: {hit['finding']}")
        for severity, finding, detail in inbound_checks(chain, world):
            if finding == "FORWARDS_INBOUND_ETH":
                add(CRITICAL, "TAKEOVER_SEQUENCE", f"stranger calls 0x{selector.hex()}, then: {detail}")
        chain.revert(base)

    # 3. Can an address baked into the bytecode move assets? Wallet infrastructure is excluded.
    #    One private key that can drain every delegated account is a different risk from a wallet
    #    trusting its own contract, so the two are rated apart. An address whose kind is unknown
    #    is treated as a key, which is the cautious assumption.
    hardcoded = [a for a in facts.hardcoded if a != delegate.lower()]
    for address in hardcoded[:MAX_HARDCODED]:
        chain.set_balance(address, ETH_BALANCE)
        hits, _, _ = try_all(chain, world, address, selectors)
        for hit in hits:
            detail = f"{address} calling 0x{hit['selector']} with {hit['shape']}: {hit['finding']}"
            if (hardcoded_is_contract or {}).get(address):
                add(MEDIUM, "TRUSTED_CONTRACT_MOVES_ASSETS", detail)
            else:
                add(CRITICAL, "OPERATOR_KEY_MOVES_ASSETS", detail)

    # 4. Which storage slots does the account's own use of this delegate write?
    _, _, own_slots = try_all(chain, world, world.victim, selectors)
    low = sorted(slot for slot in slots | own_slots if slot < LOW_SLOT_LIMIT)
    if low:
        add(MEDIUM, "LOW_SLOT_WRITES", f"writes low slots {low[:8]}, which collide with other delegates")

    # 5. Does it accept any signature on the account's behalf?
    query = calldata("isValidSignature(bytes32,bytes)", b"\x11" * 32, b"\x22" * 65)
    reply = chain.raw_call(world.victim, query, sender=STRANGER)
    if reply is not None and reply[:4] == ERC1271_MAGIC:
        add(CRITICAL, "FORGEABLE_1271", "isValidSignature accepts a junk signature")

    # 6. Does the account still receive assets?
    for severity, finding, detail in inbound_checks(chain, world):
        add(severity, finding, detail)

    # 7. Static hints: these matter, but plenty of honest wallets have them too.
    for op in ("DELEGATECALL", "CALLCODE", "SELFDESTRUCT"):
        if op in facts.opcodes:
            add(MEDIUM, f"HAS_{op}", f"{op} appears in the bytecode")

    chain.revert(start)

    worst = {f["severity"] for f in findings}
    verdict = "UNSAFE" if CRITICAL in worst else "CAUTION" if MEDIUM in worst else "NO_FINDING"
    unique = list({(f["severity"], f["finding"], f["detail"]): f for f in findings}.values())
    return {
        "delegate": delegate,
        "verdict": verdict,
        "size": facts.size,
        "selectors": len(facts.selectors),
        "hardcoded": facts.hardcoded,
        "findings": unique,
    }

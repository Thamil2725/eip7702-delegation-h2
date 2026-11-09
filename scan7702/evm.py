"""Static facts read from runtime bytecode. These are hints: the dynamic probe decides severity."""
from dataclasses import dataclass, field

OP_NAMES = {0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL", 0xFF: "SELFDESTRUCT", 0xF0: "CREATE",
            0xF5: "CREATE2", 0x55: "SSTORE", 0x33: "CALLER", 0x32: "ORIGIN"}
EQ, XOR, SUB, JUMPI = 0x14, 0x18, 0x03, 0x57
PUSH0, PUSH1, PUSH4, PUSH20, PUSH32 = 0x5F, 0x60, 0x63, 0x73, 0x7F

# Well-known contracts that wallets legitimately trust. Confirmed to have code on mainnet.
KNOWN_INFRA = {
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",  # ERC-4337 EntryPoint v0.6
    "0x0000000071727de22e5e9d8baf0edac6f37da032",  # ERC-4337 EntryPoint v0.7
    "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",  # ERC-4337 EntryPoint v0.8
    "0x433709009b8330fda32311df1c2afa402ed8d009",  # ERC-4337 EntryPoint v0.9
    "0x000000000022d473030f116ddee9f6b43ac78ba3",  # Permit2
}


@dataclass
class StaticFacts:
    size: int = 0
    selectors: list = field(default_factory=list)
    opcodes: set = field(default_factory=set)
    hardcoded: list = field(default_factory=list)


def strip_metadata(code):
    """Remove the trailing CBOR metadata solc appends, so its bytes are not read as opcodes."""
    if len(code) > 2:
        length = int.from_bytes(code[-2:], "big")
        if 0 < length < len(code) - 2 and code[-2 - length] in (0xA1, 0xA2, 0xA3, 0xA4):
            return code[: -2 - length]
    return code


def disassemble(code):
    """Linear sweep yielding (opcode, push data)."""
    i = 0
    while i < len(code):
        op = code[i]
        size = op - PUSH1 + 1 if PUSH1 <= op <= PUSH32 else 0
        yield op, code[i + 1 : i + 1 + size]
        i += 1 + size


def analyse(code):
    facts = StaticFacts(size=len(code))
    ops = list(disassemble(strip_metadata(code)))
    selectors, hardcoded = [], []
    for i, (op, data) in enumerate(ops):
        if op in OP_NAMES:
            facts.opcodes.add(OP_NAMES[op])
        if op == PUSH4 and len(data) == 4:
            # Dispatcher shape: PUSH4 <sel> then EQ/XOR/SUB, with a JUMPI within the next few opcodes.
            following = [o for o, _ in ops[i + 1 : i + 6]]
            if following[:2] and any(o in (EQ, XOR, SUB) for o in following[:2]) and JUMPI in following:
                selectors.append(data)
        # An address appears as PUSH20, or as PUSH32 with a zero top when it is a solc immutable.
        value = None
        if op == PUSH20 and len(data) == 20:
            value = data
        elif op == PUSH32 and len(data) == 32 and data[:12] == b"\0" * 12:
            value = data[12:]
        if value and int.from_bytes(value, "big") >= 2**120 and value != b"\xff" * 20:
            hardcoded.append("0x" + value.hex())
    facts.selectors = list(dict.fromkeys(selectors))
    facts.hardcoded = [a for a in dict.fromkeys(hardcoded) if a not in KNOWN_INFRA and not looks_like_text(a)]
    return facts


def looks_like_text(address):
    """PUSH20 also carries revert strings such as 'mint to zero address'."""
    return all(0x20 <= byte < 0x7F for byte in bytes.fromhex(address[2:]))

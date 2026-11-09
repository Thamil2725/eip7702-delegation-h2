"""A small JSON-RPC client and a throwaway local chain. Nothing here needs a funded key."""
import http.client
import json
import shutil
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path

from eth_abi import decode, encode
from eth_account import Account
from eth_utils import keccak

ROOT = Path(__file__).resolve().parent.parent
GAS = 3_000_000


class RpcError(Exception):
    pass


def split_types(signature):
    """'f(address,(uint256,bytes)[])' -> ['address', '(uint256,bytes)[]']"""
    inner = signature[signature.index("(") + 1 : signature.rindex(")")]
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += (ch == "(") - (ch == ")")
        cur += ch
    return out + [cur] if cur else out


def calldata(signature, *args):
    return keccak(text=signature)[:4] + encode(split_types(signature), list(args))


class Rpc:
    """JSON-RPC over one kept-alive connection, which is much faster than reconnecting."""

    def __init__(self, url):
        self.url = urllib.parse.urlparse(url)
        self.conn = None

    def _connect(self):
        cls = http.client.HTTPSConnection if self.url.scheme == "https" else http.client.HTTPConnection
        self.conn = cls(self.url.netloc, timeout=120)

    def __call__(self, method, *params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)})
        headers = {"content-type": "application/json", "user-agent": "scan7702/1.0"}
        for attempt in range(3):
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request("POST", self.url.path or "/", body, headers)
                out = json.loads(self.conn.getresponse().read())
                break
            except (OSError, http.client.HTTPException, json.JSONDecodeError):
                self.conn = None
                if attempt == 2:
                    raise
                time.sleep(0.5 * (attempt + 1))
        if "error" in out:
            raise RpcError(out["error"].get("message", str(out["error"])))
        return out["result"]


class Chain:
    def __init__(self, url):
        self.rpc = Rpc(url)

    def code(self, address, block="latest"):
        return bytes.fromhex(self.rpc("eth_getCode", address, block)[2:])

    def balance(self, address):
        return int(self.rpc("eth_getBalance", address, "latest"), 16)

    def nonce(self, address):
        return int(self.rpc("eth_getTransactionCount", address, "latest"), 16)

    def chain_id(self):
        return int(self.rpc("eth_chainId"), 16)

    def receipt(self, tx_hash, timeout=300):
        """Wait for a transaction to be mined and return its receipt."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = self.rpc("eth_getTransactionReceipt", tx_hash)
            if found:
                return found
            time.sleep(0.002)
        raise TimeoutError(f"no receipt for {tx_hash} after {timeout}s")

    def raw_call(self, to, data, sender=None):
        """eth_call; returns bytes, or None if the call reverted."""
        tx = {"to": to, "data": "0x" + bytes(data).hex(), "gas": hex(GAS)}
        if sender:
            tx["from"] = sender
        try:
            return bytes.fromhex(self.rpc("eth_call", tx, "latest")[2:])
        except RpcError:
            return None

    def read(self, to, signature, returns, *args):
        out = self.raw_call(to, calldata(signature, *args))
        if out is None or len(out) < 32 * len(returns):
            return None
        return decode(returns, out)[0]


class LocalChain(Chain):
    """An anvil process on a free port, with gas priced at zero and any sender usable."""

    def __init__(self):
        self.proc = None
        self.rpc = None

    def __enter__(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        local = ROOT / ".tools" / "foundry" / "anvil.exe"
        binary = str(local) if local.exists() else shutil.which("anvil")
        if not binary:
            raise SystemExit("anvil not found: install Foundry (see README)")
        self.proc = subprocess.Popen(
            [binary, "--port", str(port), "--hardfork", "prague", "--silent", "--auto-impersonate",
             "--base-fee", "0", "--gas-price", "0", "--gas-limit", "60000000", "--steps-tracing"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        super().__init__(f"http://127.0.0.1:{port}")
        for _ in range(100):
            try:
                self.rpc("eth_chainId")
                return self
            except OSError:
                time.sleep(0.1)
        self.proc.kill()
        raise SystemExit("anvil did not start")

    def __exit__(self, *exc):
        self.proc.kill()
        self.proc.wait()

    def snapshot(self):
        return self.rpc("evm_snapshot")

    def revert(self, snapshot_id):
        self.rpc("evm_revert", snapshot_id)

    def set_code(self, address, code):
        self.rpc("anvil_setCode", address, "0x" + bytes(code).hex())

    def set_balance(self, address, wei):
        self.rpc("anvil_setBalance", address, hex(wei))

    def send(self, sender, to, data=b"", value=0):
        """Send as any address. Returns the receipt, whether the transaction succeeded or not."""
        tx = {"from": sender, "to": to, "data": "0x" + bytes(data).hex(), "value": hex(value), "gas": hex(GAS)}
        return self.receipt(self.rpc("eth_sendTransaction", tx))

    def deploy(self, source, name):
        artifact = json.loads((ROOT / "out" / source / f"{name}.json").read_text())
        sender = "0x" + "de" * 20
        self.set_balance(sender, 10**20)
        tx = {"from": sender, "data": artifact["bytecode"]["object"], "gas": hex(GAS * 5)}
        return self.receipt(self.rpc("eth_sendTransaction", tx))["contractAddress"]

    def delegate(self, key, delegate_to, sponsor_key):
        """Set an account's code with a real type-4 transaction paid for by a sponsor."""
        account, sponsor = Account.from_key(key), Account.from_key(sponsor_key)
        auth = account.sign_authorization(
            {"chainId": self.chain_id(), "address": delegate_to, "nonce": self.nonce(account.address)}
        )
        signed = sponsor.sign_transaction(
            {"type": 4, "chainId": self.chain_id(), "nonce": self.nonce(sponsor.address), "to": sponsor.address,
             "value": 0, "data": b"", "gas": 200_000, "maxFeePerGas": 1, "maxPriorityFeePerGas": 0,
             "accessList": [], "authorizationList": [auth]}
        )
        return self.receipt(self.rpc("eth_sendRawTransaction", "0x" + signed.raw_transaction.hex()))

"""Merkle-batched anchoring. No fake transaction hashes are ever produced."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional, Sequence


class AnchorError(Exception):
    pass


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        raise AnchorError("cannot anchor an empty batch")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: Sequence[bytes], index: int) -> list[tuple[str, bytes]]:
    if not 0 <= index < len(leaves):
        raise AnchorError("index out of range")
    path: list[tuple[str, bytes]] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = idx ^ 1
        path.append(("right" if sibling > idx else "left", level[sibling]))
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return path


def verify_proof(leaf: bytes, path: Sequence[tuple[str, bytes]], root: bytes) -> bool:
    node = leaf
    for side, sibling in path:
        node = _hash_pair(sibling, node) if side == "left" else _hash_pair(node, sibling)
    return node == root


@dataclass
class AnchorResult:
    merkle_root: bytes
    leaf_count: int
    tx_hash: Optional[str]
    confirmed: bool
    note: str


class PolygonAnchor:
    def __init__(self, *, rpc_url: str, contract_address: str, private_key: str):
        if not (rpc_url and contract_address and private_key):
            raise AnchorError(
                "anchoring requires POLYGON_RPC_URL, ANCHOR_CONTRACT_ADDRESS and "
                "ANCHOR_PRIVATE_KEY. Refusing to fabricate a transaction hash."
            )
        try:
            from web3 import Web3
        except ImportError as exc:
            raise AnchorError("web3 is not installed; install requirements-blockchain.txt") from exc

        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self._w3.is_connected():
            raise AnchorError("cannot reach configured Polygon RPC")
        self._key = private_key
        self._abi = [
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "root", "type": "bytes32"},
                    {"internalType": "uint64", "name": "leafCount", "type": "uint64"},
                ],
                "name": "anchorRoot",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}],
                "name": "isAnchored",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function",
            },
        ]
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(contract_address), abi=self._abi
        )

    def anchor(self, leaves: Sequence[bytes]) -> AnchorResult:
        root = merkle_root(leaves)
        account = self._w3.eth.account.from_key(self._key)
        tx = self._contract.functions.anchorRoot(root, len(leaves)).build_transaction(
            {
                "from": account.address,
                "nonce": self._w3.eth.get_transaction_count(account.address),
                "gas": 140_000,
                "maxFeePerGas": self._w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": self._w3.to_wei(30, "gwei"),
                "chainId": self._w3.eth.chain_id,
            }
        )
        signed = self._w3.eth.account.sign_transaction(tx, private_key=self._key)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        tx_hash = self._w3.eth.send_raw_transaction(raw)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        if receipt["status"] != 1:
            raise AnchorError(f"anchoring transaction reverted: {tx_hash.hex()}")
        return AnchorResult(
            merkle_root=root,
            leaf_count=len(leaves),
            tx_hash=self._w3.to_hex(tx_hash),
            confirmed=True,
            note=f"{len(leaves)} messages anchored under one root",
        )

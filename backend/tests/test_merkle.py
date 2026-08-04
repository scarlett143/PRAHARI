import pytest

from app.blockchain.anchor import AnchorError, PolygonAnchor, leaf_hash, merkle_proof, merkle_root, verify_proof


def test_merkle_root_and_inclusion_proofs():
    leaves = [leaf_hash(f"message-{index}".encode()) for index in range(11)]
    root = merkle_root(leaves)
    assert root != merkle_root(list(reversed(leaves)))
    for index, leaf in enumerate(leaves):
        assert verify_proof(leaf, merkle_proof(leaves, index), root)
    assert not verify_proof(leaf_hash(b"forged"), merkle_proof(leaves, 2), root)


def test_anchor_refuses_fake_transaction_hashes():
    with pytest.raises(AnchorError, match="Refusing to fabricate"):
        PolygonAnchor(rpc_url="", contract_address="", private_key="")

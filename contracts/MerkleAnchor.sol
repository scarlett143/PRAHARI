// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MerkleAnchor {
    error NotAuthorized();
    error AlreadyAnchored();
    error ZeroRoot();

    event RootAnchored(bytes32 indexed root, address indexed submitter, uint64 leafCount, uint256 timestamp);
    event AnchorerUpdated(address indexed account, bool allowed);

    address public immutable owner;
    mapping(address => bool) public anchorers;
    mapping(bytes32 => uint256) public anchoredAt;

    constructor() {
        owner = msg.sender;
        anchorers[msg.sender] = true;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    function setAnchorer(address account, bool allowed) external onlyOwner {
        anchorers[account] = allowed;
        emit AnchorerUpdated(account, allowed);
    }

    function anchorRoot(bytes32 root, uint64 leafCount) external {
        if (!anchorers[msg.sender]) revert NotAuthorized();
        if (root == bytes32(0)) revert ZeroRoot();
        if (anchoredAt[root] != 0) revert AlreadyAnchored();
        anchoredAt[root] = block.timestamp;
        emit RootAnchored(root, msg.sender, leafCount, block.timestamp);
    }

    function isAnchored(bytes32 root) external view returns (bool) {
        return anchoredAt[root] != 0;
    }

    function verifyInclusion(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        bool[] calldata isLeftSibling
    ) external view returns (bool) {
        if (anchoredAt[root] == 0) return false;
        if (proof.length != isLeftSibling.length) return false;
        bytes32 node = leaf;
        for (uint256 i = 0; i < proof.length; ++i) {
            node = isLeftSibling[i]
                ? sha256(abi.encodePacked(bytes1(0x01), proof[i], node))
                : sha256(abi.encodePacked(bytes1(0x01), node, proof[i]));
        }
        return node == root;
    }
}

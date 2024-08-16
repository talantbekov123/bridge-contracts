// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract ERC20MintBurnWithHashVerification is ERC20 {
    using ECDSA for bytes32;

    address private signer; // Address of the trusted signer

    event Mint(address indexed account, uint256 amount);
    event Burn(address indexed account, uint256 amount);

    constructor(address initialAccount, uint256 initialBalance, address _signer) ERC20("MockToken", "MTK") {
        signer = _signer;
        _mint(initialAccount, initialBalance);
    }

    // Only allows minting if the provided hash and signature are valid
    function mint(address account, uint256 amount, bytes32 hash, bytes memory signature) public {
        require(verify(hash, signature), "Invalid signature");
        require(hash == generateHash(msg.sender, amount), "Hash mismatch");

        _mint(account, amount);
        emit Mint(account, amount);
    }

    // Only allows burning if the provided hash and signature are valid
    function burn(address account, uint256 amount, bytes32 hash, bytes memory signature) public {
        require(verify(hash, signature), "Invalid signature");
        require(hash == generateHash(msg.sender, amount), "Hash mismatch");

        _burn(account, amount);
        emit Burn(account, amount);
    }

    // Generates a hash for the mint/burn operation
    function generateHash(address sender, uint256 amount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, amount));
    }

    // Verifies that the hash was signed by the trusted signer
    function verify(bytes32 hash, bytes memory signature) internal view returns (bool) {
        bytes32 signedMessageHash = MessageHashUtils.toEthSignedMessageHash(hash);
        return signedMessageHash.recover(signature) == signer;
    }

    // Function to update the signer, in case the signer key is rotated
    function updateSigner(address newSigner) external {
        // Implement access control here (e.g., onlyOwner)
        signer = newSigner;
    }
}

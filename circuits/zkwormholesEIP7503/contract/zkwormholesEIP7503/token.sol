// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.26;

import "./plonk_vk.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

interface IVerifier {
    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool);
}

contract Token is ERC20, Ownable, ERC20Permit {
    constructor(address initialOwner)
        ERC20("token", "tkn")
        Ownable(initialOwner)
        ERC20Permit("token")
    {}

    // WARNING anyone can mint
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function reMint(address to, uint256 amount, uint256 blockNum ) public {
        //TODO nullifier WARNING anyone can double spend

        bytes32 blkhash = blockhash(blockNum);
        bytes32[] memory publicInputs = [bytes32(to), bytes32(amount), blkhash];
        if (!IVerifier(verifier).verify(snarkProof, publicInputs)) {
            revert VerificationFailed();
        }

        _mint(to, amount);

    }
}
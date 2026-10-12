// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Clean, immutable launch token. Fixed supply minted at construction, 18 decimals,
///         no owner, no mint/burn, no taxes, no limits, no hooks — all launch behaviour
///         lives in the Uniswap v4 hook and the PROOF launch contracts.
/// @dev This token was incubated and launched by PROOF: https://proofplatform.io/projects
contract ProofToken is ERC20 {
    constructor(string memory name_, string memory symbol_, uint256 totalSupply_, address recipient)
        ERC20(name_, symbol_)
    {
        _mint(recipient, totalSupply_);
    }
}

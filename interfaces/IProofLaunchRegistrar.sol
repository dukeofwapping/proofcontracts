// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";

/// @notice Implemented by the PROOF singletons (hook, vault, splitter) that need to learn
///         about a new launch at creation time. Called only by the ProofLaunchManager.
/// @dev `data` is an ABI-encoded, implementation-specific launch config; each registrar
///      defines and validates its own layout (typed structs arrive with Phases 2-4).
interface IProofLaunchRegistrar {
    function registerLaunch(PoolKey calldata key, bytes calldata data) external;
}

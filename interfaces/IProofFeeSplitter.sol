// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";

/// @notice Earn-time fee accounting sink. The hook credits the tax to the splitter as
///         ERC-6909 claim tokens on the PoolManager (physical ETH may not exist yet during
///         the swap callbacks) and reports the amount here in the same callback; only the
///         hook may record. The splitter redeems claims for real ETH at payout time.
interface IProofFeeSplitter {
    /// @notice Report `amount` of tax ETH (as claims) earned by `poolId` right now.
    function record(PoolId poolId, uint256 amount) external;

    /// @notice Called once by the hook when the launch's public trading opens — anchors
    ///         the split schedule's period boundaries at that timestamp.
    function onPublicOpened(PoolId poolId) external;
}

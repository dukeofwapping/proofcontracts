// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice The launch manager's transient (EIP-1153) liquidity authorization, read by the
///         hook in `beforeAddLiquidity`.
///
/// Uniswap v4 liquidity operations are permissionless, and an unhooked liquidity path
/// defeats a tax hook completely: a holder can place tokens as a narrow range order just
/// below spot, let an ordinary buyer fill it, withdraw the ETH, and pay NO sell tax; the
/// mirror-image trick buys tokens with no buy tax and no max-wallet accounting. Launch
/// pools therefore accept liquidity ONLY from the manager's own authorized mint, marked by
/// this transient lock (the same pattern as the vault's swap lock).
interface IProofLiquidityLock {
    /// @return poolId the pool the manager is currently minting into (0 when idle)
    function liquidityLock() external view returns (bytes32 poolId);
}

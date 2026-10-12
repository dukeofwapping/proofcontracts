// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice The vault's transient (EIP-1153) execution lock, read by the hook during the
///         EXECUTION phase as the third authentication layer (Implementation Plan §5.2).
///         The lock is set immediately before the vault's own PoolManager swap and cleared
///         right after settlement; it can never be live during a foreign swap.
interface IProofVaultLock {
    /// @return poolId  PoolId the vault is currently swapping on (bytes32(0) when idle)
    /// @return mode    0 = idle, 1 = EXECUTOR (tax-exempt), 2 = PASS (taxed)
    /// @return amountOut exact token output the current swap was authorized for
    function executionLock() external view returns (bytes32 poolId, uint8 mode, uint256 amountOut);
}

uint8 constant LOCK_MODE_NONE = 0;
uint8 constant LOCK_MODE_EXECUTOR = 1;
uint8 constant LOCK_MODE_PASS = 2;

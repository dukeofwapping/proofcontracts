// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Pricing/tick math for PROOF v4 launches (Implementation Plan §5.3).
///
/// Coordinate system: pools are native-ETH pools, so ETH (address(0)) is always currency0
/// and the launch token currency1. The v4 price is TOKEN per ETH (token1/token0). Buys
/// (ETH -> TOKEN) are zeroForOne and move the tick DOWN. The V2-mimicking token-only
/// position therefore spans [minAlignedTick, startingTick], with the pool initialized
/// exactly at the aligned starting tick so mints require zero ETH and liquidity is live
/// from the first buy.
///
/// Both ETH and ProofToken have 18 decimals, so raw-unit ratios equal human ratios and no
/// decimal adjustment is required anywhere in this library.
library LaunchMath {
    error InvalidVirtualEth();
    error TickNotAligned(int24 tick, int24 spacing);

    /// @notice sqrtPriceX96 for the V2-equivalent starting price P0 = lpTokens / virtualEth
    ///         (TOKEN per ETH). sqrt(P0) * 2^96 computed as sqrt(P0 * 2^96) * 2^48 to stay
    ///         within 256 bits for any realistic supply.
    function startingSqrtPriceX96(uint256 lpTokens, uint256 virtualEth) internal pure returns (uint160) {
        if (virtualEth == 0) revert InvalidVirtualEth();
        uint256 ratioX96 = FullMath.mulDiv(lpTokens, 1 << 96, virtualEth);
        uint256 sqrtX48 = Math.sqrt(ratioX96); // floor(sqrt(P0) * 2^48)
        return uint160(sqrtX48 << 48);
    }

    /// @notice Round a tick to the NEAREST multiple of `spacing`, clamped to the usable range.
    function alignToSpacing(int24 tick, int24 spacing) internal pure returns (int24 aligned) {
        int24 floorAligned = _floorDiv(tick, spacing) * spacing;
        aligned = (tick - floorAligned) * 2 >= spacing ? floorAligned + spacing : floorAligned;
        int24 minUsable = minAlignedTick(spacing);
        int24 maxUsable = maxAlignedTick(spacing);
        if (aligned < minUsable) aligned = minUsable;
        if (aligned > maxUsable) aligned = maxUsable;
    }

    /// @notice Smallest usable tick that is a multiple of `spacing` (>= TickMath.MIN_TICK).
    function minAlignedTick(int24 spacing) internal pure returns (int24) {
        // MIN_TICK is negative; integer division truncates toward zero, which rounds UP for
        // negatives — exactly the ceil we need to stay inside the usable range.
        return (TickMath.MIN_TICK / spacing) * spacing;
    }

    /// @notice Largest usable tick that is a multiple of `spacing` (<= TickMath.MAX_TICK).
    function maxAlignedTick(int24 spacing) internal pure returns (int24) {
        return (TickMath.MAX_TICK / spacing) * spacing;
    }

    function requireAligned(int24 tick, int24 spacing) internal pure {
        if (tick % spacing != 0) revert TickNotAligned(tick, spacing);
    }

    /// @notice Market cap, in wei of ETH, of `totalSupply` tokens at the price of `tick`.
    /// @dev mcap = supply / price, price = (sqrtP / 2^96)^2 TOKEN per ETH — computed as two
    ///      sequential mulDivs to avoid overflowing sqrtP^2.
    function mcapAtTick(uint256 totalSupply, int24 tick) internal pure returns (uint256) {
        uint160 sqrtP = TickMath.getSqrtPriceAtTick(tick);
        return FullMath.mulDiv(FullMath.mulDiv(totalSupply, 1 << 96, sqrtP), 1 << 96, sqrtP);
    }

    /// @notice Liquidity for a token-only (token1-only) range holding `tokenAmount`,
    ///         mirroring v4-periphery LiquidityAmounts.getLiquidityForAmount1.
    /// @dev amount1 = L * (sqrtPb - sqrtPa) / 2^96  =>  L = amount1 * 2^96 / (sqrtPb - sqrtPa)
    function liquidityForTokenAmount(int24 tickLower, int24 tickUpper, uint256 tokenAmount)
        internal
        pure
        returns (uint128)
    {
        uint160 sqrtPa = TickMath.getSqrtPriceAtTick(tickLower);
        uint160 sqrtPb = TickMath.getSqrtPriceAtTick(tickUpper);
        return uint128(FullMath.mulDiv(tokenAmount, 1 << 96, sqrtPb - sqrtPa));
    }

    function _floorDiv(int24 a, int24 b) private pure returns (int24) {
        int24 q = a / b;
        if (a % b != 0 && (a < 0) != (b < 0)) q--;
        return q;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {IPositionManager} from "@uniswap/v4-periphery/src/interfaces/IPositionManager.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";
import {IAllowanceTransfer} from "permit2/src/interfaces/IAllowanceTransfer.sol";

import {ProofToken} from "./ProofToken.sol";
import {LaunchMath} from "./libraries/LaunchMath.sol";
import {IProofLaunchRegistrar} from "./interfaces/IProofLaunchRegistrar.sol";
import {IProofLiquidityLock} from "./interfaces/IProofLiquidityLock.sol";

/// @notice PROOF launch orchestrator (one per chain). `createLaunch` deploys a clean
///         ERC20, holds out the team allocation, initializes a native-ETH v4 pool at the
///         V2-equivalent starting price, and mints 1-3 token-only liquidity ranges whose
///         position NFTs go straight to the PROOF admin (the owner of this contract).
///
/// Zero ETH is seeded: every range sits at or below the starting tick (token1-only), the
/// pool is initialized exactly at the aligned starting tick, and every mint is executed
/// with amount0Max = 0 so any ETH requirement reverts the launch.
contract ProofLaunchManager is Ownable2Step, IProofLiquidityLock {
    // ---------------------------------------------------------------- types

    /// @dev Sentinels: tickLower == type(int24).min => min aligned tick;
    ///      tickUpper == type(int24).max => the computed starting tick.
    struct RangeParams {
        int24 tickLower;
        int24 tickUpper;
        uint16 shareBps; // share of the LP token allocation in this range
    }

    struct CreateParams {
        string name;
        string symbol;
        uint256 totalSupply; // raw (18 decimals)
        uint16 lpBps; // share of supply to LP, e.g. 6500
        uint256 virtualEth; // V2-equivalent virtual ETH reserve, e.g. 4 ether
        uint24 lpFee; // pool LP fee, e.g. 3000 = 0.30%
        int24 tickSpacing; // e.g. 60
        IHooks hooks; // ProofLaunchHook (address(0) allowed for hookless test pools)
        RangeParams[] ranges; // empty => single default range [min, startingTick] @ 100%
        bytes hookData; // opaque launch config forwarded to the hook registrar
        bytes32 tokenSalt; // CREATE2 salt for the token address (see `createLaunch`)
    }

    struct LaunchInfo {
        address token;
        PoolKey key;
        int24 startingTick;
        uint256 lpTokens;
        uint64 createdAt;
    }

    // ---------------------------------------------------------------- state

    IPoolManager public immutable poolManager;
    IPositionManager public immutable positionManager;
    IAllowanceTransfer public immutable permit2;

    /// @notice Receives the team allocation and mint dust (updatable by PROOF).
    address public proofWallet;

    mapping(PoolId => LaunchInfo) internal _launches;
    address[] public allTokens;

    /// @notice Pool of the launch that deployed `token` (zero for unknown tokens). The public
    ///         webapp resolves a launch page from a token address alone with this one call;
    ///         every other read (vault, hook, `launchOf`) is keyed by the pool id it returns.
    mapping(address => PoolId) public poolIdOf;

    /// @dev Transient slot marking "this manager is minting the launch ranges right now",
    ///      read by the hook to authorize the only liquidity adds a launch pool accepts.
    uint256 private constant LIQ_LOCK_SLOT = 0x50524f4f465f4c49515f4c4f434b; // "PROOF_LIQ_LOCK"

    /// @inheritdoc IProofLiquidityLock
    function liquidityLock() external view returns (bytes32 poolId) {
        assembly {
            poolId := tload(LIQ_LOCK_SLOT)
        }
    }

    // ---------------------------------------------------------------- errors/events

    error ZeroAddress();
    error InvalidBps();
    error SharesMustSum(uint256 got);
    error RangeOutOfOrder();
    error RangeAboveStartingTick();
    error TooManyRanges();
    error PoolAlreadyInitialized(PoolId poolId, address token);
    error RangeGapAtStart();
    error SupplyTooLarge();

    event LaunchCreated(
        PoolId indexed poolId, address indexed token, int24 startingTick, uint256 lpTokens, uint256 teamTokens
    );

    constructor(
        IPoolManager poolManager_,
        IPositionManager positionManager_,
        IAllowanceTransfer permit2_,
        address proofWallet_,
        address admin
    ) Ownable(admin) {
        if (proofWallet_ == address(0)) revert ZeroAddress();
        poolManager = poolManager_;
        positionManager = positionManager_;
        permit2 = permit2_;
        proofWallet = proofWallet_;
    }

    // ---------------------------------------------------------------- admin

    function setProofWallet(address wallet) external onlyOwner {
        if (wallet == address(0)) revert ZeroAddress();
        proofWallet = wallet;
    }

    /// @notice Deploy token + pool + ranges for a new launch. See contract natspec.
    /// @dev The token is deployed with CREATE2 under `p.tokenSalt`. v4 pools are
    ///      permissionless to initialize, so a mempool watcher can pre-empt a launch by
    ///      initializing the pool key of a predictable token address; with plain CREATE a
    ///      reverted attempt rolls the nonce back and the retry would hit the same blocked
    ///      address forever. A salt gives operations an unbounded, cheap escape: on
    ///      `PoolAlreadyInitialized`, bump the salt and resubmit. (It also enables vanity
    ///      token addresses.) Prefer a private mempool for this call where one exists.
    function createLaunch(CreateParams calldata p) external onlyOwner returns (address token, PoolId poolId) {
        if (p.lpBps == 0 || p.lpBps > 10_000) revert InvalidBps();
        if (p.totalSupply > type(uint96).max) revert SupplyTooLarge();

        // 1. Token: full supply to this contract, team share straight out to the PROOF wallet.
        ProofToken t = new ProofToken{salt: p.tokenSalt}(p.name, p.symbol, p.totalSupply, address(this));
        token = address(t);
        uint256 lpTokens = (p.totalSupply * p.lpBps) / 10_000;
        uint256 teamTokens = p.totalSupply - lpTokens;
        if (teamTokens > 0) t.transfer(proofWallet, teamTokens);

        // 2. Starting price: P0 = lpTokens / virtualEth (TOKEN per ETH), aligned to spacing,
        //    pool initialized exactly at the aligned tick.
        int24 startingTick = LaunchMath.alignToSpacing(
            TickMath.getTickAtSqrtPrice(LaunchMath.startingSqrtPriceX96(lpTokens, p.virtualEth)), p.tickSpacing
        );
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(token),
            fee: p.lpFee,
            tickSpacing: p.tickSpacing,
            hooks: p.hooks
        });
        poolId = key.toId();
        // Diagnose squatting explicitly instead of surfacing v4's generic revert, so the
        // launch bot can retry with a fresh salt automatically.
        (uint160 existing,,,) = StateLibrary.getSlot0(poolManager, poolId);
        if (existing != 0) revert PoolAlreadyInitialized(poolId, token);
        poolManager.initialize(key, TickMath.getSqrtPriceAtTick(startingTick));

        // 3. Hook learns about the launch FIRST: the ranges are minted under its gate.
        if (address(p.hooks) != address(0)) {
            IProofLaunchRegistrar(address(p.hooks)).registerLaunch(key, p.hookData);
        }

        // 4. Token-only ranges, position NFTs minted directly to the PROOF admin, wrapped
        //    in the transient authorization the hook checks.
        bytes32 pid = PoolId.unwrap(poolId);
        assembly {
            tstore(LIQ_LOCK_SLOT, pid)
        }
        _mintRanges(key, t, startingTick, lpTokens, p);
        assembly {
            tstore(LIQ_LOCK_SLOT, 0)
        }

        // 5. Rounding dust from liquidity math goes to the PROOF wallet.
        uint256 dust = t.balanceOf(address(this));
        if (dust > 0) t.transfer(proofWallet, dust);

        _launches[poolId] = LaunchInfo({
            token: token, key: key, startingTick: startingTick, lpTokens: lpTokens, createdAt: uint64(block.timestamp)
        });
        allTokens.push(token);
        poolIdOf[token] = poolId;
        emit LaunchCreated(poolId, token, startingTick, lpTokens, teamTokens);
    }

    // ---------------------------------------------------------------- views

    function launchOf(PoolId poolId) external view returns (LaunchInfo memory) {
        return _launches[poolId];
    }

    function launchCount() external view returns (uint256) {
        return allTokens.length;
    }

    // ---------------------------------------------------------------- internal

    function _mintRanges(
        PoolKey memory key,
        ProofToken t,
        int24 startingTick,
        uint256 lpTokens,
        CreateParams calldata p
    ) internal {
        // Resolve ranges (default: single full token-only range).
        RangeParams[] memory ranges;
        if (p.ranges.length == 0) {
            ranges = new RangeParams[](1);
            ranges[0] = RangeParams(LaunchMath.minAlignedTick(p.tickSpacing), startingTick, 10_000);
        } else {
            if (p.ranges.length > 3) revert TooManyRanges();
            ranges = new RangeParams[](p.ranges.length);
            for (uint256 i; i < p.ranges.length; i++) {
                ranges[i] = p.ranges[i];
                if (ranges[i].tickLower == type(int24).min) {
                    ranges[i].tickLower = LaunchMath.minAlignedTick(p.tickSpacing);
                }
                if (ranges[i].tickUpper == type(int24).max) ranges[i].tickUpper = startingTick;
            }
        }

        // Validate: aligned, ordered, non-overlapping, at/below the starting tick, shares sum.
        uint256 shareSum;
        for (uint256 i; i < ranges.length; i++) {
            LaunchMath.requireAligned(ranges[i].tickLower, p.tickSpacing);
            LaunchMath.requireAligned(ranges[i].tickUpper, p.tickSpacing);
            if (ranges[i].tickLower >= ranges[i].tickUpper) revert RangeOutOfOrder();
            // Contiguous, not merely non-overlapping: a gap below the starting tick is a
            // liquidity void the first buy would price straight through.
            if (i > 0 && ranges[i].tickLower != ranges[i - 1].tickUpper) revert RangeOutOfOrder();
            if (ranges[i].tickUpper > startingTick) revert RangeAboveStartingTick();
            shareSum += ranges[i].shareBps;
        }
        // The top range must reach the starting tick so liquidity is live from the first buy.
        if (ranges[ranges.length - 1].tickUpper != startingTick) revert RangeGapAtStart();
        if (shareSum != 10_000) revert SharesMustSum(shareSum);

        // Approvals: PositionManager pulls the token through Permit2.
        t.approve(address(permit2), lpTokens);
        permit2.approve(address(t), address(positionManager), uint160(lpTokens), uint48(block.timestamp + 60));

        // One MINT_POSITION per range + a single SETTLE_PAIR, minted to the PROOF admin.
        bytes memory actions;
        bytes[] memory params = new bytes[](ranges.length + 1);
        for (uint256 i; i < ranges.length; i++) {
            uint256 tokenShare = (lpTokens * ranges[i].shareBps) / 10_000;
            uint128 liquidity = LaunchMath.liquidityForTokenAmount(ranges[i].tickLower, ranges[i].tickUpper, tokenShare);
            actions = abi.encodePacked(actions, uint8(Actions.MINT_POSITION));
            params[i] = abi.encode(
                key,
                ranges[i].tickLower,
                ranges[i].tickUpper,
                liquidity,
                0, // amount0Max: the zero-ETH guarantee — any ETH requirement reverts
                tokenShare, // amount1Max
                owner(), // position NFT straight to the PROOF admin
                bytes("")
            );
        }
        actions = abi.encodePacked(actions, uint8(Actions.SETTLE_PAIR));
        params[ranges.length] = abi.encode(key.currency0, key.currency1);

        positionManager.modifyLiquidities(abi.encode(actions, params), block.timestamp);
    }
}

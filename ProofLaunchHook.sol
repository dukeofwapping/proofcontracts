// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {
    BeforeSwapDelta,
    BeforeSwapDeltaLibrary,
    toBeforeSwapDelta
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IProofLaunchRegistrar} from "./interfaces/IProofLaunchRegistrar.sol";
import {IProofFeeSplitter} from "./interfaces/IProofFeeSplitter.sol";
import {IProofVaultLock, LOCK_MODE_NONE, LOCK_MODE_EXECUTOR, LOCK_MODE_PASS} from "./interfaces/IProofVaultLock.sol";
import {IProofLiquidityLock} from "./interfaces/IProofLiquidityLock.sol";

/// @notice PROOF launch hook (one per chain, attached to every launch pool).
///
/// Responsibilities (Implementation Plan §5.2):
///  - Phase gating: Configured (dead) -> Execution (vault-only buys) -> Public (open) /
///    Cancelled (dead forever).
///  - ETH taxes on both directions, linearly decaying from start (10/15) to resting
///    (2.5/2.5) over `decaySeconds` of public trading; taxes pushed to the fee splitter
///    with earn-time accounting. The config is hard-capped at registration: start taxes at
///    most 10% buy / 15% sell, resting taxes at most 2.5% / 2.5% (MAX_* constants).
///  - Max-wallet ramp during early public trading: cumulative tokens bought per tx.origin,
///    capped at a per-minute-growing % of supply, enforcement structurally off once the
///    ramp reaches its cap.
///  - Liquidity gating: only the launch manager's own authorized mint may add liquidity.
///    An open liquidity path would defeat the taxes entirely — a holder could place tokens
///    as a narrow range order below spot, let an ordinary buyer fill it and withdraw the
///    ETH with NO sell tax, and the mirror trick buys with no buy tax and no max-wallet
///    accounting. Third-party LPing is therefore blocked for the life of the pool.
///
/// Swap authentication (three layers, §5.2):
///  1. Every callback requires msg.sender == PoolManager.
///  2. The `sender` param is set BY the PoolManager to the caller of swap(); pre-PUBLIC
///     the hook requires sender == vault exactly.
///  3. The vault's transient execution lock must be live and match the swap (pool,
///     direction, exact-out amount). `hookData` is never read at all.
contract ProofLaunchHook is IHooks, IProofLaunchRegistrar {
    // ---------------------------------------------------------------- types

    enum Phase {
        Unregistered,
        Configured,
        Execution,
        Public,
        Cancelled
    }

    /// @notice Hard ceilings on the per-launch tax config (basis points). A launch can never be
    ///         registered above these, whatever the operator or the bot sends; the agreed
    ///         defaults (10/15 start, 2.5/2.5 resting) sit exactly at the start caps and below the resting caps.
    uint16 public constant MAX_START_BUY_BPS = 1_000; // 10%
    uint16 public constant MAX_START_SELL_BPS = 1_500; // 15%
    uint16 public constant MAX_RESTING_BUY_BPS = 250; // 2.5%
    uint16 public constant MAX_RESTING_SELL_BPS = 250; // 2.5%

    /// @dev ABI-decoded from ProofLaunchManager.CreateParams.hookData at registration.
    struct LaunchTaxConfig {
        uint16 startBuyBps; // e.g. 1000 (10%)
        uint16 startSellBps; // e.g. 1500 (15%)
        uint16 restingBuyBps; // e.g. 250
        uint16 restingSellBps; // e.g. 250
        uint32 decaySeconds; // e.g. 1800
        uint16 mwStartBps; // max wallet at open, of supply, e.g. 20 (0.2%)
        uint16 mwStepBps; // e.g. 10 (+0.1% per step)
        uint32 mwStepSeconds; // e.g. 60
        uint16 mwCapBps; // e.g. 100 (1%); 0 disables the ramp entirely
    }

    struct LaunchState {
        // slot 1
        Phase phase;
        uint16 startBuyBps;
        uint16 startSellBps;
        uint16 restingBuyBps;
        uint16 restingSellBps;
        uint32 decaySeconds;
        uint64 publicOpenedAt;
        // slot 2
        uint16 mwStartBps;
        uint16 mwStepBps;
        uint32 mwStepSeconds;
        uint16 mwCapBps;
        uint96 totalSupply;
    }

    // ---------------------------------------------------------------- state

    IPoolManager public immutable poolManager;
    address public immutable launchManager;
    address public immutable vault;
    address public immutable feeSplitter;

    mapping(PoolId => LaunchState) public launches;
    /// @notice Cumulative tokens bought per tx.origin while the max-wallet ramp is live.
    mapping(PoolId => mapping(address origin => uint256)) public boughtDuringRamp;

    // ---------------------------------------------------------------- errors/events

    error NotPoolManager();
    error NotLaunchManager();
    error NotVault();
    error NotRegistered();
    error AlreadyRegistered();
    error TradingNotOpen();
    error OnlyVaultDuringExecution();
    error ExecutionLockMismatch();
    error SellsBlockedDuringExecution();
    error InvalidTaxConfig();
    error InvalidPool();
    error InvalidPhaseTransition(Phase from, Phase to);
    error MaxWalletExceeded(uint256 wouldHold, uint256 maxAllowed);
    error SupplyTooLarge();
    error LiquidityNotAllowed();
    error HookNotUsed();

    event LaunchRegistered(PoolId indexed poolId, LaunchTaxConfig config, uint96 totalSupply);
    event PhaseChanged(PoolId indexed poolId, Phase phase);
    event TaxCollected(PoolId indexed poolId, uint256 ethAmount, bool isBuy);

    // ---------------------------------------------------------------- setup

    error ZeroAddress();

    constructor(IPoolManager poolManager_, address launchManager_, address vault_, address feeSplitter_) {
        // Audit (P8): immutable wiring — a zero here would brick every launch permanently.
        if (
            address(poolManager_) == address(0) || launchManager_ == address(0) || vault_ == address(0)
                || feeSplitter_ == address(0)
        ) revert ZeroAddress();
        poolManager = poolManager_;
        launchManager = launchManager_;
        vault = vault_;
        feeSplitter = feeSplitter_;
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: true,
            afterSwapReturnDelta: true,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    modifier onlyPoolManager() {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        _;
    }

    // ---------------------------------------------------------------- registration & lifecycle

    /// @inheritdoc IProofLaunchRegistrar
    function registerLaunch(PoolKey calldata key, bytes calldata data) external {
        if (msg.sender != launchManager) revert NotLaunchManager();
        if (address(key.hooks) != address(this) || !key.currency0.isAddressZero()) revert InvalidPool();
        PoolId id = key.toId();
        if (launches[id].phase != Phase.Unregistered) revert AlreadyRegistered();

        LaunchTaxConfig memory c = abi.decode(data, (LaunchTaxConfig));
        if (
            c.startBuyBps > MAX_START_BUY_BPS || c.startSellBps > MAX_START_SELL_BPS
                || c.restingBuyBps > MAX_RESTING_BUY_BPS || c.restingSellBps > MAX_RESTING_SELL_BPS
                || c.restingBuyBps > c.startBuyBps || c.restingSellBps > c.startSellBps || c.decaySeconds == 0
        ) revert InvalidTaxConfig();
        if (
            c.mwCapBps != 0
                && (c.mwStartBps == 0
                    || c.mwStartBps > c.mwCapBps
                    || c.mwStepSeconds == 0
                    || c.mwStepBps == 0
                    || c.mwCapBps > 10_000)
        ) revert InvalidTaxConfig();

        uint256 supply = IERC20(Currency.unwrap(key.currency1)).totalSupply();
        if (supply > type(uint96).max) revert SupplyTooLarge();

        launches[id] = LaunchState({
            phase: Phase.Configured,
            startBuyBps: c.startBuyBps,
            startSellBps: c.startSellBps,
            restingBuyBps: c.restingBuyBps,
            restingSellBps: c.restingSellBps,
            decaySeconds: c.decaySeconds,
            publicOpenedAt: 0,
            mwStartBps: c.mwStartBps,
            mwStepBps: c.mwStepBps,
            mwStepSeconds: c.mwStepSeconds,
            mwCapBps: c.mwCapBps,
            totalSupply: uint96(supply)
        });
        emit LaunchRegistered(id, c, uint96(supply));
    }

    /// @notice Lifecycle transitions, driven exclusively by the vault:
    ///         Configured -> Execution -> Public; Configured/Execution -> Cancelled.
    function setPhase(PoolId id, Phase to) external {
        if (msg.sender != vault) revert NotVault();
        Phase from = launches[id].phase;
        bool ok = (from == Phase.Configured && (to == Phase.Execution || to == Phase.Cancelled))
            || (from == Phase.Execution && (to == Phase.Public || to == Phase.Cancelled));
        if (!ok) revert InvalidPhaseTransition(from, to);
        launches[id].phase = to;
        if (to == Phase.Public) {
            launches[id].publicOpenedAt = uint64(block.timestamp);
            IProofFeeSplitter(feeSplitter).onPublicOpened(id);
        }
        emit PhaseChanged(id, to);
    }

    // ---------------------------------------------------------------- views (webapp/bot)

    function phaseOf(PoolId id) external view returns (Phase) {
        return launches[id].phase;
    }

    function currentBuyTaxBps(PoolId id) external view returns (uint256) {
        return _taxBps(launches[id], true);
    }

    function currentSellTaxBps(PoolId id) external view returns (uint256) {
        return _taxBps(launches[id], false);
    }

    /// @return maxTokens current per-origin cumulative buy cap (0 = unlimited / ramp over)
    function currentMaxWalletTokens(PoolId id) external view returns (uint256 maxTokens) {
        LaunchState storage s = launches[id];
        if (s.phase != Phase.Public || s.mwCapBps == 0) return 0;
        uint256 bpsNow = _mwBpsNow(s);
        if (bpsNow >= s.mwCapBps) return 0;
        return (uint256(s.totalSupply) * bpsNow) / 10_000;
    }

    // ---------------------------------------------------------------- swap callbacks

    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        external
        onlyPoolManager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId id = key.toId();
        LaunchState storage s = launches[id];
        Phase ph = s.phase;

        if (ph == Phase.Unregistered) revert NotRegistered();
        if (ph == Phase.Configured || ph == Phase.Cancelled) revert TradingNotOpen();

        if (ph == Phase.Execution) {
            // Layer 2: PoolManager-authenticated caller must be the vault.
            if (sender != vault) revert OnlyVaultDuringExecution();
            if (!params.zeroForOne) revert SellsBlockedDuringExecution();
            // Layer 3: live transient lock matching this exact swap (exactOut buy).
            (bytes32 lockPool, uint8 mode, uint256 amountOut) = IProofVaultLock(vault).executionLock();
            if (
                lockPool != PoolId.unwrap(id) || mode == LOCK_MODE_NONE || params.amountSpecified <= 0
                    || uint256(params.amountSpecified) != amountOut
            ) revert ExecutionLockMismatch();
            // EXECUTOR is tax-exempt; PASS is taxed on the unspecified ETH input in afterSwap.
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        // PUBLIC. Tax here only when ETH is the SPECIFIED currency:
        //   buy exactIn  (zeroForOne, amountSpecified < 0): tax = ethIn * bps / 1e4
        //   sell exactOut (!zeroForOne, amountSpecified > 0): tax = ethOut * bps / (1e4 - bps)
        //     (pool outputs the tax on top; the swapper still nets their exact ETH)
        uint256 tax;
        if (params.zeroForOne && params.amountSpecified < 0) {
            tax = (uint256(-params.amountSpecified) * _taxBps(s, true)) / 10_000;
        } else if (!params.zeroForOne && params.amountSpecified > 0) {
            uint256 bps = _taxBps(s, false);
            tax = (uint256(params.amountSpecified) * bps) / (10_000 - bps);
        }
        if (tax > 0) {
            _collect(id, key.currency0, tax, params.zeroForOne);
            return (IHooks.beforeSwap.selector, toBeforeSwapDelta(int128(uint128(tax)), 0), 0);
        }
        return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function afterSwap(address, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata)
        external
        onlyPoolManager
        returns (bytes4, int128)
    {
        PoolId id = key.toId();
        LaunchState storage s = launches[id];
        Phase ph = s.phase;

        uint256 taxBps;
        if (ph == Phase.Execution) {
            // Reached only for vault swaps (beforeSwap enforced). PASS pays the full
            // starting buy tax; EXECUTOR is exempt.
            (bytes32 lockPool, uint8 mode,) = IProofVaultLock(vault).executionLock();
            if (lockPool == PoolId.unwrap(id) && mode == LOCK_MODE_PASS) taxBps = s.startBuyBps;
        } else {
            // PUBLIC: tax here only when ETH is the UNSPECIFIED currency.
            if (params.zeroForOne && params.amountSpecified > 0) taxBps = _taxBps(s, true); // buy exactOut
            else if (!params.zeroForOne && params.amountSpecified < 0) taxBps = _taxBps(s, false); // sell exactIn
            // Max-wallet ramp applies to every public buy.
            if (params.zeroForOne) _checkMaxWallet(s, id, delta);
        }

        int128 hookDelta;
        if (taxBps > 0) {
            uint256 tax;
            if (params.zeroForOne) {
                // ETH input was unspecified: gross user outlay = ethIn + tax, tax = gross * bps / 1e4.
                uint256 ethIn = uint256(uint128(-delta.amount0()));
                tax = (ethIn * taxBps) / (10_000 - taxBps);
            } else {
                // ETH output was unspecified: skim bps of the gross output.
                uint256 ethOut = uint256(uint128(delta.amount0()));
                tax = (ethOut * taxBps) / 10_000;
            }
            if (tax > 0) {
                _collect(id, key.currency0, tax, params.zeroForOne);
                hookDelta = int128(uint128(tax));
            }
        }
        return (IHooks.afterSwap.selector, hookDelta);
    }

    // ---------------------------------------------------------------- internal

    /// @dev Taxes are credited as ERC-6909 claim tokens on the PoolManager rather than
    ///      physical ETH: during the swap callbacks the swapper has not settled yet, so the
    ///      PoolManager may hold no ETH at all (`take` would fail). Claims are pure
    ///      accounting; the splitter redeems them for real ETH at distribution time.
    function _collect(PoolId id, Currency eth, uint256 tax, bool isBuy) internal {
        poolManager.mint(feeSplitter, eth.toId(), tax);
        IProofFeeSplitter(feeSplitter).record(id, tax);
        emit TaxCollected(id, tax, isBuy);
    }

    function _taxBps(LaunchState storage s, bool isBuy) internal view returns (uint256) {
        (uint256 start, uint256 resting) = isBuy
            ? (uint256(s.startBuyBps), uint256(s.restingBuyBps))
            : (uint256(s.startSellBps), uint256(s.restingSellBps));
        uint256 elapsed = block.timestamp - s.publicOpenedAt;
        if (elapsed >= s.decaySeconds) return resting;
        return start - ((start - resting) * elapsed) / s.decaySeconds;
    }

    function _mwBpsNow(LaunchState storage s) internal view returns (uint256) {
        uint256 elapsed = block.timestamp - s.publicOpenedAt;
        return uint256(s.mwStartBps) + uint256(s.mwStepBps) * (elapsed / s.mwStepSeconds);
    }

    function _checkMaxWallet(LaunchState storage s, PoolId id, BalanceDelta delta) internal {
        uint16 cap = s.mwCapBps;
        if (cap == 0) return;
        uint256 bpsNow = _mwBpsNow(s);
        if (bpsNow >= cap) return; // ramp complete: enforcement (and its storage) permanently off
        uint256 maxTokens = (uint256(s.totalSupply) * bpsNow) / 10_000;
        uint256 newTotal = boughtDuringRamp[id][tx.origin] + uint256(uint128(delta.amount1()));
        if (newTotal > maxTokens) revert MaxWalletExceeded(newTotal, maxTokens);
        boughtDuringRamp[id][tx.origin] = newTotal;
    }

    // ---------------------------------------------------------------- unused IHooks callbacks

    function beforeInitialize(address, PoolKey calldata, uint160) external pure returns (bytes4) {
        revert HookNotUsed();
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure returns (bytes4) {
        revert HookNotUsed();
    }

    /// @notice Liquidity may be added ONLY inside the launch manager's authorized mint,
    ///         proven by its transient lock naming this pool. See the contract header for
    ///         why an open liquidity path would nullify every tax in this hook.
    function beforeAddLiquidity(address, PoolKey calldata key, ModifyLiquidityParams calldata, bytes calldata)
        external
        view
        onlyPoolManager
        returns (bytes4)
    {
        if (IProofLiquidityLock(launchManager).liquidityLock() != PoolId.unwrap(key.toId())) {
            revert LiquidityNotAllowed();
        }
        return IHooks.beforeAddLiquidity.selector;
    }

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure returns (bytes4, BalanceDelta) {
        revert HookNotUsed();
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        revert HookNotUsed();
    }

    function afterRemoveLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure returns (bytes4, BalanceDelta) {
        revert HookNotUsed();
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        revert HookNotUsed();
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        revert HookNotUsed();
    }
}

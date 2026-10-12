// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {TransientStateLibrary} from "@uniswap/v4-core/src/libraries/TransientStateLibrary.sol";

import {ProofLaunchHook} from "./ProofLaunchHook.sol";
import {IProofVaultLock, LOCK_MODE_EXECUTOR, LOCK_MODE_PASS} from "./interfaces/IProofVaultLock.sol";

/// @notice PROOF contribution + vesting vault (one per chain, multi-launch).
///
/// Lifecycle per launch (Implementation Plan §5.4):
///   configureLaunch (admin) -> contribute (whitelisted wallets, fixed amount, webapp)
///   -> startExecution (admin; closes contributions, hook -> EXECUTION)
///   -> executeBuy x N (whitelisted executor EOAs, own ETH, exactOut, tax-exempt)
///   -> execute (admin; one pooled exactOut buy, taxed, skipped when nobody
///      contributed; optionally opens PUBLIC atomically) -> claim (25% TGE + linear vesting) / withdrawServiceFee (admin)
///   or cancelLaunch (admin) -> claimRefund (full deposit).
///
/// The vault is the ONLY contract that can swap pre-PUBLIC: it swaps directly on the
/// PoolManager inside its own unlock callback (never a shared router) under a transient
/// execution lock the hook cross-checks (§5.2 layer 3).
contract ProofContributionVault is Ownable2Step, ReentrancyGuardTransient, IProofVaultLock, IUnlockCallback {
    using TransientStateLibrary for IPoolManager;

    // ---------------------------------------------------------------- types

    enum Status {
        None,
        Open, // configured; contributions open until deadline/execution
        Executing, // executor buys + pass buy window; contributions closed
        Executed, // pass buy done; vesting live once public opens
        Cancelled // refunds open
    }

    struct LaunchConfig {
        PoolKey key;
        Status status;
        uint96 contributionAmount; // fixed per wallet, e.g. 0.125 ether
        uint96 buyAmountTokens; // fixed tokens per participant (executor & pass), e.g. 0.2% supply
        uint64 contributionDeadline;
        uint16 tgeBps; // e.g. 2500 = 25% at TGE
        uint32 vestSeconds; // e.g. 60 days
        uint64 vestStart; // set when public trading opens
        uint32 contributorCount;
        uint32 executorBuysDone;
        uint96 totalContributed; // ETH accounting, segregated per launch
        uint96 passBuyEthSpent;
        bool serviceFeeWithdrawn;
    }

    struct Contributor {
        bool contributed;
        bool refunded;
        uint96 claimedTokens;
    }

    // ---------------------------------------------------------------- state

    IPoolManager public immutable poolManager;
    ProofLaunchHook public hook; // set once post-deploy (hook needs the vault address first)

    mapping(PoolId => LaunchConfig) internal _launches;
    mapping(PoolId => mapping(address => Contributor)) internal _contributors;
    mapping(PoolId => mapping(address => bool)) public isWhitelisted;
    mapping(PoolId => mapping(address => bool)) public executorBought;

    /// @notice Global executor whitelist (changes rarely; PROOF-operated EOAs).
    mapping(address => bool) public isExecutor;

    /// @notice ETH the vault owes across all launches (unconsumed contributions, unclaimed
    ///         refunds, unwithdrawn service fees). Anything above this is stray ETH that
    ///         can be swept without ever touching launch funds.
    uint256 public totalObligations;

    // Transient execution lock (EIP-1153) — read by the hook via executionLock().
    uint256 private constant LOCK_POOL_SLOT = 0x50524f4f465f4c4f434b5f504f4f4c; // "PROOF_LOCK_POOL"
    uint256 private constant LOCK_MODE_SLOT = 0x50524f4f465f4c4f434b5f4d4f4445; // "PROOF_LOCK_MODE"
    uint256 private constant LOCK_AMT_SLOT = 0x50524f4f465f4c4f434b5f414d54; // "PROOF_LOCK_AMT"

    // ---------------------------------------------------------------- errors/events

    error HookAlreadySet();
    error HookNotSet();
    error ZeroAddress();
    error NotPoolManager();
    error LaunchExists();
    error LaunchNotFound();
    error WrongStatus(Status expected, Status actual);
    error HookNotConfigured();
    error InvalidConfig();
    error NotWhitelisted();
    error WrongContributionAmount(uint256 expected, uint256 got);
    error AlreadyContributed();
    error ContributionsClosed();
    error NotExecutor();
    error AlreadyBought();
    error InsufficientPooledEth(uint256 needed, uint256 available);
    error NothingToClaim();
    error NotOpenedYet();
    error AlreadyRefunded();
    error NothingContributed();
    error AlreadyWithdrawn();
    error EthTransferFailed();
    error DeadlinePassed();
    error PartialFill(uint256 wanted, uint256 got);

    event LaunchConfigured(
        PoolId indexed poolId,
        uint256 contributionAmount,
        uint256 buyAmountTokens,
        uint64 deadline,
        uint16 tgeBps,
        uint32 vestSeconds
    );
    event WhitelistUpdated(PoolId indexed poolId, uint256 count, bool allowed);
    event ExecutorsUpdated(uint256 count, bool allowed);
    event Contributed(PoolId indexed poolId, address indexed wallet, uint256 amount);
    event ExecutionStarted(PoolId indexed poolId);
    event BuyExecuted(PoolId indexed poolId, address indexed wallet, uint256 tokensOut, uint256 ethPaid);
    event PassBuyExecuted(PoolId indexed poolId, uint256 tokensOut, uint256 ethSpent, uint256 contributors);
    /// @notice The pass buy stage completed with no contributors, so no swap was made.
    event PassBuySkipped(PoolId indexed poolId);
    event PublicOpened(PoolId indexed poolId, uint64 vestStart);
    event Claimed(PoolId indexed poolId, address indexed wallet, uint256 tokens);
    event Refunded(PoolId indexed poolId, address indexed wallet, uint256 amount);
    event ServiceFeeWithdrawn(PoolId indexed poolId, uint256 amount);
    event LaunchCancelled(PoolId indexed poolId);

    constructor(IPoolManager poolManager_, address admin) Ownable(admin) {
        poolManager = poolManager_;
    }

    receive() external payable {}

    // ---------------------------------------------------------------- one-time wiring

    /// @notice The hook is deployed after the vault (its address is a hook constructor
    ///         arg), so it is wired here exactly once.
    function setHook(ProofLaunchHook hook_) external onlyOwner {
        if (address(hook) != address(0)) revert HookAlreadySet();
        if (address(hook_) == address(0)) revert ZeroAddress();
        hook = hook_;
    }

    // ---------------------------------------------------------------- admin: configuration

    function configureLaunch(
        PoolKey calldata key,
        uint96 contributionAmount,
        uint96 buyAmountTokens,
        uint64 contributionDeadline,
        uint16 tgeBps,
        uint32 vestSeconds
    ) external onlyOwner {
        if (address(hook) == address(0)) revert HookNotSet();
        PoolId id = key.toId();
        if (_launches[id].status != Status.None) revert LaunchExists();
        if (hook.phaseOf(id) != ProofLaunchHook.Phase.Configured) revert HookNotConfigured();
        if (
            contributionAmount == 0 || buyAmountTokens == 0 || tgeBps > 10_000 || vestSeconds == 0
                || contributionDeadline <= block.timestamp
        ) revert InvalidConfig();

        LaunchConfig storage l = _launches[id];
        l.key = key;
        l.status = Status.Open;
        l.contributionAmount = contributionAmount;
        l.buyAmountTokens = buyAmountTokens;
        l.contributionDeadline = contributionDeadline;
        l.tgeBps = tgeBps;
        l.vestSeconds = vestSeconds;
        emit LaunchConfigured(id, contributionAmount, buyAmountTokens, contributionDeadline, tgeBps, vestSeconds);
    }

    function setDeadline(PoolId id, uint64 newDeadline) external onlyOwner {
        LaunchConfig storage l = _requireStatus(id, Status.Open);
        if (newDeadline <= block.timestamp) revert InvalidConfig();
        l.contributionDeadline = newDeadline;
    }

    function setWhitelist(PoolId id, address[] calldata wallets, bool allowed) external onlyOwner {
        if (_launches[id].status == Status.None) revert LaunchNotFound();
        for (uint256 i; i < wallets.length; i++) {
            isWhitelisted[id][wallets[i]] = allowed;
        }
        emit WhitelistUpdated(id, wallets.length, allowed);
    }

    function setExecutors(address[] calldata wallets, bool allowed) external onlyOwner {
        for (uint256 i; i < wallets.length; i++) {
            isExecutor[wallets[i]] = allowed;
        }
        emit ExecutorsUpdated(wallets.length, allowed);
    }

    // ---------------------------------------------------------------- contributions

    function contribute(PoolId id) external payable {
        LaunchConfig storage l = _requireStatus(id, Status.Open);
        if (block.timestamp > l.contributionDeadline) revert ContributionsClosed();
        if (!isWhitelisted[id][msg.sender]) revert NotWhitelisted();
        Contributor storage c = _contributors[id][msg.sender];
        if (c.contributed) revert AlreadyContributed();
        if (msg.value != l.contributionAmount) revert WrongContributionAmount(l.contributionAmount, msg.value);

        c.contributed = true;
        l.contributorCount += 1;
        l.totalContributed += uint96(msg.value);
        totalObligations += msg.value;
        emit Contributed(id, msg.sender, msg.value);
    }

    // ---------------------------------------------------------------- launch execution

    /// @notice Closes contributions and moves the hook to EXECUTION. Executor buys and the
    ///         pass buy become possible; nothing else can touch the pool.
    function startExecution(PoolId id) external onlyOwner {
        LaunchConfig storage l = _requireStatus(id, Status.Open);
        l.status = Status.Executing;
        hook.setPhase(id, ProofLaunchHook.Phase.Execution);
        emit ExecutionStarted(id);
    }

    /// @notice Called BY each executor wallet itself (tx.origin = the EOA, which is what
    ///         explorers display). ETH comes attached from the wallet; the buy is an
    ///         exactOut for the launch's fixed token amount, tax-exempt; excess refunded.
    function executeBuy(PoolId id) external payable nonReentrant returns (uint256 ethPaid) {
        LaunchConfig storage l = _requireStatus(id, Status.Executing);
        if (!isExecutor[msg.sender]) revert NotExecutor();
        if (executorBought[id][msg.sender]) revert AlreadyBought();
        executorBought[id][msg.sender] = true;
        l.executorBuysDone += 1;

        ethPaid = _executeBuy(l.key, l.buyAmountTokens, LOCK_MODE_EXECUTOR, msg.sender);
        if (ethPaid > msg.value) revert InsufficientPooledEth(ethPaid, msg.value);
        uint256 refund = msg.value - ethPaid;
        if (refund > 0) _sendEth(msg.sender, refund);
        emit BuyExecuted(id, msg.sender, l.buyAmountTokens, ethPaid);
    }

    /// @notice The single pooled Proof Pass buy: exactOut for contributors x buyAmount,
    ///         taxed, funded strictly from this launch's pooled contributions. Tokens stay
    ///         in the vault for vesting. Optionally opens public trading atomically. With
    ///         zero contributors the swap is skipped and the launch simply completes.
    function execute(PoolId id, bool openAtomically) external onlyOwner nonReentrant {
        LaunchConfig storage l = _requireStatus(id, Status.Executing);
        uint256 tokensOut = uint256(l.buyAmountTokens) * l.contributorCount;

        if (tokensOut == 0) {
            // No contributions: there is nothing to buy and nothing to vest. The launch still
            // completes — the executor buys stand and trading can open — with no swap at all
            // (requested 2026-10-12; before this the call reverted and stranded the launch).
            l.status = Status.Executed;
            emit PassBuySkipped(id);
        } else {
            uint256 ethPaid = _executeBuy(l.key, tokensOut, LOCK_MODE_PASS, address(this));
            if (ethPaid > l.totalContributed) revert InsufficientPooledEth(ethPaid, l.totalContributed);
            l.passBuyEthSpent = uint96(ethPaid);
            totalObligations -= ethPaid;
            l.status = Status.Executed;
            emit PassBuyExecuted(id, tokensOut, ethPaid, l.contributorCount);
        }

        if (openAtomically) _openPublic(id, l);
    }

    /// @notice Non-atomic variant: open public trading after the pass buy.
    function openTrading(PoolId id) external onlyOwner {
        LaunchConfig storage l = _requireStatus(id, Status.Executed);
        if (l.vestStart != 0) revert InvalidConfig();
        _openPublic(id, l);
    }

    function cancelLaunch(PoolId id) external onlyOwner {
        LaunchConfig storage l = _launches[id];
        if (l.status != Status.Open && l.status != Status.Executing) revert WrongStatus(Status.Open, l.status);
        l.status = Status.Cancelled;
        hook.setPhase(id, ProofLaunchHook.Phase.Cancelled);
        emit LaunchCancelled(id);
    }

    // ---------------------------------------------------------------- claims / refunds / fees

    /// @notice Claim vested tokens: tgeBps immediately at public open, the rest per-second
    ///         linear over vestSeconds.
    function claim(PoolId id) external nonReentrant returns (uint256 amount) {
        LaunchConfig storage l = _requireStatus(id, Status.Executed);
        if (l.vestStart == 0) revert NotOpenedYet();
        Contributor storage c = _contributors[id][msg.sender];
        if (!c.contributed) revert NothingContributed();

        amount = vestedAmount(id, msg.sender) - c.claimedTokens;
        if (amount == 0) revert NothingToClaim();
        c.claimedTokens += uint96(amount);
        IERC20(Currency.unwrap(l.key.currency1)).transfer(msg.sender, amount);
        emit Claimed(id, msg.sender, amount);
    }

    function claimRefund(PoolId id) external nonReentrant {
        LaunchConfig storage l = _requireStatus(id, Status.Cancelled);
        Contributor storage c = _contributors[id][msg.sender];
        if (!c.contributed) revert NothingContributed();
        if (c.refunded) revert AlreadyRefunded();
        c.refunded = true;
        totalObligations -= l.contributionAmount;
        _sendEth(msg.sender, l.contributionAmount);
        emit Refunded(id, msg.sender, l.contributionAmount);
    }

    /// @notice Stray ETH sent directly to the vault (donations, accidental sends): only
    ///         the surplus above tracked obligations is sweepable — launch funds are
    ///         structurally out of reach. Audit addition (P8).
    function sweepExcessEth(address to) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 excess = address(this).balance - totalObligations;
        if (excess == 0) revert NothingContributed();
        _sendEth(to, excess);
    }

    /// @notice PROOF's service fee: whatever remains of this launch's pooled contributions
    ///         after the pass buy.
    function withdrawServiceFee(PoolId id) external onlyOwner nonReentrant {
        LaunchConfig storage l = _requireStatus(id, Status.Executed);
        if (l.serviceFeeWithdrawn) revert AlreadyWithdrawn();
        l.serviceFeeWithdrawn = true;
        uint256 amount = uint256(l.totalContributed) - l.passBuyEthSpent;
        totalObligations -= amount;
        if (amount > 0) _sendEth(msg.sender, amount);
        emit ServiceFeeWithdrawn(id, amount);
    }

    // ---------------------------------------------------------------- views

    function launchOf(PoolId id) external view returns (LaunchConfig memory) {
        return _launches[id];
    }

    function contributorOf(PoolId id, address wallet) external view returns (Contributor memory) {
        return _contributors[id][wallet];
    }

    /// @notice Total vested (claimable + already claimed) tokens for a contributor.
    function vestedAmount(PoolId id, address wallet) public view returns (uint256) {
        LaunchConfig storage l = _launches[id];
        Contributor storage c = _contributors[id][wallet];
        if (!c.contributed || l.status != Status.Executed || l.vestStart == 0) return 0;
        uint256 alloc = l.buyAmountTokens;
        uint256 elapsed = block.timestamp - l.vestStart;
        if (elapsed >= l.vestSeconds) return alloc;
        uint256 tge = (alloc * l.tgeBps) / 10_000;
        return tge + ((alloc - tge) * elapsed) / l.vestSeconds;
    }

    function claimableAmount(PoolId id, address wallet) external view returns (uint256) {
        return vestedAmount(id, wallet) - _contributors[id][wallet].claimedTokens;
    }

    /// @inheritdoc IProofVaultLock
    function executionLock() external view returns (bytes32 poolId, uint8 mode, uint256 amountOut) {
        assembly {
            poolId := tload(LOCK_POOL_SLOT)
            mode := tload(LOCK_MODE_SLOT)
            amountOut := tload(LOCK_AMT_SLOT)
        }
    }

    // ---------------------------------------------------------------- swap engine

    function _executeBuy(PoolKey memory key, uint256 tokensOut, uint8 mode, address recipient)
        internal
        returns (uint256 ethPaid)
    {
        bytes memory r = poolManager.unlock(abi.encode(key, tokensOut, mode, recipient));
        ethPaid = abi.decode(r, (uint256));
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        (PoolKey memory key, uint256 tokensOut, uint8 mode, address recipient) =
            abi.decode(data, (PoolKey, uint256, uint8, address));

        // Lock lives ONLY around our own swap; the callback runs vault code exclusively.
        bytes32 pid = PoolId.unwrap(key.toId());
        assembly {
            tstore(LOCK_POOL_SLOT, pid)
            tstore(LOCK_MODE_SLOT, mode)
            tstore(LOCK_AMT_SLOT, tokensOut)
        }
        poolManager.swap(
            key,
            SwapParams({
                zeroForOne: true, amountSpecified: int256(tokensOut), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            ""
        );
        assembly {
            tstore(LOCK_POOL_SLOT, 0)
            tstore(LOCK_MODE_SLOT, 0)
            tstore(LOCK_AMT_SLOT, 0)
        }

        // Settle the full ETH owed (swap + any hook tax) from the vault's balance and take
        // the exact token output to the recipient.
        uint256 owed;
        int256 d0 = poolManager.currencyDelta(address(this), key.currency0);
        if (d0 < 0) {
            owed = uint256(-d0);
            // Sync the native currency first: `settle{value:}` reads the PoolManager's
            // transient synced-currency slot, which anything earlier in the same tx may
            // have left pointing at an ERC20 (audit L-1).
            poolManager.sync(key.currency0);
            poolManager.settle{value: owed}();
        }
        int256 d1 = poolManager.currencyDelta(address(this), key.currency1);
        // An exact-output swap CAN under-fill if it runs out of liquidity or hits the price
        // limit. Silently accepting a partial fill would under-collateralise vesting (the
        // vault promises every contributor a fixed allocation), so refuse it (audit M-2).
        if (uint256(d1) != tokensOut) revert PartialFill(tokensOut, d1 > 0 ? uint256(d1) : 0);
        poolManager.take(key.currency1, recipient, uint256(d1));
        return abi.encode(owed);
    }

    // ---------------------------------------------------------------- internal

    function _openPublic(PoolId id, LaunchConfig storage l) internal {
        l.vestStart = uint64(block.timestamp);
        hook.setPhase(id, ProofLaunchHook.Phase.Public);
        emit PublicOpened(id, l.vestStart);
    }

    function _requireStatus(PoolId id, Status expected) internal view returns (LaunchConfig storage l) {
        l = _launches[id];
        if (l.status != expected) revert WrongStatus(expected, l.status);
    }

    function _sendEth(address to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert EthTransferFailed();
    }
}

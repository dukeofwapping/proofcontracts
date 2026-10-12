// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

import {IProofFeeSplitter} from "./interfaces/IProofFeeSplitter.sol";

/// @notice PROOF fee splitter (one per chain, multi-launch). Implementation Plan §5.5.
///
/// Earn-time division with one warm SSTORE per taxed swap: the split schedule is stepwise
/// (period 0: open -> +48h, period 1: -> +60d, period 2: after), so `record` buckets each
/// accrual into its period at the moment it is earned. Period totals are immutable
/// history — claims simply apply each period's team share, so the division is locked at
/// earn time regardless of when anyone claims.
///
/// Tax ETH arrives as ERC-6909 claim tokens on the PoolManager (minted by the hook during
/// swap callbacks); payouts burn claims and take real ETH inside this contract's own
/// unlock callback.
///
/// Roles: PROOF (owner) configures launches, updates team wallets, pushes distributions
/// and sweeps its own share to the single global PROOF fee recipient; each launch's team
/// wallet can pull its own share at any time.
contract ProofFeeSplitter is Ownable2Step, ReentrancyGuardTransient, IProofFeeSplitter, IUnlockCallback {
    // ---------------------------------------------------------------- types

    struct SplitConfig {
        address teamWallet;
        uint16 teamBps0; // team share while t < anchor + period0 (default 6667)
        uint16 teamBps1; // team share while t < anchor + period0 + period1 (default 7500)
        uint16 teamBps2; // team share afterwards (default 10000)
        uint32 period0; // e.g. 48 hours
        uint32 period1; // e.g. 58 days
        uint64 anchor; // public-open timestamp, set by the hook; 0 = pre-open
    }

    struct Accrual {
        uint128 p0;
        uint128 p1;
        uint128 p2;
        uint128 teamClaimed;
        uint128 proofClaimed;
    }

    // ---------------------------------------------------------------- state

    IPoolManager public immutable poolManager;
    address public hook; // set once (hook is deployed after the splitter)
    /// @notice The single global PROOF fee recipient EOA.
    address public proofRecipient;

    mapping(PoolId => SplitConfig) public configs;
    mapping(PoolId => Accrual) public accruals;

    // ---------------------------------------------------------------- errors/events

    error HookAlreadySet();
    error NotHook();
    error ZeroAddress();
    error NotPoolManager();
    error InvalidConfig();
    error NotConfigured();
    error AlreadyConfigured();
    error NotTeamWallet();
    error NothingToPay();
    error EthTransferFailed();

    event LaunchSplitConfigured(
        PoolId indexed poolId, address teamWallet, uint16 bps0, uint16 bps1, uint16 bps2, uint32 period0, uint32 period1
    );
    event TeamWalletUpdated(PoolId indexed poolId, address teamWallet);
    event ProofRecipientUpdated(address recipient);
    event Recorded(PoolId indexed poolId, uint256 amount, uint8 period);
    event Anchored(PoolId indexed poolId, uint64 anchor);
    event TeamPaid(PoolId indexed poolId, address wallet, uint256 amount);
    event ProofPaid(PoolId indexed poolId, uint256 amount);

    constructor(IPoolManager poolManager_, address proofRecipient_, address admin) Ownable(admin) {
        if (proofRecipient_ == address(0)) revert ZeroAddress();
        poolManager = poolManager_;
        proofRecipient = proofRecipient_;
    }

    receive() external payable {}

    // ---------------------------------------------------------------- wiring & config

    function setHook(address hook_) external onlyOwner {
        if (hook != address(0)) revert HookAlreadySet();
        if (hook_ == address(0)) revert ZeroAddress();
        hook = hook_;
    }

    function setProofRecipient(address recipient) external onlyOwner {
        if (recipient == address(0)) revert ZeroAddress();
        proofRecipient = recipient;
        emit ProofRecipientUpdated(recipient);
    }

    /// @notice Per-launch schedule; must be set before claims (fees can technically accrue
    ///         first — pre-open accruals are period 0 by definition).
    function configureLaunch(
        PoolId id,
        address teamWallet,
        uint16 teamBps0,
        uint16 teamBps1,
        uint16 teamBps2,
        uint32 period0,
        uint32 period1
    ) external onlyOwner {
        if (configs[id].teamWallet != address(0)) revert AlreadyConfigured();
        if (teamWallet == address(0)) revert ZeroAddress();
        if (teamBps0 > 10_000 || teamBps1 > 10_000 || teamBps2 > 10_000 || period0 == 0 || period1 == 0) {
            revert InvalidConfig();
        }
        SplitConfig storage c = configs[id];
        c.teamWallet = teamWallet;
        c.teamBps0 = teamBps0;
        c.teamBps1 = teamBps1;
        c.teamBps2 = teamBps2;
        c.period0 = period0;
        c.period1 = period1;
        emit LaunchSplitConfigured(id, teamWallet, teamBps0, teamBps1, teamBps2, period0, period1);
    }

    /// @notice Team payout wallets are updatable ONLY by PROOF (per agreement).
    /// @dev Rotation first pays everything the CURRENT wallet has already earned, so the
    ///      rotation power cannot be used to redirect fees the team accrued in the past —
    ///      it only ever affects future payouts (audit finding: retroactive-seizure window).
    function setTeamWallet(PoolId id, address teamWallet) external onlyOwner nonReentrant {
        if (teamWallet == address(0)) revert ZeroAddress();
        SplitConfig storage c = configs[id];
        if (c.teamWallet == address(0)) revert NotConfigured();
        _payTeam(id, c);
        c.teamWallet = teamWallet;
        emit TeamWalletUpdated(id, teamWallet);
    }

    // ---------------------------------------------------------------- hook entry points

    /// @inheritdoc IProofFeeSplitter
    function record(PoolId id, uint256 amount) external {
        if (msg.sender != hook) revert NotHook();
        uint8 period = _currentPeriod(configs[id]);
        Accrual storage a = accruals[id];
        if (period == 0) a.p0 += uint128(amount);
        else if (period == 1) a.p1 += uint128(amount);
        else a.p2 += uint128(amount);
        emit Recorded(id, amount, period);
    }

    /// @inheritdoc IProofFeeSplitter
    function onPublicOpened(PoolId id) external {
        if (msg.sender != hook) revert NotHook();
        if (configs[id].anchor == 0) {
            configs[id].anchor = uint64(block.timestamp);
            emit Anchored(id, uint64(block.timestamp));
        }
    }

    // ---------------------------------------------------------------- payouts

    /// @notice Pull: the launch's team wallet claims its outstanding share.
    function claimTeam(PoolId id) external nonReentrant {
        SplitConfig storage c = configs[id];
        if (c.teamWallet == address(0)) revert NotConfigured();
        if (msg.sender != c.teamWallet) revert NotTeamWallet();
        _payTeam(id, c);
    }

    /// @notice Push: PROOF distributes both sides' outstanding shares.
    function distribute(PoolId id) external onlyOwner nonReentrant {
        SplitConfig storage c = configs[id];
        if (c.teamWallet == address(0)) revert NotConfigured();
        _payTeam(id, c);
        _payProof(id);
    }

    /// @notice PROOF sweeps its outstanding share for one launch to the global recipient.
    function claimProof(PoolId id) external onlyOwner nonReentrant {
        if (configs[id].teamWallet == address(0)) revert NotConfigured();
        _payProof(id);
    }

    /// @notice Stray raw ETH (not claim-backed accounting) sent directly to the splitter.
    function sweepExcessEth(address to) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 bal = address(this).balance;
        if (bal == 0) revert NothingToPay();
        (bool ok,) = to.call{value: bal}("");
        if (!ok) revert EthTransferFailed();
    }

    // ---------------------------------------------------------------- views

    function totalAccrued(PoolId id) public view returns (uint256) {
        Accrual storage a = accruals[id];
        return uint256(a.p0) + a.p1 + a.p2;
    }

    /// @notice Total team entitlement to date (claimed + outstanding), by earn-time periods.
    function teamEntitled(PoolId id) public view returns (uint256) {
        SplitConfig storage c = configs[id];
        Accrual storage a = accruals[id];
        return (uint256(a.p0) * c.teamBps0 + uint256(a.p1) * c.teamBps1 + uint256(a.p2) * c.teamBps2) / 10_000;
    }

    function proofEntitled(PoolId id) public view returns (uint256) {
        return totalAccrued(id) - teamEntitled(id);
    }

    function teamOutstanding(PoolId id) public view returns (uint256) {
        return teamEntitled(id) - accruals[id].teamClaimed;
    }

    function proofOutstanding(PoolId id) public view returns (uint256) {
        return proofEntitled(id) - accruals[id].proofClaimed;
    }

    // ---------------------------------------------------------------- internal

    function _currentPeriod(SplitConfig storage c) internal view returns (uint8) {
        uint64 anchor = c.anchor;
        if (anchor == 0) return 0; // pre-open accruals (pass buy tax) are period 0
        // Audit fix (P8): if fees somehow accrue post-open before the schedule is
        // configured, bucket them into period 0 rather than falling through to period 2
        // with zeroed shares. record() must never revert (it would brick swaps).
        if (c.period0 == 0) return 0;
        uint256 elapsed = block.timestamp - anchor;
        if (elapsed < c.period0) return 0;
        if (elapsed < uint256(c.period0) + c.period1) return 1;
        return 2;
    }

    function _payTeam(PoolId id, SplitConfig storage c) internal {
        uint256 amount = teamOutstanding(id);
        if (amount > 0) {
            accruals[id].teamClaimed += uint128(amount);
            _redeemAndSend(c.teamWallet, amount);
            emit TeamPaid(id, c.teamWallet, amount);
        }
    }

    function _payProof(PoolId id) internal {
        uint256 amount = proofOutstanding(id);
        if (amount > 0) {
            accruals[id].proofClaimed += uint128(amount);
            _redeemAndSend(proofRecipient, amount);
            emit ProofPaid(id, amount);
        }
    }

    /// @dev Burn `amount` of native-currency ERC-6909 claims and send the freed ETH to `to`.
    function _redeemAndSend(address to, uint256 amount) internal {
        poolManager.unlock(abi.encode(to, amount));
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        (address to, uint256 amount) = abi.decode(data, (address, uint256));
        poolManager.burn(address(this), 0, amount); // native currency id = 0
        poolManager.take(Currency.wrap(address(0)), to, amount);
        return "";
    }
}

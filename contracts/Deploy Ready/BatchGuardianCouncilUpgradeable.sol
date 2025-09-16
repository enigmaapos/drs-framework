// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
  BatchGuardianCouncilUpgradeable
  - UUPS upgradeable
  - Two batches (active, standby) of fixed GUARDIAN_COUNT (7)
  - DAO-managed reseed/rotate
  - Recovery proposals carry (callTarget, callData) executed atomically
  - 5/7 threshold; 6/7 => warning + last-honest veto; 7/7 => lock + auto-activate standby
  - Last-honest guardian gets 48h veto to halt & promote standby
*/

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

contract BatchGuardianCouncilUpgradeable is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    // -------- Constants / Limits --------
    uint8 public constant GUARDIAN_COUNT = 7;
    uint8 public constant THRESHOLD = 5; // 5-of-7
    uint256 public constant RECOVERY_WINDOW = 3 days;
    uint256 public constant LAST_HONEST_VETO_WINDOW = 48 hours;

    // -------- Roles / Authority --------
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");

    // The DAO address is also set as DEFAULT_ADMIN_ROLE in AccessControl
    address public dao;

    // -------- Batches --------
    address[GUARDIAN_COUNT] public activeGuardians;   // Batch-1
    address[GUARDIAN_COUNT] public standbyGuardians;  // Batch-2

    mapping(address => bool) public isActiveGuardian;
    mapping(address => bool) public isStandbyGuardian;

    // -------- Lock / Compromise flags --------
    bool public locked;   // when true, only DAO can reseed/rotate
    bool public warning;  // set when 6/7 approvals seen in any proposal

    // -------- Recovery proposals (generic) --------
    enum RecovKind { DEPLOYER, ADMIN }

    struct RecoveryRequest {
        address proposed;     // human-readable "new" address (optional)
        uint8 approvals;
        uint256 deadline;
        bool executed;
        address callTarget;   // target contract to call when executing
        bytes callData;       // exact calldata to perform atomic swap (grant->revoke) or other admin op
        mapping(address => bool) hasApproved; // active guardian approvals
    }

    RecoveryRequest private _deployerRecovery;
    RecoveryRequest private _adminRecovery;

    // -------- Last-honest veto --------
    struct TempVeto {
        address guardian;
        uint256 expiry;
    }
    TempVeto public tempVeto;

    // -------- Events --------
    event DaoChanged(address indexed oldDao, address indexed newDao);

    event ActiveBatchSeeded(address[GUARDIAN_COUNT] guardians);
    event StandbyBatchSeeded(address[GUARDIAN_COUNT] guardians);
    event StandbyActivated(address[GUARDIAN_COUNT] newActive);

    event WarningRaised(RecovKind kind, uint8 approvals);
    event AutoLocked(RecovKind kind);

    event RecoveryProposed(RecovKind kind, address indexed proposer, address proposed, address callTarget, uint256 deadline);
    event RecoveryApproved(RecovKind kind, address indexed guardian, uint8 approvals);
    event RecoveryExecuted(RecovKind kind, address indexed proposed, address callTarget);
    event RecoveryFailed(RecovKind kind, address indexed proposer, address callTarget, bytes returnData);

    event LastHonestAssigned(address indexed guardian, uint256 expiry);
    event LastHonestHalted(address indexed guardian, RecovKind kind);

    // -------- Errors (short) --------
    error Unauthorized();
    error ZeroAddress();
    error LockedErr();
    error NotGuardian();
    error AlreadyApproved();
    error NoActiveRequest();
    error RequestExpired();
    error ThresholdNotMet();
    error BadArrayLength();

    // -------- Modifiers --------
    modifier onlyDAO() {
        if (!hasRole(DAO_ROLE, msg.sender)) revert Unauthorized();
        _;
    }

    modifier notLocked() {
        if (locked) revert LockedErr();
        _;
    }

    modifier onlyActiveG() {
        if (!isActiveGuardian[msg.sender]) revert NotGuardian();
        _;
    }

    // -------- Initializer (replaces constructor) --------
    function initialize(
        address dao_,
        address[GUARDIAN_COUNT] memory batchActive,
        address[GUARDIAN_COUNT] memory batchStandby
    ) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        if (dao_ == address(0)) revert ZeroAddress();

        // set DAO roles
        _grantRole(DEFAULT_ADMIN_ROLE, dao_);
        _grantRole(DAO_ROLE, dao_);
        dao = dao_;

        // seed batches
        _seedActiveBatch(batchActive);
        _seedStandbyBatch(batchStandby);

        // initial flags
        locked = false;
        warning = false;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
    }

    // -------- UUPS authorization (DAO as admin) --------
    function _authorizeUpgrade(address) internal override onlyDAO {}

    // ============================
    //  DAO Controls (reseeding)
    // ============================
    function setDAO(address newDAO) external onlyDAO {
        if (newDAO == address(0)) revert ZeroAddress();
        address old = dao;
        // grant roles to new DAO and revoke from old
        _grantRole(DEFAULT_ADMIN_ROLE, newDAO);
        _grantRole(DAO_ROLE, newDAO);
        _revokeRole(DAO_ROLE, dao);
        _revokeRole(DEFAULT_ADMIN_ROLE, dao);

        dao = newDAO;
        emit DaoChanged(old, newDAO);
    }

    /// @notice DAO can fully reseed the active batch (even when locked).
    function daoSeedActiveBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        _clearActive();
        _seedActiveBatch(batch);
    }

    /// @notice DAO can fully reseed the standby batch (even when locked).
    function daoSeedStandbyBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        _clearStandby();
        _seedStandbyBatch(batch);
    }

    /// @notice DAO can manually activate the standby batch into active, then clear standby.
    function daoActivateStandby() external onlyDAO {
        _activateStandby();
    }

    /// @notice DAO can clear lock & warning after recovery and reseeding are completed.
    function daoClearLockAndWarning() external onlyDAO {
        locked = false;
        warning = false;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
    }

    // ==================================================
    //  Recovery proposals (Active guardians only)
    //  propose includes callTarget+callData to be executed
    //  callData should be crafted to perform atomic swap (grant then revoke)
    // ==================================================

    /// @notice Propose a recovery. `callTarget` and `callData` define the exact atomic action executed.
    /// `proposed` is optional helper (e.g., new admin address) for UX and logs.
    function proposeRecovery(
        RecovKind kind,
        address proposed,
        address callTarget,
        bytes calldata callData
    ) external notLocked onlyActiveG whenNotPaused {
        if (callTarget == address(0) || callData.length == 0) revert ZeroAddress();

        RecoveryRequest storage R = _getReq(kind);
        _resetReq(R, proposed);
        R.callTarget = callTarget;
        R.callData = callData;

        emit RecoveryProposed(kind, msg.sender, proposed, callTarget, R.deadline);
    }

    /// @notice Approve the active recovery (active guardians only).
    function approveRecovery(RecovKind kind) external notLocked onlyActiveG whenNotPaused {
        RecoveryRequest storage R = _getReq(kind);
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.hasApproved[msg.sender]) revert AlreadyApproved();

        R.hasApproved[msg.sender] = true;
        R.approvals += 1;

        // If approvals reach GUARDIAN_COUNT - 1 (6 of 7) assign last honest veto
        if (R.approvals == GUARDIAN_COUNT - 1) {
            address last = address(0);
            for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
                address g = activeGuardians[i];
                if (!R.hasApproved[g]) {
                    last = g;
                    break;
                }
            }
            if (last != address(0)) {
                tempVeto.guardian = last;
                tempVeto.expiry = block.timestamp + LAST_HONEST_VETO_WINDOW;
                emit LastHonestAssigned(last, tempVeto.expiry);
            }
        }

        if (R.approvals == 6 && !warning) {
            warning = true;
            emit WarningRaised(kind, R.approvals);
        }
        if (R.approvals == 7 && !locked) {
            locked = true;
            emit AutoLocked(kind);
            // auto-activate standby to guarantee liveness
            _activateStandby();
            // clear temp veto if any
            tempVeto.guardian = address(0);
            tempVeto.expiry = 0;
        }

        emit RecoveryApproved(kind, msg.sender, R.approvals);
    }

    /// @notice Execute the active recovery once threshold met. The council will perform the exact `callTarget.call(callData)`.
    function executeRecovery(RecovKind kind) external nonReentrant whenNotPaused {
        RecoveryRequest storage R = _getReq(kind);
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals < THRESHOLD) revert ThresholdNotMet();

        // Execute the provided calldata on the callTarget (atomic)
        (bool ok, bytes memory ret) = R.callTarget.call(R.callData);
        if (!ok) {
            // emit failure with return data for off-chain debugging
            emit RecoveryFailed(kind, R.proposed, R.callTarget, ret);
            revert("recovery call failed");
        }

        R.executed = true;
        // clear any temp veto (not needed after success)
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
        emit RecoveryExecuted(kind, R.proposed, R.callTarget);
    }

    // ========================
    //  Last-Honest Halt & Promote (fast path)
    // ========================
    /// @notice The guardian assigned the temp veto can halt the recovery and promote standby immediately.
    function lastHonestHaltAndPromote(RecovKind kind) external whenNotPaused onlyActiveG {
        if (tempVeto.guardian == address(0)) revert("no temp veto");
        if (msg.sender != tempVeto.guardian) revert("not last honest");
        if (block.timestamp > tempVeto.expiry) revert("veto expired");

        RecoveryRequest storage R = _getReq(kind);
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();

        // verify approvals still equal GUARDIAN_COUNT - 1 for safety
        if (R.approvals != GUARDIAN_COUNT - 1) revert("approvals changed");

        // cancel request
        R.callTarget = address(0);
        R.callData = bytes("");
        R.proposed = address(0);
        R.approvals = 0;
        R.deadline = 0;
        R.executed = false;

        // clear temp veto
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;

        // promote standby to active immediately
        _activateStandby();

        emit LastHonestHalted(msg.sender, kind);
    }

    // ========================
    //  Auto-Activation Path
    // ========================
    /// @notice Anyone can trigger auto-activation of standby when locked to maintain liveness.
    function activateStandbyIfLocked() external {
        if (!locked) revert LockedErr();
        _activateStandby();
    }

    // ======== Views ========
    function getActiveGuardians() external view returns (address[GUARDIAN_COUNT] memory) {
        return activeGuardians;
    }

    function getStandbyGuardians() external view returns (address[GUARDIAN_COUNT] memory) {
        return standbyGuardians;
    }

    function getRecoveryState(RecovKind kind)
        external
        view
        returns (address proposed, uint8 approvals, uint256 deadline, bool executed, address callTarget, bytes memory callData)
    {
        RecoveryRequest storage R = _getReq(kind);
        return (R.proposed, R.approvals, R.deadline, R.executed, R.callTarget, R.callData);
    }

    function getTempVeto() external view returns (address guardian, uint256 expiry) {
        return (tempVeto.guardian, tempVeto.expiry);
    }

    // ======== Internal Helpers ========
    function _getReq(RecovKind kind) internal view returns (RecoveryRequest storage) {
        if (kind == RecovKind.DEPLOYER) return _deployerRecovery;
        return _adminRecovery;
    }

    function _resetReq(RecoveryRequest storage R, address proposed) internal {
        R.proposed = proposed;
        R.approvals = 0;
        R.deadline = block.timestamp + RECOVERY_WINDOW;
        R.executed = false;
        R.callTarget = address(0);
        R.callData = bytes("");
        // clear temp veto when a new request starts
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
        // NOTE: We don't iterate to clear `hasApproved` mapping for gas reasons.
    }

    function _seedActiveBatch(address[GUARDIAN_COUNT] memory batch) internal {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = batch[i];
            if (g == address(0)) revert ZeroAddress();
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
        }
        emit ActiveBatchSeeded(batch);
    }

    function _seedStandbyBatch(address[GUARDIAN_COUNT] memory batch) internal {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = batch[i];
            if (g == address(0)) revert ZeroAddress();
            standbyGuardians[i] = g;
            isStandbyGuardian[g] = true;
        }
        emit StandbyBatchSeeded(batch);
    }

    function _clearActive() internal {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = activeGuardians[i];
            if (g != address(0)) isActiveGuardian[g] = false;
            activeGuardians[i] = address(0);
        }
    }

    function _clearStandby() internal {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = standbyGuardians[i];
            if (g != address(0)) isStandbyGuardian[g] = false;
            standbyGuardians[i] = address(0);
        }
    }

    function _activateStandby() internal {
        _clearActive();
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = standbyGuardians[i];
            require(g != address(0), "standby not seeded");
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
            isStandbyGuardian[g] = false;
            standbyGuardians[i] = address(0);
        }
        emit StandbyActivated(activeGuardians);
    }

    // -------- UUPS gap (reserve) --------
    uint256[45] private __gap;
}

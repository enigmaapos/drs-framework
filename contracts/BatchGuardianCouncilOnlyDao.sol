// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BatchGuardianCouncil Only DAO 
 * @notice Decentralized Recovery System (DRS) with dual-batch guardian councils.
 *         - Batch-1: active guardians (7)
 *         - Batch-2: standby guardians (7) — activated automatically on lock or by DAO
 *         - 5-of-7 threshold for recovery approvals
 *         - 6/7 => warning; 7/7 => auto-lock (only DAO can act while locked)
 *         - ONLY DAO can reseed/rotate guardian batches (prevents attacker self-seeding)
 *
 * @dev Target protocol integrates by implementing IRecoverDeployer / IRecoverAdmin (or both).
 *      Council is generic and reusable across systems.
 */
interface IRecoverDeployer {
    function recoverDeployer(address newDeployer) external;
}

interface IRecoverAdmin {
    function recoverAdmin(address newAdmin) external;
}

contract BatchGuardianCouncil {
    // -------- Constants / Limits --------
    uint8 public constant GUARDIAN_COUNT = 7;
    uint8 public constant THRESHOLD = 5; // 5-of-7
    uint256 public constant RECOVERY_WINDOW = 3 days;

    // -------- Roles / Authority --------
    address public immutable target; // protected system (protocol/contracts) to receive recoveries
    address public dao;              // DAO/Multisig authority (root governance)

    // -------- Batches --------
    address[GUARDIAN_COUNT] public activeGuardians;   // Batch-1
    address[GUARDIAN_COUNT] public standbyGuardians;  // Batch-2

    mapping(address => bool) public isActiveGuardian;
    mapping(address => bool) public isStandbyGuardian;

    // -------- Lock / Compromise flags --------
    bool public locked;             // when true, only DAO can operate
    bool public warning;            // set when 6/7 approvals seen in any proposal

    // -------- Recovery proposals --------
    enum RecovKind { DEPLOYER, ADMIN }

    struct RecoveryRequest {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        // Track who approved (active guardians only)
        mapping(address => bool) hasApproved;
    }

    RecoveryRequest private _deployerRecovery;
    RecoveryRequest private _adminRecovery;

    // -------- Events --------
    event DaoChanged(address indexed oldDao, address indexed newDao);

    event ActiveBatchSeeded(address[7] guardians);
    event StandbyBatchSeeded(address[7] guardians);
    event StandbyActivated(address[7] newActive);

    event WarningRaised(RecovKind kind, uint8 approvals);
    event AutoLocked(RecovKind kind);

    event RecoveryProposed(RecovKind kind, address indexed proposer, address proposed, uint256 deadline);
    event RecoveryApproved(RecovKind kind, address indexed guardian, uint8 approvals);
    event RecoveryExecuted(RecovKind kind, address indexed proposed);

    // -------- Errors --------
    error Unauthorized();
    error ZeroAddress();
    error Locked();
    error NotGuardian();
    error AlreadyApproved();
    error NoActiveRequest();
    error RequestExpired();
    error ThresholdNotMet();
    error BadArrayLength();
    error NotActiveGuardian();
    error NotStandbyGuardian();

    // -------- Modifiers --------
    modifier onlyDAO() {
        if (msg.sender != dao) revert Unauthorized();
        _;
    }

    modifier notLocked() {
        if (locked) revert Locked();
        _;
    }

    modifier onlyActiveG() {
        if (!isActiveGuardian[msg.sender]) revert NotGuardian();
        _;
    }

    // -------- Constructor --------
    /**
     * @param _dao      DAO/Multisig root authority that can seed/rotate batches and act under lock
     * @param _target   Target contract that implements recovery interfaces (deployer/admin)
     * @param batch1    Active guardians (7)
     * @param batch2    Standby guardians (7)
     */
    constructor(address _dao, address _target, address[GUARDIAN_COUNT] memory batch1, address[GUARDIAN_COUNT] memory batch2) {
        if (_dao == address(0) || _target == address(0)) revert ZeroAddress();
        dao = _dao;
        target = _target;

        _seedActiveBatch(batch1);
        _seedStandbyBatch(batch2);
    }

    // ======== DAO Controls ========

    function setDAO(address newDAO) external onlyDAO {
        if (newDAO == address(0)) revert ZeroAddress();
        address old = dao;
        dao = newDAO;
        emit DaoChanged(old, newDAO);
    }

    /**
     * @notice DAO can fully reseed the active batch (even when locked).
     */
    function daoSeedActiveBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        _clearActive();
        _seedActiveBatch(batch);
    }

    /**
     * @notice DAO can fully reseed the standby batch (even when locked).
     */
    function daoSeedStandbyBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        _clearStandby();
        _seedStandbyBatch(batch);
    }

    /**
     * @notice DAO can manually activate the standby batch into active, then clear standby.
     */
    function daoActivateStandby() external onlyDAO {
        _activateStandby();
    }

    /**
     * @notice DAO can clear lock & warning after recovery and reseeding are completed.
     */
    function daoClearLockAndWarning() external onlyDAO {
        locked = false;
        warning = false;
    }

    // ======== Guardian Proposals (Active guardians only) ========

    function proposeRecovery(RecovKind kind, address proposed) external notLocked onlyActiveG {
        if (proposed == address(0)) revert ZeroAddress();

        RecoveryRequest storage R = _getReq(kind);
        // reset the request + approvals
        _resetReq(R, proposed);

        emit RecoveryProposed(kind, msg.sender, proposed, R.deadline);
    }

    function approveRecovery(RecovKind kind) external notLocked onlyActiveG {
        RecoveryRequest storage R = _getReq(kind);
        if (R.proposed == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.hasApproved[msg.sender]) revert AlreadyApproved();

        R.hasApproved[msg.sender] = true;
        R.approvals += 1;

        // Raise early warnings and locks
        if (R.approvals == 6 && !warning) {
            warning = true;
            emit WarningRaised(kind, R.approvals);
        }
        if (R.approvals == 7 && !locked) {
            locked = true;
            emit AutoLocked(kind);
        }

        emit RecoveryApproved(kind, msg.sender, R.approvals);
    }

    function executeRecovery(RecovKind kind) external notLocked onlyActiveG {
        RecoveryRequest storage R = _getReq(kind);
        if (R.proposed == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals < THRESHOLD) revert ThresholdNotMet();

        // Call target
        if (kind == RecovKind.DEPLOYER) {
            IRecoverDeployer(target).recoverDeployer(R.proposed);
        } else {
            IRecoverAdmin(target).recoverAdmin(R.proposed);
        }

        R.executed = true;
        emit RecoveryExecuted(kind, R.proposed);
    }

    // ======== Auto-Activation Path ========

    /**
     * @notice Anyone can trigger auto-activation of standby when locked.
     *         This keeps recovery liveness even if DAO is slow — *but*
     *         only the DAO can reseed afterwards, preserving root authority.
     */
    function activateStandbyIfLocked() external {
        if (!locked) revert Locked(); // reuse Locked error for "not locked"
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
        returns (address proposed, uint8 approvals, uint256 deadline, bool executed)
    {
        RecoveryRequest storage R = _getReq(kind);
        return (R.proposed, R.approvals, R.deadline, R.executed);
    }

    // ======== Internal Helpers ========

    function _getReq(RecovKind kind) internal view returns (RecoveryRequest storage) {
        if (kind == RecovKind.DEPLOYER) return _deployerRecovery;
        return _adminRecovery;
    }

    function _resetReq(RecoveryRequest storage R, address proposed) internal {
        // reset storage (mapping cannot be zeroed wholesale; approvals cleared lazily)
        R.proposed = proposed;
        R.approvals = 0;
        R.deadline = block.timestamp + RECOVERY_WINDOW;
        R.executed = false;

        // NOTE: We deliberately avoid iterating activeGuardians to clear approvals mapping
        //       to keep gas predictable. Re-approval attempts will fail due to mapping check
        //       being overwritten only for newly approving guardians in this round.
        //       Different request key (new deadline/proposed) implies fresh round logically.
        //       (If you want hard reset, add a per-request nonce and include it in hasApproved key.)
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
        // Move standby => active
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

        // Keep contract in locked or unlocked state as-is.
        // Typically DAO will clear lock after reseeding or once safe.
    }
}

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
    uint256 public constant DAO_COMMIT_WINDOW = 7 days;

    // -------- Roles / Authority --------
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");

    address public dao;
    address private _pendingDAO;
    uint256 private _daoCommitExpiry;

    // -------- Batches --------
    address[GUARDIAN_COUNT] public activeGuardians;
    address[GUARDIAN_COUNT] public standbyGuardians;

    mapping(address => bool) public isActiveGuardian;
    mapping(address => bool) public isStandbyGuardian;

    address[GUARDIAN_COUNT] private _pendingActiveBatch;
    uint256 private _activeBatchCommitExpiry;

    address[GUARDIAN_COUNT] private _pendingStandbyBatch;
    uint256 private _standbyBatchCommitExpiry;

    // -------- Flags --------
    bool public locked;
    bool public warning;

    // -------- Recovery --------
    enum RecovKind { DEPLOYER, ADMIN }

    struct RecoveryRequest {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        address callTarget;
        bytes callData;
        mapping(address => bool) hasApproved;
    }
    
    // Using a mapping for robustness
    mapping(RecovKind => RecoveryRequest) private _recoveryRequests;

    // -------- Last-Honest Veto --------
    struct TempVeto {
        address guardian;
        uint256 expiry;
    }
    TempVeto public tempVeto;

    // -------- Events --------
    event DaoChangeProposed(address indexed proposer, address indexed newDao);
    event DaoChanged(address indexed oldDao, address indexed newDao);
    event ActiveBatchSeeded(address[GUARDIAN_COUNT] guardians);
    event ActiveBatchProposed(address[GUARDIAN_COUNT] guardians);
    event StandbyBatchSeeded(address[GUARDIAN_COUNT] guardians);
    event StandbyBatchProposed(address[GUARDIAN_COUNT] guardians);
    event StandbyActivated(address[GUARDIAN_COUNT] newActive);
    event WarningRaised(RecovKind kind, uint8 approvals);
    event AutoLocked(RecovKind kind);
    event RecoveryProposed(RecovKind kind, address indexed proposer, address proposed, address callTarget, uint256 deadline);
    event RecoveryApproved(RecovKind kind, address indexed guardian, uint8 approvals);
    event RecoveryExecuted(RecovKind kind, address indexed proposed, address callTarget);
    event RecoveryFailed(RecovKind kind, address indexed proposer, address callTarget, bytes returnData);
    event LastHonestAssigned(address indexed guardian, uint256 expiry);
    event LastHonestHalted(address indexed guardian, RecovKind kind);

    // -------- Errors --------
    error Unauthorized();
    error ZeroAddress();
    error LockedErr();
    error NotGuardian();
    error AlreadyApproved();
    error NoActiveRequest();
    error RequestExpired();
    error ThresholdNotMet();
    error BadArrayLength();
    error NoPendingUpdate();
    error CommitDeadlineNotMet();

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

    // -------- Init --------
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

        _grantRole(DEFAULT_ADMIN_ROLE, dao_);
        _grantRole(DAO_ROLE, dao_);
        dao = dao_;

        _seedActiveBatch(batchActive);
        _seedStandbyBatch(batchStandby);

        locked = false;
        warning = false;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
    }

    function _authorizeUpgrade(address) internal override onlyDAO {}

    // -------- DAO Controls (Two-Step Authorization) --------
    function proposeNewDAO(address newDAO) external onlyDAO {
        require(newDAO != address(0), "zero address");
        _pendingDAO = newDAO;
        _daoCommitExpiry = block.timestamp + DAO_COMMIT_WINDOW;
        emit DaoChangeProposed(msg.sender, newDAO);
    }

    function commitNewDAO() external {
        require(msg.sender == _pendingDAO, "not proposed DAO");
        require(_pendingDAO != address(0), "no pending DAO");
        require(block.timestamp <= _daoCommitExpiry, "commit window expired");
        
        address old = dao;
        _grantRole(DEFAULT_ADMIN_ROLE, _pendingDAO);
        _grantRole(DAO_ROLE, _pendingDAO);
        _revokeRole(DAO_ROLE, dao);
        _revokeRole(DEFAULT_ADMIN_ROLE, dao);
        dao = _pendingDAO;
        _pendingDAO = address(0);
        _daoCommitExpiry = 0;
        
        emit DaoChanged(old, dao);
    }
    
    function daoProposeSeedActiveBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            if (batch[i] == address(0)) revert ZeroAddress();
            _pendingActiveBatch[i] = batch[i];
        }
        _activeBatchCommitExpiry = block.timestamp + DAO_COMMIT_WINDOW;
        emit ActiveBatchProposed(batch);
    }

    function daoCommitSeedActiveBatch() external onlyDAO {
        require(block.timestamp > _activeBatchCommitExpiry, "commit window active");
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            require(_pendingActiveBatch[i] != address(0), "no pending batch");
        }
        _clearActive();
        _seedActiveBatch(_pendingActiveBatch);
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            _pendingActiveBatch[i] = address(0);
        }
    }
    
    function daoProposeSeedStandbyBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            if (batch[i] == address(0)) revert ZeroAddress();
            _pendingStandbyBatch[i] = batch[i];
        }
        _standbyBatchCommitExpiry = block.timestamp + DAO_COMMIT_WINDOW;
        emit StandbyBatchProposed(batch);
    }

    function daoCommitSeedStandbyBatch() external onlyDAO {
        require(block.timestamp > _standbyBatchCommitExpiry, "commit window active");
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            require(_pendingStandbyBatch[i] != address(0), "no pending batch");
        }
        _clearStandby();
        _seedStandbyBatch(_pendingStandbyBatch);
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            _pendingStandbyBatch[i] = address(0);
        }
    }

    function daoActivateStandby() external onlyDAO {
        _activateStandby();
    }

    function daoClearLockAndWarning() external onlyDAO {
        locked = false;
        warning = false;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
    }

    // -------- Recovery Proposals --------
    function proposeRecovery(
    RecovKind kind,
    address proposed,
    address callTarget,
    bytes calldata callData
) external notLocked onlyActiveG whenNotPaused {
    // --- CHECKS ---
    if (callTarget == address(0) || callData.length == 0) revert ZeroAddress();

    // --- EFFECTS ---
    _requestNonce[kind] += 1;
    uint256 nonce = _requestNonce[kind];

    RecoveryRequest storage R = _recoveryRequests[kind];
    R.proposed = proposed;
    R.approvals = 1; // proposer auto-approves
    R.deadline = block.timestamp + RECOVERY_WINDOW;
    R.executed = false;
    R.callTarget = callTarget;
    R.callData = callData;

    _lastApprovedNonce[kind][msg.sender] = nonce;

    // --- INTERACTIONS (events/logging only) ---
    emit RecoveryProposed(kind, msg.sender, proposed, callTarget, R.deadline);
    emit RecoveryApproved(kind, msg.sender, R.approvals);
}

    function approveRecovery(RecovKind kind) external notLocked onlyActiveG whenNotPaused {
    // --- CHECKS ---
    RecoveryRequest storage R = _recoveryRequests[kind];
    if (R.callTarget == address(0)) revert NoActiveRequest();
    if (R.executed) revert AlreadyExecuted();
    if (block.timestamp > R.deadline) revert RequestExpired();

    uint256 nonce = _requestNonce[kind];
    if (_lastApprovedNonce[kind][msg.sender] == nonce) revert AlreadyApproved();

    // --- EFFECTS ---
    _lastApprovedNonce[kind][msg.sender] = nonce;
    R.approvals += 1;

    address last = address(0);
    if (R.approvals == GUARDIAN_COUNT - 1) {
        for (uint256 i; i < GUARDIAN_COUNT; ++i) {
            address g = activeGuardians[i];
            if (_lastApprovedNonce[kind][g] != nonce) {
                last = g;
                break;
            }
        }
        if (last != address(0)) {
            tempVeto.guardian = last;
            tempVeto.expiry = block.timestamp + LAST_HONEST_VETO_WINDOW;
        }
    }

    // --- INTERACTIONS (events/logging only) ---
    emit RecoveryApproved(kind, msg.sender, R.approvals);
    if (last != address(0)) {
        emit LastHonestAssigned(last, tempVeto.expiry);
    }
}

    function executeRecovery(RecovKind kind) external nonReentrant whenNotPaused {
        RecoveryRequest storage R = _recoveryRequests[kind];

        // Checks
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals < THRESHOLD) revert ThresholdNotMet();

        // Effects (all state changes happen before the external call)
        R.executed = true;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
        
        // Interactions
        (bool ok, bytes memory ret) = R.callTarget.call(R.callData);
        if (!ok) {
            emit RecoveryFailed(kind, R.proposed, R.callTarget, ret);
            revert("recovery call failed");
        }
        emit RecoveryExecuted(kind, R.proposed, R.callTarget);
    }

    function lastHonestHaltAndPromote(RecovKind kind) external whenNotPaused onlyActiveG {
        if (tempVeto.guardian == address(0)) revert("no temp veto");
        if (msg.sender != tempVeto.guardian) revert("not last honest");
        if (block.timestamp > tempVeto.expiry) revert("veto expired");

        RecoveryRequest storage R = _recoveryRequests[kind];
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyApproved();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals != GUARDIAN_COUNT - 1) revert("approvals changed");
        
        // Resetting the request
        delete _recoveryRequests[kind];

        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;

        _activateStandby();
        emit LastHonestHalted(msg.sender, kind);
    }

    function activateStandbyIfLocked() external {
        if (!locked) revert LockedErr();
        _activateStandby();
    }

    // -------- Views --------
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
        RecoveryRequest storage R = _recoveryRequests[kind];
        return (R.proposed, R.approvals, R.deadline, R.executed, R.callTarget, R.callData);
    }

    function getTempVeto() external view returns (address guardian, uint256 expiry) {
        return (tempVeto.guardian, tempVeto.expiry);
    }

    // -------- Internals --------
    function _resetReq(RecoveryRequest storage R, address proposed) internal {
        // Resetting the mapping entry is tricky, so we'll just overwrite the values
        R.proposed = proposed;
        R.approvals = 0;
        R.deadline = block.timestamp + RECOVERY_WINDOW;
        R.executed = false;
        R.callTarget = address(0);
        R.callData = "";
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
        // The mapping for hasApproved[address] is not cleared here for efficiency,
        // it will be correctly reset by the hasApproved[msg.sender] check in the next proposal.
    }

    function _seedActiveBatch(address[GUARDIAN_COUNT] memory batch) internal {
        for (uint256 i; i < GUARDIAN_COUNT; ++i) {
            address g = batch[i];
            if (g == address(0)) revert ZeroAddress();
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
        }
        emit ActiveBatchSeeded(batch);
    }

    function _seedStandbyBatch(address[GUARDIAN_COUNT] memory batch) internal {
        for (uint256 i; i < GUARDIAN_COUNT; ++i) {
            address g = batch[i];
            if (g == address(0)) revert ZeroAddress();
            standbyGuardians[i] = g;
            isStandbyGuardian[g] = true;
        }
        emit StandbyBatchSeeded(batch);
    }

    function _clearActive() internal {
        for (uint256 i; i < GUARDIAN_COUNT; ++i) {
            address g = activeGuardians[i];
            if (g != address(0)) isActiveGuardian[g] = false;
            activeGuardians[i] = address(0);
        }
    }

    function _clearStandby() internal {
        for (uint256 i; i < GUARDIAN_COUNT; ++i) {
            address g = standbyGuardians[i];
            if (g != address(0)) isStandbyGuardian[g] = false;
            standbyGuardians[i] = address(0);
        }
    }

    function _activateStandby() internal {
        _clearActive();
        for (uint256 i; i < GUARDIAN_COUNT; ++i) {
            address g = standbyGuardians[i];
            require(g != address(0), "standby not seeded");
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
            isStandbyGuardian[g] = false;
            standbyGuardians[i] = address(0);
        }
        emit StandbyActivated(activeGuardians);
    }

// --- added for nonce approach ---
mapping(RecovKind => uint256) private _requestNonce;
mapping(RecovKind => mapping(address => uint256)) private _lastApprovedNonce;
// --- end added ---
    
    uint256[44] private __gap;
}

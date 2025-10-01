// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
  BatchGuardianCouncilUpgradeable (Admin-only recovery track)
  - UUPS upgradeable
  - Two batches (active, standby) of fixed GUARDIAN_COUNT (7)
  - DAO-managed reseed/rotate (two-step: propose -> commit window)
  - Recovery proposals carry (callTarget, callData) executed atomically
  - 5/7 threshold; 6/7 => warning + last-honest veto; 7/7 => lock + auto-activate standby
  - Last-honest guardian gets 48h veto to halt & promote standby
*/

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";

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
    uint256 public constant COMMIT_DELAY = 1 days; // simple timelock before commit


    // -------- Roles / Authority --------
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");

    address public dao;
    address private _pendingDAO;
    uint256 private _daoCommitEarliest;
    uint256 private _daoCommitDeadline;

    // -------- Batches --------
    address[GUARDIAN_COUNT] public activeGuardians;
    address[GUARDIAN_COUNT] public standbyGuardians;

    mapping(address => bool) public isActiveGuardian;
    mapping(address => bool) public isStandbyGuardian;

    address[GUARDIAN_COUNT] private _pendingActiveBatch;
    uint256 private _activeBatchCommitEarliest;
    uint256 private _activeBatchCommitDeadline;

    address[GUARDIAN_COUNT] private _pendingStandbyBatch;
    uint256 private _standbyBatchCommitEarliest;
    uint256 private _standbyBatchCommitDeadline;

    // -------- Flags --------
    bool public locked;
    bool public warning;

// --- NEW TIMELOCK CONSTANT ---
uint256 public constant EXECUTION_TIMELOCK = 4 hours; // Example: 4 hours delay after approval


    // -------- Recovery (Admin-only) --------
    struct RecoveryRequest {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        address callTarget;
        bytes callData;

uint256 readyToExecuteTimestamp; // When the timelock expires
    }

    RecoveryRequest private _adminRecovery;
    uint256 private _adminRequestNonce;
    mapping(address => uint256) private _lastApprovedNonceAdmin;

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

    // Recovery flow events (Admin-only, no kind arg)
    event WarningRaised(uint8 approvals);
    event AutoLocked();
    event RecoveryProposed(address indexed proposer, address proposed, address callTarget, uint256 deadline);
    event RecoveryApproved(address indexed guardian, uint8 approvals);
    event RecoveryExecuted(address indexed proposed, address callTarget);
    event RecoveryFailed(address indexed proposer, address callTarget, bytes returnData);
    event LastHonestAssigned(address indexed guardian, uint256 expiry);
    event LastHonestHalted(address indexed guardian);
    event RecoveryReset(uint256 newNonce);
event RecoveryReadyForExecution(
    uint256 indexed nonce, 
    uint256 timelockExpiry
);

    // -------- Errors --------
    error Unauthorized();
    error ZeroAddress();
    error LockedErr();
    error NotGuardian();
    error AlreadyExecuted();
    error AlreadyApproved();
    error NoActiveRequest();
    error RequestExpired();
    error ThresholdNotMet();
    error BadArrayLength();
    error NoPendingUpdate();
    error CommitTooEarly();
    error CommitTooLate();
    error InvalidCallTarget();
    error InvalidCallData();
    error CallFailed(bytes reason);
    error NotLastHonest();
    error VetoExpired();
    error DuplicateGuardian();
    error OverlapGuardian();

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

        // initialize admin recovery to zero (delete semantics)
        delete _adminRecovery;
        _adminRequestNonce = 0;
    }

    function _authorizeUpgrade(address) internal override onlyDAO {}

    // -------- DAO Controls (Two-Step Authorization) --------
    function proposeNewDAO(address newDAO) external onlyDAO {
        if (newDAO == address(0)) revert ZeroAddress();
        _pendingDAO = newDAO;
        _daoCommitEarliest = block.timestamp + COMMIT_DELAY;
        _daoCommitDeadline = _daoCommitEarliest + DAO_COMMIT_WINDOW;
        emit DaoChangeProposed(msg.sender, newDAO);
    }

    function commitNewDAO() external {
        if (msg.sender != _pendingDAO) revert Unauthorized();
        if (_pendingDAO == address(0)) revert NoPendingUpdate();
        if (block.timestamp < _daoCommitEarliest) revert CommitTooEarly();
        if (block.timestamp > _daoCommitDeadline) revert CommitTooLate();

        address old = dao;
        _grantRole(DEFAULT_ADMIN_ROLE, _pendingDAO);
        _grantRole(DAO_ROLE, _pendingDAO);
        _revokeRole(DAO_ROLE, dao);
        _revokeRole(DEFAULT_ADMIN_ROLE, dao);
        dao = _pendingDAO;
        _pendingDAO = address(0);
        _daoCommitEarliest = 0;
        _daoCommitDeadline = 0;

        emit DaoChanged(old, dao);
    }

    function daoProposeSeedActiveBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        _validateBatchArray(batch);
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            _pendingActiveBatch[i] = batch[i];
        }
        _activeBatchCommitEarliest = block.timestamp + COMMIT_DELAY;
        _activeBatchCommitDeadline = _activeBatchCommitEarliest + DAO_COMMIT_WINDOW;
        emit ActiveBatchProposed(batch);
    }

    function daoCommitSeedActiveBatch() external onlyDAO {
        if (block.timestamp < _activeBatchCommitEarliest) revert CommitTooEarly();
        if (block.timestamp > _activeBatchCommitDeadline) revert CommitTooLate();
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            if (_pendingActiveBatch[i] == address(0)) revert NoPendingUpdate();
        }
        _clearActive();
        _seedActiveBatch(_pendingActiveBatch);
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            _pendingActiveBatch[i] = address(0);
        }
        _activeBatchCommitEarliest = 0;
        _activeBatchCommitDeadline = 0;
    }

    function daoProposeSeedStandbyBatch(address[GUARDIAN_COUNT] calldata batch) external onlyDAO {
        _validateBatchArray(batch);
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            _pendingStandbyBatch[i] = batch[i];
        }
        _standbyBatchCommitEarliest = block.timestamp + COMMIT_DELAY;
        _standbyBatchCommitDeadline = _standbyBatchCommitEarliest + DAO_COMMIT_WINDOW;
        emit StandbyBatchProposed(batch);
    }

    function daoCommitSeedStandbyBatch() external onlyDAO {
        if (block.timestamp < _standbyBatchCommitEarliest) revert CommitTooEarly();
        if (block.timestamp > _standbyBatchCommitDeadline) revert CommitTooLate();
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            if (_pendingStandbyBatch[i] == address(0)) revert NoPendingUpdate();
        }
        _clearStandby();
        _seedStandbyBatch(_pendingStandbyBatch);
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            _pendingStandbyBatch[i] = address(0);
        }
        _standbyBatchCommitEarliest = 0;
        _standbyBatchCommitDeadline = 0;
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

    // -------- Pause controls --------
    function pause() external onlyDAO {
        _pause();
    }

    function unpause() external onlyDAO {
        _unpause();
    }

    // -------- Recovery Proposals (Admin-only) --------
    function proposeRecovery(
        address proposed,
        address callTarget,
        bytes calldata callData
    ) external notLocked onlyActiveG whenNotPaused {
        if (callTarget == address(0)) revert InvalidCallTarget();
        if (callData.length == 0) revert InvalidCallData();
        if (proposed == address(0)) revert ZeroAddress();

        // increment nonce to invalidate previous approvals
        _adminRequestNonce += 1;
        uint256 nonce = _adminRequestNonce;

        RecoveryRequest storage R = _adminRecovery;
        R.proposed = proposed;
        R.approvals = 1; // proposer auto-approves
        R.deadline = block.timestamp + RECOVERY_WINDOW;
        R.executed = false;
        R.callTarget = callTarget;
        R.callData = callData;

        _lastApprovedNonceAdmin[msg.sender] = nonce;

        emit RecoveryProposed(msg.sender, proposed, callTarget, R.deadline);
        emit RecoveryApproved(msg.sender, R.approvals);
    }

    function approveRecovery() external notLocked onlyActiveG whenNotPaused {
    RecoveryRequest storage R = _adminRecovery;
    if (R.callTarget == address(0)) revert NoActiveRequest();
    if (R.executed) revert AlreadyExecuted();
    if (block.timestamp > R.deadline) revert RequestExpired();

    uint256 nonce = _adminRequestNonce;
    if (_lastApprovedNonceAdmin[msg.sender] == nonce) revert AlreadyApproved();

    _lastApprovedNonceAdmin[msg.sender] = nonce;
    R.approvals += 1;

    // --- NEW LOGIC: START EXECUTION TIMELOCK AT THRESHOLD (5/7) ---
    // If 5 approvals are reached, set the time when the proposal can be executed.
    if (R.approvals == THRESHOLD) {
        // R.readyToExecuteTimestamp is a new field in RecoveryRequest struct
        // EXECUTION_TIMELOCK is a new constant (e.g., 4 hours)
        R.readyToExecuteTimestamp = block.timestamp + EXECUTION_TIMELOCK;
        
        // Emit event to notify off-chain systems that execution timelock has started
        // assuming this new event exists: event RecoveryReadyForExecution(uint256 indexed nonce, uint256 timelockExpiry);
        emit RecoveryReadyForExecution(nonce, R.readyToExecuteTimestamp);
    }
    // ---------------------------------------------------------------------

    address last = address(0);
    if (R.approvals == GUARDIAN_COUNT - 1) { // 6/7
        // find missing guardian to assign last-honest
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = activeGuardians[i];
            if (_lastApprovedNonceAdmin[g] != nonce) {
                last = g;
                break;
            }
        }
        if (last != address(0)) {
            tempVeto.guardian = last;
            tempVeto.expiry = block.timestamp + LAST_HONEST_VETO_WINDOW;
            warning = true;
            emit WarningRaised(R.approvals);
            emit LastHonestAssigned(last, tempVeto.expiry);
        }
    }

    // handle unanimous approvals (7/7)
    if (R.approvals >= GUARDIAN_COUNT) {
        // lock and auto-activate standby per spec
        locked = true;
        emit AutoLocked();
        
        delete _adminRecovery;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
        
        _activateStandby();
        
        _adminRequestNonce += 1;
        emit RecoveryReset(_adminRequestNonce);
        return;
    }

    emit RecoveryApproved(msg.sender, R.approvals);
}

function executeRecovery() external nonReentrant whenNotPaused {
    RecoveryRequest storage R = _adminRecovery;

    if (R.callTarget == address(0)) revert NoActiveRequest();
    if (R.executed) revert AlreadyExecuted();
    if (block.timestamp > R.deadline) revert RequestExpired();
    if (R.approvals < THRESHOLD) revert ThresholdNotMet();

    // --- EXECUTION TIMELOCK ENFORCEMENT (NEW LINE) ---
    // The R.readyToExecuteTimestamp was set in approveRecovery() when R.approvals == THRESHOLD (5/7)
    require(
        block.timestamp >= R.readyToExecuteTimestamp, 
        "DRS: Execution Timelock not expired"
    );
    // --------------------------------------------------

    // Effects
    R.executed = true;
    tempVeto.guardian = address(0);
    tempVeto.expiry = 0;

    // Interaction
    (bool ok, bytes memory ret) = R.callTarget.call(R.callData);
    if (!ok) {
        // revert with custom error including returned bytes
        revert CallFailed(ret);
    }

    emit RecoveryExecuted(R.proposed, R.callTarget);
    delete _adminRecovery;
    _adminRequestNonce += 1;
    emit RecoveryReset(_adminRequestNonce);
}
    

    function lastHonestHaltAndPromote() external whenNotPaused onlyActiveG {
        if (tempVeto.guardian == address(0)) revert NoActiveRequest();
        if (msg.sender != tempVeto.guardian) revert NotLastHonest();
        if (block.timestamp > tempVeto.expiry) revert VetoExpired();

        RecoveryRequest storage R = _adminRecovery;
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyExecuted();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals != GUARDIAN_COUNT - 1) revert ThresholdNotMet();

        // Resetting the request
        delete _adminRecovery;

        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;

        // Promote standby to active
        _activateStandby();
        warning = false; // clear warning after this action
        emit LastHonestHalted(msg.sender);
        // bump nonce to prevent reuse
        _adminRequestNonce += 1;
        emit RecoveryReset(_adminRequestNonce);
    }

    // Only DAO may activate standby if locked (explicit healing path)
    function activateStandbyIfLocked() external onlyDAO {
        if (!locked) revert LockedErr();
        _activateStandby();
        // clear lock/warning state after activation to allow recovery
        locked = false;
        warning = false;
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
    }

    // -------- Views --------
    function getActiveGuardians() external view returns (address[GUARDIAN_COUNT] memory) {
        return activeGuardians;
    }

    function getStandbyGuardians() external view returns (address[GUARDIAN_COUNT] memory) {
        return standbyGuardians;
    }

    function getLastHonestGuardian() external view returns (address) {
        return tempVeto.guardian;
    }

    function getLastHonestExpiry() external view returns (uint256) {
        return tempVeto.expiry;
    }

    function getWarningFlag() external view returns (bool) {
        return warning;
    }

    // External tuple getter for the admin recovery
    function getRecoveryState()
        external
        view
        returns (
            address proposed,
            uint8 approvals,
            uint256 deadline,
            bool executed,
            address callTarget,
            bytes memory callData
        )
    {
        RecoveryRequest storage R = _adminRecovery;
        return (R.proposed, R.approvals, R.deadline, R.executed, R.callTarget, R.callData);
    }

    // Individual getters
    function getRecoveryProposed() external view returns (address) {
        return _adminRecovery.proposed;
    }

    function getRecoveryApprovals() external view returns (uint8) {
        return _adminRecovery.approvals;
    }

    function getRecoveryDeadline() external view returns (uint256) {
        return _adminRecovery.deadline;
    }

    function getRecoveryExecuted() external view returns (bool) {
        return _adminRecovery.executed;
    }

    function getRecoveryCallTarget() external view returns (address) {
        return _adminRecovery.callTarget;
    }

    function getRecoveryCallData() external view returns (bytes memory) {
        return _adminRecovery.callData;
    }

    function getPendingDAOState()
        external
        view
        returns (address pendingDAO, uint256 commitEarliest, uint256 commitDeadline)
    {
        return (_pendingDAO, _daoCommitEarliest, _daoCommitDeadline);
    }

    function getPendingActiveBatchState()
        external
        view
        returns (address[GUARDIAN_COUNT] memory pendingBatch, uint256 commitEarliest, uint256 commitDeadline)
    {
        return (_pendingActiveBatch, _activeBatchCommitEarliest, _activeBatchCommitDeadline);
    }

    function getPendingStandbyBatchState()
        external
        view
        returns (address[GUARDIAN_COUNT] memory pendingBatch, uint256 commitEarliest, uint256 commitDeadline)
    {
        return (_pendingStandbyBatch, _standbyBatchCommitEarliest, _standbyBatchCommitDeadline);
    }

    function getAdminRequestNonce() external view returns (uint256) {
        return _adminRequestNonce;
    }

    function hasApproved(address guardian) external view returns (bool) {
        return _lastApprovedNonceAdmin[guardian] == _adminRequestNonce;
    }

    // -------- Internals --------
    function _seedActiveBatch(address[GUARDIAN_COUNT] memory batch) internal {
        _ensureNoDuplicates(batch);
        _ensureNoOverlapWithStandby(batch);

        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = batch[i];
            if (g == address(0)) revert ZeroAddress();
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
        }
        emit ActiveBatchSeeded(batch);
    }

    function _seedStandbyBatch(address[GUARDIAN_COUNT] memory batch) internal {
        _ensureNoDuplicates(batch);
        _ensureNoOverlapWithActive(batch);

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
        // clear active and move standby into active
        _clearActive();
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            address g = standbyGuardians[i];
            if (g == address(0)) revert ZeroAddress(); // standby must be seeded
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
            isStandbyGuardian[g] = false;
            standbyGuardians[i] = address(0);
        }
        emit StandbyActivated(activeGuardians);
    }

    // Validate batch param not zero and duplicates check
    function _validateBatchArray(address[GUARDIAN_COUNT] calldata /*batch*/) internal pure {
        // array length is guaranteed by type; placeholder for future dynamic-array use
    }

    function _ensureNoDuplicates(address[GUARDIAN_COUNT] memory batch) internal pure {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            for (uint256 j = i + 1; j < GUARDIAN_COUNT; ++j) {
                if (batch[i] == batch[j]) revert DuplicateGuardian();
            }
        }
    }

    function _ensureNoOverlapWithStandby(address[GUARDIAN_COUNT] memory batch) internal view {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            for (uint256 j = 0; j < GUARDIAN_COUNT; ++j) {
                if (batch[i] != address(0) && standbyGuardians[j] != address(0) && batch[i] == standbyGuardians[j]) {
                    revert OverlapGuardian();
                }
            }
        }
    }

    function _ensureNoOverlapWithActive(address[GUARDIAN_COUNT] memory batch) internal view {
        for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
            for (uint256 j = 0; j < GUARDIAN_COUNT; ++j) {
                if (batch[i] != address(0) && activeGuardians[j] != address(0) && batch[i] == activeGuardians[j]) {
                    revert OverlapGuardian();
                }
            }
        }
    }

// In any contract inheriting AccessControlUpgradeable (e.g., BatchGuardianCouncilUpgradeable.sol)

function grantRole(bytes32 role, address account) public virtual override {
    revert("Unauthorized: Direct role granting is disabled.");
}

function revokeRole(bytes32 role, address account) public virtual override {
    revert("Unauthorized: Direct role revocation is disabled.");
}

function renounceRole(bytes32 role, address account) public virtual override {
    revert("Unauthorized: Direct role renouncement is disabled.");
}

    uint256[44] private __gap;
}

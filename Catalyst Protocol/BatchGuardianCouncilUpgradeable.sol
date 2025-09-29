// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
  BatchGuardianCouncilUpgradeable
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

    // -------- Recovery --------
    enum RecovKind { DEPLOYER, ADMIN }

    struct RecoveryRequest {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        address callTarget;
        bytes callData;
        // removed nested mapping(hasApproved) in favor of nonce-based approach
    }

    // Using a mapping for robustness
    mapping(RecovKind => RecoveryRequest) private _recoveryRequests;

    // -------- Last-Honest Veto --------
    struct TempVeto {
        address guardian;
        uint256 expiry;
    }
    TempVeto public tempVeto;

    // -------- Nonces (nonce-based approval tracking) --------
    mapping(RecovKind => uint256) private _requestNonce;
    mapping(RecovKind => mapping(address => uint256)) private _lastApprovedNonce;

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
    event RecoveryReset(RecovKind kind, uint256 newNonce);

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

    // -------- Recovery Proposals --------
    function proposeRecovery(
        RecovKind kind,
        address proposed,
        address callTarget,
        bytes calldata callData
    ) external notLocked onlyActiveG whenNotPaused {
        if (callTarget == address(0)) revert InvalidCallTarget();
        if (callData.length == 0) revert InvalidCallData();

        // increment nonce to invalidate previous approvals
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

        emit RecoveryProposed(kind, msg.sender, proposed, callTarget, R.deadline);
        emit RecoveryApproved(kind, msg.sender, R.approvals);
    }

    function approveRecovery(RecovKind kind) external notLocked onlyActiveG whenNotPaused {
        RecoveryRequest storage R = _recoveryRequests[kind];
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyExecuted();
        if (block.timestamp > R.deadline) revert RequestExpired();

        uint256 nonce = _requestNonce[kind];
        if (_lastApprovedNonce[kind][msg.sender] == nonce) revert AlreadyApproved();

        _lastApprovedNonce[kind][msg.sender] = nonce;
        R.approvals += 1;

        address last = address(0);
        if (R.approvals == GUARDIAN_COUNT - 1) {
            // find missing guardian to assign last-honest
            for (uint256 i = 0; i < GUARDIAN_COUNT; ++i) {
                address g = activeGuardians[i];
                if (_lastApprovedNonce[kind][g] != nonce) {
                    last = g;
                    break;
                }
            }
            if (last != address(0)) {
                tempVeto.guardian = last;
                tempVeto.expiry = block.timestamp + LAST_HONEST_VETO_WINDOW;
                warning = true;
                emit WarningRaised(kind, R.approvals);
                emit LastHonestAssigned(last, tempVeto.expiry);
            }
        }

        // handle unanimous approvals (7/7)
        if (R.approvals >= GUARDIAN_COUNT) {
            // lock and auto-activate standby per spec
            locked = true;
            emit AutoLocked(kind);
            // clear request before activating standby to avoid dangling request state
            delete _recoveryRequests[kind];
            tempVeto.guardian = address(0);
            tempVeto.expiry = 0;
            // activate standby; will clear standby array into active
            _activateStandby();
            // increment nonce to avoid re-approvals on the deleted request
            _requestNonce[kind] += 1;
            emit RecoveryReset(kind, _requestNonce[kind]);
            return;
        }

        emit RecoveryApproved(kind, msg.sender, R.approvals);
    }

    function executeRecovery(RecovKind kind) external nonReentrant whenNotPaused {
        RecoveryRequest storage R = _recoveryRequests[kind];

        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyExecuted();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals < THRESHOLD) revert ThresholdNotMet();

        // Effects
        R.executed = true;
        // clear veto
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;

        // Interactions: low-level call and bubble revert reasons if any
        (bool ok, bytes memory ret) = R.callTarget.call(R.callData);
        if (!ok) {
            emit RecoveryFailed(kind, R.proposed, R.callTarget, ret);
            // bubble revert reason:
            assembly {
                let returndata_size := mload(ret)
                revert(add(ret, 32), returndata_size)
            }
        }

        // Success: clear the request to avoid stale state
        emit RecoveryExecuted(kind, R.proposed, R.callTarget);
        delete _recoveryRequests[kind];
        // bump nonce to invalidate previous approvals (safety)
        _requestNonce[kind] += 1;
        emit RecoveryReset(kind, _requestNonce[kind]);
    }

    function lastHonestHaltAndPromote(RecovKind kind) external whenNotPaused onlyActiveG {
        if (tempVeto.guardian == address(0)) revert NoActiveRequest();
        if (msg.sender != tempVeto.guardian) revert NotLastHonest();
        if (block.timestamp > tempVeto.expiry) revert VetoExpired();

        RecoveryRequest storage R = _recoveryRequests[kind];
        if (R.callTarget == address(0)) revert NoActiveRequest();
        if (R.executed) revert AlreadyExecuted();
        if (block.timestamp > R.deadline) revert RequestExpired();
        if (R.approvals != GUARDIAN_COUNT - 1) revert ThresholdNotMet();

        // Resetting the request
        delete _recoveryRequests[kind];

        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;

        // Promote standby to active
        _activateStandby();
        warning = false; // clear warning after this action
        emit LastHonestHalted(msg.sender, kind);
        // bump nonce to prevent reuse
        _requestNonce[kind] += 1;
        emit RecoveryReset(kind, _requestNonce[kind]);
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

function getPendingDAOState()
    external
    view
    returns (address pendingDAO, uint256 commitEarliest, uint256 commitDeadline)
{
    return (_pendingDAO, _daoCommitEarliest, _daoCommitDeadline);
}

function getRecoveryProposed(uint8 kind) external view returns (address) {
    return recoveryState[kind].proposed;
}

function getRecoveryApprovals(uint8 kind) external view returns (uint8) {
    return recoveryState[kind].approvals;
}

function getRecoveryDeadline(uint8 kind) external view returns (uint256) {
    return recoveryState[kind].deadline;
}

function getRecoveryExecuted(uint8 kind) external view returns (bool) {
    return recoveryState[kind].executed;
}

function getRecoveryCallTarget(uint8 kind) external view returns (address) {
    return recoveryState[kind].callTarget;
}

function getRecoveryCallData(uint8 kind) external view returns (bytes memory) {
    return recoveryState[kind].callData;
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

function getRequestNonce(RecovKind kind) external view returns (uint256) {
    return _requestNonce[kind];
}

function hasApproved(RecovKind kind, address guardian) external view returns (bool) {
    return _lastApprovedNonce[kind][guardian] == _requestNonce[kind];
}

    // -------- Internals --------
    function _resetReq(RecoveryRequest storage R, address proposed) internal {
        R.proposed = proposed;
        R.approvals = 0;
        R.deadline = block.timestamp + RECOVERY_WINDOW;
        R.executed = false;
        R.callTarget = address(0);
        R.callData = "";
        tempVeto.guardian = address(0);
        tempVeto.expiry = 0;
    }

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
            require(g != address(0), "standby not seeded");
            activeGuardians[i] = g;
            isActiveGuardian[g] = true;
            isStandbyGuardian[g] = false;
            standbyGuardians[i] = address(0);
        }
        emit StandbyActivated(activeGuardians);
    }

    // Validate batch param not zero and duplicates check
    function _validateBatchArray(address[GUARDIAN_COUNT] calldata batch) internal pure {
        // array length is guaranteed by type; leave placeholder in case future dynamic arrays used
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

    uint256[44] private __gap;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRecoverableV2 {
    function onDRSRecover(bytes32 role, address oldAccount, address newAccount) external;
}

/// @title Batch Guardian Council (DRS v2) - UUPS upgradeable
/// @notice Two independent batches enable instant failover if Batch A is compromised/locked.
/// @dev Manager (DAO/multisig) is the entity allowed to refill/rotate batches and to authorize upgrades.
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract BatchGuardianCouncilDRSUpgradeable is Initializable, UUPSUpgradeable {
    // -------- Errors --------
    error NotGuardian();
    error NotManager();
    error BadInput();
    error NoActive();
    error Expired();
    error AlreadyApproved();
    error Threshold();
    error Locked();

    // -------- Configurable state (was immutable in non-upgradeable) --------
    bytes32 public ROLE;
    address public TARGET;
    address public manager; // DAO/multisig that owns refill/rotation & upgrades

    uint8   public THRESHOLD;      // per-batch threshold (e.g., 5)
    uint8   public BATCH_SIZE;     // per-batch size (e.g., 7)
    uint256 public RECOVERY_WINDOW;

    // -------- Batch state --------
    struct Batch {
        address[] guardians;            // length = BATCH_SIZE
        mapping(address => bool) isGuardian;
        // Active recovery (per batch)
        address proposed;
        mapping(address => bool) hasApproved;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        bool warn_6of7;
        bool lock_7of7;
    }

    Batch[2] private _batches;          // [0] primary, [1] standby
    uint8 public activeBatch;           // 0 or 1

    // -------- Events --------
    event ManagerChanged(address indexed oldManager, address indexed newManager);
    event BatchInitialized(uint8 indexed batchId, address[] guardians);
    event GuardianReplaced(uint8 indexed batchId, uint8 indexed idx, address oldG, address newG);
    event RecoveryProposed(uint8 indexed batchId, address indexed proposer, address indexed proposed, uint256 deadline);
    event RecoveryApproved(uint8 indexed batchId, address indexed guardian, uint8 approvals);
    event RecoveryExecuted(uint8 indexed batchId, address indexed proposed);
    event BatchWarning(uint8 indexed batchId, bytes32 flag);
    event BatchLocked(uint8 indexed batchId, bytes32 reason);
    event Failover(uint8 fromBatch, uint8 toBatch);
    event BatchRefilled(uint8 indexed batchId, address[] guardians);

    // -------- Modifiers --------
    modifier onlyManager() {
        if (msg.sender != manager) revert NotManager();
        _;
    }
    modifier onlyGuardianOfActive() {
        if (!_batches[activeBatch].isGuardian[msg.sender]) revert NotGuardian();
        _;
    }

    // -------- Initialization (replaces constructor) --------
    /// @notice Initialize the upgradeable council
    /// @param role_ role identifier passed to target on recovery
    /// @param target_ recovery target (must implement IRecoverableV2)
    /// @param manager_ manager (DAO/multisig) address
    /// @param batchA guardians for batch A
    /// @param batchB guardians for batch B
    /// @param threshold_ number approvals required to execute recovery (1..BATCH_SIZE)
    /// @param recoveryWindowSecs how long a proposal is valid (secs)
    function initialize(
        bytes32 role_,
        address target_,
        address manager_,
        address[] memory batchA,
        address[] memory batchB,
        uint8 threshold_,
        uint256 recoveryWindowSecs
    ) public initializer {
        if (target_ == address(0) || manager_ == address(0)) revert BadInput();
        if (batchA.length == 0 || batchA.length != batchB.length) revert BadInput();
        if (threshold_ == 0 || threshold_ > batchA.length) revert BadInput();

        ROLE = role_;
        TARGET = target_;
        manager = manager_;

        THRESHOLD = threshold_;
        BATCH_SIZE = uint8(batchA.length);
        RECOVERY_WINDOW = recoveryWindowSecs;

        _initBatch(0, batchA);
        _initBatch(1, batchB);
        activeBatch = 0;

        // initialize UUPS
        __UUPSUpgradeable_init();
    }

    /// @dev UUPS upgrade authorization: manager must call upgrade
    function _authorizeUpgrade(address) internal override onlyManager {}

    // -------- Internal helpers --------
    function _initBatch(uint8 id, address[] memory set_) internal {
        if (set_.length == 0) revert BadInput();
        if (id > 1) revert BadInput();
        Batch storage b = _batches[id];

        // ensure fresh (if previously seeded, clear old guardians)
        if (b.guardians.length > 0) {
            for (uint8 i = 0; i < b.guardians.length; i++) {
                address old = b.guardians[i];
                if (old != address(0)) {
                    b.isGuardian[old] = false;
                }
            }
            delete b.guardians;
        }

        b.guardians = new address[](set_.length);
        for (uint8 i = 0; i < set_.length; i++) {
            address g = set_[i];
            if (g == address(0) || b.isGuardian[g]) revert BadInput();
            b.guardians[i] = g;
            b.isGuardian[g] = true;
        }

        // reset recovery state for safety
        b.proposed = address(0);
        b.approvals = 0;
        b.deadline = 0;
        b.executed = false;
        b.warn_6of7 = false;
        b.lock_7of7 = false;

        emit BatchInitialized(id, set_);
    }

    // -------- Manager ops --------
    function setManager(address newManager) external onlyManager {
        if (newManager == address(0)) revert BadInput();
        emit ManagerChanged(manager, newManager);
        manager = newManager;
    }

    /// @notice Replace a guardian in a specific batch (manager-only).
    function setGuardian(uint8 batchId, uint8 idx, address newGuardian) external onlyManager {
        if (batchId > 1) revert BadInput();
        Batch storage b = _batches[batchId];
        if (idx >= b.guardians.length) revert BadInput();
        if (newGuardian == address(0)) revert BadInput();

        address old = b.guardians[idx];
        if (old == newGuardian) return;

        // ensure newGuardian isn't already present in the same batch
        if (b.isGuardian[newGuardian]) revert BadInput();

        b.isGuardian[old] = false;
        b.guardians[idx] = newGuardian;
        b.isGuardian[newGuardian] = true;

        emit GuardianReplaced(batchId, idx, old, newGuardian);
    }

    // -------- Recovery (active batch) --------
    /// @notice Propose a recovery by an active guardian; clears previous approvals for that batch
    function propose(address newAccount) external onlyGuardianOfActive {
        Batch storage b = _batches[activeBatch];
        if (b.lock_7of7) revert Locked();

        // reset recovery fields
        b.proposed   = newAccount;
        b.approvals  = 0;
        b.deadline   = block.timestamp + RECOVERY_WINDOW;
        b.executed   = false;
        b.warn_6of7  = false;
        // clear approvals mapping (iterate batch)
        for (uint8 i = 0; i < b.guardians.length; i++) {
            address g = b.guardians[i];
            if (g != address(0)) b.hasApproved[g] = false;
        }

        // auto-approve by proposer
        b.hasApproved[msg.sender] = true;
        b.approvals = 1;

        emit RecoveryProposed(activeBatch, msg.sender, newAccount, b.deadline);
        emit RecoveryApproved(activeBatch, msg.sender, 1);
    }

    /// @notice Approve the active batch's recovery proposal
    function approve() external onlyGuardianOfActive {
        Batch storage b = _batches[activeBatch];
        if (b.proposed == address(0)) revert NoActive();
        if (block.timestamp > b.deadline) revert Expired();
        if (b.hasApproved[msg.sender]) revert AlreadyApproved();
        if (b.lock_7of7) revert Locked();

        b.hasApproved[msg.sender] = true;
        uint8 newCount = b.approvals + 1;
        b.approvals = newCount;
        emit RecoveryApproved(activeBatch, msg.sender, newCount);

        // compromise signaling for BATCH_SIZE == 7-like councils
        if (b.guardians.length == 7) {
            if (newCount == 6 && !b.warn_6of7) {
                b.warn_6of7 = true;
                emit BatchWarning(activeBatch, "WARN_6_OF_7");
            } else if (newCount == 7) {
                b.lock_7of7 = true;
                emit BatchLocked(activeBatch, "LOCK_7_OF_7");
                _failover(); // auto switch to standby
            }
        }
    }

    /// @notice Execute the active batch's recovery proposal if threshold met
    /// @param oldAccountHint optional old account to pass to target callback
    function execute(address oldAccountHint) external {
        Batch storage b = _batches[activeBatch];
        if (b.proposed == address(0)) revert NoActive();
        if (b.executed) revert AlreadyApproved();
        if (block.timestamp > b.deadline) revert Expired();
        if (b.approvals < THRESHOLD) revert Threshold();

        b.executed = true;
        // call the target contract to perform the recovery action
        IRecoverableV2(TARGET).onDRSRecover(ROLE, oldAccountHint, b.proposed);

        emit RecoveryExecuted(activeBatch, b.proposed);
    }

    // -------- Failover & Refill --------
    function _failover() internal {
        uint8 from = activeBatch;
        uint8 to = from == 0 ? 1 : 0;
        activeBatch = to;
        emit Failover(from, to);
        // note: standby remains intact; manager should refill the old batch as needed
    }

    /// @notice Manager can reinitialize/replace a whole batch (refill the locked one)
    function refillBatch(uint8 batchId, address[] calldata newSet) external onlyManager {
        if (batchId > 1) revert BadInput();
        if (newSet.length == 0) revert BadInput();
        Batch storage b = _batches[batchId];

        // wipe existing guardians presence
        for (uint8 i = 0; i < b.guardians.length; i++) {
            address g = b.guardians[i];
            if (g != address(0)) b.isGuardian[g] = false;
        }
        delete b.guardians;

        // reset recovery state
        b.proposed = address(0);
        b.approvals = 0;
        b.deadline = 0;
        b.executed = false;
        b.warn_6of7 = false;
        b.lock_7of7 = false;

        // set new guardians
        b.guardians = new address[](newSet.length);
        for (uint8 i = 0; i < newSet.length; i++) {
            address g = newSet[i];
            if (g == address(0) || b.isGuardian[g]) revert BadInput();
            b.guardians[i] = g;
            b.isGuardian[g] = true;
        }

        emit BatchRefilled(batchId, newSet);
    }

    // -------- Views --------
    function batchStatus(uint8 batchId)
        external
        view
        returns (
            address[] memory set_,
            address proposed,
            uint8 approvals,
            uint256 deadline,
            bool executed,
            bool warn6,
            bool lock7
        )
    {
        if (batchId > 1) revert BadInput();
        Batch storage b = _batches[batchId];
        return (b.guardians, b.proposed, b.approvals, b.deadline, b.executed, b.warn_6of7, b.lock_7of7);
    }

    function isGuardianIn(uint8 batchId, address account) external view returns (bool) {
        if (batchId > 1) revert BadInput();
        return _batches[batchId].isGuardian[account];
    }

    // -------- Storage gap for upgrade safety --------
    uint256[50] private __gap;
}

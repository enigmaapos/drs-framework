// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRecoverableV2 {
    function onDRSRecover(bytes32 role, address oldAccount, address newAccount) external;
}

/// @title Batch Guardian Council (DRS v2)
/// @notice Two independent batches enable instant failover if Batch A is compromised/locked.
/// @dev DAO (manager) is the *only* entity allowed to (re)fill batches.
contract BatchGuardianCouncil {
    // -------- Errors --------
    error NotGuardian();
    error NotManager();
    error BadInput();
    error NoActive();
    error Expired();
    error AlreadyApproved();
    error Threshold();
    error Locked();

    // -------- Immutable config --------
    bytes32 public immutable ROLE;
    address public immutable TARGET;
    address public manager; // DAO/multisig that owns refill/rotation

    uint8   public immutable THRESHOLD;      // per-batch threshold (e.g., 5)
    uint8   public immutable BATCH_SIZE;     // per-batch size (e.g., 7)
    uint256 public immutable RECOVERY_WINDOW;

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

    // -------- Modifiers --------
    modifier onlyManager() {
        if (msg.sender != manager) revert NotManager();
        _;
    }
    modifier onlyGuardianOfActive() {
        if (!_batches[activeBatch].isGuardian[msg.sender]) revert NotGuardian();
        _;
    }

    // -------- Constructor --------
    constructor(
        bytes32 role_,
        address target_,
        address manager_,
        address[] memory batchA,
        address[] memory batchB,
        uint8 threshold_,
        uint256 recoveryWindowSecs
    ) {
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
    }

    function _initBatch(uint8 id, address[] memory set_) internal {
        Batch storage b = _batches[id];
        b.guardians = new address[](set_.length);
        for (uint8 i = 0; i < set_.length; i++) {
            address g = set_[i];
            if (g == address(0) || b.isGuardian[g]) revert BadInput();
            b.guardians[i] = g;
            b.isGuardian[g] = true;
        }
        emit BatchInitialized(id, set_);
    }

    // -------- Manager ops --------
    function setManager(address newManager) external onlyManager {
        if (newManager == address(0)) revert BadInput();
        emit ManagerChanged(manager, newManager);
        manager = newManager;
    }

    /// @notice Replace a guardian in a specific batch (DAO-only).
    function setGuardian(uint8 batchId, uint8 idx, address newGuardian) external onlyManager {
        if (batchId > 1 || idx >= _batches[batchId].guardians.length || newGuardian == address(0)) revert BadInput();
        Batch storage b = _batches[batchId];
        address old = b.guardians[idx];
        if (old == newGuardian) return;
        b.isGuardian[old] = false;
        if (b.isGuardian[newGuardian]) revert BadInput();
        b.guardians[idx] = newGuardian;
        b.isGuardian[newGuardian] = true;
        emit GuardianReplaced(batchId, idx, old, newGuardian);
    }

    // -------- Recovery (active batch) --------
    function propose(address newAccount) external onlyGuardianOfActive {
        Batch storage b = _batches[activeBatch];
        if (b.lock_7of7) revert Locked();

        // reset
        b.proposed   = newAccount;
        b.approvals  = 0;
        b.deadline   = block.timestamp + RECOVERY_WINDOW;
        b.executed   = false;
        b.warn_6of7  = false;

        // clear approvals
        for (uint8 i = 0; i < b.guardians.length; i++) {
            address g = b.guardians[i];
            if (g != address(0)) b.hasApproved[g] = false;
        }

        emit RecoveryProposed(activeBatch, msg.sender, newAccount, b.deadline);
    }

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

        // compromise signaling for 7-of-7 councils
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

    function execute(address oldAccountHint) external {
        Batch storage b = _batches[activeBatch];
        if (b.proposed == address(0)) revert NoActive();
        if (b.executed) revert AlreadyApproved();
        if (block.timestamp > b.deadline) revert Expired();
        if (b.approvals < THRESHOLD) revert Threshold();

        b.executed = true;
        IRecoverableV2(TARGET).onDRSRecover(ROLE, oldAccountHint, b.proposed);
        emit RecoveryExecuted(activeBatch, b.proposed);
    }

    // -------- Failover & Refill --------
    function _failover() internal {
        uint8 from = activeBatch;
        uint8 to = from == 0 ? 1 : 0;
        activeBatch = to;
        emit Failover(from, to);
        // note: standby batch state is independent; DAO should refill the locked batch off-chain/on-chain later
    }

    /// @notice DAO can reinitialize a whole batch (e.g., refill the locked one).
    function refillBatch(uint8 batchId, address[] calldata newSet) external onlyManager {
        if (batchId > 1 || newSet.length != _batches[batchId].guardians.length) revert BadInput();

        // wipe
        Batch storage b = _batches[batchId];
        for (uint8 i = 0; i < b.guardians.length; i++) {
            address g = b.guardians[i];
            if (g != address(0)) b.isGuardian[g] = false;
        }
        delete b.guardians;

        // reset batch flags and recovery
        b.proposed = address(0);
        b.approvals = 0;
        b.deadline = 0;
        b.executed = false;
        b.warn_6of7 = false;
        b.lock_7of7 = false;

        // set new
        _initBatch(batchId, newSet);
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
        require(batchId <= 1, "bad id");
        Batch storage b = _batches[batchId];
        return (b.guardians, b.proposed, b.approvals, b.deadline, b.executed, b.warn_6of7, b.lock_7of7);
    }

    function isGuardianIn(uint8 batchId, address account) external view returns (bool) {
        require(batchId <= 1, "bad id");
        return _batches[batchId].isGuardian[account];
    }
}

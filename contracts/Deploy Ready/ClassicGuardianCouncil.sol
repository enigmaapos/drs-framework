// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IRecoverable
/// @notice Target contracts implement this to finalize a recovery.
/// @dev role = keccak256("DEPLOYER") / keccak256("ADMIN") / custom.
///      oldAccount/newAccount are hints; target may ignore oldAccount if not needed.
interface IRecoverable {
    function onDRSRecover(bytes32 role, address oldAccount, address newAccount) external;
}

/// @title Classic Guardian Council (DRS v1)
/// @notice Single council with configurable N-of-M threshold, expiry window, and lock flags.
/// @dev Lightweight and upgrade-safe. Manager (DAO/multisig) can rotate guardians.
contract ClassicGuardianCouncil {
    // -------- Errors (short to save bytecode) --------
    error NotGuardian();
    error AlreadyApproved();
    error NoActive();
    error Expired();
    error Threshold();
    error Locked();
    error NotManager();
    error BadInput();

    // -------- Storage --------
    bytes32 public immutable ROLE;          // e.g., keccak256("DEPLOYER") or keccak256("ADMIN")
    address public immutable TARGET;        // contract that implements IRecoverable
    address public manager;                 // DAO/multisig that can manage guardians

    uint8   public immutable GUARDIAN_COUNT;
    uint8   public immutable THRESHOLD;     // e.g., 5 for 5-of-7
    uint256 public immutable RECOVERY_WINDOW; // seconds until request expires

    address[] public guardians;             // length = GUARDIAN_COUNT
    mapping(address => bool) public isGuardian;

    struct Recovery {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        // approvals tracking:
        mapping(address => bool) hasApproved;
    }
    Recovery private _recovery;

    // Compromise flags
    bool public warning_6of7; // set when approvals hit (GUARDIAN_COUNT - 1) and GUARDIAN_COUNT==7
    bool public locked_7of7;  // set when approvals == GUARDIAN_COUNT (auto-lock)

    // -------- Events --------
    event ManagerChanged(address indexed oldManager, address indexed newManager);
    event GuardianSet(uint8 indexed idx, address indexed guardian);
    event RecoveryProposed(address indexed proposer, address indexed proposed, uint256 deadline);
    event RecoveryApproved(address indexed guardian, uint8 approvals);
    event RecoveryExecuted(address indexed proposed);
    event WarningRaised(bytes32 flag);
    event Locked(bytes32 reason);

    // -------- Modifiers --------
    modifier onlyGuardian() {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        _;
    }
    modifier onlyManager() {
        if (msg.sender != manager) revert NotManager();
        _;
    }

    // -------- Constructor --------
    constructor(
        bytes32 role_,
        address target_,
        address manager_,
        address[] memory guardianSet,
        uint8 threshold_,
        uint256 recoveryWindowSecs
    ) {
        if (target_ == address(0) || manager_ == address(0)) revert BadInput();
        if (guardianSet.length == 0 || threshold_ == 0 || threshold_ > guardianSet.length) revert BadInput();

        ROLE = role_;
        TARGET = target_;
        manager = manager_;
        GUARDIAN_COUNT = uint8(guardianSet.length);
        THRESHOLD = threshold_;
        RECOVERY_WINDOW = recoveryWindowSecs;

        guardians = guardianSet;
        for (uint8 i = 0; i < guardianSet.length; i++) {
            address g = guardianSet[i];
            if (g == address(0) || isGuardian[g]) revert BadInput();
            isGuardian[g] = true;
            emit GuardianSet(i, g);
        }
    }

    // -------- Manager ops --------
    function setManager(address newManager) external onlyManager {
        if (newManager == address(0)) revert BadInput();
        emit ManagerChanged(manager, newManager);
        manager = newManager;
    }

    /// @notice Rotate a guardian (e.g., after key loss) without affecting active request.
    function setGuardian(uint8 idx, address newGuardian) external onlyManager {
        if (idx >= guardians.length || newGuardian == address(0)) revert BadInput();
        address old = guardians[idx];
        if (old == newGuardian) return;
        isGuardian[old] = false;
        guardians[idx] = newGuardian;
        if (isGuardian[newGuardian]) revert BadInput();
        isGuardian[newGuardian] = true;
        emit GuardianSet(idx, newGuardian);
    }

    // -------- Recovery flow --------
    function propose(address newAccount) external onlyGuardian {
        if (locked_7of7) revert Locked();
        // reset state
        _recovery.proposed = newAccount;
        _recovery.approvals = 0;
        _recovery.deadline = block.timestamp + RECOVERY_WINDOW;
        _recovery.executed = false;
        // clear approvals map
        for (uint8 i = 0; i < guardians.length; i++) {
            address g = guardians[i];
            if (g != address(0)) _recovery.hasApproved[g] = false;
        }
        warning_6of7 = false;

        emit RecoveryProposed(msg.sender, newAccount, _recovery.deadline);
    }

    function approve() external onlyGuardian {
        if (_recovery.proposed == address(0)) revert NoActive();
        if (block.timestamp > _recovery.deadline) revert Expired();
        if (_recovery.hasApproved[msg.sender]) revert AlreadyApproved();
        if (locked_7of7) revert Locked();

        _recovery.hasApproved[msg.sender] = true;
        uint8 newCount = _recovery.approvals + 1;
        _recovery.approvals = newCount;
        emit RecoveryApproved(msg.sender, newCount);

        // Compromise signals for 7-of-7 councils
        if (guardians.length == 7) {
            if (newCount == 6 && !warning_6of7) {
                warning_6of7 = true;
                emit WarningRaised("WARN_6_OF_7");
            } else if (newCount == 7) {
                locked_7of7 = true;
                emit Locked("LOCK_7_OF_7");
            }
        }
    }

    function execute(address oldAccountHint) external {
        if (_recovery.proposed == address(0)) revert NoActive();
        if (_recovery.executed) revert AlreadyApproved();
        if (block.timestamp > _recovery.deadline) revert Expired();
        if (_recovery.approvals < THRESHOLD) revert Threshold();
        // Call target to finalize the role transfer
        _recovery.executed = true;
        IRecoverable(TARGET).onDRSRecover(ROLE, oldAccountHint, _recovery.proposed);
        emit RecoveryExecuted(_recovery.proposed);
    }

    // -------- Views --------
    function activeRecovery()
        external
        view
        returns (address proposed, uint8 approvals, uint256 deadline, bool executed)
    {
        Recovery storage r = _recovery;
        return (r.proposed, r.approvals, r.deadline, r.executed);
    }

    function guardiansList() external view returns (address[] memory) {
        return guardians;
    }
}

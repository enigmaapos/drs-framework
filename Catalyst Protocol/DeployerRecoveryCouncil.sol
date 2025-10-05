// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface the target contract must implement for integration.
interface IRecoverable {
    /// @notice Called by the council to tell the target to swap the deployer.
    /// @param newDeployer the address to become deployer
    /// @param oldDeployer the previous deployer address (for optional sanity checking)
    function swapDeployer(address newDeployer, address oldDeployer) external;

    /// @notice Used by the council to fetch the current deployer for sanity checks.
    function deployer() external view returns (address);
}

/// @title Deployer Recovery Council (DRS v1.2)
/// @notice Guardians manage recovery of the DEPLOYER role on a target contract.
/// - 5-of-7 = ready (4h delay), 6 = warning, 7 = locked (auto-lock).
contract DeployerRecoveryCouncil {
    // -------- Errors --------
    error NotGuardian();
    error AlreadyApproved();
    error NoActive();
    error Expired();
    error ThresholdNotReached();
    error Locked();
    error NotManager();
    error BadInput();
    error DelayNotElapsed();
    error AlreadyExecuted();

    // -------- Constants --------
    bytes32 public constant ROLE = keccak256("DEPLOYER");
    uint256 public constant EXECUTION_DELAY = 4 hours;

    // -------- Storage --------
    address public immutable TARGET;      // contract implementing IRecoverable
    address public manager;               // DAO/multisig manager
    address[] public guardians;
    mapping(address => bool) public isGuardian;

    uint8 public immutable THRESHOLD;     // e.g., 5 of 7
    uint256 public immutable RECOVERY_WINDOW;

    struct Recovery {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        uint256 readyTime;   // when execution allowed (after 4h delay)
        bool executed;
        mapping(address => bool) hasApproved;
    }
    Recovery private _recovery;

    // -------- Security Flags --------
    bool public warning_6of7; // triggered at 6 approvals
    bool public locked_7of7;  // triggered at 7 approvals (auto-lock)

    // -------- Events --------
    event GuardianSet(uint8 indexed idx, address indexed guardian);
    event ManagerChanged(address indexed oldManager, address indexed newManager);
    event RecoveryProposed(address indexed proposer, address indexed proposed, uint256 deadline);
    event RecoveryApproved(address indexed guardian, uint8 approvals);
    event RecoveryReady(uint256 readyTime);
    event RecoveryExecuted(address indexed newDeployer, address indexed oldDeployer);
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
    /// @param target_ target contract that implements IRecoverable (swapDeployer + deployer view)
    /// @param manager_ multisig/DAO manager
    /// @param guardianSet list of guardian addresses (recommended length 7)
    /// @param threshold_ approvals required to allow execution (e.g., 5)
    /// @param recoveryWindowSecs proposal expiry window in seconds
    constructor(
        address target_,
        address manager_,
        address[] memory guardianSet,
        uint8 threshold_,
        uint256 recoveryWindowSecs
    ) {
        if (target_ == address(0) || manager_ == address(0)) revert BadInput();
        if (guardianSet.length == 0 || threshold_ == 0 || threshold_ > guardianSet.length)
            revert BadInput();

        TARGET = target_;
        manager = manager_;
        guardians = guardianSet;
        THRESHOLD = threshold_;
        RECOVERY_WINDOW = recoveryWindowSecs;

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

    function setGuardian(uint8 idx, address newGuardian) external onlyManager {
        if (idx >= guardians.length || newGuardian == address(0)) revert BadInput();
        address old = guardians[idx];
        if (old == newGuardian) return;
        isGuardian[old] = false;
        if (isGuardian[newGuardian]) revert BadInput();
        guardians[idx] = newGuardian;
        isGuardian[newGuardian] = true;
        emit GuardianSet(idx, newGuardian);
    }

    // -------- Recovery flow --------
    function propose(address newDeployer) external onlyGuardian {
        if (locked_7of7) revert Locked();

        // initialize new recovery
        _recovery.proposed = newDeployer;
        _recovery.approvals = 0;
        _recovery.deadline = block.timestamp + RECOVERY_WINDOW;
        _recovery.readyTime = 0;
        _recovery.executed = false;
        warning_6of7 = false;

        // reset approvals map
        for (uint8 i = 0; i < guardians.length; i++) {
            address g = guardians[i];
            if (g != address(0)) _recovery.hasApproved[g] = false;
        }

        emit RecoveryProposed(msg.sender, newDeployer, _recovery.deadline);
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

        // --- Security logic for 7-member council (only triggers if guardians.length == 7) ---
        if (guardians.length == 7) {
            if (newCount == 5) {
                _recovery.readyTime = block.timestamp + EXECUTION_DELAY;
                emit RecoveryReady(_recovery.readyTime);
            } else if (newCount == 6 && !warning_6of7) {
                warning_6of7 = true;
                emit WarningRaised("WARN_6_OF_7");
            } else if (newCount == 7 && !locked_7of7) {
                locked_7of7 = true;
                emit Locked("LOCK_7_OF_7");
            }
        } else {
            // For non-7 councils: if approvals == threshold, schedule readyTime
            if (newCount == THRESHOLD) {
                _recovery.readyTime = block.timestamp + EXECUTION_DELAY;
                emit RecoveryReady(_recovery.readyTime);
            }
        }
    }

    /// @notice Execute recovery after conditions met. Calls `swapDeployer(new, old)` on target.
    function execute() external {
        if (_recovery.proposed == address(0)) revert NoActive();
        if (_recovery.executed) revert AlreadyExecuted();
        if (block.timestamp > _recovery.deadline) revert Expired();
        if (_recovery.approvals < THRESHOLD) revert ThresholdNotReached();
        if (_recovery.readyTime == 0 || block.timestamp < _recovery.readyTime) revert DelayNotElapsed();
        if (locked_7of7) revert Locked();

        // fetch old deployer from target for sanity check and event
        address oldDeployer = IRecoverable(TARGET).deployer();
        address newDeployer = _recovery.proposed;

        // mark executed and clear active proposal to prevent replay
        _recovery.executed = true;

        // clear stored proposal state (leave flags warning_6of7/locked_7of7 as-is)
        _recovery.proposed = address(0);
        _recovery.approvals = 0;
        _recovery.deadline = 0;
        _recovery.readyTime = 0;
        // note: we don't iterate to clear hasApproved here (they will be cleared on next propose)

        // perform the swap on the target
        IRecoverable(TARGET).swapDeployer(newDeployer, oldDeployer);

        emit RecoveryExecuted(newDeployer, oldDeployer);
    }

    // -------- Views / Helpers --------

    /// @notice Returns the active recovery data.
    function activeRecovery()
        external
        view
        returns (address proposed, uint8 approvals, uint256 deadline, uint256 readyTime, bool executed)
    {
        Recovery storage r = _recovery;
        return (r.proposed, r.approvals, r.deadline, r.readyTime, r.executed);
    }

    /// @notice Returns guardian list.
    function guardiansList() external view returns (address[] memory) {
        return guardians;
    }

    /// @notice Returns which guardians have approved the active recovery (in order of guardians array).
    function guardianApprovals() external view returns (address[] memory approved) {
        uint8 count = _recovery.approvals;
        if (count == 0) return new address;
        approved = new address[](count);
        uint8 j = 0;
        for (uint8 i = 0; i < guardians.length && j < count; i++) {
            if (_recovery.hasApproved[guardians[i]]) {
                approved[j++] = guardians[i];
            }
        }
    }
}

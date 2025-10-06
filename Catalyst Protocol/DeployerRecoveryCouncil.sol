// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal interface target contracts must implement to support recovery.
interface IRecoverableTarget {
    /// @notice Triggered by the DRS when recovery is executed.
    function onDRSRecover(bytes32 kind, address oldAccount, address newAccount) external;

    /// @notice Returns current deployer/admin address.
    function deployerAddress() external view returns (address);
}

/// @title Deployer Recovery Council (DRS v2.0)
/// @notice 7-Guardian recovery council for safely replacing deployer/admin roles.
/// - 5/7 approvals → 4-hour delay.
/// - 6/7 approvals → Warning stage + last honest veto (48h).
/// - 7/7 approvals → Auto-lock + standby reseed.
contract DeployerRecoveryCouncil {
    // -------- Errors --------
    error NotGuardian();
    error AlreadyApproved();
    error NoActive();
    error Expired();
    error ThresholdNotReached();
    error LockedError(); // renamed to avoid collision with event
    error NotManager();
    error BadInput();
    error DelayNotElapsed();
    error AlreadyExecuted();
    error NotLastHonest();
    error NotCouncil();

    // -------- Constants --------
    bytes32 public constant ROLE_DEPLOYER = keccak256("DEPLOYER");
    uint256 public constant EXECUTION_DELAY = 4 hours;
    uint256 public constant VETO_WINDOW = 48 hours;

    // -------- Storage --------
    address public immutable TARGET;      // contract implementing IRecoverableTarget
    address public manager;               // DAO/multisig manager
    address[] public guardians;
    address[] public standbyGuardians;    // reseed batch
    mapping(address => bool) public isGuardian;

    uint8 public immutable THRESHOLD;     // approvals needed (e.g., 5)
    uint256 public immutable RECOVERY_WINDOW;

    struct Recovery {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        uint256 readyTime;
        bool executed;
        mapping(address => bool) hasApproved;
    }
    Recovery private _recovery;

    // -------- Security Flags --------
    bool public warning_6of7;
    bool public locked_7of7;
    address public lastHonestGuardian;
    uint256 public lastHonestExpiry;

    // -------- Events --------
    event GuardianSet(uint8 indexed idx, address indexed guardian);
    event ManagerChanged(address indexed oldManager, address indexed newManager);
    event RecoveryProposed(address indexed proposer, address indexed proposed, uint256 deadline);
    event RecoveryApproved(address indexed guardian, uint8 approvals);
    event RecoveryReady(uint256 readyTime);
    event RecoveryExecuted(address indexed newDeployer, address indexed oldDeployer);
    event WarningRaised(bytes32 flag);
    event Locked(bytes32 reason);
    event LastHonestAssigned(address indexed guardian, uint256 expiry);
    event RecoveryVetoed(address indexed guardian);
    event StandbyActivated(address[] newGuardians);

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
        address target_,
        address manager_,
        address[] memory guardianSet,
        address[] memory standbySet,
        uint8 threshold_,
        uint256 recoveryWindowSecs
    ) {
        if (target_ == address(0) || manager_ == address(0)) revert BadInput();
        if (guardianSet.length == 0 || threshold_ == 0 || threshold_ > guardianSet.length)
            revert BadInput();

        TARGET = target_;
        manager = manager_;
        guardians = guardianSet;
        standbyGuardians = standbySet;
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

    function managerReseed(address[] calldata newBatch) external onlyManager {
        if (newBatch.length != guardians.length) revert BadInput();
        for (uint8 i = 0; i < newBatch.length; i++) {
            address g = newBatch[i];
            if (g == address(0)) revert BadInput();
            guardians[i] = g;
            isGuardian[g] = true;
        }
        locked_7of7 = false;
        emit StandbyActivated(newBatch);
    }

    // -------- Recovery flow --------
    function propose(address newDeployer) external onlyGuardian {
        if (locked_7of7) revert LockedError();
        if (newDeployer == address(0)) revert BadInput();

        _recovery.proposed = newDeployer;
        _recovery.approvals = 0;
        _recovery.deadline = block.timestamp + RECOVERY_WINDOW;
        _recovery.readyTime = 0;
        _recovery.executed = false;

        warning_6of7 = false;
        lastHonestGuardian = address(0);
        lastHonestExpiry = 0;

        for (uint8 i = 0; i < guardians.length; i++) {
            _recovery.hasApproved[guardians[i]] = false;
        }

        emit RecoveryProposed(msg.sender, newDeployer, _recovery.deadline);
    }

    function approve() external onlyGuardian {
        if (_recovery.proposed == address(0)) revert NoActive();
        if (block.timestamp > _recovery.deadline) revert Expired();
        if (_recovery.hasApproved[msg.sender]) revert AlreadyApproved();
        if (locked_7of7) revert LockedError();

        _recovery.hasApproved[msg.sender] = true;
        uint8 newCount = _recovery.approvals + 1;
        _recovery.approvals = newCount;
        emit RecoveryApproved(msg.sender, newCount);

        uint8 total = uint8(guardians.length);

        if (newCount == 5 && _recovery.readyTime == 0) {
            _recovery.readyTime = block.timestamp + EXECUTION_DELAY;
            emit RecoveryReady(_recovery.readyTime);
        } else if (newCount == 6 && !warning_6of7 && total == 7) {
            warning_6of7 = true;
            address lastGuardian = _findLastGuardian();
            lastHonestGuardian = lastGuardian;
            lastHonestExpiry = block.timestamp + VETO_WINDOW;
            emit WarningRaised(bytes32("WARN_6_OF_7"));
            emit LastHonestAssigned(lastGuardian, lastHonestExpiry);
        } else if (newCount == 7 && total == 7 && !locked_7of7) {
            locked_7of7 = true;
            emit Locked(bytes32("LOCK_7_OF_7"));
            _activateStandby();
        }
    }

    function _findLastGuardian() internal view returns (address) {
        for (uint8 i = 0; i < guardians.length; i++) {
            address g = guardians[i];
            if (!_recovery.hasApproved[g]) return g;
        }
        return address(0);
    }

    function vetoRecovery() external {
        if (msg.sender != lastHonestGuardian) revert NotLastHonest();
        if (block.timestamp > lastHonestExpiry) revert Expired();
        _recovery.proposed = address(0);
        _recovery.approvals = 0;
        _recovery.deadline = 0;
        _recovery.readyTime = 0;
        _recovery.executed = false;
        emit RecoveryVetoed(msg.sender);
    }

    function execute() external {
        if (_recovery.proposed == address(0)) revert NoActive();
        if (_recovery.executed) revert AlreadyExecuted();
        if (block.timestamp > _recovery.deadline) revert Expired();
        if (_recovery.approvals < THRESHOLD) revert ThresholdNotReached();
        if (_recovery.readyTime == 0 || block.timestamp < _recovery.readyTime) revert DelayNotElapsed();
        if (locked_7of7) revert LockedError();

        address oldDeployer = IRecoverableTarget(TARGET).deployerAddress();
        address newDeployer = _recovery.proposed;

        _recovery.executed = true;
        _recovery.proposed = address(0);

        IRecoverableTarget(TARGET).onDRSRecover(
            bytes32("DEPLOYER"),
            oldDeployer,
            newDeployer
        );

        emit RecoveryExecuted(newDeployer, oldDeployer);
    }

    function _activateStandby() internal {
        uint256 len = standbyGuardians.length;
        if (len == 0) return;

        for (uint8 i = 0; i < guardians.length; i++) {
            isGuardian[guardians[i]] = false;
        }
        guardians = standbyGuardians;
        for (uint8 i = 0; i < len; i++) {
            isGuardian[guardians[i]] = true;
        }
        emit StandbyActivated(guardians);
    }

    // -------- Views --------
    function activeRecovery()
        external
        view
        returns (address proposed, uint8 approvals, uint256 deadline, uint256 readyTime, bool executed)
    {
        Recovery storage r = _recovery;
        return (r.proposed, r.approvals, r.deadline, r.readyTime, r.executed);
    }

    function guardiansList() external view returns (address[] memory) {
        return guardians;
    }

    function guardianApprovals() external view returns (address[] memory approved) {
        uint8 count = _recovery.approvals;
        approved = new address[](count);
        uint8 j;
        for (uint8 i = 0; i < guardians.length && j < count; i++) {
            if (_recovery.hasApproved[guardians[i]]) approved[j++] = guardians[i];
        }
    }
}

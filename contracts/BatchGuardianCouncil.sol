// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BatchGuardianCouncil (Upgradable)
 * @notice Decentralized Recovery System (DRS) with two guardian batches per protected role:
 *         - Batch A (Active Council): current signers for recoveries.
 *         - Batch B (Standby Council): pre-approved, can promote itself or be promoted by DAO.
 * 
 * Key flows:
 * 1) Recovery: Active guardians propose -> approve -> execute (update role holder).
 * 2) Promotion: Standby guardians approve -> promote to Active. DAO can also promote.
 * 3) Last Honest Halt: if Active approvals reach threshold-1, the single remaining guardian can halt
 *    the recovery and promote Standby (fast failover).
 *
 * Optional execution hook:
 * - If roleTarget != address(0) and roleSelector != 0x00, execute() will call:
 *     (bool ok,) = roleTarget.call(abi.encodeWithSelector(roleSelector, newHolder));
 *   to set the protected role on the external contract.
 *
 * Designed to be generic and reusable in other systems (e.g., Catalyst, safes, upgrade admins).
 */

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

contract BatchGuardianCouncil is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    // -------- Roles --------
    bytes32 public constant DAO_ROLE = keccak256("DAO_ROLE");

    // -------- Config --------
    uint256 public constant MAX_GUARDIANS = 15; // keep gas bounded
    uint256 public constant PROMOTION_WINDOW = 3 days;
    uint256 public constant RECOVERY_WINDOW  = 3 days;

    // Optional on-chain execution hook (external target + selector)
    address public roleTarget;      // e.g., address of a proxy admin holder
    bytes4  public roleSelector;    // e.g., IRoleManaged.updateRole.selector

    // Current protected role holder (purely informational if you use external hook)
    address public roleHolder;

    // Council storage
    struct Council {
        address[] list;
        mapping(address => bool) isG;
        uint8 threshold; // e.g., 5 for 7:5
    }

    Council private _active;   // Batch A
    Council private _standby;  // Batch B

    // Recovery request (Active batch)
    struct Recovery {
        address proposed;
        uint8 approvals;
        uint256 deadline;
        bool executed;
        mapping(address => bool) voted;
    }
    Recovery private _rec;

    // Promotion request (Standby batch self-promotion)
    struct Promotion {
        uint8 approvals;
        uint256 deadline;
        bool executed;
        mapping(address => bool) voted;
    }
    Promotion private _pro;

    // -------- Events --------
    event Init(address dao, address roleTarget, bytes4 roleSelector, address roleHolder);
    event ActiveSet(address[] guardians, uint8 threshold);
    event StandbySet(address[] guardians, uint8 threshold);
    event RecoveryProposed(address proposed, uint256 deadline);
    event RecoveryApproved(address guardian, uint8 approvals);
    event RecoveryExecuted(address oldHolder, address newHolder);
    event PromotionProposed(uint256 deadline);
    event PromotionApproved(address guardian, uint8 approvals);
    event PromotionExecuted(address[] newActive, uint8 threshold);
    event LastHonestHaltAndPromote(address halter);
    event StandbyRefilled(address[] guardians, uint8 threshold);
    event Paused(address by);
    event Unpaused(address by);

    // -------- Errors (short to save bytecode) --------
    error BadArg();
    error NotG();
    error Dup();
    error Late();
    error Done();
    error NoReq();
    error Thresh();
    error NotLast();
    error NotDAO();

    // -------- Initializer --------
    struct InitConfig {
        address dao;              // admin governance / multisig
        address roleTarget_;      // optional external target (0 = disabled)
        bytes4  roleSelector_;    // optional selector (0 = disabled)
        address roleHolder_;      // starting holder (info + for hook)
        address[] activeGs;       // batch A
        uint8 activeThresh;       // e.g., 5
        address[] standbyGs;      // batch B
        uint8 standbyThresh;      // e.g., 5
    }

    function initialize(InitConfig calldata cfg) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        if (
            cfg.dao == address(0) ||
            cfg.activeGs.length == 0 || cfg.activeGs.length > MAX_GUARDIANS ||
            cfg.standbyGs.length == 0 || cfg.standbyGs.length > MAX_GUARDIANS ||
            cfg.activeThresh == 0 || cfg.activeThresh > cfg.activeGs.length ||
            cfg.standbyThresh == 0 || cfg.standbyThresh > cfg.standbyGs.length
        ) revert BadArg();

        _grantRole(DEFAULT_ADMIN_ROLE, cfg.dao);
        _grantRole(DAO_ROLE,            cfg.dao);

        roleTarget   = cfg.roleTarget_;
        roleSelector = cfg.roleSelector_;
        roleHolder   = cfg.roleHolder_;

        // set Active
        _setCouncil(_active, cfg.activeGs, cfg.activeThresh);
        emit ActiveSet(cfg.activeGs, cfg.activeThresh);

        // set Standby
        _setCouncil(_standby, cfg.standbyGs, cfg.standbyThresh);
        emit StandbySet(cfg.standbyGs, cfg.standbyThresh);

        emit Init(cfg.dao, roleTarget, roleSelector, roleHolder);
    }

    // -------- Council internal setter --------
    function _setCouncil(Council storage c, address[] memory gs, uint8 th) internal {
        // clear old list
        uint256 len = c.list.length;
        for (uint256 i = 0; i < len; ++i) {
            c.isG[c.list[i]] = false;
        }
        delete c.list;

        // set new
        address prev = address(0);
        for (uint256 i = 0; i < gs.length; ++i) {
            address g = gs[i];
            if (g == address(0)) revert BadArg();
            if (c.isG[g]) revert Dup();
            c.isG[g] = true;
            c.list.push(g);
            // optional basic for ordering uniqueness (not required)
            prev = g;
        }
        c.threshold = th;
    }

    // -------- Modifiers --------
    modifier onlyActiveG() {
        if (!_active.isG[msg.sender]) revert NotG();
        _;
    }
    modifier onlyStandbyG() {
        if (!_standby.isG[msg.sender]) revert NotG();
        _;
    }
    modifier onlyDAO() {
        if (!hasRole(DAO_ROLE, msg.sender)) revert NotDAO();
        _;
    }

    // -------- Pause controls --------
    function pause() external onlyDAO { _pause(); emit Paused(msg.sender); }
    function unpause() external onlyDAO { _unpause(); emit Unpaused(msg.sender); }

    // =========================
    //  RECOVERY (Active batch)
    // =========================

    /// @notice Propose a new role holder (Active guardians)
    function proposeRecovery(address newHolder) external whenNotPaused onlyActiveG {
        if (newHolder == address(0)) revert BadArg();

        _rec.proposed = newHolder;
        _rec.approvals = 0;
        _rec.deadline = block.timestamp + RECOVERY_WINDOW;
        _rec.executed = false;

        // clear votes
        uint256 n = _active.list.length;
        for (uint256 i = 0; i < n; ++i) {
            _rec.voted[_active.list[i]] = false;
        }
        emit RecoveryProposed(newHolder, _rec.deadline);
    }

    /// @notice Approve recovery (Active guardians)
    function approveRecovery() external whenNotPaused onlyActiveG {
        if (_rec.proposed == address(0)) revert NoReq();
        if (_rec.executed) revert Done();
        if (block.timestamp > _rec.deadline) revert Late();
        if (_rec.voted[msg.sender]) revert Dup();

        _rec.voted[msg.sender] = true;
        _rec.approvals += 1;
        emit RecoveryApproved(msg.sender, _rec.approvals);
    }

    /// @notice Execute recovery once threshold met
    function executeRecovery() external nonReentrant whenNotPaused {
        if (_rec.proposed == address(0)) revert NoReq();
        if (_rec.executed) revert Done();
        if (block.timestamp > _rec.deadline) revert Late();
        if (_rec.approvals < _active.threshold) revert Thresh();

        address old = roleHolder;
        roleHolder = _rec.proposed;
        _rec.executed = true;

        // optional external hook
        if (roleTarget != address(0) && roleSelector != bytes4(0)) {
            (bool ok, ) = roleTarget.call(abi.encodeWithSelector(roleSelector, roleHolder));
            require(ok, "HOOK");
        }

        emit RecoveryExecuted(old, roleHolder);
    }

    // ==================================
    //  PROMOTION (Standby -> Active)
    // ==================================

    /// @notice Standby proposes to promote itself to Active (starts its own voting)
    function proposePromotion() external whenNotPaused onlyStandbyG {
        _pro.approvals = 0;
        _pro.deadline = block.timestamp + PROMOTION_WINDOW;
        _pro.executed = false;

        uint256 n = _standby.list.length;
        for (uint256 i = 0; i < n; ++i) {
            _pro.voted[_standby.list[i]] = false;
        }
        emit PromotionProposed(_pro.deadline);
    }

    /// @notice Standby guardians approve promotion
    function approvePromotion() external whenNotPaused onlyStandbyG {
        if (_pro.deadline == 0) revert NoReq();
        if (_pro.executed) revert Done();
        if (block.timestamp > _pro.deadline) revert Late();
        if (_pro.voted[msg.sender]) revert Dup();

        _pro.voted[msg.sender] = true;
        _pro.approvals += 1;
        emit PromotionApproved(msg.sender, _pro.approvals);
    }

    /// @notice Execute promotion when standby threshold met (Standby becomes Active)
    function executePromotion() public nonReentrant whenNotPaused {
        if (_pro.deadline == 0) revert NoReq();
        if (_pro.executed) revert Done();
        if (block.timestamp > _pro.deadline) revert Late();
        if (_pro.approvals < _standby.threshold) revert Thresh();

        // swap councils: standby -> active, old active discarded
        address[] memory newActive = _standby.list;
        uint8 th = _standby.threshold;

        // Move standby to active
        _setCouncil(_active, newActive, th);
        emit PromotionExecuted(newActive, th);

        _pro.executed = true;

        // NOTE: DAO must call refillStandby() to populate a fresh standby batch.
    }

    /// @notice DAO can force promotion without a standby vote (break-glass)
    function daoPromoteStandby() external onlyDAO {
        // construct a synthetic promotion and execute
        _pro.deadline = block.timestamp + 1; // minimal fresh window
        _pro.approvals = _standby.threshold; // satisfy threshold
        _pro.executed = false;
        executePromotion();
    }

    // ====================================
    //  LAST HONEST HALT + PROMOTE (fast)
    // ====================================

    /// @notice If Active approvals == threshold-1, the single remaining (not yet voted) active guardian
    ///         can halt the recovery and promote the standby instantly.
    function lastHonestHaltAndPromote() external whenNotPaused onlyActiveG {
        if (_rec.proposed == address(0)) revert NoReq();
        if (_rec.executed) revert Done();
        if (block.timestamp > _rec.deadline) revert Late();

        uint8 need = _active.threshold;
        if (_rec.approvals != need - 1) revert NotLast(); // only when exactly one signature is left

        // ensure caller is the last non-voter
        if (_rec.voted[msg.sender]) revert Dup();

        // cancel current recovery implicitly by overwriting state below:
        // 1) promote standby immediately
        _pro.deadline = block.timestamp + 1;
        _pro.approvals = _standby.threshold;
        _pro.executed = false;
        executePromotion();

        emit LastHonestHaltAndPromote(msg.sender);
    }

    // ========================
    //  DAO management (Standby)
    // ========================

    /// @notice Refill or replace the Standby batch (post-promotion maintenance)
    function refillStandby(address[] calldata gs, uint8 th) external onlyDAO {
        if (gs.length == 0 || gs.length > MAX_GUARDIANS || th == 0 || th > gs.length) revert BadArg();
        _setCouncil(_standby, gs, th);
        emit StandbyRefilled(gs, th);
    }

    /// @notice DAO can update the optional execution hook
    function setExecutionHook(address target, bytes4 selector) external onlyDAO {
        roleTarget = target;
        roleSelector = selector;
    }

    /// @notice DAO can update current recorded role holder (metadata only if hook disabled)
    function setRoleHolder(address newHolder) external onlyDAO {
        if (newHolder == address(0)) revert BadArg();
        roleHolder = newHolder;
    }

    // -------- Views --------
    function activeGuardians() external view returns (address[] memory list, uint8 threshold) {
        return (_active.list, _active.threshold);
    }

    function standbyGuardians() external view returns (address[] memory list, uint8 threshold) {
        return (_standby.list, _standby.threshold);
    }

    function recoveryStatus() external view returns (address proposed, uint8 approvals, uint256 deadline, bool executed) {
        return (_rec.proposed, _rec.approvals, _rec.deadline, _rec.executed);
    }

    function promotionStatus() external view returns (uint8 approvals, uint256 deadline, bool executed) {
        return (_pro.approvals, _pro.deadline, _pro.executed);
    }

    // -------- UUPS --------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}

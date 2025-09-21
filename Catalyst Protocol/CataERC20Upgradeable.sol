// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
  CataERC20Upgradeable.sol
  ------------------------
  Upgradeable, recyclable capped ERC20 token for production use.

  Key production hardening included:
  - AccessControlEnumerableUpgradeable for role enumeration support.
  - PausableUpgradeable for emergency pause/unpause.
  - explicit setMinter() function and events to assign MINTER_ROLE.
  - mint() protected by MINTER_ROLE and whenNotPaused.
  - burn() allowed for any holder and whenNotPaused.
  - _authorizeUpgrade guarded by DEFAULT_ADMIN_ROLE (use multisig/timelock).
  - initializer only; follow OZ reinitializer conventions for future upgrades.
  - storage gap for future state additions.
  - comments + events for operational clarity.

  IMPORTANT deployment notes (do these AFTER deploying the proxy):
  1. Initialize contract with initialize(name, symbol, initialAdmin, councilAddr).
     initialAdmin will receive the initial minted allocation (100_000_000 * 1e18).
  2. Deploy your CatalystStaking (or other minter) contract.
  3. Call setMinter(catalystStakingAddress) from DEFAULT_ADMIN_ROLE (initialAdmin).
  4. (Strongly recommended) Move DEFAULT_ADMIN_ROLE to a multisig/timelock:
     - grant DEFAULT_ADMIN_ROLE to your multisig/timelock
     - revoke DEFAULT_ADMIN_ROLE from the deployer EOA
  5. (Optional) Pause in emergency via pause()/unpause() using admin/multisig.
*/

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract CataERC20Upgradeable is
    Initializable,
    ERC20Upgradeable,
    AccessControlEnumerableUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    // -------------------------
    // Roles
    // -------------------------
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // -------------------------
    // Supply caps
    // -------------------------
    uint256 public constant MAX_SUPPLY = 1_000_000_000 ether; // 1B CATA (18 decimals)

    // -------------------------
    // Council
    // -------------------------
    address public council; // BatchGuardianCouncil contract or governance contract

    // -------------------------
    // Events
    // -------------------------
    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);
    event MinterSet(address indexed oldMinter, address indexed newMinter);
    event MinterRevoked(address indexed revokedMinter);
    event Paused(address account);
    event Unpaused(address account);

    // -------------------------
    // Modifiers
    // -------------------------
    modifier onlyCouncil() {
        require(msg.sender == council, "CATA: only council");
        _;
    }

    // -------------------------
    // Initializer
    // -------------------------
    /// @notice Initialize token with name, symbol and initial admin and council.
    /// @dev initialAdmin will receive initial minted allocation and will have DEFAULT_ADMIN_ROLE.
    function initialize(
        string memory name_,
        string memory symbol_,
        address initialAdmin,
        address council_
    ) external initializer {
        __ERC20_init(name_, symbol_);
        __AccessControlEnumerable_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        require(initialAdmin != address(0), "CATA: initial admin zero");
        require(council_ != address(0), "CATA: council zero");

        // Grant admin role to initialAdmin
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);

        // Set council
        council = council_;

        // Mint initial allocation to initialAdmin (configurable here)
        // NOTE: deployer/operator should move admin to multisig/timelock after setup.
        _mint(initialAdmin, 100_000_000 * 1e18);
    }

    // -------------------------
    // Mint & Burn
    // -------------------------
    /// @notice Mint tokens (only accounts with MINTER_ROLE).
    /// @dev Cap enforced and mint disabled when paused.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        require(totalSupply() + amount <= MAX_SUPPLY, "CATA: cap exceeded");
        _mint(to, amount);
    }

    /// @notice Burn caller's tokens (reduces total supply).
    function burn(uint256 amount) external whenNotPaused {
        _burn(msg.sender, amount);
    }

    // -------------------------
    // Minter management (production-safe)
    // -------------------------
    /// @notice Set a new minter (grant MINTER_ROLE). Callable by DEFAULT_ADMIN_ROLE.
    /// @dev This function grants MINTER_ROLE to newMinter and emits MinterSet.
    ///      It does NOT automatically revoke old minters. Operator should revoke old roles if desired.
    function setMinter(address newMinter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMinter != address(0), "CATA: zero minter");
        // track old minter is hard to define if multiple; emit event with newMinter only.
        _grantRole(MINTER_ROLE, newMinter);
        emit MinterSet(address(0), newMinter);
    }

    /// @notice Revoke MINTER_ROLE from an address. Callable by DEFAULT_ADMIN_ROLE.
    function revokeMinter(address minter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(minter != address(0), "CATA: zero minter");
        if (hasRole(MINTER_ROLE, minter)) {
            _revokeRole(MINTER_ROLE, minter);
            emit MinterRevoked(minter);
        }
    }

    // -------------------------
    // Council Management
    // -------------------------
    /// @notice Set new council address. Callable by DEFAULT_ADMIN_ROLE.
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "CATA: zero council");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    /// @notice Swap admin from oldAdmin to newAdmin; callable only by council contract.
    /// @dev newAdmin will receive DEFAULT_ADMIN_ROLE and oldAdmin will have it revoked.
    function swapAdmin(address newAdmin, address oldAdmin) external onlyCouncil {
        require(newAdmin != address(0), "CATA: zero new admin");

        if (!hasRole(DEFAULT_ADMIN_ROLE, newAdmin)) {
            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        }

        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE, oldAdmin)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        }

        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // -------------------------
    // Pause / Unpause (emergency)
    // -------------------------
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
        emit Paused(msg.sender);
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
        emit Unpaused(msg.sender);
    }

    // -------------------------
    // UUPS Upgrade Authorization
    // -------------------------
    /// @notice Authorize an upgrade. IMPORTANT: DEFAULT_ADMIN_ROLE should be a multisig/timelock.
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // -------------------------
    // ERC20 Hooks
    // -------------------------
    /// @dev Prevent transfers/mints/burns while paused (PausableUpgradeable provides whenNotPaused hooks).
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        super._beforeTokenTransfer(from, to, amount);

        // standard pause check (PausableUpgradeable sets _paused)
        require(!paused(), "CATA: token transfer while paused");
    }

    // -------------------------
    // Storage gap for future variables
    // -------------------------
    uint256[50] private __gap;
}

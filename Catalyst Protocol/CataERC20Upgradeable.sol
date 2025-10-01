// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * CataERC20Upgradeable.sol
 * ------------------------
 * Upgradeable, recyclable capped ERC20 token for production use.
 *
 * - AccessControlUpgradeable for role-based access control.
 * - PausableUpgradeable for emergency pause/unpause.
 * - explicit setMinter() function and events to assign MINTER_ROLE.
 * - mint() protected by MINTER_ROLE and whenNotPaused.
 * - burn() allowed for any holder and whenNotPaused.
 * - Recyclable supply: burned tokens free up minting capacity under MAX_SUPPLY.
 * - _authorizeUpgrade guarded by DEFAULT_ADMIN_ROLE (use multisig/timelock).
 * - initializer only; follow OZ reinitializer conventions for future upgrades.
 * - storage gap for future state additions.
*/

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract CataERC20Upgradeable is
    Initializable,
    ERC20Upgradeable,
AccessControlUpgradeable,
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
    address public council;

    // -------------------------
    // Events
    // -------------------------
    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);
    event MinterSet(address indexed oldMinter, address indexed newMinter);
    event MinterRevoked(address indexed revokedMinter);

    // Recyclable Supply Events
    event TokensMinted(address indexed to, uint256 amount, uint256 newTotalSupply);
    event TokensBurned(address indexed from, uint256 amount, uint256 newTotalSupply);
    event TokensRecycled(uint256 burnedAmount, uint256 newMintableCapacity);

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
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        require(initialAdmin != address(0), "CATA: initial admin zero");
        require(council_ != address(0), "CATA: council zero");

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        council = council_;

        // Initial allocation (configurable if desired)
        _mint(initialAdmin, 100_000_000 * 1e18);
        emit TokensMinted(initialAdmin, 100_000_000 * 1e18, totalSupply());
    }


    // -------------------------
    // Mint & Burn (Recyclable Supply)
    // -------------------------
    function mint(address to, uint256 amount)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
    {
        require(totalSupply() + amount <= MAX_SUPPLY, "CATA: cap exceeded");
        _mint(to, amount);
        emit TokensMinted(to, amount, totalSupply());
    }

    function burn(uint256 amount) external whenNotPaused {
        _burn(msg.sender, amount);
        emit TokensBurned(msg.sender, amount, totalSupply());

        uint256 capacity = MAX_SUPPLY - totalSupply();
        emit TokensRecycled(amount, capacity);
    }

    /// @notice Returns how many tokens can still be minted under the cap.
    function getMintableCapacity() public view returns (uint256) {
        return MAX_SUPPLY - totalSupply();
    }

    // -------------------------
    // Minter management (production-safe)
    // -------------------------
    /// @notice Grant MINTER_ROLE to newMinter. Admin only.
    function setMinter(address newMinter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMinter != address(0), "CATA: zero minter");
        _grantRole(MINTER_ROLE, newMinter);
        emit MinterSet(address(0), newMinter);
    }

    /// @notice Revoke MINTER_ROLE from an address. Admin only.
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
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "CATA: zero council");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    /// @notice Swap admin privileges; callable only by the council contract/address.
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
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // -------------------------
    // UUPS Upgrade Authorization
    // -------------------------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // -------------------------
    // ERC20 Hooks
    // -------------------------
    /// @dev Enforce pause on transfers/mints/burns.
    function _update(address from, address to, uint256 value) internal override(ERC20Upgradeable) {
        require(!paused(), "CATA: token transfer while paused");
        super._update(from, to, value);
    }

// -----------------------------------------------------------------
    // 🔒 ACCESS CONTROL OVERRIDES (Disabling Direct Role Manipulation)
    // -----------------------------------------------------------------
    
    /// @dev Overrides AccessControlUpgradeable's public grantRole to enforce secure, explicit role management.
    function grantRole(bytes32 role, address account) public virtual override {
        // This prevents the Admin from calling grantRole(DEFAULT_ADMIN_ROLE, otherAddress)
        // and creating multiple Admins, which would bypass the Council's control.
        revert("CataERC20: Granting roles is disabled. Use explicit wrappers.");
    }

    /// @dev Overrides AccessControlUpgradeable's public revokeRole to enforce secure, explicit role management.
    function revokeRole(bytes32 role, address account) public virtual override {
        revert("CataERC20: Revoking roles is disabled. Use explicit wrappers.");
    }
    
    // You may also want to disable the ability for an account to voluntarily renounce the role
    function renounceRole(bytes32 role, address account) public virtual override {
        revert("CataERC20: Renouncing roles is disabled. Use explicit wrappers.");
    }


    // -------------------------
    // Storage gap for future variables
    // -------------------------
    uint256[50] private __gap;
}

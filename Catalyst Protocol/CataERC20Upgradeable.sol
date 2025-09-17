// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title CATA ERC20 Token (Upgradeable)
/// @notice Recyclable capped token (1B max). Only CatalystStaking can mint.
/// GuardianCouncil manages admin and upgrades.
contract CataERC20Upgradeable is Initializable, ERC20Upgradeable, AccessControlUpgradeable, UUPSUpgradeable {
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
    address public council; // BatchGuardianCouncil contract

    // -------------------------
    // Events
    // -------------------------
    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);

    // -------------------------
    // Modifiers
    // -------------------------
    modifier onlyCouncil() {
        require(msg.sender == council, "CATA: only council");
        _;
    }

    // -------------------------
    // Init
    // -------------------------
    function initialize(
        string memory name_,
        string memory symbol_,
        address initialAdmin,
        address council_
    ) external initializer {
        __ERC20_init(name_, symbol_);
        __AccessControl_init();
        __UUPSUpgradeable_init();

        require(initialAdmin != address(0), "CATA: initial admin zero");
        require(council_ != address(0), "CATA: council zero");

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        council = council_;
    }

    // -------------------------
    // Mint & Burn
    // -------------------------
    /// @notice Mint new tokens (only CatalystStaking via MINTER_ROLE).
    /// Enforces the 1B global supply cap.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= MAX_SUPPLY, "CATA: cap exceeded");
        _mint(to, amount);
    }

    /// @notice Burn tokens from caller.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    // -------------------------
    // Council Management
    // -------------------------
    /// @notice Set the council address (only DEFAULT_ADMIN_ROLE).
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "CATA: zero council");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    /// @notice Atomically grant new admin and revoke old admin. Called by the guardian council.
    function swapAdmin(address newAdmin, address oldAdmin) external onlyCouncil {
        require(newAdmin != address(0), "CATA: zero new admin");

        // grant new first
        if (!hasRole(DEFAULT_ADMIN_ROLE, newAdmin)) {
            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        }

        // revoke old second
        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE, oldAdmin)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        }

        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // -------------------------
    // UUPS Upgrade
    // -------------------------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}

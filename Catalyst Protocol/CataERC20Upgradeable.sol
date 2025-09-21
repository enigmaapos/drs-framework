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
  - Recyclable supply: burned tokens free up minting capacity under MAX_SUPPLY.
  - _authorizeUpgrade guarded by DEFAULT_ADMIN_ROLE (use multisig/timelock).
  - initializer only; follow OZ reinitializer conventions for future upgrades.
  - storage gap for future state additions.
  - events for clarity on mint, burn, recycle actions.

  Deployment notes:
  1. Initialize with initialize(name, symbol, initialAdmin, councilAddr).
  2. Set minter contracts using setMinter().
  3. Move DEFAULT_ADMIN_ROLE to multisig/timelock.
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
    address public council;

    // -------------------------
    // Events
    // -------------------------
    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);
    event MinterSet(address indexed oldMinter, address indexed newMinter);
    event MinterRevoked(address indexed revokedMinter);
    event Paused(address account);
    event Unpaused(address account);

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

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        council = council_;

        // Initial allocation (configurable if desired)
        _mint(initialAdmin, 100_000_000 * 1e18);
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

    function burn(uint256 amount) 
        external 
        whenNotPaused 
    {
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
    // Minter management
    // -------------------------
    function setMinter(address newMinter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMinter != address(0), "CATA: zero minter");
        _grantRole(MINTER_ROLE, newMinter);
        emit MinterSet(address(0), newMinter);
    }

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
    // Pause / Unpause
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
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // -------------------------
    // ERC20 Hooks
    // -------------------------
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        super._beforeTokenTransfer(from, to, amount);
        require(!paused(), "CATA: token transfer while paused");
    }

    // -------------------------
    // Storage gap
    // -------------------------
    uint256[50] private __gap;
}

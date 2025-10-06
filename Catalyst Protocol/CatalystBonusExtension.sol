// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

/// @notice Minimal interface to read data from the main staking contract
interface ICatalystCore {
    function participatingWallets(uint256) external view returns (address);
    function participatingWalletsLength() external view returns (uint256);
    function burnedCatalystByAddress(address) external view returns (uint256);
    function treasuryBalance() external view returns (uint256);
    function cataERC20() external view returns (IERC20Upgradeable);
    function BP_DENOM() external view returns (uint256);
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/// @title Catalyst Bonus Extension
/// @notice External module that handles Top 1 % Burner Bonus logic to reduce core size.
contract CatalystBonusExtension {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // ---------- Constants ----------
    uint256 public constant MAX_PARTICIPANTS_LIMIT = 5000;
    uint256 public constant TOP_BURNER_PERCENT = 1;   // 1 %
    uint256 public constant TREASURY_BONUS_BP = 500;  // 5 % of treasury
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");

    // ---------- Events ----------
    event TopBurnerBonusDistributed(uint256 totalRecipients, uint256 totalBonus, uint256 perWallet);

    // ================================================================
    // 🔹 VIEW: Eligible count
    // ================================================================
    function topBurnerEligibleCount(address core) external view returns (uint256) {
        uint256 total = ICatalystCore(core).participatingWalletsLength();
        if (total == 0) return 0;
        uint256 count = (total * TOP_BURNER_PERCENT) / 100;
        if (count == 0 && total > 0) count = 1;
        return count;
    }

    // ================================================================
    // 🔹 VIEW: Leaderboard (for front-end)
    // ================================================================
    /// @notice Returns top N burners and their burned amounts (view-only)
    function viewTopBurners(address core, uint256 limit)
        external
        view
        returns (address[] memory burners, uint256[] memory burned)
    {
        ICatalystCore C = ICatalystCore(core);
        uint256 total = C.participatingWalletsLength();
        if (total == 0) return (new address (0), new uint256 (0));
        if (total > MAX_PARTICIPANTS_LIMIT) total = MAX_PARTICIPANTS_LIMIT;

        uint256 topCount = (total * TOP_BURNER_PERCENT) / 100;
        if (topCount == 0) topCount = 1;
        if (limit > 0 && limit < topCount) topCount = limit;

        burners = new address[](topCount);
        burned = new uint256[](topCount);

        (address[] memory wallets, uint256[] memory burns) = _getSortedBurners(C, total, topCount);

        for (uint256 i = 0; i < topCount; i++) {
            burners[i] = wallets[i];
            burned[i] = burns[i];
        }
    }

    // ================================================================
    // 🔹 MAIN: Distribution
    // ================================================================
    function distributeTopBurnerBonus(address core) external {
        ICatalystCore C = ICatalystCore(core);
        require(C.hasRole(CONTRACT_ADMIN_ROLE, msg.sender), "Not admin");

        uint256 total = C.participatingWalletsLength();
        require(total > 0, "No participants");
        require(total <= MAX_PARTICIPANTS_LIMIT, "Too many participants");

        uint256 topCount = (total * TOP_BURNER_PERCENT) / 100;
        if (topCount == 0) topCount = 1;

        uint256 bonusPool = (C.treasuryBalance() * TREASURY_BONUS_BP) / C.BP_DENOM();
        require(bonusPool > 0, "No treasury bonus");

        (address[] memory topBurners, ) = _getSortedBurners(C, total, topCount);
        uint256 perWallet = bonusPool / topBurners.length;
        require(perWallet > 0, "Bonus too small");

        IERC20Upgradeable token = C.cataERC20();
        for (uint256 i = 0; i < topBurners.length; i++) {
            token.safeTransfer(topBurners[i], perWallet);
        }

        emit TopBurnerBonusDistributed(topBurners.length, bonusPool, perWallet);
    }

    // ================================================================
    // 🔹 INTERNAL: Sorting helper
    // ================================================================
    function _getSortedBurners(
        ICatalystCore C,
        uint256 n,
        uint256 topCount
    ) internal view returns (address[] memory wallets, uint256[] memory burns) {
        wallets = new address[](n);
        burns = new uint256[](n);

        for (uint256 i = 0; i < n; i++) {
            wallets[i] = C.participatingWallets(i);
            burns[i] = C.burnedCatalystByAddress(wallets[i]);
        }

        // Simple selection sort
        for (uint256 i = 0; i < topCount && i < n; i++) {
            uint256 maxIdx = i;
            for (uint256 j = i + 1; j < n; j++) {
                if (burns[j] > burns[maxIdx]) maxIdx = j;
            }
            (burns[i], burns[maxIdx]) = (burns[maxIdx], burns[i]);
            (wallets[i], wallets[maxIdx]) = (wallets[maxIdx], wallets[i]);
        }

        if (topCount > n) topCount = n;
    }
}

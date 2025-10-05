// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
CatalystStakingUpgradeable.sol
Standalone upgradeable staking contract with:
- custodial NFT staking (term + permanent)
- collection registration (UNVERIFIED / VERIFIED / BLUECHIP)
- fee split (burn / treasury / deployer)
- blue-chip enrollment & harvest
- reward minting via CATA token (staking contract must have MINTER_ROLE in CATA)
- caps: GLOBAL= 500,000,000 TERM=375,000,000 PERM=125,000,000 (bluechip belongs to perm)
*/

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
interface ICataToken {
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
}

contract CatalystStakingUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{

using SafeERC20Upgradeable for IERC20Upgradeable;

// ---------- Custom Errors for Reverts (Gas-efficient) ----------
error NotCouncil(); // Replaces "only council"
error ZeroAddr(); // Replaces "initial admin zero", "contract admin zero", "council zero", "cata zero", "deployer zero", "zero new", "CATA: zero address", "zero"
error AlreadyReg(); // Replaces "already reg"
error BadAddr(); // Replaces "bad addr"
error SupplyRange(); // Replaces "supply range"
error InsufficientCATA(); // Replaces "insufficient CATA"
error TransferFailed(); // Replaces "transferFrom failed", "deployer transfer failed", "surcharge transfer", "deployer transfer"
error ZeroFee(); // Replaces "zero fee"
error NotReg(); // Replaces "not reg"
error NotUnverified(); // Replaces "not unverified"
error NotExpired(); // Replaces "not expired"
error NoEscrow(); // Replaces "no escrow"
error EscrowMissing(); // Replaces "escrow missing"
error Cap20k(); // Replaces "cap 20k"
error GlobalCap(); // Replaces "global cap"
error TermCap(); // Replaces "term cap"
error PermCap(); // Replaces "perm cap"
error AlreadyStaked(); // Replaces "already staked"
error NotStaked(); // Replaces "not staked"
error TermActive(); // Replaces "term active"
error FeeRequired(); // Replaces "fee"
error BatchLimit(); // Replaces "batch"
error NoBlocks(); // Replaces "no blocks"
error NotCurrentDeployer(); // Replaces "CATA: not current deployer"
error NotBluechip(); // Replaces "not bluechip"
error NotEnrolled(); // Replaces "already enrolled", "not enrolled"
error NoToken(); // Replaces "no token"
error NotOwnerOfZero(); // Replaces "not owner of 0" (Used in place of catch block)
error UnauthorizedRoleGrant(); // Replaces "Unauthorized: Direct role granting is disabled."
error UnauthorizedRoleRevocation(); // Replaces "Unauthorized: Direct role revocation is disabled."
error UnauthorizedRoleRenouncement(); // Replaces "Unauthorized: Direct role renouncement is disabled."
error Mismatch(); // Used in onDRSRecover

// ---------- Roles ----------
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");
// ---------- External contracts ----------
    ICataToken public cata;
// CATA token (mint & burn)
    IERC20Upgradeable public cataERC20;
// ERC20 interface for transfers
    address public deployerAddress;
// receives deployer share from fee split
    address public council;
// guardian council address (for swapAdmin)
   address public deployerCouncil;
// ✅ dedicated deployer recovery council

    // ---------- Caps (NFTs) ----------
    uint256 public constant GLOBAL_NFT_CAP = 500_000_000;
uint256 public constant TERM_NFT_CAP   = 375_000_000;
uint256 public constant PERM_NFT_CAP   = 125_000_000;
// ---------- Fee split BPs ----------
    uint256 public constant BP_DENOM = 10000;
uint256 public constant BURN_BP = 9000;    // 90% burned from fee amount
    uint256 public constant TREASURY_BP = 900;
// 9% to treasury (contract)
    uint256 public constant DEPLOYER_BP = 100;
// 1% to deployerAddress

    // ---------- Collection / Tiering ----------
    enum CollectionTier { UNVERIFIED, VERIFIED, BLUECHIP }

    struct CollectionConfig {
        uint32 totalStaked;
// number of tokens staked in this collection
        uint32 totalStakers;
// number of distinct stakers
        bool registered;
        uint32 declaredSupply;
    }

    struct CollectionMeta {
        CollectionTier tier;
        address registrant;
        uint256 surchargeEscrow;
uint256 registeredAtBlock;
        uint256 lastTierProposalBlock;
    }

// ---------- Collection / Status ----------
enum CollectionStatus {
    NOT_REGISTERED,
    UNVERIFIED,
    VERIFIED,
    BLUECHIP
}

/// @notice Returns the current status of a collection
function getCollectionStatus(address collection) external view returns (CollectionStatus) {
    if (registeredIndex[collection] == 0) {
        return CollectionStatus.NOT_REGISTERED;
    }

    CollectionMeta memory meta = collectionMeta[collection];

    if (meta.tier == CollectionTier.UNVERIFIED) {
        return CollectionStatus.UNVERIFIED;
    } else if (meta.tier == CollectionTier.VERIFIED) {
        return CollectionStatus.VERIFIED;
    } else if (meta.tier == CollectionTier.BLUECHIP) {
        return CollectionStatus.BLUECHIP;
    }

    // fallback — should never hit
    return CollectionStatus.NOT_REGISTERED;
}

    address[] public registeredCollections;
    mapping(address => uint256) public registeredIndex;
// 1-based index
    mapping(address => CollectionConfig) public collectionConfigs;
    mapping(address => CollectionMeta)  public collectionMeta;
// ---------- Top collections (placeholder) ----------
    address[] public topCollections;
    uint256 public topPercent;
// used by eligibleCount

    // ---------- Treasury & Burn tracking ----------
    uint256 public treasuryBalance;
mapping(address => uint256) public burnedCatalystByCollection;
    mapping(address => uint256) public burnedCatalystByAddress;
    mapping(address => bool) public isParticipating;
    address[] public participatingWallets;
mapping(address => uint256) public lastBurnBlock;

    // ---------- Staking bookkeeping ----------
    struct StakeInfo {
        bool currentlyStaked;
bool isPermanent;
        uint256 stakeBlock;
        uint256 unstakeDeadlineBlock; // 0 if permanent
        uint256 lastHarvestBlock;
    }

    // collection => owner => tokenId => StakeInfo
    mapping(address => mapping(address => mapping(uint256 => StakeInfo))) public stakeLog;
// collection => owner => list of tokenIds
    mapping(address => mapping(address => uint256[])) public stakePortfolioByUser;
// tokenId index in portfolio
    mapping(address => mapping(uint256 => uint256)) public indexOfTokenIdInStakePortfolio;
// global counters
    uint256 public totalStakedAll;      // total NFTs staked (should be <= GLOBAL_NFT_CAP)
    uint256 public totalStakedTerm;
// term stake count (<= TERM_NFT_CAP)
    uint256 public totalStakedPerm;
// permanent stake count (<= PERM_NFT_CAP)
    uint256 public totalStakedNFTsCount;
// shorthand (equals totalStakedAll)

    // ---------- Reward config ----------
    uint256 public baseRewardRate;
// abstract units (minted by CATA)
    uint256 public numberOfBlocksPerRewardUnit;
// divisor to scale rewards
    uint256 public rewardRateIncrementPerNFT;
// small increment when staking
    uint256 public welcomeBonusBaseRate;
// minted on stake
    uint256 public welcomeBonusIncrementPerNFT;
// ---------- Staking policy params ----------
    uint256 public termDurationBlocks;
    uint256 public unstakeBurnFee;
// CATA fee (amount) to pay on unstake
    uint256 public permanentStakeFeeBase;
// CATA fee for permanent stake

    // ---------- Registration surcharge & upgrade rules ----------
    uint256 public unverifiedSurchargeBP;
// e.g., 12000 = 120% (surcharge > 10000 allowed)
    uint256 public tierUpgradeMinAgeBlocks;
    uint256 public tierUpgradeMinBurn;
// in CATA units
    uint256 public tierUpgradeMinStakers;
    uint256 public surchargeForfeitBlocks;
// ---------- Bluechip (non-custodial) ----------
    mapping(address => bool) public isBluechipCollection;
// bluechipWallets[collection][wallet] - use address(0) as global slot
    mapping(address => mapping(address => bool)) public bluechipWallets;
mapping(address => mapping(address => uint256)) public bluechipLastHarvestBlock;
    uint256 public bluechipWalletFee;
// fee in CATA amount for enrollment

    // ---------- Registration fee curve constants (example CATA amounts) ----------
    uint256 public constant SMALL_MIN_FEE = 1 * 10**18;
uint256 public constant SMALL_MAX_FEE = 10 * 10**18;
    uint256 public constant MED_MIN_FEE = 11 * 10**18;
uint256 public constant MED_MAX_FEE = 50 * 10**18;
    uint256 public constant LARGE_MIN_FEE = 51 * 10**18;
uint256 public constant LARGE_MAX_FEE_CAP = 200 * 10**18;

    // ---------- Limits ----------
    uint256 public constant MAX_STAKE_PER_COLLECTION = 20_000;
uint256 public constant MAX_HARVEST_BATCH = 50;

    // ---------- Events ----------
    event TreasuryDeposit(address indexed from, uint256 amount);
event CollectionAdded(address indexed collection, uint256 declaredSupply, uint256 baseFee, uint256 escrow, CollectionTier tier);
    event CollectionRemoved(address indexed collection);
event EscrowForfeited(address indexed collection, uint256 toTreasury, uint256 burned, address deployer, uint256 toDeployer);
event NFTStaked(address indexed who, address indexed collection, uint256 indexed tokenId);
    event NFTUnstaked(address indexed who, address indexed collection, uint256 indexed tokenId);
event RewardsHarvested(address indexed who, address indexed collection, uint256 payout, uint256 burned);
    event PermanentStakeFeePaid(address indexed who, uint256 fee);
event BluechipEnrolled(address indexed who);
    event BluechipHarvested(address indexed who, address indexed collection, uint256 amount);
    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
event CouncilSet(address indexed oldCouncil, address indexed newCouncil);
   event DeployerCouncilSet(address indexed oldCouncil, address indexed newCouncil);
// ✅ new
event CataTokenUpdated(address indexed oldCata, address indexed newCata);
event DeployerAddressUpdated(address indexed oldDeployer, address indexed newDeployer);
event TreasuryWithdraw(address indexed to, uint256 amount);


    // ---------- Modifiers ----------
    modifier onlyCouncil() {
        if (msg.sender != council) revert NotCouncil();
_;
    }

    // ---------- Initialize ----------
    function initialize(
        address initialAdmin,
        address contractAdmin,
        address council_,
        address cataToken,
        address deployerAddr
    ) external initializer {
        __AccessControl_init();
__ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        if (initialAdmin == address(0)) revert ZeroAddr();
        if (contractAdmin == address(0)) revert ZeroAddr();
        if (council_ == address(0)) revert ZeroAddr();
        if (cataToken == address(0)) revert ZeroAddr();
        if (deployerAddr == address(0)) revert ZeroAddr();

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(CONTRACT_ADMIN_ROLE, contractAdmin);

        council = council_;
        cata = ICataToken(cataToken);
        cataERC20 = IERC20Upgradeable(cataToken);
        deployerAddress = deployerAddr;

        // sensible defaults
        numberOfBlocksPerRewardUnit = 6500;
baseRewardRate = 10;
        rewardRateIncrementPerNFT = 1;
        welcomeBonusBaseRate = 5;
        welcomeBonusIncrementPerNFT = 1;
        termDurationBlocks = 65000;
        unstakeBurnFee = 1 * 10**18;
permanentStakeFeeBase = 10 * 10**18;

        unverifiedSurchargeBP = 12000; // 120% surcharge
        tierUpgradeMinAgeBlocks = 10000;
tierUpgradeMinBurn = 1 * 10**18;
        tierUpgradeMinStakers = 2;
        surchargeForfeitBlocks = 200000;

        bluechipWalletFee = 1 * 10**18;

        topPercent = 10;
// default top percent used by eligibleCount
    }

    // ---------- UUPS authorize ----------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // ---------- Council administration ----------
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newCouncil == address(0)) revert ZeroAddr();
address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    /// ✅ New dedicated deployer council setter
    function setDeployerCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newCouncil == address(0)) revert ZeroAddr();
address old = deployerCouncil;
        deployerCouncil = newCouncil;
        emit DeployerCouncilSet(old, newCouncil);
    }

function setCataToken(address newCata) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (newCata == address(0)) revert ZeroAddr();
    address old = address(cata);
// update both references
    cata = ICataToken(newCata);
    cataERC20 = IERC20Upgradeable(newCata);

    emit CataTokenUpdated(old, newCata);
}

function setDeployerAddress(address newDeployer) external {
    if (msg.sender != deployerAddress) revert NotCurrentDeployer();
    if (newDeployer == address(0)) revert ZeroAddr();

    address old = deployerAddress;
    deployerAddress = newDeployer;

    emit DeployerAddressUpdated(old, newDeployer);
}


    function swapAdmin(address newAdmin, address oldAdmin) external onlyCouncil {
        if (newAdmin == address(0)) revert ZeroAddr();
if (!hasRole(DEFAULT_ADMIN_ROLE, newAdmin)) {
            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
}
        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE, oldAdmin)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
}
        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // ---------- Registration helpers ----------
    function _isRegistered(address collection) internal view returns (bool) {
        return registeredIndex[collection] != 0;
    }

    function registeredCount() external view returns (uint256) {
        return registeredCollections.length;
    }

    function eligibleCount() external view returns (uint256) {
        uint256 total = registeredCollections.length;
if (total == 0) return 0;
        uint256 count = (total * topPercent) / 100;
if (count == 0) count = 1;
        return count;
    }

    // ---------- Fee curve ----------
    function _calculateRegistrationBaseFee(uint256 declaredSupply) internal pure returns (uint256) {
        // Since original had an internal check, I'll keep it for clarity of logic, though it's usually omitted for pure functions with external callers.
        // require(declaredSupply >= 1, "declared>=1");

        if (declaredSupply <= 5000) {
            uint256 numerator = declaredSupply * (SMALL_MAX_FEE - SMALL_MIN_FEE);
return SMALL_MIN_FEE + (numerator / 5000);
        } else if (declaredSupply <= 10000) {
            uint256 numerator = (declaredSupply - 5000) * (MED_MAX_FEE - MED_MIN_FEE);
return MED_MIN_FEE + (numerator / 5000);
        } else {
            uint256 extra = declaredSupply - 10000;
uint256 range = 10000;
            if (extra >= range) return LARGE_MAX_FEE_CAP;
            uint256 numerator = extra * (LARGE_MAX_FEE_CAP - LARGE_MIN_FEE);
return LARGE_MIN_FEE + (numerator / range);
        }
    }

    function _computeFeeAndSurchargeForTier(uint256 baseFee, CollectionTier tier) internal view returns (uint256 totalFee, uint256 surcharge) {
        uint256 multBP = (tier == CollectionTier.UNVERIFIED) ?
unverifiedSurchargeBP : BP_DENOM;
        uint256 total = (baseFee * multBP) / BP_DENOM;
        uint256 sur = (multBP > BP_DENOM) ?
(total - baseFee) : 0;
        return (total, sur);
    }

    /// @dev Transfer total `amount` from payer to contract and split: burn / treasury / deployer
    function _splitFeeFromSender(address payer, uint256 amount, address collection, bool attributeToUser) internal {
    if (amount == 0) revert ZeroFee();

    bool ok = cataERC20.transferFrom(payer, address(this), amount);
    if (!ok) revert TransferFailed();

    uint256 burnAmt = (amount * BURN_BP) / BP_DENOM;
    uint256 treasuryAmt = (amount * TREASURY_BP) / BP_DENOM;
    uint256 deployerAmt = amount - burnAmt - treasuryAmt;
// 🔥 burn
    if (burnAmt > 0) {
        cata.burn(burnAmt);
    burnedCatalystByCollection[collection] += burnAmt;
        if (attributeToUser) {
            burnedCatalystByAddress[payer] += burnAmt;
lastBurnBlock[payer] = block.number;
            if (!isParticipating[payer]) {
                isParticipating[payer] = true;
participatingWallets.push(payer);
            }
        }
    }

    // 🏦 treasury
    if (treasuryAmt > 0) {
        treasuryBalance += treasuryAmt;
emit TreasuryDeposit(payer, treasuryAmt);
    }

    // 👤 deployer
    if (deployerAmt > 0) {
        bool ok2 = cataERC20.transfer(deployerAddress, deployerAmt);
        if (!ok2) revert TransferFailed();
    }
}

    // ---------- Collection registration (admin-only) ----------
    function setCollectionConfig(address collection, uint256 declaredMaxSupply, CollectionTier tier) external onlyRole(CONTRACT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (collection == address(0)) revert BadAddr();
        if (_isRegistered(collection)) revert AlreadyReg();
        if (declaredMaxSupply < 1 || declaredMaxSupply > MAX_STAKE_PER_COLLECTION) revert SupplyRange();

        uint256 baseFee = _calculateRegistrationBaseFee(declaredMaxSupply);
        (uint256 totalFee, uint256 surcharge) = _computeFeeAndSurchargeForTier(baseFee, CollectionTier(tier));
        if (cataERC20.balanceOf(msg.sender) < totalFee) revert InsufficientCATA();
// transfer & split base fee (burn/treasury/deployer)
        _splitFeeFromSender(msg.sender, baseFee, collection, true);
        uint256 escrowAmt = 0;
        if (surcharge > 0) {
            bool ok = cataERC20.transferFrom(msg.sender, address(this), surcharge);
            if (!ok) revert TransferFailed();
            escrowAmt = surcharge;
        }

        registeredCollections.push(collection);
        registeredIndex[collection] = registeredCollections.length;
        collectionConfigs[collection] = CollectionConfig({
            totalStaked: 0,
            totalStakers: 0,
            registered: true,
            declaredSupply: uint32(declaredMaxSupply)
        });
        collectionMeta[collection] = CollectionMeta({
            tier: tier,
            registrant: msg.sender,
            surchargeEscrow: escrowAmt,
            registeredAtBlock: block.number,
            lastTierProposalBlock: 0
        });
        _maybeRebuildTopCollections();
        emit CollectionAdded(collection, declaredMaxSupply, baseFee, escrowAmt, CollectionTier(tier));
    }

    // ---------- Public registerCollection (permissionless) ----------
    function registerCollection(address collection, uint256 declaredMaxSupply, CollectionTier requestedTier) external nonReentrant whenNotPaused {
        if (collection == address(0)) revert BadAddr();
        if (_isRegistered(collection)) revert AlreadyReg();
        if (declaredMaxSupply < 1 || declaredMaxSupply > MAX_STAKE_PER_COLLECTION) revert SupplyRange();

        bool allowVerified = false;
        if (hasRole(CONTRACT_ADMIN_ROLE, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            allowVerified = true;
        } else {
            // try ownerOf(0)
            try IERC721(collection).ownerOf(0) returns (address ownerAddr) {
                if (ownerAddr == msg.sender) allowVerified = true;
            } catch {
                // Simplified error handling for size limit.
                // allowVerified remains false if the call reverts or if it's not the sender.
            }
        }

        CollectionTier tierToUse = requestedTier;
        if (!allowVerified && requestedTier == CollectionTier.VERIFIED) {
            tierToUse = CollectionTier.UNVERIFIED;
        }

        uint256 baseFee = _calculateRegistrationBaseFee(declaredMaxSupply);
        (uint256 totalFee, uint256 surcharge) = _computeFeeAndSurchargeForTier(baseFee, tierToUse);
        if (cataERC20.balanceOf(msg.sender) < totalFee) revert InsufficientCATA();

        // transfer & split base fee
        _splitFeeFromSender(msg.sender, baseFee, collection, true);
        uint256 escrowAmt = 0;
        if (surcharge > 0) {
            bool ok = cataERC20.transferFrom(msg.sender, address(this), surcharge);
            if (!ok) revert TransferFailed();
            escrowAmt = surcharge;
        }

        registeredCollections.push(collection);
        registeredIndex[collection] = registeredCollections.length;
        collectionConfigs[collection] = CollectionConfig({
            totalStaked: 0,
            totalStakers: 0,
            registered: true,
            declaredSupply: uint32(declaredMaxSupply)
        });
        collectionMeta[collection] = CollectionMeta({
            tier: tierToUse,
            registrant: msg.sender,
            surchargeEscrow: escrowAmt,
            registeredAtBlock: block.number,
            lastTierProposalBlock: 0
        });
        _updateTopCollectionsOnBurn(collection);
        _maybeRebuildTopCollections();

        emit CollectionAdded(collection, declaredMaxSupply, baseFee, escrowAmt, tierToUse);
    }

    // ---------- removeCollection ----------
    function removeCollection(address collection) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        if (!collectionConfigs[collection].registered) revert NotReg();
        collectionConfigs[collection].registered = false;

        uint256 idx = registeredIndex[collection];
        if (idx != 0) {
            uint256 i = idx - 1;
            uint256 last = registeredCollections.length - 1;
            if (i != last) {
                address lastAddr = registeredCollections[last];
                registeredCollections[i] = lastAddr;
                registeredIndex[lastAddr] = i + 1;
            }
            registeredCollections.pop();
            registeredIndex[collection] = 0;
        }

        // remove from topCollections if present
        for (uint256 t = 0; t < topCollections.length; t++) {
            if (topCollections[t] == collection) {
                for (uint256 j = t; j + 1 < topCollections.length; j++) topCollections[j] = topCollections[j + 1];
                topCollections.pop();
                break;
            }
        }

        emit CollectionRemoved(collection);
    }

    // ---------- Tier upgrade eligibility & escrow forfeit ----------
    function _eligibleForTierUpgrade(address collection) internal view returns (bool) {
        CollectionMeta memory m = collectionMeta[collection];
        if (m.tier != CollectionTier.UNVERIFIED) return false;
        if (block.number < m.registeredAtBlock + tierUpgradeMinAgeBlocks) return false;
        if (burnedCatalystByCollection[collection] < tierUpgradeMinBurn) return false;
        if (collectionConfigs[collection].totalStakers < tierUpgradeMinStakers) return false;
        return true;
    }

    function forfeitEscrowIfExpired(address collection) 
    external 
    onlyRole(CONTRACT_ADMIN_ROLE) 
    nonReentrant 
{
    CollectionMeta storage m = collectionMeta[collection];
    if (!collectionConfigs[collection].registered) revert NotReg();
    if (m.tier != CollectionTier.UNVERIFIED) revert NotUnverified();
    if (block.number < m.registeredAtBlock + surchargeForfeitBlocks) revert NotExpired();

    uint256 amt = m.surchargeEscrow;
    if (amt == 0) revert NoEscrow();

    // --- EFFECTS ---
    m.surchargeEscrow = 0;
// --- SPLIT ---
    uint256 burnAmt = (amt * BURN_BP) / BP_DENOM;
// 90%
    uint256 treasuryAmt = (amt * TREASURY_BP) / BP_DENOM;
// 9%
    uint256 deployerAmt = amt - burnAmt - treasuryAmt;
// 1%

    // --- CHECKS ---
    uint256 bal = cataERC20.balanceOf(address(this));
    if (bal < amt) revert EscrowMissing();

    // --- INTERACTIONS ---
    if (burnAmt > 0) {
        cata.burn(burnAmt);
    }

    if (treasuryAmt > 0) {
        treasuryBalance += treasuryAmt;
    }

    if (deployerAmt > 0) {
        bool ok = cataERC20.transfer(deployerAddress, deployerAmt);
        if (!ok) revert TransferFailed();
    }

    // 🔥 Consolidated log of full split
    emit EscrowForfeited(collection, treasuryAmt, burnAmt, deployerAddress, deployerAmt);
}

    // ---------- Staking ----------
    // ---------- Term Stake ----------
function termStake(address collection, uint256 tokenId)
    public
    nonReentrant
    whenNotPaused
{
    _termStake(collection, tokenId, msg.sender);
}

function _termStake(address collection, uint256 tokenId, address user) internal {
    // -------- CHECKS --------
    if (!collectionConfigs[collection].registered) revert NotReg();
    if (collectionConfigs[collection].totalStaked >= MAX_STAKE_PER_COLLECTION) revert Cap20k();
    if (totalStakedAll + 1 > GLOBAL_NFT_CAP) revert GlobalCap();
    if (totalStakedTerm + 1 > TERM_NFT_CAP) revert TermCap();
    StakeInfo storage info = stakeLog[collection][user][tokenId];
    if (info.currentlyStaked) revert AlreadyStaked();

    // -------- EFFECTS --------
    info.stakeBlock = block.number;
    info.lastHarvestBlock = block.number;
    info.currentlyStaked = true;
    info.isPermanent = false;
    info.unstakeDeadlineBlock = block.number + termDurationBlocks;

    CollectionConfig storage cfg = collectionConfigs[collection];
    if (stakePortfolioByUser[collection][user].length == 0) cfg.totalStakers += 1;
    cfg.totalStaked += 1;

    totalStakedAll += 1;
    totalStakedTerm += 1;
    totalStakedNFTsCount += 1;
    baseRewardRate += rewardRateIncrementPerNFT;

    stakePortfolioByUser[collection][user].push(tokenId);
    indexOfTokenIdInStakePortfolio[collection][tokenId] =
        stakePortfolioByUser[collection][user].length - 1;
    uint256 dynamicWelcome =
        welcomeBonusBaseRate + (totalStakedNFTsCount * welcomeBonusIncrementPerNFT);
// -------- INTERACTIONS --------
    IERC721(collection).safeTransferFrom(user, address(this), tokenId);
    cata.mint(user, dynamicWelcome);

    emit NFTStaked(user, collection, tokenId);
}

// ---------- Permanent Stake ----------
function permanentStake(address collection, uint256 tokenId)
    public
    nonReentrant
    whenNotPaused
{
    _permanentStake(collection, tokenId, msg.sender);
}

function _permanentStake(address collection, uint256 tokenId, address user) internal {
    // -------- CHECKS --------
    if (!collectionConfigs[collection].registered) revert NotReg();
    if (collectionConfigs[collection].totalStaked >= MAX_STAKE_PER_COLLECTION) revert Cap20k();
    if (totalStakedAll + 1 > GLOBAL_NFT_CAP) revert GlobalCap();
    if (totalStakedPerm + 1 > PERM_NFT_CAP) revert PermCap();
    uint256 fee = permanentStakeFeeBase;
    if (cataERC20.balanceOf(user) < fee) revert InsufficientCATA();

    StakeInfo storage info = stakeLog[collection][user][tokenId];
    if (info.currentlyStaked) revert AlreadyStaked();
// -------- EFFECTS --------
    info.stakeBlock = block.number;
    info.lastHarvestBlock = block.number;
    info.currentlyStaked = true;
    info.isPermanent = true;
    info.unstakeDeadlineBlock = 0;

    CollectionConfig storage cfg = collectionConfigs[collection];
    if (stakePortfolioByUser[collection][user].length == 0) cfg.totalStakers += 1;
    cfg.totalStaked += 1;
    totalStakedAll += 1;
    totalStakedPerm += 1;
    totalStakedNFTsCount += 1;
    baseRewardRate += rewardRateIncrementPerNFT;

    stakePortfolioByUser[collection][user].push(tokenId);
    indexOfTokenIdInStakePortfolio[collection][tokenId] =
        stakePortfolioByUser[collection][user].length - 1;
    uint256 dynamicWelcome =
        welcomeBonusBaseRate + (totalStakedNFTsCount * welcomeBonusIncrementPerNFT);
// -------- INTERACTIONS --------
    // collect fee
    _splitFeeFromSender(user, fee, collection, true);
// transfer NFT
    IERC721(collection).safeTransferFrom(user, address(this), tokenId);

    // welcome bonus
    cata.mint(user, dynamicWelcome);

    emit PermanentStakeFeePaid(user, fee);
    emit NFTStaked(user, collection, tokenId);
}

// ---------- Unstake ----------
function unstake(address collection, uint256 tokenId)
    public
    nonReentrant
    whenNotPaused
{
    _unstake(collection, tokenId, msg.sender);
}

function _unstake(address collection, uint256 tokenId, address user) internal {
    // -------- CHECKS --------
    StakeInfo storage info = stakeLog[collection][user][tokenId];
    if (!info.currentlyStaked) revert NotStaked();
    if (!info.isPermanent && block.number < info.unstakeDeadlineBlock) revert TermActive();

    // Harvest first
    _harvest(collection, user, tokenId);
// -------- EFFECTS --------
    bool wasPermanent = info.isPermanent;
    info.currentlyStaked = false;

    uint256[] storage port = stakePortfolioByUser[collection][user];
    uint256 idx = indexOfTokenIdInStakePortfolio[collection][tokenId];
    uint256 last = port.length - 1;
    if (idx != last) {
        uint256 lastTokenId = port[last];
        port[idx] = lastTokenId;
        indexOfTokenIdInStakePortfolio[collection][lastTokenId] = idx;
    }
    port.pop();
    delete indexOfTokenIdInStakePortfolio[collection][tokenId];

    CollectionConfig storage cfg = collectionConfigs[collection];
    if (stakePortfolioByUser[collection][user].length == 0 && cfg.totalStakers > 0) cfg.totalStakers -= 1;
    if (cfg.totalStaked > 0) cfg.totalStaked -= 1;
    if (baseRewardRate >= rewardRateIncrementPerNFT) baseRewardRate -= rewardRateIncrementPerNFT;

    totalStakedAll -= 1;
    totalStakedNFTsCount -= 1;
    if (wasPermanent) {
        if (totalStakedPerm > 0) totalStakedPerm -= 1;
    } else {
        if (totalStakedTerm > 0) totalStakedTerm -= 1;
    }

    // -------- INTERACTIONS --------
    if (cataERC20.balanceOf(user) < unstakeBurnFee) revert FeeRequired();
    _splitFeeFromSender(user, unstakeBurnFee, collection, true);
    IERC721(collection).safeTransferFrom(address(this), user, tokenId);

    emit NFTUnstaked(user, collection, tokenId);
}

// ---------- Batch functions ----------
function batchTermStake(address collection, uint256[] calldata tokenIds)
    external
    nonReentrant
    whenNotPaused
{
    uint256 len = tokenIds.length;
    if (len == 0 || len > MAX_HARVEST_BATCH) revert BatchLimit();
    for (uint256 i = 0; i < len; i++) {
        _termStake(collection, tokenIds[i], msg.sender);
    }
}

function batchPermanentStake(address collection, uint256[] calldata tokenIds)
    external
    nonReentrant
    whenNotPaused
{
    uint256 len = tokenIds.length;
    if (len == 0 || len > MAX_HARVEST_BATCH) revert BatchLimit();
    for (uint256 i = 0; i < len; i++) {
        _permanentStake(collection, tokenIds[i], msg.sender);
    }
}

function batchUnstake(address collection, uint256[] calldata tokenIds)
    external
    nonReentrant
    whenNotPaused
{
    uint256 len = tokenIds.length;
    if (len == 0 || len > MAX_HARVEST_BATCH) revert BatchLimit();
    for (uint256 i = 0; i < len; i++) {
        _unstake(collection, tokenIds[i], msg.sender);
    }
} 


   // ---------- Harvest ----------
function harvest(address collection, uint256 tokenId)
    external
    nonReentrant
    whenNotPaused
{
    _harvest(collection, msg.sender, tokenId);
}

function _harvest(address collection, address user, uint256 tokenId) internal {
    // -------- CHECKS --------
    StakeInfo storage info = stakeLog[collection][user][tokenId];
    if (!info.currentlyStaked) revert NotStaked();

    uint256 blocksPassed = block.number - info.lastHarvestBlock;
    if (blocksPassed == 0) revert NoBlocks();
// -------- EFFECTS --------
    uint256 reward = blocksPassed * baseRewardRate;
    info.lastHarvestBlock = block.number;
// -------- INTERACTIONS --------
    if (reward > 0) {
        uint256 userShare = _applyTaxAndSplit(user, reward, collection);
        emit RewardsHarvested(user, collection, tokenId, userShare);
    }
}

//---------- Harvest Batch ----------
function harvestBatch(address collection, uint256[] calldata tokenIds)
    external
    nonReentrant
    whenNotPaused
{
    uint256 len = tokenIds.length;
    if (len == 0 || len > MAX_HARVEST_BATCH) revert BatchLimit();

    for (uint256 i = 0; i < len; i++) {
        _harvest(collection, msg.sender, tokenIds[i]);
    }
}  

    function pendingRewards(address collection, address owner, uint256 tokenId) public view returns (uint256) {
    StakeInfo memory info = stakeLog[collection][owner][tokenId];
    if (!info.currentlyStaked || baseRewardRate == 0) return 0;
    if (!info.isPermanent && block.number < info.unstakeDeadlineBlock) {
        // term still active but not ready -> rewards continue
    } else if (!info.isPermanent && block.number >= info.unstakeDeadlineBlock) {
        // term expired and not harvested -> no more rewards
        return 0;
    }

    uint256 blocksPassed = block.number - info.lastHarvestBlock;
    if (blocksPassed == 0) return 0;
// ✅ Use same formula as _harvest
    uint256 reward = blocksPassed * baseRewardRate;
// ✅ Apply the same 90/10 split preview
    uint256 userShare = (reward * 90) / 100;
    return userShare;
}

    // ---------- Bluechip non-custodial ----------
    function setBluechipCollection(address collection, bool isBluechip) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        if (collection == address(0)) revert ZeroAddr();
        if (registeredIndex[collection] == 0) revert NotReg();
        isBluechipCollection[collection] = isBluechip;
    }

    function enrollBluechip() external nonReentrant whenNotPaused {
        address wallet = msg.sender;
        if (bluechipWallets[address(0)][wallet]) revert NotEnrolled(); // Re-use NotEnrolled for 'already enrolled'
        uint256 fee = bluechipWalletFee;
        if (fee > 0) {
            // move fee to contract & split as per immutable split (attributeToUser=false for enroll)
            bool ok = cataERC20.transferFrom(wallet, address(this), fee);
            if (!ok) revert TransferFailed();
            // split: burn / deployer / treasury (no attribute to user)
            uint256 burnAmt = (fee * BURN_BP) / BP_DENOM;
            uint256 treasuryAmt = (fee * TREASURY_BP) / BP_DENOM;
            uint256 deployerAmt = fee - burnAmt - treasuryAmt;
            if (burnAmt > 0) {
                cata.burn(burnAmt);
            }
            if (deployerAmt > 0) {
                bool ok2 = cataERC20.transfer(deployerAddress, deployerAmt);
                if (!ok2) revert TransferFailed();
            }
            if (treasuryAmt > 0) {
                treasuryBalance += treasuryAmt;
                emit TreasuryDeposit(wallet, treasuryAmt);
            }
        }
        bluechipWallets[address(0)][wallet] = true;
        bluechipLastHarvestBlock[address(0)][wallet] = block.number;
        emit BluechipEnrolled(wallet);
    }

   function harvestBluechip(address collection) external nonReentrant whenNotPaused {
    if (!isBluechipCollection[collection]) revert NotBluechip();
    if (!bluechipWallets[address(0)][msg.sender]) revert NotEnrolled();
    if (IERC721(collection).balanceOf(msg.sender) == 0) revert NoToken();

    uint256 last = bluechipLastHarvestBlock[address(0)][msg.sender];
    uint256 blocksElapsed = block.number - last;
    if (blocksElapsed == 0) return;

    uint256 reward = (blocksElapsed * baseRewardRate) / numberOfBlocksPerRewardUnit;
    if (reward == 0) {
        bluechipLastHarvestBlock[address(0)][msg.sender] = block.number;
        return;
    }

    // ✅ Apply universal 90/10 split with 90/9/1 tax rule
    uint256 userShare = _applyTaxAndSplit(msg.sender, reward, collection);
    bluechipLastHarvestBlock[address(0)][msg.sender] = block.number;
    emit BluechipHarvested(msg.sender, collection, userShare);
}

function _applyTaxAndSplit(address user, uint256 amount, address collection) internal returns (uint256 userShare) {
    if (amount == 0) return 0;
// ✅ User keeps 90%
    userShare = (amount * 90) / 100;
    if (userShare > 0) {
        cata.mint(user, userShare);
    }

    // ✅ Tax = 10%
    uint256 tax = amount - userShare;
// Split tax: 90/9/1
    uint256 burnAmt = (tax * 9000) / 10000;
    uint256 treasuryAmt = (tax * 900) / 10000;
    uint256 deployerAmt = tax - burnAmt - treasuryAmt;
// 🔥 Burn
    if (burnAmt > 0) {
        cata.mint(address(this), burnAmt);
        cata.burn(burnAmt);
        burnedCatalystByCollection[collection] += burnAmt;
        burnedCatalystByAddress[user] += burnAmt;
        lastBurnBlock[user] = block.number;
        _updateTopCollectionsOnBurn(collection);
    }

    // 🏦 Treasury
    if (treasuryAmt > 0) {
        cata.mint(address(this), treasuryAmt);
        treasuryBalance += treasuryAmt;
        emit TreasuryDeposit(user, treasuryAmt);
    }

    // 👤 Deployer
    if (deployerAmt > 0) {
        cata.mint(deployerAddress, deployerAmt);
    }

    return userShare;
}

    // ---------- Utilities & placeholders ----------
    function _updateTopCollectionsOnBurn(address collection) internal {
        // placeholder: update ranking when burns occur (left intentionally simple)
        // Could maintain a top-N sorted list by burnedCatalystByCollection[collection]
    }

    function _maybeRebuildTopCollections() internal {
        // placeholder: optionally recompute topCollections periodically
    }

// -----------------------------
// Admin Utilities
// -----------------------------


function withdrawTreasury(address to, uint256 amount) 
    external 
  
    onlyRole(DEFAULT_ADMIN_ROLE) 
    nonReentrant 
{
    if (to == address(0)) revert ZeroAddr();
    if (amount > treasuryBalance) revert InsufficientCATA(); // Re-use InsufficientCATA for insufficient balance
    treasuryBalance -= amount;
    cataERC20.safeTransfer(to, amount);
    emit TreasuryWithdraw(to, amount);
}

    // ---------- Pause control ----------
    function pause() external onlyRole(CONTRACT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(CONTRACT_ADMIN_ROLE) {
        _unpause();
    }

function onDRSRecover(bytes32, address oldAccount, address newAccount) external {
    if (msg.sender != deployerCouncil) revert NotCouncil();
    if (newAccount == address(0)) revert ZeroAddr();
    if (deployerAddress != oldAccount) revert Mismatch();

    address old = deployerAddress;
    deployerAddress = newAccount;
    emit DeployerAddressUpdated(old, newAccount);
}

// In any contract inheriting AccessControlUpgradeable (e.g., CataERC20Upgradeable, CatalystGovernanceUpgradeable, BatchGuardianCouncilUpgradeable.sol)

/// @dev Overrides grantRole, disabling direct external calls.
// Parameter names are removed (e.g., 'role' and 'account') to silence compiler warnings.
function grantRole(bytes32, address) public virtual override {
    revert UnauthorizedRoleGrant();
}

/// @dev Overrides revokeRole, disabling direct external calls.
// Parameter names are removed to silence compiler warnings.
function revokeRole(bytes32, address) public virtual override {
    revert UnauthorizedRoleRevocation();
}

/// @dev Overrides renounceRole, preventing accounts from voluntarily relinquishing a role.
// Parameter names are removed to silence compiler warnings.
function renounceRole(bytes32, address) public virtual override {
    revert UnauthorizedRoleRenouncement();
}


    // ---------- ERC721 receiver ----------
    // allow receiving ERC721 tokens via safeTransferFrom
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

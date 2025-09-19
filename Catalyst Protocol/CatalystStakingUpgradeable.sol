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
    // ---------- Roles ----------
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");

    // ---------- External contracts ----------
    ICataToken public cata;           // CATA token (mint & burn)
    IERC20Upgradeable public cataERC20; // ERC20 interface for transfers
    address public deployerAddress;   // receives deployer share from fee split
    address public council;           // guardian council address (for swapAdmin)

    // ---------- Caps (NFTs) ----------
    uint256 public constant GLOBAL_NFT_CAP = 500_000_000;
uint256 public constant TERM_NFT_CAP   = 375_000_000;
uint256 public constant PERM_NFT_CAP   = 125_000_000;

    // ---------- Fee split BPs ----------
    uint256 public constant BP_DENOM = 10000;
    uint256 public constant BURN_BP = 9000;    // 90% burned from fee amount
    uint256 public constant TREASURY_BP = 900; // 9% to treasury (contract)
    uint256 public constant DEPLOYER_BP = 100; // 1% to deployerAddress

    // ---------- Collection / Tiering ----------
    enum CollectionTier { UNVERIFIED, VERIFIED, BLUECHIP }

    struct CollectionConfig {
        uint32 totalStaked;      // number of tokens staked in this collection
        uint32 totalStakers;     // number of distinct stakers
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

    address[] public registeredCollections;
    mapping(address => uint256) public registeredIndex; // 1-based index
    mapping(address => CollectionConfig) public collectionConfigs;
    mapping(address => CollectionMeta)  public collectionMeta;

    // ---------- Top collections (placeholder) ----------
    address[] public topCollections;
    uint256 public topPercent; // used by eligibleCount

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
    uint256 public totalStakedTerm;     // term stake count (<= TERM_NFT_CAP)
    uint256 public totalStakedPerm;     // permanent stake count (<= PERM_NFT_CAP)
    uint256 public totalStakedNFTsCount; // shorthand (equals totalStakedAll)

    // ---------- Reward config ----------
    uint256 public baseRewardRate;                 // abstract units (minted by CATA)
    uint256 public numberOfBlocksPerRewardUnit;   // divisor to scale rewards
    uint256 public rewardRateIncrementPerNFT;     // small increment when staking
    uint256 public welcomeBonusBaseRate;          // minted on stake
    uint256 public welcomeBonusIncrementPerNFT;

    // ---------- Staking policy params ----------
    uint256 public termDurationBlocks;
    uint256 public unstakeBurnFee; // CATA fee (amount) to pay on unstake
    uint256 public permanentStakeFeeBase; // CATA fee for permanent stake

    // ---------- Registration surcharge & upgrade rules ----------
    uint256 public unverifiedSurchargeBP; // e.g., 12000 = 120% (surcharge > 10000 allowed)
    uint256 public tierUpgradeMinAgeBlocks;
    uint256 public tierUpgradeMinBurn; // in CATA units
    uint256 public tierUpgradeMinStakers;
    uint256 public surchargeForfeitBlocks;

    // ---------- Bluechip (non-custodial) ----------
    mapping(address => bool) public isBluechipCollection;
    // bluechipWallets[collection][wallet] - use address(0) as global slot
    mapping(address => mapping(address => bool)) public bluechipWallets;
    mapping(address => mapping(address => uint256)) public bluechipLastHarvestBlock;
    uint256 public bluechipWalletFee; // fee in CATA amount for enrollment

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
    event EscrowForfeited(address indexed collection, uint256 toTreasury, uint256 burned);
    event NFTStaked(address indexed who, address indexed collection, uint256 indexed tokenId);
    event NFTUnstaked(address indexed who, address indexed collection, uint256 indexed tokenId);
    event RewardsHarvested(address indexed who, address indexed collection, uint256 payout, uint256 burned);
    event PermanentStakeFeePaid(address indexed who, uint256 fee);
    event BluechipEnrolled(address indexed who);
    event BluechipHarvested(address indexed who, address indexed collection, uint256 amount);
    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);

    // ---------- Modifiers ----------
    modifier onlyCouncil() {
        require(msg.sender == council, "only council");
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

        require(initialAdmin != address(0), "initial admin zero");
        require(contractAdmin != address(0), "contract admin zero");
        require(council_ != address(0), "council zero");
        require(cataToken != address(0), "cata zero");
        require(deployerAddr != address(0), "deployer zero");

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

        topPercent = 10; // default top percent used by eligibleCount
    }

    // ---------- UUPS authorize ----------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // ---------- Council administration ----------
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "zero");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    function swapAdmin(address newAdmin, address oldAdmin) external onlyCouncil {
        require(newAdmin != address(0), "zero new");
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
        require(declaredSupply >= 1, "declared>=1");
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
        uint256 multBP = (tier == CollectionTier.UNVERIFIED) ? unverifiedSurchargeBP : BP_DENOM;
        uint256 total = (baseFee * multBP) / BP_DENOM;
        uint256 sur = (multBP > BP_DENOM) ? (total - baseFee) : 0;
        return (total, sur);
    }

    /// @dev Transfer total `amount` from payer to contract and split: burn / treasury / deployer
    function _splitFeeFromSender(address payer, uint256 amount, address collection, bool attributeToUser) internal {
        require(amount > 0, "zero fee");
        bool ok = cataERC20.transferFrom(payer, address(this), amount);
        require(ok, "transferFrom failed");

        uint256 burnAmt = (amount * BURN_BP) / BP_DENOM;
        uint256 treasuryAmt = (amount * TREASURY_BP) / BP_DENOM;
        uint256 deployerAmt = amount - burnAmt - treasuryAmt;

        // burn (via CATA burn)
        if (burnAmt > 0) {
            // approve not needed: cata.burn burns from contract's own balance; but here burn should be from payer?
            // We already transferred `amount` from payer to this contract, so burning contract-held tokens is correct.
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

        // deployer share
        if (deployerAmt > 0) {
            bool ok2 = cataERC20.transfer(deployerAddress, deployerAmt);
            require(ok2, "deployer transfer failed");
        }

        // treasury share remains in contract's balance
        if (treasuryAmt > 0) {
            treasuryBalance += treasuryAmt;
            emit TreasuryDeposit(payer, treasuryAmt);
        }
    }

    // ---------- Collection registration (admin-only) ----------
    function setCollectionConfig(address collection, uint256 declaredMaxSupply, CollectionTier tier) external onlyRole(CONTRACT_ADMIN_ROLE) nonReentrant whenNotPaused {
        require(collection != address(0), "bad addr");
        require(!_isRegistered(collection), "already reg");
        require(declaredMaxSupply >= 1 && declaredMaxSupply <= MAX_STAKE_PER_COLLECTION, "supply range");

        uint256 baseFee = _calculateRegistrationBaseFee(declaredMaxSupply);
        (uint256 totalFee, uint256 surcharge) = _computeFeeAndSurchargeForTier(baseFee, CollectionTier(tier));
        require(cataERC20.balanceOf(msg.sender) >= totalFee, "insufficient CATA");

        // transfer & split base fee (burn/treasury/deployer)
        _splitFeeFromSender(msg.sender, baseFee, collection, true);

        uint256 escrowAmt = 0;
        if (surcharge > 0) {
            bool ok = cataERC20.transferFrom(msg.sender, address(this), surcharge);
            require(ok, "surcharge transfer");
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
        require(collection != address(0), "bad addr");
        require(!_isRegistered(collection), "already reg");
        require(declaredMaxSupply >= 1 && declaredMaxSupply <= MAX_STAKE_PER_COLLECTION, "supply range");

        bool allowVerified = false;
        if (hasRole(CONTRACT_ADMIN_ROLE, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            allowVerified = true;
        } else {
            // try ownerOf(0)
            try IERC721(collection).ownerOf(0) returns (address ownerAddr) {
                if (ownerAddr == msg.sender) allowVerified = true;
            } catch {
                // try IOwnable pattern omitted to keep file compact (could add if needed)
                allowVerified = false;
            }
        }

        CollectionTier tierToUse = requestedTier;
        if (!allowVerified && requestedTier == CollectionTier.VERIFIED) {
            tierToUse = CollectionTier.UNVERIFIED;
        }

        uint256 baseFee = _calculateRegistrationBaseFee(declaredMaxSupply);
        (uint256 totalFee, uint256 surcharge) = _computeFeeAndSurchargeForTier(baseFee, tierToUse);

        require(cataERC20.balanceOf(msg.sender) >= totalFee, "insufficient balance");

        // transfer & split base fee
        _splitFeeFromSender(msg.sender, baseFee, collection, true);

        uint256 escrowAmt = 0;
        if (surcharge > 0) {
            bool ok = cataERC20.transferFrom(msg.sender, address(this), surcharge);
            require(ok, "surcharge transfer");
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
        require(collectionConfigs[collection].registered, "not reg");
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

    function forfeitEscrowIfExpired(address collection) external onlyRole(CONTRACT_ADMIN_ROLE) {
    CollectionMeta storage m = collectionMeta[collection];
    require(collectionConfigs[collection].registered, "not reg");
    require(m.tier == CollectionTier.UNVERIFIED, "not unverified");
    require(block.number >= m.registeredAtBlock + surchargeForfeitBlocks, "not expired");

    uint256 amt = m.surchargeEscrow;
    require(amt > 0, "no escrow");

    // Apply 90/9/1 split
    uint256 burnAmt = (amt * BURN_BP) / BP_DENOM;        // 90%
    uint256 treasuryAmt = (amt * TREASURY_BP) / BP_DENOM; // 9%
    uint256 deployerAmt = amt - burnAmt - treasuryAmt;    // 1%

    // Burn portion
    if (burnAmt > 0) {
        cata.burn(burnAmt);
    }

    // Treasury portion
    if (treasuryAmt > 0) {
        treasuryBalance += treasuryAmt;
        emit TreasuryDeposit(address(this), treasuryAmt);
    }

    // Deployer portion
    if (deployerAmt > 0) {
        bool ok = cataERC20.transfer(deployerAddress, deployerAmt);
        require(ok, "deployer transfer failed");
    }

    m.surchargeEscrow = 0;

    emit EscrowForfeited(collection, treasuryAmt, burnAmt);
}

    // ---------- Staking ----------
    function termStake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        require(collectionConfigs[collection].registered, "not reg");
        require(collectionConfigs[collection].totalStaked < MAX_STAKE_PER_COLLECTION, "cap 20k");

        // enforce global caps
        require(totalStakedAll + 1 <= GLOBAL_NFT_CAP, "global cap");
        require(totalStakedTerm + 1 <= TERM_NFT_CAP, "term cap");

        IERC721(collection).safeTransferFrom(msg.sender, address(this), tokenId);

        StakeInfo storage info = stakeLog[collection][msg.sender][tokenId];
        require(!info.currentlyStaked, "already staked");

        info.stakeBlock = block.number;
        info.lastHarvestBlock = block.number;
        info.currentlyStaked = true;
        info.isPermanent = false;
        info.unstakeDeadlineBlock = block.number + termDurationBlocks;

        CollectionConfig storage cfg = collectionConfigs[collection];
        if (stakePortfolioByUser[collection][msg.sender].length == 0) cfg.totalStakers += 1;
        cfg.totalStaked += 1;

        totalStakedAll += 1;
        totalStakedTerm += 1;
        totalStakedNFTsCount += 1;
        baseRewardRate += rewardRateIncrementPerNFT;

        stakePortfolioByUser[collection][msg.sender].push(tokenId);
        indexOfTokenIdInStakePortfolio[collection][tokenId] = stakePortfolioByUser[collection][msg.sender].length - 1;

        uint256 dynamicWelcome = welcomeBonusBaseRate + (totalStakedNFTsCount * welcomeBonusIncrementPerNFT);
        cata.mint(msg.sender, dynamicWelcome);

        emit NFTStaked(msg.sender, collection, tokenId);
    }

    function permanentStake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        require(collectionConfigs[collection].registered, "not reg");
        require(collectionConfigs[collection].totalStaked < MAX_STAKE_PER_COLLECTION, "cap 20k");

        // enforce global caps
        require(totalStakedAll + 1 <= GLOBAL_NFT_CAP, "global cap");
        require(totalStakedPerm + 1 <= PERM_NFT_CAP, "perm cap");

        uint256 fee = permanentStakeFeeBase;
        require(cataERC20.balanceOf(msg.sender) >= fee, "insufficient CATA");

        IERC721(collection).safeTransferFrom(msg.sender, address(this), tokenId);

        StakeInfo storage info = stakeLog[collection][msg.sender][tokenId];
        require(!info.currentlyStaked, "already staked");

        // transfer & split fee
        _splitFeeFromSender(msg.sender, fee, collection, true);

        info.stakeBlock = block.number;
        info.lastHarvestBlock = block.number;
        info.currentlyStaked = true;
        info.isPermanent = true;
        info.unstakeDeadlineBlock = 0;

        CollectionConfig storage cfg = collectionConfigs[collection];
        if (stakePortfolioByUser[collection][msg.sender].length == 0) cfg.totalStakers += 1;
        cfg.totalStaked += 1;

        totalStakedAll += 1;
        totalStakedPerm += 1;
        totalStakedNFTsCount += 1;
        baseRewardRate += rewardRateIncrementPerNFT;

        stakePortfolioByUser[collection][msg.sender].push(tokenId);
        indexOfTokenIdInStakePortfolio[collection][tokenId] = stakePortfolioByUser[collection][msg.sender].length - 1;

        uint256 dynamicWelcome = welcomeBonusBaseRate + (totalStakedNFTsCount * welcomeBonusIncrementPerNFT);
        cata.mint(msg.sender, dynamicWelcome);

        emit PermanentStakeFeePaid(msg.sender, fee);
        emit NFTStaked(msg.sender, collection, tokenId);
    }

    function batchTermStake(address collection, uint256[] calldata tokenIds) external {
        require(tokenIds.length > 0 && tokenIds.length <= MAX_HARVEST_BATCH, "batch");
        for (uint256 i = 0; i < tokenIds.length; i++) termStake(collection, tokenIds[i]);
    }

    function batchPermanentStake(address collection, uint256[] calldata tokenIds) external {
        require(tokenIds.length > 0 && tokenIds.length <= MAX_HARVEST_BATCH, "batch");
        for (uint256 i = 0; i < tokenIds.length; i++) permanentStake(collection, tokenIds[i]);
    }

    function unstake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        StakeInfo storage info = stakeLog[collection][msg.sender][tokenId];
        require(info.currentlyStaked, "not staked");
        if (!info.isPermanent) require(block.number >= info.unstakeDeadlineBlock, "term active");

        _harvest(collection, msg.sender, tokenId);

        require(cataERC20.balanceOf(msg.sender) >= unstakeBurnFee, "fee");
        _splitFeeFromSender(msg.sender, unstakeBurnFee, collection, true);

        info.currentlyStaked = false;

        uint256[] storage port = stakePortfolioByUser[collection][msg.sender];
        uint256 idx = indexOfTokenIdInStakePortfolio[collection][tokenId];
        uint256 last = port.length - 1;
        if (idx != last) {
            uint256 lastTokenId = port[last];
            port[idx] = lastTokenId;
            indexOfTokenIdInStakePortfolio[collection][lastTokenId] = idx;
        }
        port.pop();
        delete indexOfTokenIdInStakePortfolio[collection][tokenId];

        IERC721(collection).safeTransferFrom(address(this), msg.sender, tokenId);

        CollectionConfig storage cfg = collectionConfigs[collection];
        if (stakePortfolioByUser[collection][msg.sender].length == 0 && cfg.totalStakers > 0) cfg.totalStakers -= 1;
        if (cfg.totalStaked > 0) cfg.totalStaked -= 1;

        if (baseRewardRate >= rewardRateIncrementPerNFT) baseRewardRate -= rewardRateIncrementPerNFT;

        totalStakedAll -= 1;
        totalStakedNFTsCount -= 1;
        if (info.isPermanent) {
            if (totalStakedPerm > 0) totalStakedPerm -= 1;
        } else {
            if (totalStakedTerm > 0) totalStakedTerm -= 1;
        }

        emit NFTUnstaked(msg.sender, collection, tokenId);
    }

    function batchUnstake(address collection, uint256[] calldata tokenIds) external {
        uint256 len = tokenIds.length;
        require(len > 0 && len <= MAX_HARVEST_BATCH, "batch");
        for (uint256 i = 0; i < len; i++) {
            unstake(collection, tokenIds[i]);
        }
    }

    // ---------- Harvest ----------
    function _getDynamicHarvestBurnFeeRate() internal pure returns (uint256) {
        return 10; // 10% for example
    }

    function _harvest(address collection, address user, uint256 tokenId) internal {
        StakeInfo storage info = stakeLog[collection][user][tokenId];
        uint256 reward = pendingRewards(collection, user, tokenId);
        if (reward == 0) {
            info.lastHarvestBlock = block.number;
            return;
        }

        uint256 feeRateBP = _getDynamicHarvestBurnFeeRate();
        // feeRateBP is percent (0..100) not BP here (kept as earlier design)
        uint256 burnAmt = (reward * feeRateBP) / 100;
        uint256 payout = (reward > burnAmt) ? (reward - burnAmt) : 0;

        // Mint reward to user
        cata.mint(user, payout);

        // Mint+burn for the burned portion to avoid inflating circulating supply
        if (burnAmt > 0) {
            cata.mint(address(this), burnAmt);
            cata.burn(burnAmt);
            burnedCatalystByCollection[collection] += burnAmt;
            burnedCatalystByAddress[user] += burnAmt;
            lastBurnBlock[user] = block.number;
            _updateTopCollectionsOnBurn(collection);
        }

        info.lastHarvestBlock = block.number;
        emit RewardsHarvested(user, collection, payout, burnAmt);
    }

    function harvestBatch(address collection, uint256[] calldata tokenIds) external nonReentrant whenNotPaused {
        require(tokenIds.length > 0 && tokenIds.length <= MAX_HARVEST_BATCH, "batch");
        for (uint256 i = 0; i < tokenIds.length; i++) _harvest(collection, msg.sender, tokenIds[i]);
    }

    function pendingRewards(address collection, address owner, uint256 tokenId) public view returns (uint256) {
        StakeInfo memory info = stakeLog[collection][owner][tokenId];
        if (!info.currentlyStaked || baseRewardRate == 0 || totalStakedNFTsCount == 0) return 0;
        if (!info.isPermanent && block.number >= info.unstakeDeadlineBlock) return 0;

        uint256 blocksPassed = block.number - info.lastHarvestBlock;
        if (blocksPassed == 0) return 0;
        uint256 numerator = blocksPassed * baseRewardRate;
        uint256 rewardAmount = (numerator / numberOfBlocksPerRewardUnit) / totalStakedNFTsCount;
        return rewardAmount;
    }

    // ---------- Bluechip non-custodial ----------
    function setBluechipCollection(address collection, bool isBluechip) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        require(collection != address(0), "zero");
        require(registeredIndex[collection] != 0, "not reg");
        isBluechipCollection[collection] = isBluechip;
    }

    function enrollBluechip() external nonReentrant whenNotPaused {
        address wallet = msg.sender;
        require(!bluechipWallets[address(0)][wallet], "already enrolled");
        uint256 fee = bluechipWalletFee;
        if (fee > 0) {
            // move fee to contract & split as per immutable split (attributeToUser=false for enroll)
            bool ok = cataERC20.transferFrom(wallet, address(this), fee);
            require(ok, "fee transfer");
            // split: burn / deployer / treasury (no attribute to user)
            uint256 burnAmt = (fee * BURN_BP) / BP_DENOM;
            uint256 treasuryAmt = (fee * TREASURY_BP) / BP_DENOM;
            uint256 deployerAmt = fee - burnAmt - treasuryAmt;
            if (burnAmt > 0) {
                cata.burn(burnAmt);
            }
            if (deployerAmt > 0) {
                bool ok2 = cataERC20.transfer(deployerAddress, deployerAmt);
                require(ok2, "deployer transfer");
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
        require(isBluechipCollection[collection], "not bluechip");
        require(bluechipWallets[address(0)][msg.sender], "not enrolled");
        require(IERC721(collection).balanceOf(msg.sender) > 0, "no token");

        uint256 last = bluechipLastHarvestBlock[address(0)][msg.sender];
        uint256 blocksElapsed = block.number - last;
        if (blocksElapsed == 0) return;
        uint256 reward = (blocksElapsed * baseRewardRate) / numberOfBlocksPerRewardUnit;
        if (reward == 0) {
            bluechipLastHarvestBlock[address(0)][msg.sender] = block.number;
            return;
        }

        cata.mint(msg.sender, reward);
        bluechipLastHarvestBlock[address(0)][msg.sender] = block.number;
        emit BluechipHarvested(msg.sender, collection, reward);
    }

    // ---------- Utilities & placeholders ----------
    function _updateTopCollectionsOnBurn(address collection) internal {
        // placeholder: update ranking when burns occur (left intentionally simple)
        // Could maintain a top-N sorted list by burnedCatalystByCollection[collection]
    }

    function _maybeRebuildTopCollections() internal {
        // placeholder: optionally recompute topCollections periodically
    }

    // ---------- Pause control ----------
    function pause() external onlyRole(CONTRACT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(CONTRACT_ADMIN_ROLE) {
        _unpause();
    }

    // ---------- ERC721 receiver ----------
    // allow receiving ERC721 tokens via safeTransferFrom
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

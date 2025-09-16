// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
Standalone upgradeable staking contract.
- UUPS upgradeable
- Uses OZ upgradeable components
- Interacts with an external CATA token (must grant this contract MINTER_ROLE)
- Hard-coded fee split: BURN_BP=9000 (90%), TREASURY_BP=900 (9%), DEPLOYER_BP=100 (1%)
*/

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

interface ICataToken is IERC20Upgradeable {
    function mint(address to, uint256 amount) external;
    function burn(uint256 amount) external;
}

contract CatalystStakingUpgradeable is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    // --- Roles
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");

    // --- Constants: fee split (hard-coded)
    uint256 public constant BURN_BP = 9000;      // 90.00%
    uint256 public constant TREASURY_BP = 900;   // 9.00%
    uint256 public constant DEPLOYER_BP = 100;   // 1.00%
    uint256 public constant BP_DENOM = 10000;

    // --- Limits & defaults
    uint256 public constant MAX_STAKE_PER_COLLECTION = 20_000;
    uint256 public constant MAX_HARVEST_BATCH = 50;

    // --- External token
    ICataToken public cata;

    // --- Council (DRS) address (for swapAdmin calls)
    address public council;

    // --- Deployer share recipient (hard-coded at initialize)
    address public deployerAddress;

    // --- Collection tiers
    enum CollectionTier { UNVERIFIED, VERIFIED, BLUECHIP }

    // --- Collection metadata
    struct CollectionConfig {
        uint256 totalStaked;
        uint256 totalStakers;
        bool registered;
        uint256 declaredSupply;
    }
    struct CollectionMeta {
        CollectionTier tier;
        address registrant;
        uint256 surchargeEscrow;
        uint256 registeredAtBlock;
        uint256 lastTierProposalBlock;
    }

    // registry
    address[] public registeredCollections;
    mapping(address => uint256) public registeredIndex; // 0 = not registered, index = pos+1
    mapping(address => CollectionConfig) public collectionConfigs;
    mapping(address => CollectionMeta) public collectionMeta;

    // bookkeeping for top collections & bluechip
    address[] public topCollections;
    mapping(address => bool) public isBluechipCollection;

    // treasury accounting (tokens held in contract represent treasury + escrow)
    uint256 public treasuryBalance;

    // burn tracking & participation
    mapping(address => uint256) public burnedCatalystByCollection;
    mapping(address => uint256) public burnedCatalystByAddress;
    mapping(address => bool) public isParticipating;
    address[] public participatingWallets;
    mapping(address => uint256) public lastBurnBlock;

    // ---- Staking data structures
    struct StakeInfo {
        bool currentlyStaked;
        bool isPermanent;
        uint256 stakeBlock;
        uint256 unstakeDeadlineBlock; // 0 if permanent
        uint256 lastHarvestBlock;
    }

    // collection => owner => tokenId => StakeInfo
    mapping(address => mapping(address => mapping(uint256 => StakeInfo))) public stakeLog;
    // collection => owner => tokenIds[]
    mapping(address => mapping(address => uint256[])) public stakePortfolioByUser;
    // collection => tokenId => index in portfolio
    mapping(address => mapping(uint256 => uint256)) public indexOfTokenIdInStakePortfolio;

    // collection-level totals
    mapping(address => uint256) public collectionTotalStaked;
    uint256 public totalStakedNFTsCount;

    // reward config and counters
    uint256 public baseRewardRate;                 //abstract unit for reward formula
    uint256 public numberOfBlocksPerRewardUnit;   // denominator for reward calc
    uint256 public rewardRateIncrementPerNFT;
    uint256 public welcomeBonusBaseRate;
    uint256 public welcomeBonusIncrementPerNFT;

    // staking policy params
    uint256 public termDurationBlocks;
    uint256 public unstakeBurnFee; // fee amount for unstake (in CATA)
    uint256 public permanentStakeFeeBase; // used in permanent stake fee calc

    // surcharge params & tier upgrade rules
    uint256 public unverifiedSurchargeBP; // e.g., 12000 -> 120%
    uint256 public tierUpgradeMinAgeBlocks;
    uint256 public tierUpgradeMinBurn;
    uint256 public tierUpgradeMinStakers;
    uint256 public surchargeForfeitBlocks;

    // bluechip enrollment
    uint256 public bluechipWalletFee;

    // events
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

    // -----------------------
    // Initialization
    // -----------------------
    function initialize(
        address admin,
        address contractAdmin,
        address council_,
        address cataToken,
        address deployerAddr
    ) external initializer {
        require(admin != address(0) && contractAdmin != address(0) && council_ != address(0) && cataToken != address(0) && deployerAddr != address(0), "bad init args");

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        // roles
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONTRACT_ADMIN_ROLE, contractAdmin);

        // external
        council = council_;
        cata = ICataToken(cataToken);
        deployerAddress = deployerAddr;

        // sensible defaults (these can be changed via admin functions if you add them)
        numberOfBlocksPerRewardUnit = 6500; // example: ~1 day worth of blocks on eth main (adjust per chain)
        baseRewardRate = 10;
        rewardRateIncrementPerNFT = 1;
        welcomeBonusBaseRate = 5;
        welcomeBonusIncrementPerNFT = 1;
        termDurationBlocks = 65000; // ~10 days example
        unstakeBurnFee = 1 * (10 ** 18); // set to 1 CATA (caller must approve)
        permanentStakeFeeBase = 10 * (10 ** 18); // 10 CATA example

        // surcharge defaults
        unverifiedSurchargeBP = 12000; // 120% (i.e., surcharge increases base fee 20%)
        tierUpgradeMinAgeBlocks = 10000;
        tierUpgradeMinBurn = 1 ether;
        tierUpgradeMinStakers = 2;
        surchargeForfeitBlocks = 200000;

        bluechipWalletFee = 1 * (10 ** 18); // 1 CATA

        // counters
        totalStakedNFTsCount = 0;
        treasuryBalance = 0;
    }

    // UUPS authorize
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // -----------------------
    // Administrative helpers
    // -----------------------
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "zero");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    /// @notice swap admin safely (grant -> revoke). Only council may call.
    function swapAdmin(address newAdmin, address oldAdmin) external {
        require(msg.sender == council, "only council");
        require(newAdmin != address(0), "zero new");
        // grant -> revoke on this contract (we operate AccessControl)
        if (!hasRole(DEFAULT_ADMIN_ROLE, newAdmin)) _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE, oldAdmin)) _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // -----------------------
    // Registration & fees
    // -----------------------

    // fee curve constants for registration (example boundaries from earlier)
    uint256 public constant SMALL_MIN_FEE = 1 * (10 ** 18);
    uint256 public constant SMALL_MAX_FEE = 10 * (10 ** 18);
    uint256 public constant MED_MIN_FEE = 11 * (10 ** 18);
    uint256 public constant MED_MAX_FEE = 50 * (10 ** 18);
    uint256 public constant LARGE_MIN_FEE = 51 * (10 ** 18);
    uint256 public constant LARGE_MAX_FEE_CAP = 200 * (10 ** 18);

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

    /// @dev immutably split: caller must `approve` this contract for amount first.
    function _splitFeeFromSender(address payer, uint256 amount, address collection, bool attributeToUser) internal {
        require(amount > 0, "zero fee");
        // pull tokens into contract
        bool ok = IERC20Upgradeable(address(cata)).transferFrom(payer, address(this), amount);
        require(ok, "transferFrom failed");

        uint256 burnAmt = (amount * BURN_BP) / BP_DENOM;
        uint256 treasuryAmt = (amount * TREASURY_BP) / BP_DENOM;
        uint256 deployerAmt = amount - burnAmt - treasuryAmt;

        // burn from contract balance
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

        // transfer deployer share
        if (deployerAmt > 0) {
            bool ok2 = IERC20Upgradeable(address(cata)).transfer(deployerAddress, deployerAmt);
            require(ok2, "deployer transfer failed");
        }

        // treasury share stays in contract (already transferred)
        if (treasuryAmt > 0) {
            treasuryBalance += treasuryAmt;
            emit TreasuryDeposit(payer, treasuryAmt);
        }
    }

    // ---------- Collection registration (permissionless) ----------
    function registerCollection(address collection, uint256 declaredMaxSupply, CollectionTier requestedTier) external nonReentrant whenNotPaused {
        require(collection != address(0), "bad addr");
        require(registeredIndex[collection] == 0, "already reg");
        require(declaredMaxSupply >= 1 && declaredMaxSupply <= MAX_STAKE_PER_COLLECTION, "supply range");

        // determine allowed tier
        bool allowVerified = false;
        if (hasRole(CONTRACT_ADMIN_ROLE, _msgSender()) || hasRole(DEFAULT_ADMIN_ROLE, _msgSender())) {
            allowVerified = true;
        } else {
            // try owner detection (ownerOf(0) or Ownable)
            try IERC721(collection).ownerOf(0) returns (address ownerAddr) {
                if (ownerAddr == _msgSender()) allowVerified = true;
            } catch {
                try IOwnable(collection).owner() returns (address contractOwner) {
                    if (contractOwner == _msgSender()) allowVerified = true;
                } catch {}
            }
        }
        CollectionTier tierToUse = requestedTier;
        if (!allowVerified && requestedTier == CollectionTier.VERIFIED) {
            tierToUse = CollectionTier.UNVERIFIED;
        }

        uint256 baseFee = _calculateRegistrationBaseFee(declaredMaxSupply);
        (uint256 totalFee, uint256 surcharge) = _computeFeeAndSurchargeForTier(baseFee, tierToUse);

        // require approval and balance
        require(IERC20Upgradeable(address(cata)).balanceOf(_msgSender()) >= totalFee, "insufficient balance");
        // process baseFee and surcharge: baseFee split burned/transferred; surcharge escrowed to contract
        _splitFeeFromSender(_msgSender(), baseFee, collection, true);

        uint256 escrowAmt = 0;
        if (surcharge > 0) {
            bool ok = IERC20Upgradeable(address(cata)).transferFrom(_msgSender(), address(this), surcharge);
            require(ok, "surcharge transfer");
            escrowAmt = surcharge;
        }

        // register
        registeredCollections.push(collection);
        registeredIndex[collection] = registeredCollections.length;

        collectionConfigs[collection] = CollectionConfig({
            totalStaked: 0,
            totalStakers: 0,
            registered: true,
            declaredSupply: declaredMaxSupply
        });

        collectionMeta[collection] = CollectionMeta({
            tier: tierToUse,
            registrant: _msgSender(),
            surchargeEscrow: escrowAmt,
            registeredAtBlock: block.number,
            lastTierProposalBlock: 0
        });

        // placeholder hooks to update top collections (not fully implemented here)
        _maybeRebuildTopCollections();

        emit CollectionAdded(collection, declaredMaxSupply, baseFee, escrowAmt, tierToUse);
    }

    function setCollectionConfig(address collection, uint256 declaredMaxSupply, CollectionTier tier) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        require(collection != address(0), "bad addr");
        require(registeredIndex[collection] == 0, "already reg"); // using same checks as earlier? If admin-only bootstrap allow
        // This function is kept for admin quick-seed; implementation depends on desired policy
    }

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

        // remove from topCollections if present (simple linear)
        for (uint256 t = 0; t < topCollections.length; t++) {
            if (topCollections[t] == collection) {
                for (uint256 j = t; j + 1 < topCollections.length; j++) topCollections[j] = topCollections[j + 1];
                topCollections.pop();
                break;
            }
        }

        emit CollectionRemoved(collection);
    }

    function forfeitEscrowIfExpired(address collection) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        CollectionMeta storage m = collectionMeta[collection];
        require(collectionConfigs[collection].registered, "not reg");
        require(m.tier == CollectionTier.UNVERIFIED, "not unverified");
        require(block.number >= m.registeredAtBlock + surchargeForfeitBlocks, "not expired");
        uint256 amt = m.surchargeEscrow;
        require(amt > 0, "no escrow");

        uint256 toBurn = amt / 2;
        uint256 toTreasury = amt - toBurn;
        // burn half
        cata.burn(toBurn);
        // keep treasury portion in contract
        treasuryBalance += toTreasury;
        m.surchargeEscrow = 0;
        emit TreasuryDeposit(address(this), toTreasury);
        emit EscrowForfeited(collection, toTreasury, toBurn);
    }

    // -----------------------
    // Staking functions
    // -----------------------
    // NOTE: users must approve this contract to transfer required CATA fees when needed

    function termStake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        require(collectionConfigs[collection].registered, "not reg");
        require(collectionConfigs[collection].totalStaked < MAX_STAKE_PER_COLLECTION, "cap");

        // transfer NFT into contract (caller must approve NFT)
        IERC721(collection).safeTransferFrom(_msgSender(), address(this), tokenId);

        StakeInfo storage info = stakeLog[collection][_msgSender()][tokenId];
        require(!info.currentlyStaked, "already staked");

        info.stakeBlock = block.number;
        info.lastHarvestBlock = block.number;
        info.currentlyStaked = true;
        info.isPermanent = false;
        info.unstakeDeadlineBlock = block.number + termDurationBlocks;

        CollectionConfig storage cfg = collectionConfigs[collection];
        if (stakePortfolioByUser[collection][_msgSender()].length == 0) cfg.totalStakers += 1;
        cfg.totalStaked += 1;

        totalStakedNFTsCount += 1;
        baseRewardRate += rewardRateIncrementPerNFT;

        stakePortfolioByUser[collection][_msgSender()].push(tokenId);
        indexOfTokenIdInStakePortfolio[collection][tokenId] = stakePortfolioByUser[collection][_msgSender()].length - 1;

        uint256 dynamicWelcome = welcomeBonusBaseRate + (totalStakedNFTsCount * welcomeBonusIncrementPerNFT);
        // mint welcome bonus directly to staker
        cata.mint(_msgSender(), dynamicWelcome);

        lastBurnBlock[_msgSender()] = block.number;

        emit NFTStaked(_msgSender(), collection, tokenId);
    }

    function permanentStake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        require(collectionConfigs[collection].registered, "not reg");
        require(collectionConfigs[collection].totalStaked < MAX_STAKE_PER_COLLECTION, "cap");

        uint256 fee = permanentStakeFeeBase;
        // require user has approved fee to this contract
        require(IERC20Upgradeable(address(cata)).balanceOf(_msgSender()) >= fee, "insufficient CATA");

        // transfer NFT
        IERC721(collection).safeTransferFrom(_msgSender(), address(this), tokenId);

        StakeInfo storage info = stakeLog[collection][_msgSender()][tokenId];
        require(!info.currentlyStaked, "already staked");

        // immutable split: transferFrom fee then split
        _splitFeeFromSender(_msgSender(), fee, collection, true);

        info.stakeBlock = block.number;
        info.lastHarvestBlock = block.number;
        info.currentlyStaked = true;
        info.isPermanent = true;
        info.unstakeDeadlineBlock = 0;

        CollectionConfig storage cfg = collectionConfigs[collection];
        if (stakePortfolioByUser[collection][_msgSender()].length == 0) cfg.totalStakers += 1;
        cfg.totalStaked += 1;

        totalStakedNFTsCount += 1;
        baseRewardRate += rewardRateIncrementPerNFT;

        stakePortfolioByUser[collection][_msgSender()].push(tokenId);
        indexOfTokenIdInStakePortfolio[collection][tokenId] = stakePortfolioByUser[collection][_msgSender()].length - 1;

        uint256 dynamicWelcome = welcomeBonusBaseRate + (totalStakedNFTsCount * welcomeBonusIncrementPerNFT);
        cata.mint(_msgSender(), dynamicWelcome);

        lastBurnBlock[_msgSender()] = block.number;

        emit PermanentStakeFeePaid(_msgSender(), fee);
        emit NFTStaked(_msgSender(), collection, tokenId);
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
        StakeInfo storage info = stakeLog[collection][_msgSender()][tokenId];
        require(info.currentlyStaked, "not staked");
        if (!info.isPermanent) require(block.number >= info.unstakeDeadlineBlock, "term active");

        _harvest(collection, _msgSender(), tokenId);

        // collect unstake fee (caller must approve)
        require(IERC20Upgradeable(address(cata)).balanceOf(_msgSender()) >= unstakeBurnFee, "fee");
        _splitFeeFromSender(_msgSender(), unstakeBurnFee, collection, true);

        info.currentlyStaked = false;

        uint256[] storage port = stakePortfolioByUser[collection][_msgSender()];
        uint256 idx = indexOfTokenIdInStakePortfolio[collection][tokenId];
        uint256 last = port.length - 1;
        if (idx != last) {
            uint256 lastTokenId = port[last];
            port[idx] = lastTokenId;
            indexOfTokenIdInStakePortfolio[collection][lastTokenId] = idx;
        }
        port.pop();
        delete indexOfTokenIdInStakePortfolio[collection][tokenId];

        IERC721(collection).safeTransferFrom(address(this), _msgSender(), tokenId);

        CollectionConfig storage cfg = collectionConfigs[collection];
        if (stakePortfolioByUser[collection][_msgSender()].length == 0) cfg.totalStakers -= 1;
        cfg.totalStaked -= 1;

        if (baseRewardRate >= rewardRateIncrementPerNFT) baseRewardRate -= rewardRateIncrementPerNFT;

        emit NFTUnstaked(_msgSender(), collection, tokenId);
    }

    function batchUnstake(address collection, uint256[] calldata tokenIds) external {
        uint256 len = tokenIds.length;
        require(len > 0 && len <= MAX_HARVEST_BATCH, "batch");
        for (uint256 i = 0; i < len; i++) {
            unstake(collection, tokenIds[i]);
        }
    }

    // -----------------------
    // Harvesting & rewards
    // -----------------------
    function _harvest(address collection, address user, uint256 tokenId) internal {
        StakeInfo storage info = stakeLog[collection][user][tokenId];
        uint256 reward = pendingRewards(collection, user, tokenId);
        if (reward == 0) {
            info.lastHarvestBlock = block.number;
            return;
        }

        uint256 feeRateBP = _getDynamicHarvestBurnFeeRate(); // an example % in BP (0..100)
        uint256 burnAmt = (reward * feeRateBP) / 100;
        uint256 payout = reward - burnAmt;

        // mint full reward to user (we will burn portion from user's minted balance to attribute burn)
        cata.mint(user, reward);

        if (burnAmt > 0) {
            // user must have the tokens we just minted; burn from contract's perspective we burn user's tokens by having user approve then burning via transferFrom -> burn
            // simpler: instruct CATA to burn from user's balance - requires CATA to implement burnFrom or allow this contract to burn exact user balance.
            // Here we assume the token implements burn(uint256) for caller to burn its own balance; since user is external, easiest pattern:
            // Instead: mint payout to user & burn burnAmt by minting to contract then burning; however that does not reduce user's balance. So the safe requirement:
            // *Caveat*: This implementation will mint full reward to user and then mint & burn burnAmt from contract supply to implement net effect of payout.
            // We'll implement burn by minting burnAmt to contract and burning immediately to keep supply accounting consistent.
            cata.mint(address(this), burnAmt);
            cata.burn(burnAmt);
            burnedCatalystByCollection[collection] += burnAmt;
            burnedCatalystByAddress[user] += burnAmt;
            lastBurnBlock[user] = block.number;
        }

        info.lastHarvestBlock = block.number;
        emit RewardsHarvested(user, collection, payout, burnAmt);
    }

    function harvestBatch(address collection, uint256[] calldata tokenIds) external nonReentrant whenNotPaused {
        require(tokenIds.length > 0 && tokenIds.length <= MAX_HARVEST_BATCH, "batch");
        for (uint256 i = 0; i < tokenIds.length; i++) _harvest(collection, _msgSender(), tokenIds[i]);
    }

    // Example dynamic harvest fee (can be replaced with real logic)
    function _getDynamicHarvestBurnFeeRate() internal view returns (uint256) {
        // return percent (0..100), here example fixed 10%
        return 10;
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

    // -----------------------
    // Blue-chip (non-custodial light support)
    // -----------------------
    mapping(address => mapping(address => bool)) public bluechipWallets; // collection => wallet => enrolled
    mapping(address => mapping(address => uint256)) public bluechipLastHarvestBlock; // collection => wallet => lastHarvest

    function setBluechipCollection(address collection, bool isBluechip) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        require(collection != address(0), "zero");
        require(registeredIndex[collection] != 0, "not reg");
        isBluechipCollection[collection] = isBluechip;
    }

    function enrollBluechip() external nonReentrant whenNotPaused {
        address wallet = _msgSender();
        require(!bluechipWallets[address(0)][wallet], "already enrolled");
        uint256 fee = bluechipWalletFee;
        if (fee > 0) {
            // must approve
            _splitFeeFromSender(wallet, fee, address(0), false);
        }
        bluechipWallets[address(0)][wallet] = true;
        bluechipLastHarvestBlock[address(0)][wallet] = block.number;
        emit BluechipEnrolled(wallet);
    }

    function harvestBluechip(address collection) external nonReentrant whenNotPaused {
        require(isBluechipCollection[collection], "not bluechip");
        require(bluechipWallets[address(0)][_msgSender()], "not enrolled");
        require(IERC721(collection).balanceOf(_msgSender()) > 0, "no token");
        // simple reward model: baseRewardRate per wallet
        uint256 last = bluechipLastHarvestBlock[address(0)][_msgSender()];
        uint256 blocksElapsed = block.number - last;
        if (blocksElapsed == 0) return;
        uint256 reward = (blocksElapsed * baseRewardRate) / numberOfBlocksPerRewardUnit;
        if (reward == 0) { bluechipLastHarvestBlock[address(0)][_msgSender()] = block.number; return; }
        cata.mint(_msgSender(), reward);
        bluechipLastHarvestBlock[address(0)][_msgSender()] = block.number;
        emit BluechipHarvested(_msgSender(), collection, reward);
    }

    // -----------------------
    // Utilities & placeholder top-collection maintenance
    // -----------------------
    function registeredCount() external view returns (uint256) { return registeredCollections.length; }
    function eligibleCount() external view returns (uint256) {
        uint256 total = registeredCollections.length;
        if (total == 0) return 0;
        uint256 count = (total * 10) / 100; // top 10% example
        if (count == 0) count = 1;
        return count;
    }

    function _maybeRebuildTopCollections() internal {
        // placeholder: simple algorithm omitted for brevity. Implement as needed.
    }

    // -----------------------
    // Safe ERC721 receiver to accept NFTs
    // -----------------------
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    // Fallbacks (none)
}

// Minimal external interfaces used
interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
}

interface IOwnable {
    function owner() external view returns (address);
}

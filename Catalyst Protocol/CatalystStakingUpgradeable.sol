// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
Merged single-file:
- CatalystStakingGovernanceUpgradeable
  - Upgradeable (UUPS) + AccessControl + Pausable + ReentrancyGuard
  - NFT staking (term + permanent)
  - Collection registration (UNVERIFIED / VERIFIED / BLUECHIP)
  - Fee split and escrow logic
  - Bluechip wallet enrollment & harvest
  - Governance (propose / vote / execute) using on-chain staking & bluechip enrollment for voting weight

Changes:
- Added recyclable global CATA cap (GLOBAL_CATA_CAP) enforced using cata.totalSupply()
- Added global NFT stake cap (GLOBAL_NFT_STAKE_CAP) enforced using totalStakedNFTsCount
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
    function totalSupply() external view returns (uint256);
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
}

interface IOwnable {
    function owner() external view returns (address);
}

contract CatalystStakingGovernanceUpgradeable is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    // -----------------------
    // Roles & constants
    // -----------------------
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");
    uint256 public constant BP_DENOM = 10000;
    uint256 public constant BURN_BP = 9000;    // 90%
    uint256 public constant TREASURY_BP = 900; // 9%
    uint256 public constant DEPLOYER_BP = 100; // 1%

    // ============ Global Supply Caps ============
    uint256 public constant GLOBAL_CATA_CAP = 1_000_000_000 ether; // Max CATA token circulating at any time (recyclable)
    uint256 public constant GLOBAL_NFT_STAKE_CAP = 1_000_000_000;  // Max NFTs that can be staked at any time (recyclable)

    // -----------------------
    // External token + addresses
    // -----------------------
    ICataToken public cata;
    address public council;
    address public deployerAddress;

    // -----------------------
    // Collection & tiering
    // -----------------------
    enum CollectionTier { UNVERIFIED, VERIFIED, BLUECHIP }

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

    address[] public registeredCollections;
    mapping(address => uint256) public registeredIndex;
    mapping(address => CollectionConfig) public collectionConfigs;
    mapping(address => CollectionMeta) public collectionMeta;

    // top collections & bluechip flags
    address[] public topCollections;
    mapping(address => bool) public isBluechipCollection;

    // treasury & burn tracking
    uint256 public treasuryBalance;
    mapping(address => uint256) public burnedCatalystByCollection;
    mapping(address => uint256) public burnedCatalystByAddress;
    mapping(address => bool) public isParticipating;
    address[] public participatingWallets;
    mapping(address => uint256) public lastBurnBlock;

    // -----------------------
    // Staking book-keeping
    // -----------------------
    struct StakeInfo {
        bool currentlyStaked;
        bool isPermanent;
        uint256 stakeBlock;
        uint256 unstakeDeadlineBlock;
        uint256 lastHarvestBlock;
    }

    // collection => owner => tokenId => StakeInfo
    mapping(address => mapping(address => mapping(uint256 => StakeInfo))) public stakeLog;
    mapping(address => mapping(address => uint256[])) public stakePortfolioByUser;
    mapping(address => mapping(uint256 => uint256)) public indexOfTokenIdInStakePortfolio;

    mapping(address => uint256) public collectionTotalStaked;
    uint256 public totalStakedNFTsCount;

    // reward config
    uint256 public baseRewardRate;                 // abstract units
    uint256 public numberOfBlocksPerRewardUnit;
    uint256 public rewardRateIncrementPerNFT;
    uint256 public welcomeBonusBaseRate;
    uint256 public welcomeBonusIncrementPerNFT;

    // staking policy params
    uint256 public termDurationBlocks;
    uint256 public unstakeBurnFee; // fee in CATA for unstake
    uint256 public permanentStakeFeeBase;

    // surcharge & tier upgrade rules
    uint256 public unverifiedSurchargeBP;
    uint256 public tierUpgradeMinAgeBlocks;
    uint256 public tierUpgradeMinBurn;
    uint256 public tierUpgradeMinStakers;
    uint256 public surchargeForfeitBlocks;

    // bluechip enrollment
    uint256 public bluechipWalletFee;

    // registration fee curve constants
    uint256 public constant SMALL_MIN_FEE = 1 * 10**18;
    uint256 public constant SMALL_MAX_FEE = 10 * 10**18;
    uint256 public constant MED_MIN_FEE = 11 * 10**18;
    uint256 public constant MED_MAX_FEE = 50 * 10**18;
    uint256 public constant LARGE_MIN_FEE = 51 * 10**18;
    uint256 public constant LARGE_MAX_FEE_CAP = 200 * 10**18;

    // batch limits / caps
    uint256 public constant MAX_STAKE_PER_COLLECTION = 20_000;
    uint256 public constant MAX_HARVEST_BATCH = 50;

    // -----------------------
    // Events
    // -----------------------
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
    // GOVERNANCE STORAGE
    // -----------------------
    uint256 public constant WEIGHT_SCALE = 1e18;
    uint256 public minStakeAgeForVoting; // blocks a stake must be older than to count for governance

    enum ProposalType {
        BASE_REWARD,
        HARVEST_FEE,
        UNSTAKE_FEE,
        REGISTRATION_FEE_FALLBACK,
        VOTING_PARAM,
        TIER_UPGRADE
    }

    struct Proposal {
        ProposalType pType;
        uint8 paramTarget;
        uint256 newValue;
        address collectionAddress;
        address proposer;
        uint256 startBlock;
        uint256 endBlock;
        uint256 votesScaled;
        bool executed;
    }

    // governance mappings
    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasVoted;
    mapping(bytes32 => mapping(address => uint256)) public proposalCollectionVotesScaled;

    // governance params
    uint256 public votingDurationBlocks;
    uint256 public minVotesRequiredScaled;
    uint256 public collectionVoteCapPercent; // 0..100

    // index of proposals for frontend
    bytes32[] public proposalIds;
    mapping(bytes32 => uint256) public proposalIndex; // 1-based

    // governance events
    event ProposalCreated(bytes32 indexed id, ProposalType pType, uint8 paramTarget, address indexed collection, address indexed proposer, uint256 newValue, uint256 startBlock, uint256 endBlock);
    event VoteCast(bytes32 indexed id, address indexed voter, uint256 weightScaled, address attributedCollection);
    event ProposalMarkedExecuted(bytes32 indexed id);
    event ProposalExecuted(bytes32 indexed id, uint256 newValue);
    event VotingParamUpdated(uint8 indexed param, uint256 oldValue, uint256 newValue);
    event BaseRewardRateUpdated(uint256 oldValue, uint256 newValue);
    event HarvestFeeUpdated(uint256 oldValue, uint256 newValue);
    event UnstakeFeeUpdated(uint256 oldValue, uint256 newValue);
    event RegistrationFeeUpdated(uint256 oldValue, uint256 newValue);
    event CollectionTierUpgraded(address indexed collection, CollectionTier newTier);

    // -----------------------
    // Bluechip non-custodial
    // -----------------------
    // collection => wallet => enrolled (using address(0) for global enrollment)
    mapping(address => mapping(address => bool)) public bluechipWallets;
    mapping(address => mapping(address => uint256)) public bluechipLastHarvestBlock;

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

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONTRACT_ADMIN_ROLE, contractAdmin);

        council = council_;
        cata = ICataToken(cataToken);
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

        unverifiedSurchargeBP = 12000;
        tierUpgradeMinAgeBlocks = 10000;
        tierUpgradeMinBurn = 1 ether;
        tierUpgradeMinStakers = 2;
        surchargeForfeitBlocks = 200000;

        bluechipWalletFee = 1 * 10**18;

        // governance defaults
        votingDurationBlocks = 6500; // example ~1 day
        minVotesRequiredScaled = WEIGHT_SCALE; // one full vote required by default
        collectionVoteCapPercent = 50; // cap 50% of minVotesRequiredScaled per collection
        minStakeAgeForVoting = 0; // default to zero if you want stake immediately count

        totalStakedNFTsCount = 0;
        treasuryBalance = 0;
    }

    // UUPS authorize
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // -----------------------
    // Admin helpers
    // -----------------------
    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "zero");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    function swapAdmin(address newAdmin, address oldAdmin) external {
        require(msg.sender == council, "only council");
        require(newAdmin != address(0), "zero new");
        if (!hasRole(DEFAULT_ADMIN_ROLE, newAdmin)) _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE, oldAdmin)) _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // -----------------------
    // Fee helpers & registration
    // -----------------------
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

    /// @dev transferFrom payer -> this contract, then split/burn/transfer
    function _splitFeeFromSender(address payer, uint256 amount, address collection, bool attributeToUser) internal {
        require(amount > 0, "zero fee");
        bool ok = IERC20Upgradeable(address(cata)).transferFrom(payer, address(this), amount);
        require(ok, "transferFrom failed");

        uint256 burnAmt = (amount * BURN_BP) / BP_DENOM;
        uint256 treasuryAmt = (amount * TREASURY_BP) / BP_DENOM;
        uint256 deployerAmt = amount - burnAmt - treasuryAmt;

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

        if (deployerAmt > 0) {
            bool ok2 = IERC20Upgradeable(address(cata)).transfer(deployerAddress, deployerAmt);
            require(ok2, "deployer transfer failed");
        }

        if (treasuryAmt > 0) {
            treasuryBalance += treasuryAmt;
            emit TreasuryDeposit(payer, treasuryAmt);
        }
    }

    // ---------- Registration (permissionless) ----------
    function registerCollection(address collection, uint256 declaredMaxSupply, CollectionTier requestedTier) external nonReentrant whenNotPaused {
        require(collection != address(0), "bad addr");
        require(registeredIndex[collection] == 0, "already reg");
        require(declaredMaxSupply >= 1 && declaredMaxSupply <= MAX_STAKE_PER_COLLECTION, "supply range");

        bool allowVerified = false;
        if (hasRole(CONTRACT_ADMIN_ROLE, _msgSender()) || hasRole(DEFAULT_ADMIN_ROLE, _msgSender())) {
            allowVerified = true;
        } else {
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

        require(IERC20Upgradeable(address(cata)).balanceOf(_msgSender()) >= totalFee, "insufficient balance");
        _splitFeeFromSender(_msgSender(), baseFee, collection, true);

        uint256 escrowAmt = 0;
        if (surcharge > 0) {
            bool ok = IERC20Upgradeable(address(cata)).transferFrom(_msgSender(), address(this), surcharge);
            require(ok, "surcharge transfer");
            escrowAmt = surcharge;
        }

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

        _maybeRebuildTopCollections();
        emit CollectionAdded(collection, declaredMaxSupply, baseFee, escrowAmt, tierToUse);
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
        cata.burn(toBurn);
        treasuryBalance += toTreasury;
        m.surchargeEscrow = 0;
        emit TreasuryDeposit(address(this), toTreasury);
        emit EscrowForfeited(collection, toTreasury, toBurn);
    }

    // -----------------------
    // Staking functions
    // -----------------------
    function termStake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        require(collectionConfigs[collection].registered, "not reg");
        require(collectionConfigs[collection].totalStaked < MAX_STAKE_PER_COLLECTION, "cap");
        require(totalStakedNFTsCount + 1 <= GLOBAL_NFT_STAKE_CAP, "stake cap exceeded");

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
        _mintReward(_msgSender(), dynamicWelcome);

        lastBurnBlock[_msgSender()] = block.number;
        emit NFTStaked(_msgSender(), collection, tokenId);
    }

    function permanentStake(address collection, uint256 tokenId) public nonReentrant whenNotPaused {
        require(collectionConfigs[collection].registered, "not reg");
        require(collectionConfigs[collection].totalStaked < MAX_STAKE_PER_COLLECTION, "cap");
        require(totalStakedNFTsCount + 1 <= GLOBAL_NFT_STAKE_CAP, "stake cap exceeded");

        uint256 fee = permanentStakeFeeBase;
        require(IERC20Upgradeable(address(cata)).balanceOf(_msgSender()) >= fee, "insufficient CATA");

        IERC721(collection).safeTransferFrom(_msgSender(), address(this), tokenId);

        StakeInfo storage info = stakeLog[collection][_msgSender()][tokenId];
        require(!info.currentlyStaked, "already staked");

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
        _mintReward(_msgSender(), dynamicWelcome);

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
        if (stakePortfolioByUser[collection][_msgSender()].length == 0 && cfg.totalStakers > 0) cfg.totalStakers -= 1;
        if (cfg.totalStaked > 0) cfg.totalStaked -= 1;

        if (baseRewardRate >= rewardRateIncrementPerNFT) baseRewardRate -= rewardRateIncrementPerNFT;

        // decrement global staked count
        if (totalStakedNFTsCount > 0) totalStakedNFTsCount -= 1;

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
    // CATA mint helper (recyclable cap)
    // -----------------------
    function _mintReward(address to, uint256 amount) internal {
        if (amount == 0) return;
        uint256 current = cata.totalSupply();
        require(current + amount <= GLOBAL_CATA_CAP, "CATA: cap exceeded");
        cata.mint(to, amount);
    }

    // -----------------------
    // Harvest and pending
    // -----------------------
    function _getDynamicHarvestBurnFeeRate() internal view returns (uint256) {
        return 10; // 10% in this example (expressed as integer percentage)
    }

    function _harvest(address collection, address user, uint256 tokenId) internal {
        StakeInfo storage info = stakeLog[collection][user][tokenId];
        uint256 reward = pendingRewards(collection, user, tokenId);
        if (reward == 0) {
            info.lastHarvestBlock = block.number;
            return;
        }

        uint256 feeRatePercent = _getDynamicHarvestBurnFeeRate();
        uint256 burnAmt = (reward * feeRatePercent) / 100;
        uint256 payout = (reward > burnAmt) ? (reward - burnAmt) : 0;

        // grossMint is reward (payout + burnAmt) plus because we mint both user reward and mint burnAmt to contract to burn
        uint256 grossMint = reward + burnAmt;
        uint256 current = cata.totalSupply();
        require(current + grossMint <= GLOBAL_CATA_CAP, "CATA: cap exceeded");

        // Mint reward to user
        cata.mint(user, reward);

        // Mint burn amount to contract then burn it (to attribute/track burns)
        if (burnAmt > 0) {
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
    // Bluechip non-custodial
    // -----------------------
    function setBluechipCollection(address collection, bool _isBluechip) external onlyRole(CONTRACT_ADMIN_ROLE) whenNotPaused {
        require(collection != address(0), "zero");
        require(registeredIndex[collection] != 0, "not reg");
        isBluechipCollection[collection] = _isBluechip;
    }

    function enrollBluechip() external nonReentrant whenNotPaused {
        address wallet = _msgSender();
        require(!bluechipWallets[address(0)][wallet], "already enrolled");
        uint256 fee = bluechipWalletFee;
        if (fee > 0) {
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
        uint256 last = bluechipLastHarvestBlock[address(0)][_msgSender()];
        uint256 blocksElapsed = block.number - last;
        if (blocksElapsed == 0) return;
        uint256 reward = (blocksElapsed * baseRewardRate) / numberOfBlocksPerRewardUnit;
        if (reward == 0) { bluechipLastHarvestBlock[address(0)][_msgSender()] = block.number; return; }

        // enforce cap for this mint
        uint256 current = cata.totalSupply();
        require(current + reward <= GLOBAL_CATA_CAP, "CATA: cap exceeded");
        cata.mint(_msgSender(), reward);

        bluechipLastHarvestBlock[address(0)][_msgSender()] = block.number;
        emit BluechipHarvested(_msgSender(), collection, reward);
    }

    // -----------------------
    // Governance: create / vote / execute
    // -----------------------
    function initGovernanceParams(uint256 votingDurationBlocks_, uint256 minVotesRequiredScaled_, uint256 collectionVoteCapPercent_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(collectionVoteCapPercent_ <= 100, "cap>100");
        votingDurationBlocks = votingDurationBlocks_;
        minVotesRequiredScaled = minVotesRequiredScaled_;
        collectionVoteCapPercent = collectionVoteCapPercent_;
    }

    function propose(
        ProposalType pType,
        uint8 paramTarget,
        uint256 newValue,
        address collectionContext
    ) external whenNotPaused returns (bytes32) {
        (uint256 weight,) = _votingWeight(_msgSender());
        require(weight > 0, "Ineligible");

        bytes32 id = keccak256(abi.encodePacked(uint256(pType), paramTarget, newValue, collectionContext, block.number, _msgSender()));
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "Governance: exists");

        p.pType = pType;
        p.paramTarget = paramTarget;
        p.newValue = newValue;
        p.collectionAddress = collectionContext;
        p.proposer = _msgSender();
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;
        p.votesScaled = 0;
        p.executed = false;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, pType, paramTarget, collectionContext, _msgSender(), newValue, p.startBlock, p.endBlock);
        return id;
    }

    function vote(bytes32 id, address attributedCollection) external whenNotPaused {
        (uint256 weight, ) = _votingWeight(_msgSender());
        require(weight > 0, "Ineligible");
        Proposal storage p = proposals[id];
        require(p.startBlock != 0, "Governance: not found");
        require(block.number >= p.startBlock && block.number <= p.endBlock, "Governance: closed");
        require(!p.executed, "Governance: executed");
        require(!hasVoted[id][_msgSender()], "Governance: voted");
        require(weight > 0, "Governance: zero weight");

        uint256 cap = (minVotesRequiredScaled * collectionVoteCapPercent) / 100;
        uint256 cur = proposalCollectionVotesScaled[id][attributedCollection];
        require(cur + weight <= cap, "Governance: cap");

        hasVoted[id][_msgSender()] = true;
        p.votesScaled += weight;
        proposalCollectionVotesScaled[id][attributedCollection] = cur + weight;

        emit VoteCast(id, _msgSender(), weight, attributedCollection);
    }

    function validateForExecution(bytes32 id) public view returns (Proposal memory) {
        Proposal memory p = proposals[id];
        require(p.startBlock != 0, "Governance: not found");
        require(block.number > p.endBlock, "Governance: voting");
        require(!p.executed, "Governance: executed");
        require(p.votesScaled >= minVotesRequiredScaled, "Governance: quorum");
        return p;
    }

    function executeProposal(bytes32 id) external whenNotPaused nonReentrant {
        Proposal memory p = validateForExecution(id);
        // mark executed
        proposals[id].executed = true;
        emit ProposalMarkedExecuted(id);

        // Apply proposals
        if (p.pType == ProposalType.BASE_REWARD) {
            uint256 old = baseRewardRate;
            baseRewardRate = p.newValue;
            emit BaseRewardRateUpdated(old, baseRewardRate);
        } else if (p.pType == ProposalType.HARVEST_FEE) {
            // no stored harvest fee var in current design; emit only for now
            emit HarvestFeeUpdated(0, p.newValue);
        } else if (p.pType == ProposalType.UNSTAKE_FEE) {
            uint256 old = unstakeBurnFee;
            unstakeBurnFee = p.newValue;
            emit UnstakeFeeUpdated(old, p.newValue);
        } else if (p.pType == ProposalType.REGISTRATION_FEE_FALLBACK) {
            emit RegistrationFeeUpdated(0, p.newValue);
        } else if (p.pType == ProposalType.VOTING_PARAM) {
            uint8 t = p.paramTarget;
            if (t == 0) {
                uint256 old = minVotesRequiredScaled;
                minVotesRequiredScaled = p.newValue;
                emit VotingParamUpdated(t, old, p.newValue);
            } else if (t == 1) {
                uint256 old = votingDurationBlocks;
                votingDurationBlocks = p.newValue;
                emit VotingParamUpdated(t, old, p.newValue);
            } else if (t == 2) {
                uint256 old = collectionVoteCapPercent;
                collectionVoteCapPercent = p.newValue;
                emit VotingParamUpdated(t, old, p.newValue);
            } else revert("BadParam");
        } else if (p.pType == ProposalType.TIER_UPGRADE) {
            address col = p.collectionAddress;
            require(collectionConfigs[col].registered, "NotRegistered");
            collectionMeta[col].tier = CollectionTier.BLUECHIP;
            isBluechipCollection[col] = true;
            emit CollectionTierUpgraded(col, CollectionTier.BLUECHIP);
        } else {
            revert("BadParam");
        }

        emit ProposalExecuted(id, p.newValue);
    }

    function getProposalInfo(bytes32 id) external view returns (
        ProposalType pType,
        uint8 paramTarget,
        uint256 newValue,
        address collectionAddress,
        address proposer,
        uint256 startBlock,
        uint256 endBlock,
        uint256 votesScaled,
        bool executed
    ) {
        Proposal memory p = proposals[id];
        return (
            p.pType, p.paramTarget, p.newValue, p.collectionAddress, p.proposer,
            p.startBlock, p.endBlock, p.votesScaled, p.executed
        );
    }

    // -----------------------
    // Voting weight calculation (uses staking & bluechip)
    // -----------------------
    function _votingWeight(address voter) internal view returns (uint256 weight, address attributedCollection) {
        uint256 len = registeredCollections.length;
        for (uint256 i = 0; i < len; ++i) {
            address coll = registeredCollections[i];
            uint256[] storage port = stakePortfolioByUser[coll][voter];
            if (port.length == 0) continue;
            for (uint256 j = 0; j < port.length; ++j) {
                StakeInfo storage si = stakeLog[coll][voter][port[j]];
                if (si.currentlyStaked) {
                    if (minStakeAgeForVoting == 0 || block.number >= si.stakeBlock + minStakeAgeForVoting) {
                        return (WEIGHT_SCALE, coll);
                    }
                }
            }
        }

        // Or: enrolled blue-chip + owns at least one token in a bluechip collection
        for (uint256 i = 0; i < len; ++i) {
            address coll = registeredCollections[i];
            if (isBluechipCollection[coll] && (bluechipWallets[coll][voter] || bluechipWallets[address(0)][voter])) {
                if (IERC721(coll).balanceOf(voter) > 0) {
                    return (WEIGHT_SCALE, coll);
                }
            }
        }

        return (0, address(0));
    }

    // -----------------------
    // Utilities
    // -----------------------
    function registeredCount() external view returns (uint256) { return registeredCollections.length; }
    function eligibleCount() external view returns (uint256) {
        uint256 total = registeredCollections.length;
        if (total == 0) return 0;
        uint256 count = (total * 10) / 100;
        if (count == 0) count = 1;
        return count;
    }

    function _maybeRebuildTopCollections() internal {
        // placeholder: implement ranking logic if desired
    }

    // Receive NFTs
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    // Optional convenience getters for cap headroom
    function cataHeadroom() external view returns (uint256) {
        uint256 current = cata.totalSupply();
        if (current >= GLOBAL_CATA_CAP) return 0;
        return GLOBAL_CATA_CAP - current;
    }
    function nftStakeHeadroom() external view returns (uint256) {
        if (totalStakedNFTsCount >= GLOBAL_NFT_STAKE_CAP) return 0;
        return GLOBAL_NFT_STAKE_CAP - totalStakedNFTsCount;
    }
}

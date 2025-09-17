// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/// @title Catalyst Governance (Upgradeable)
/// @notice Lightweight governance system consuming staking stats later.
///         Upgradeable via UUPS, admin controlled by GuardianCouncil.
contract CatalystGovernanceUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    // --- Roles ---
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");

    // --- Access control ---
    address public council;

    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);

    modifier onlyCouncil() {
        require(msg.sender == council, "only council");
        _;
    }

    // --- Governance state ---
    uint256 public constant WEIGHT_SCALE = 1e18;
    uint256 public minStakeAgeForVoting; // placeholder, not enforced yet

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

    enum ProposalType {
        BASE_REWARD,
        HARVEST_FEE,
        UNSTAKE_FEE,
        REGISTRATION_FEE_FALLBACK,
        VOTING_PARAM,
        TIER_UPGRADE
    }

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasVoted;
    mapping(bytes32 => mapping(address => uint256)) public proposalCollectionVotesScaled;

    bytes32[] public proposalIds;
    mapping(bytes32 => uint256) public proposalIndex; // 1-based

    // --- Voting params ---
    uint256 public votingDurationBlocks;
    uint256 public minVotesRequiredScaled;
    uint256 public collectionVoteCapPercent; // 0..100

    // --- Parameters controlled by governance ---
    uint256 public baseRewardRate;
    uint256 public maxBaseRewardRate;
    uint256 public initialHarvestBurnFeeRate;
    uint256 public unstakeBurnFee;
    uint256 public collectionRegistrationFee;

    // --- Events ---
    event ProposalCreated(
        bytes32 indexed id,
        ProposalType pType,
        uint8 paramTarget,
        address indexed collection,
        address indexed proposer,
        uint256 newValue,
        uint256 startBlock,
        uint256 endBlock
    );
    event VoteCast(bytes32 indexed id, address indexed voter, uint256 weightScaled, address attributedCollection);
    event ProposalExecuted(bytes32 indexed id, uint256 newValue);
    event VotingParamUpdated(uint8 indexed param, uint256 oldValue, uint256 newValue);
    event BaseRewardRateUpdated(uint256 oldValue, uint256 newValue);
    event HarvestFeeUpdated(uint256 oldValue, uint256 newValue);
    event UnstakeFeeUpdated(uint256 oldValue, uint256 newValue);
    event RegistrationFeeUpdated(uint256 oldValue, uint256 newValue);
    event CollectionTierUpgraded(address indexed collection, uint8 newTier);

    // --- Errors ---
    error Ineligible();
    error BadParam();

    // -------------------------
    // Init
    // -------------------------
    function initialize(
        address admin,
        address council_,
        uint256 votingDuration,
        uint256 minVotes,
        uint256 capPercent
    ) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        require(admin != address(0) && council_ != address(0), "zero address");
        require(capPercent <= 100, "cap>100");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONTRACT_ADMIN_ROLE, admin);

        council = council_;
        votingDurationBlocks = votingDuration;
        minVotesRequiredScaled = minVotes;
        collectionVoteCapPercent = capPercent;

        maxBaseRewardRate = 1e18;
        minStakeAgeForVoting = 100; // placeholder
    }

    // -------------------------
    // Council / Admin
    // -------------------------
    function setCouncil(address newCouncil) external onlyRole(CONTRACT_ADMIN_ROLE) {
        require(newCouncil != address(0), "zero");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    function swapAdmin(address newAdmin, address oldAdmin) external onlyCouncil {
        require(newAdmin != address(0), "zero");
        if (!hasRole(DEFAULT_ADMIN_ROLE, newAdmin)) {
            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        }
        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE, oldAdmin)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        }
        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // -------------------------
    // Governance actions
    // -------------------------
    function propose(
        ProposalType pType,
        uint8 paramTarget,
        uint256 newValue,
        address collectionContext
    ) external returns (bytes32 id) {
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        id = keccak256(
            abi.encodePacked(uint256(pType), paramTarget, newValue, collectionContext, block.number, msg.sender)
        );
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = pType;
        p.paramTarget = paramTarget;
        p.newValue = newValue;
        p.collectionAddress = collectionContext;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, pType, paramTarget, collectionContext, msg.sender, newValue, p.startBlock, p.endBlock);
    }

    function vote(bytes32 id, address attributedCollection) external {
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        Proposal storage p = proposals[id];
        require(p.startBlock != 0, "not found");
        require(block.number >= p.startBlock && block.number <= p.endBlock, "closed");
        require(!p.executed, "executed");
        require(!hasVoted[id][msg.sender], "voted");

        uint256 cap = (minVotesRequiredScaled * collectionVoteCapPercent) / 100;
        uint256 cur = proposalCollectionVotesScaled[id][attributedCollection];
        require(cur + weight <= cap, "cap exceeded");

        hasVoted[id][msg.sender] = true;
        p.votesScaled += weight;
        proposalCollectionVotesScaled[id][attributedCollection] = cur + weight;

        emit VoteCast(id, msg.sender, weight, attributedCollection);
    }

    function executeProposal(bytes32 id) external nonReentrant {
        Proposal storage p = proposals[id];
        require(p.startBlock != 0, "not found");
        require(block.number > p.endBlock, "voting");
        require(!p.executed, "executed");
        require(p.votesScaled >= minVotesRequiredScaled, "quorum");

        p.executed = true;

        if (p.pType == ProposalType.BASE_REWARD) {
            uint256 old = baseRewardRate;
            baseRewardRate = p.newValue > maxBaseRewardRate ? maxBaseRewardRate : p.newValue;
            emit BaseRewardRateUpdated(old, baseRewardRate);
        } else if (p.pType == ProposalType.HARVEST_FEE) {
            uint256 old = initialHarvestBurnFeeRate;
            initialHarvestBurnFeeRate = p.newValue;
            emit HarvestFeeUpdated(old, p.newValue);
        } else if (p.pType == ProposalType.UNSTAKE_FEE) {
            uint256 old = unstakeBurnFee;
            unstakeBurnFee = p.newValue;
            emit UnstakeFeeUpdated(old, p.newValue);
        } else if (p.pType == ProposalType.REGISTRATION_FEE_FALLBACK) {
            uint256 old = collectionRegistrationFee;
            collectionRegistrationFee = p.newValue;
            emit RegistrationFeeUpdated(old, p.newValue);
        } else if (p.pType == ProposalType.VOTING_PARAM) {
            uint8 t = p.paramTarget;
            if (t == 0) { uint256 old = minVotesRequiredScaled; minVotesRequiredScaled = p.newValue; emit VotingParamUpdated(t, old, p.newValue); }
            else if (t == 1) { uint256 old = votingDurationBlocks; votingDurationBlocks = p.newValue; emit VotingParamUpdated(t, old, p.newValue); }
            else if (t == 2) { uint256 old = collectionVoteCapPercent; collectionVoteCapPercent = p.newValue; emit VotingParamUpdated(t, old, p.newValue); }
            else revert BadParam();
        } else if (p.pType == ProposalType.TIER_UPGRADE) {
            emit CollectionTierUpgraded(p.collectionAddress, 3); // 3 = BLUECHIP
        } else {
            revert BadParam();
        }

        emit ProposalExecuted(id, p.newValue);
    }

    // -------------------------
    // Info
    // -------------------------
    function getProposalInfo(bytes32 id)
        external
        view
        returns (
            ProposalType pType,
            uint8 paramTarget,
            uint256 newValue,
            address collectionAddress,
            address proposer,
            uint256 startBlock,
            uint256 endBlock,
            uint256 votesScaled,
            bool executed
        )
    {
        Proposal memory p = proposals[id];
        return (
            p.pType,
            p.paramTarget,
            p.newValue,
            p.collectionAddress,
            p.proposer,
            p.startBlock,
            p.endBlock,
            p.votesScaled,
            p.executed
        );
    }

    // -------------------------
    // Mocked voting weight
    // -------------------------
    function _votingWeight(address voter) internal view returns (uint256 weight, address attributedCollection) {
        if (voter == address(0)) return (0, address(0));
        // placeholder: everyone has equal weight
        return (WEIGHT_SCALE, address(0));
    }

    // -------------------------
    // UUPS
    // -------------------------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}

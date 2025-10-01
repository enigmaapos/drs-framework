// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

/// @notice Minimal interface for BatchGuardianCouncil (reseeding + upgrade)
interface IBatchGuardianCouncil {
    function daoSeedActiveBatch(address[7] calldata batch) external;
    function daoProposeSeedStandbyBatch(address[7] calldata batch) external;
    function daoCommitSeedStandbyBatch() external;
    function daoActivateStandby() external;
    function proposeNewDAO(address newDAO) external;
    function commitNewDAO() external;
    function daoClearLockAndWarning() external;

    /// @notice UUPS upgrade entrypoint on the council proxy/implementation hosting contract.
    function upgradeTo(address newImplementation) external;
}

/// @notice Minimal interface for CatalystStaking (for governance weights)
interface ICatalystStaking {
    /// @dev returns (weightScaled, attributedCollection)
    function votingWeight(address user) external view returns (uint256 weight, address attributedCollection);
}

/// @title Catalyst Governance (Upgradeable) with Council Reseed + Real Voting Weight
/// @notice Generic governance with specialized council management proposals.
contract CatalystGovernanceUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    // --- Roles ---
    bytes32 public constant CONTRACT_ADMIN_ROLE = keccak256("CONTRACT_ADMIN_ROLE");

    // --- Access control ---
    address public council; // batch guardian council address (for swapAdmin ops by council)

    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);
    event GuardianCouncilUpdated(address indexed oldCouncil, address indexed newCouncil);

    modifier onlyCouncil() {
        require(msg.sender == council, "only council");
        _;
    }

    // --- External contracts ---
    ICatalystStaking public staking; // CatalystStaking contract

    // --- Governance state ---
    uint256 public constant WEIGHT_SCALE = 1e18;
    uint256 public minStakeAgeForVoting; // placeholder, not enforced here (staking returns weight)

    struct Proposal {
        ProposalType pType;
        uint8 paramTarget; // semantic meaning per pType
        uint256 newValue;
        address collectionAddress; // optional context or target address (e.g., council address for reseed)
        address proposer;
        uint256 startBlock;
        uint256 endBlock;
        uint256 votesScaled;
        bool executed;
    }

    // A new struct to hold all proposal info for a clean return
    struct ProposalInfo {
        ProposalType pType;
        uint8 paramTarget;
        uint256 newValue;
        address collectionAddress;
        address proposer;
        uint256 startBlock;
        uint256 endBlock;
        uint256 votesScaled;
        bool executed;
        bytes payload;
    }

    enum ProposalType {
        BASE_REWARD,
        HARVEST_FEE,
        UNSTAKE_FEE,
        REGISTRATION_FEE_FALLBACK,
        VOTING_PARAM,
        TIER_UPGRADE,
        COUNCIL_RESEED_ACTIVE,
        COUNCIL_PROPOSE_STANDBY,
        COUNCIL_COMMIT_STANDBY,
        COUNCIL_ACTIVATE_STANDBY,
        COUNCIL_PROPOSE_NEW_DAO,
        COUNCIL_COMMIT_NEW_DAO,
        COUNCIL_CLEAR_LOCK,
        UPGRADE_COUNCIL
    }

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasVoted;
    mapping(bytes32 => mapping(address => uint256)) public proposalCollectionVotesScaled;

    // store arbitrary payloads (encoded bytes) for proposals that need more data (e.g., council reseed batch)
    mapping(bytes32 => bytes) public proposalPayloads;

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
    event CouncilReseedProposed(bytes32 indexed id, address indexed councilAddress);
    event CouncilReseedExecuted(bytes32 indexed id, address indexed councilAddress);

    // explicit success events for council operations (better observability)
    event CouncilProposeStandbyExecuted(bytes32 indexed id, address indexed councilAddress);
    event CouncilCommitStandbyExecuted(bytes32 indexed id, address indexed councilAddress);
    event CouncilActivateStandbyExecuted(bytes32 indexed id, address indexed councilAddress);
    event CouncilProposeNewDAOExecuted(bytes32 indexed id, address indexed councilAddress, address newDAO);
    event CouncilCommitNewDAOExecuted(bytes32 indexed id, address indexed councilAddress);
    event CouncilClearLockExecuted(bytes32 indexed id, address indexed councilAddress);
    event CouncilUpgraded(bytes32 indexed id, address indexed councilAddress, address newImpl);

    // --- Errors ---
    error Ineligible();
    error BadParam();
    error ZeroAddress();

    // -------------------------
    // Init
    // -------------------------
    /// @param guardianCouncil_ initial batch guardian council contract address (becomes DEFAULT_ADMIN_ROLE & CONTRACT_ADMIN_ROLE)
    /// @param staking_ CatalystStaking contract address (used to query voting weight)
    /// @param votingDuration voting length in blocks
    /// @param minVotes scaled minimum votes required (scale = WEIGHT_SCALE)
    /// @param capPercent collection cap percent (0..100)
    function initialize(
        address guardianCouncil_,
        address staking_,
        uint256 votingDuration,
        uint256 minVotes,
        uint256 capPercent
    ) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        require(guardianCouncil_ != address(0) && staking_ != address(0), "zero address");
        require(capPercent <= 100, "cap>100");

        // Guardian Council contract becomes the administrative authority for Catalyst
        _grantRole(DEFAULT_ADMIN_ROLE, guardianCouncil_);
        _grantRole(CONTRACT_ADMIN_ROLE, guardianCouncil_);

        council = guardianCouncil_;
        staking = ICatalystStaking(staking_);
        votingDurationBlocks = votingDuration;
        minVotesRequiredScaled = minVotes;
        collectionVoteCapPercent = capPercent;

        maxBaseRewardRate = 1e18;
        minStakeAgeForVoting = 0;
    }

    // -------------------------
    // Allow the council to update/rotate the guardian contract (role transfer)
    // -------------------------
    /// @notice Update the guardian council address (transfers DEFAULT_ADMIN_ROLE & CONTRACT_ADMIN_ROLE)
    function updateGuardianCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "zero");
        address old = council;
        council = newCouncil;

        // grant roles to new council then revoke from old to avoid losing admin
        if (!hasRole(DEFAULT_ADMIN_ROLE, newCouncil)) {
            _grantRole(DEFAULT_ADMIN_ROLE, newCouncil);
        }
        if (!hasRole(CONTRACT_ADMIN_ROLE, newCouncil)) {
            _grantRole(CONTRACT_ADMIN_ROLE, newCouncil);
        }

        if (old != address(0) && hasRole(DEFAULT_ADMIN_ROLE, old)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, old);
        }
        if (old != address(0) && hasRole(CONTRACT_ADMIN_ROLE, old)) {
            _revokeRole(CONTRACT_ADMIN_ROLE, old);
        }

        emit GuardianCouncilUpdated(old, newCouncil);
        emit CouncilSet(old, newCouncil);
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

    function setStaking(address newStaking) external onlyRole(CONTRACT_ADMIN_ROLE) {
        require(newStaking != address(0), "zero");
        staking = ICatalystStaking(newStaking);
    }

    /// @notice swap admin atomically (called by council)
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
    // Propose (generic)
    // -------------------------
    /// @notice Create a generic proposal.
    function propose(
        ProposalType pType,
        uint8 paramTarget,
        uint256 newValue,
        address collectionContext
    ) external returns (bytes32 id) {
        // Only allow generic proposals here.
        require(pType <= ProposalType.TIER_UPGRADE, "use specialized propose func");

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

    /// @notice Specialized proposer for council reseed active batch.
    function proposeCouncilReseedActive(address[7] calldata newBatch) external returns (bytes32 id) {
        if (council == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        for (uint256 i = 0; i < 7; ++i) {
            if (newBatch[i] == address(0)) revert BadParam();
        }

        bytes memory batchEncoded = abi.encode(newBatch);
        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_RESEED_ACTIVE), council, batchEncoded, block.number, msg.sender)
        );

        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_RESEED_ACTIVE;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        proposalPayloads[id] = batchEncoded;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_RESEED_ACTIVE, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
        emit CouncilReseedProposed(id, council);
    }

    /// @notice Specialized proposer for proposing a standby batch reseed.
    function proposeCouncilReseedStandby(address[7] calldata newBatch) external returns (bytes32 id) {
        if (council == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        for (uint256 i = 0; i < 7; ++i) {
            if (newBatch[i] == address(0)) revert BadParam();
        }

        bytes memory batchEncoded = abi.encode(newBatch);
        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_PROPOSE_STANDBY), council, batchEncoded, block.number, msg.sender)
        );

        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_PROPOSE_STANDBY;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        proposalPayloads[id] = batchEncoded;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_PROPOSE_STANDBY, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }
    
    /// @notice Specialized proposer for proposing to commit a pending standby batch.
    function proposeCouncilCommitStandby() external returns (bytes32 id) {
        if (council == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_COMMIT_STANDBY), council, block.number, msg.sender)
        );
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_COMMIT_STANDBY;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_COMMIT_STANDBY, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }
    
    /// @notice Specialized proposer for proposing to activate the standby batch.
    function proposeCouncilActivateStandby() external returns (bytes32 id) {
        if (council == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_ACTIVATE_STANDBY), council, block.number, msg.sender)
        );
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_ACTIVATE_STANDBY;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_ACTIVATE_STANDBY, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }

    /// @notice Specialized proposer for proposing a new DAO for the council.
    function proposeCouncilNewDAO(address newDAO) external returns (bytes32 id) {
        if (council == address(0) || newDAO == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        bytes memory daoEncoded = abi.encode(newDAO);
        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_PROPOSE_NEW_DAO), council, daoEncoded, block.number, msg.sender)
        );
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_PROPOSE_NEW_DAO;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;
        proposalPayloads[id] = daoEncoded;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_PROPOSE_NEW_DAO, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }
    
    /// @notice Specialized proposer for proposing to commit the new DAO.
    function proposeCouncilCommitNewDAO() external returns (bytes32 id) {
        if (council == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_COMMIT_NEW_DAO), council, block.number, msg.sender)
        );
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_COMMIT_NEW_DAO;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_COMMIT_NEW_DAO, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }

    /// @notice Specialized proposer for proposing to clear a lock on the council contract.
    function proposeCouncilClearLock() external returns (bytes32 id) {
        if (council == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        id = keccak256(
            abi.encodePacked(uint256(ProposalType.COUNCIL_CLEAR_LOCK), council, block.number, msg.sender)
        );
        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.COUNCIL_CLEAR_LOCK;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.COUNCIL_CLEAR_LOCK, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }

    /// @notice Propose an implementation upgrade for the Council (UPGRADE_COUNCIL)
    function proposeCouncilUpgrade(address newImplementation) external returns (bytes32 id) {
        if (council == address(0) || newImplementation == address(0)) revert ZeroAddress();
        (uint256 weight,) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        bytes memory implEncoded = abi.encode(newImplementation);
        id = keccak256(
            abi.encodePacked(uint256(ProposalType.UPGRADE_COUNCIL), council, implEncoded, block.number, msg.sender)
        );

        Proposal storage p = proposals[id];
        require(p.startBlock == 0, "exists");

        p.pType = ProposalType.UPGRADE_COUNCIL;
        p.paramTarget = 0;
        p.newValue = 0;
        p.collectionAddress = council;
        p.proposer = msg.sender;
        p.startBlock = block.number;
        p.endBlock = block.number + votingDurationBlocks;

        proposalPayloads[id] = implEncoded;

        if (proposalIndex[id] == 0) {
            proposalIds.push(id);
            proposalIndex[id] = proposalIds.length;
        }

        emit ProposalCreated(id, ProposalType.UPGRADE_COUNCIL, 0, council, msg.sender, 0, p.startBlock, p.endBlock);
    }

    // -------------------------
    // Vote
    // -------------------------
    function vote(bytes32 id, address attributedCollection) external {
        (uint256 weight, address attr) = _votingWeight(msg.sender);
        if (weight == 0) revert Ineligible();

        Proposal storage p = proposals[id];
        require(p.startBlock != 0, "not found");
        require(block.number >= p.startBlock && block.number <= p.endBlock, "closed");
        require(!p.executed, "executed");
        require(!hasVoted[id][msg.sender], "voted");

        // use supplied attributedCollection if nonzero, otherwise use the staking-attributed collection
        address usedAttr = attributedCollection;
        if (usedAttr == address(0)) usedAttr = attr;

        uint256 cap = (minVotesRequiredScaled * collectionVoteCapPercent) / 100;
        uint256 cur = proposalCollectionVotesScaled[id][usedAttr];
        require(cur + weight <= cap, "cap exceeded");

        hasVoted[id][msg.sender] = true;
        p.votesScaled += weight;
        proposalCollectionVotesScaled[id][usedAttr] = cur + weight;

        emit VoteCast(id, msg.sender, weight, usedAttr);
    }

    // -------------------------
    // Execute
    // -------------------------
    /// @notice Execute passed proposal.
    function executeProposal(bytes32 id) external nonReentrant {
        Proposal storage p = proposals[id];
        require(p.startBlock != 0, "not found");
        require(block.number > p.endBlock, "voting");
        require(!p.executed, "executed");
        require(p.votesScaled >= minVotesRequiredScaled, "quorum");

        // mark executed first (reentrancy safe because of nonReentrant)
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
            } else revert BadParam();

        } else if (p.pType == ProposalType.TIER_UPGRADE) {
            emit CollectionTierUpgraded(p.collectionAddress, uint8(2)); // event-only

        } else if (p.pType == ProposalType.COUNCIL_RESEED_ACTIVE) {
            bytes memory payload = proposalPayloads[id];
            require(payload.length > 0, "payload missing");
            address[7] memory batch = abi.decode(payload, (address[7]));
            for (uint256 i = 0; i < 7; ++i) {
                require(batch[i] != address(0), "zero in batch");
            }
            try IBatchGuardianCouncil(council).daoSeedActiveBatch(batch) {
                emit CouncilReseedExecuted(id, council);
                delete proposalPayloads[id];
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.COUNCIL_PROPOSE_STANDBY) {
            bytes memory payload = proposalPayloads[id];
            require(payload.length > 0, "payload missing");
            address[7] memory batch = abi.decode(payload, (address[7]));
            for (uint256 i = 0; i < 7; ++i) {
                require(batch[i] != address(0), "zero in batch");
            }
            try IBatchGuardianCouncil(council).daoProposeSeedStandbyBatch(batch) {
                emit CouncilProposeStandbyExecuted(id, council);
                delete proposalPayloads[id];
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.COUNCIL_COMMIT_STANDBY) {
            try IBatchGuardianCouncil(council).daoCommitSeedStandbyBatch() {
                emit CouncilCommitStandbyExecuted(id, council);
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.COUNCIL_ACTIVATE_STANDBY) {
            try IBatchGuardianCouncil(council).daoActivateStandby() {
                emit CouncilActivateStandbyExecuted(id, council);
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.COUNCIL_PROPOSE_NEW_DAO) {
            bytes memory payload = proposalPayloads[id];
            require(payload.length > 0, "payload missing");
            address newDAO = abi.decode(payload, (address));
            require(newDAO != address(0), "zero address");
            try IBatchGuardianCouncil(council).proposeNewDAO(newDAO) {
                emit CouncilProposeNewDAOExecuted(id, council, newDAO);
                delete proposalPayloads[id];
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.COUNCIL_COMMIT_NEW_DAO) {
            try IBatchGuardianCouncil(council).commitNewDAO() {
                emit CouncilCommitNewDAOExecuted(id, council);
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.COUNCIL_CLEAR_LOCK) {
            try IBatchGuardianCouncil(council).daoClearLockAndWarning() {
                emit CouncilClearLockExecuted(id, council);
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else if (p.pType == ProposalType.UPGRADE_COUNCIL) {
            bytes memory payload = proposalPayloads[id];
            require(payload.length > 0, "payload missing");
            address newImpl = abi.decode(payload, (address));
            require(newImpl != address(0), "zero address");

            // The governance contract must be DAO_ROLE on the council so that
            // _authorizeUpgrade on the council allows this call.
            try IBatchGuardianCouncil(council).upgradeTo(newImpl) {
                emit CouncilUpgraded(id, council, newImpl);
                delete proposalPayloads[id];
            } catch (bytes memory reason) {
                _revertWithReason(reason);
            }

        } else {
            revert BadParam();
        }

        emit ProposalExecuted(id, p.newValue);
    }

    // -------------------------
    // Info
    // -------------------------
    function getProposalInfo(bytes32 id) external view returns (ProposalInfo memory) {
        Proposal memory p = proposals[id];
        
        return ProposalInfo(
            p.pType,
            p.paramTarget,
            p.newValue,
            p.collectionAddress,
            p.proposer,
            p.startBlock,
            p.endBlock,
            p.votesScaled,
            p.executed,
            proposalPayloads[id]
        );
    }

    // -------------------------
    // Helpers for frontends
    // -------------------------
    /// @notice Encode a council batch (address[7]) for off-chain use
    function encodeCouncilBatch(address[7] calldata batch) external pure returns (bytes memory) {
        return abi.encode(batch);
    }

    /// @notice Decode previously-encoded council batch
    function decodeCouncilBatch(bytes calldata data) external pure returns (address[7] memory batch) {
        return abi.decode(data, (address[7]));
    }

    // -------------------------
    // Voting weight (wired to staking)
    // -------------------------
    function _votingWeight(address voter) internal view returns (uint256 weight, address attributedCollection) {
        if (address(staking) == address(0)) return (0, address(0));
        try staking.votingWeight(voter) returns (uint256 w, address a) {
            return (w, a);
        } catch {
            return (0, address(0));
        }
    }

    // -------------------------
    // Utility: revert with reason bytes if present
    // -------------------------
    function _revertWithReason(bytes memory reason) internal pure {
        if (reason.length == 0) revert(); // generic revert
        assembly {
            revert(add(reason, 32), mload(reason))
        }
    }

// In any contract inheriting AccessControlUpgradeable (e.g., CataERC20Upgradeable, CatalystGovernanceUpgradeable, BatchGuardianCouncilUpgradeable.sol)

/// @dev Overrides grantRole, disabling direct external calls.
// Parameter names are removed (e.g., 'role' and 'account') to silence compiler warnings.
function grantRole(bytes32, address) public virtual override {
    revert("Unauthorized: Direct role granting is disabled.");
}

/// @dev Overrides revokeRole, disabling direct external calls.
// Parameter names are removed to silence compiler warnings.
function revokeRole(bytes32, address) public virtual override {
    revert("Unauthorized: Direct role revocation is disabled.");
}

/// @dev Overrides renounceRole, preventing accounts from voluntarily relinquishing a role.
// Parameter names are removed to silence compiler warnings.
function renounceRole(bytes32, address) public virtual override {
    revert("Unauthorized: Direct role renouncement is disabled.");
}


    // -------------------------
    // UUPS
    // -------------------------
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}

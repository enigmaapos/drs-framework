// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GuardianLib.sol";

interface IAdminSetter {
    function setAdmin(address newAdmin) external returns (bool);
}

interface IDeployerSetter {
    function setDeployer(address newDeployer) external returns (bool);
}

/// @title DRS_Shared - One guardian council protecting both deployer + admin (separate proposals)
/// @notice Keeps two independent recovery states but a single shared guardian set.
contract DRS_Shared {
    using GuardianLib for GuardianLib.Council;

    // -------- Errors --------
    error ZeroAddress();
    error OnlyDeployerCanResetWhileLocked();
    error OnlyAdminCanResetWhileLocked();
    error NotAuthorized();

    // -------- State --------
    address public deployerAddress;
    address public adminAddress;

    IDeployerSetter public deployerHandler; // optional external hook (can be address(0))
    IAdminSetter public adminHandler;       // optional external hook (can be address(0))

    // We maintain *two* councils that share the same guardian membership. To keep it simple and
    // composable, we always reset/update both councils’ membership simultaneously.
    GuardianLib.Council private councilForDeployer;
    GuardianLib.Council private councilForAdmin;

    // -------- Events --------
    event DeployerSet(address indexed oldDeployer, address indexed newDeployer);
    event AdminSet(address indexed oldAdmin, address indexed newAdmin);
    event SharedCouncilReset(uint8 newSize, uint8 newThreshold);

    constructor(
        address initialDeployer,
        address initialAdmin,
        address[] memory guardians,
        uint8 threshold,
        uint256 windowSeconds,
        address deployerHandlerAddress, // can be zero to skip external call
        address adminHandlerAddress     // can be zero to skip external call
    ) {
        if (initialDeployer == address(0) || initialAdmin == address(0)) revert ZeroAddress();
        deployerAddress = initialDeployer;
        adminAddress = initialAdmin;
        if (deployerHandlerAddress != address(0)) deployerHandler = IDeployerSetter(deployerHandlerAddress);
        if (adminHandlerAddress != address(0)) adminHandler = IAdminSetter(adminHandlerAddress);

        councilForDeployer.init(guardians, threshold, windowSeconds);
        councilForAdmin.init(guardians, threshold, windowSeconds);
    }

    // -------- Deployer scope --------
    function proposeDeployer(address newDeployer) external { councilForDeployer.propose(newDeployer); }
    function approveDeployer() external { councilForDeployer.approve(); }
    function executeDeployer() external {
        address next = councilForDeployer.execute(deployerAddress);
        address old = deployerAddress;

        if (address(deployerHandler) != address(0)) {
            require(deployerHandler.setDeployer(next), "deployerHandler failed");
        }
        deployerAddress = next;
        emit DeployerSet(old, next);
    }

    // -------- Admin scope --------
    function proposeAdmin(address newAdmin) external { councilForAdmin.propose(newAdmin); }
    function approveAdmin() external { councilForAdmin.approve(); }
    function executeAdmin() external {
        address next = councilForAdmin.execute(adminAddress);
        address old = adminAddress;

        if (address(adminHandler) != address(0)) {
            require(adminHandler.setAdmin(next), "adminHandler failed");
        }
        adminAddress = next;
        emit AdminSet(old, next);
    }

    // -------- Shared guardian membership ops --------

    /// @notice Reset both councils’ membership at once.
    /// - If deployer-council is locked, only current deployer can reset.
    /// - If admin-council is locked, only current admin can reset.
    /// - If both locked, require both roles to authorize (simple policy: must be the same caller).
    function resetSharedCouncil(address[] calldata guardians, uint8 threshold) external {
        bool dLocked = councilForDeployer.locked();
        bool aLocked = councilForAdmin.locked();

        if (dLocked && msg.sender != deployerAddress) revert OnlyDeployerCanResetWhileLocked();
        if (aLocked && msg.sender != adminAddress) revert OnlyAdminCanResetWhileLocked();

        councilForDeployer.resetCouncil(guardians, threshold);
        councilForAdmin.resetCouncil(guardians, threshold);
        emit SharedCouncilReset(uint8(guardians.length), threshold);
    }

    /// @notice Emergency reset by last approver for either scope (if locked by unanimity).
    /// Caller chooses which scope to reset (0 = deployer scope, 1 = admin scope).
    function emergencyResetByLastApprover(uint8 scope, address[] calldata guardians, uint8 threshold) external {
        if (scope == 0) {
            councilForDeployer.emergencyResetByLastApprover(guardians, threshold);
        } else if (scope == 1) {
            councilForAdmin.emergencyResetByLastApprover(guardians, threshold);
        } else {
            revert NotAuthorized();
        }
    }

    // -------- Tuning --------
    function setThreshold(uint8 newThreshold) external {
        // anyone with either role or any guardian can adjust (policy choice — customize as needed)
        if (msg.sender != deployerAddress && msg.sender != adminAddress &&
            !councilForDeployer.isGuardian(msg.sender)) revert NotAuthorized();

        councilForDeployer.setThreshold(newThreshold);
        councilForAdmin.setThreshold(newThreshold);
    }

    function setWindow(uint256 newWindow) external {
        if (msg.sender != deployerAddress && msg.sender != adminAddress &&
            !councilForDeployer.isGuardian(msg.sender)) revert NotAuthorized();

        councilForDeployer.setWindow(newWindow);
        councilForAdmin.setWindow(newWindow);
    }

    // -------- Views --------
    function guardians() external view returns (address[] memory) {
        // both councils share identical sets; read from one
        return councilForDeployer.getGuardians();
    }

    function deployerCouncilStatus() external view returns (
        uint8 size, uint8 threshold, bool locked, address proposed, uint8 approvals, uint256 deadline, address lastApprover
    ) { return councilForDeployer.status(); }

    function adminCouncilStatus() external view returns (
        uint8 size, uint8 threshold, bool locked, address proposed, uint8 approvals, uint256 deadline, address lastApprover
    ) { return councilForAdmin.status(); }

    function isGuardian(address a) external view returns (bool) {
        return councilForDeployer.isGuardian(a); // same set in both
    }
}

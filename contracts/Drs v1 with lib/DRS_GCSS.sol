// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GuardianLib.sol";

/// @title DRS_GCSS - Guardian Council Security System (deployer-focused)
/// @notice Protects a "deployerAddress" (e.g., fee recipient / privileged operator) with a guardian council.
contract DRS_GCSS {
    using GuardianLib for GuardianLib.Council;

    // -------- Errors --------
    error NotDeployer();
    error OnlyDeployerCanResetWhileLocked();
    error ZeroAddress();

    // -------- State --------
    address public deployerAddress;
    GuardianLib.Council private council;

    // -------- Events --------
    event DeployerSet(address indexed oldDeployer, address indexed newDeployer);
/// @dev Event to track staking deployer syncs
event StakingDeployerUpdated(address indexed newDeployer);
  event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);

    constructor(
        address initialDeployer,
        address[] memory guardians,
        uint8 threshold,
        uint256 windowSeconds
    ) {
        if (initialDeployer == address(0)) revert ZeroAddress();
        deployerAddress = initialDeployer;
        council.init(guardians, threshold, windowSeconds);
    }

    // -------- Council API (deployer scope) --------
    function proposeDeployer(address newDeployer) external {
        council.propose(newDeployer);
    }

    function approveDeployer() external {
        council.approve();
    }

    function executeDeployer() external {
        address next = council.execute(deployerAddress);
        address old = deployerAddress;
        deployerAddress = next;
        emit DeployerSet(old, next);
    }

/// @notice Optionally sync staking contract’s deployer to match
function updateStakingDeployer() external {
    require(council.isGuardian(msg.sender), "Not a guardian");
    staking.setDeployerAddress(deployerAddress);
    emit StakingDeployerUpdated(deployerAddress);
}

    // -------- Resets & Params --------
    /// @notice Reset guardian set; if locked, only current deployer can do this.
    function resetDeployerCouncil(address[] calldata guardians, uint8 threshold) external {
        // If locked, only the entity that currently holds deployerAddress can reset.
        if (council.locked()) {
            if (msg.sender != deployerAddress) revert OnlyDeployerCanResetWhileLocked();
        } else {
            // Unlocked: allow current deployer or any guardian (optional policy).
            if (msg.sender != deployerAddress && !council.isGuardian(msg.sender)) revert NotDeployer();
        }
        council.resetCouncil(guardians, threshold);
    }

    /// @notice Emergency reset by the last approver when council has become locked by unanimity.
    function emergencyResetByLastApprover(address[] calldata guardians, uint8 threshold) external {
        council.emergencyResetByLastApprover(guardians, threshold);
    }

    function setThreshold(uint8 newThreshold) external {
        if (msg.sender != deployerAddress && !council.isGuardian(msg.sender)) revert NotDeployer();
        council.setThreshold(newThreshold);
    }

    function setWindow(uint256 newWindow) external {
        if (msg.sender != deployerAddress && !council.isGuardian(msg.sender)) revert NotDeployer();
        council.setWindow(newWindow);
    }

/// @notice Withdraw ERC20 tokens (e.g., CATA 1% deployer fee) to current deployer
function withdraw(address token, uint256 amount) external {
    if (msg.sender != deployerAddress) revert NotDeployer();
    IERC20(token).safeTransfer(deployerAddress, amount);
    emit TokensWithdrawn(token, deployerAddress, amount);
}

/// @notice Withdraw native ETH (if contract ever receives it)
function withdrawETH(uint256 amount) external {
    if (msg.sender != deployerAddress) revert NotDeployer();
    payable(deployerAddress).transfer(amount);
    emit TokensWithdrawn(address(0), deployerAddress, amount);
}

    // -------- Views --------
    function councilStatus() external view returns (
        uint8 size, uint8 threshold, bool locked, address proposed, uint8 approvals, uint256 deadline, address lastApprover
    ) {
        return council.status();
    }

    function guardians() external view returns (address[] memory) {
        return council.getGuardians();
    }

    function isGuardian(address a) external view returns (bool) {
        return council.isGuardian(a);
    }
}

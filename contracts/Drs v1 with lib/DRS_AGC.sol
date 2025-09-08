// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GuardianLib.sol";

/// @notice Minimal interface a host contract can expose for applying admin change.
/// @dev Your main system (e.g., Catalyst proxy admin or AccessControl manager) should implement this.
interface IAdminHandler {
    function setAdmin(address newAdmin) external returns (bool);
    // Optional extras if you want a "safe revoke" on old admin:
    function revokeAdmin(address oldAdmin) external returns (bool);
}

/// @title DRS_AGC - Admin Guardian Council (protects DEFAULT_ADMIN-like power)
/// @notice Uses a guardian council to propose/approve/execute admin rotation via an external handler.
contract DRS_AGC {
    using GuardianLib for GuardianLib.Council;

    // -------- Errors --------
    error ZeroAddress();
    error OnlyAdminCanResetWhileLocked();

    // -------- State --------
    address public adminAddress;          // tracked admin (mirror of your system’s admin)
    IAdminHandler public handler;         // external hook to actually set/revoke admin in host system
    GuardianLib.Council private council;

    // -------- Events --------
    event AdminSet(address indexed oldAdmin, address indexed newAdmin);

    constructor(
        address initialAdmin,
        address handlerAddress,
        address[] memory guardians,
        uint8 threshold,
        uint256 windowSeconds
    ) {
        if (initialAdmin == address(0) || handlerAddress == address(0)) revert ZeroAddress();
        adminAddress = initialAdmin;
        handler = IAdminHandler(handlerAddress);
        council.init(guardians, threshold, windowSeconds);
    }

    // -------- Council API (admin scope) --------
    function proposeAdmin(address newAdmin) external {
        council.propose(newAdmin);
    }

    function approveAdmin() external {
        council.approve();
    }

    /// @notice Executes admin rotation by calling the external handler.
    /// Optionally, your handler can implement safe revoke of the old admin.
    function executeAdmin(bool revokeOld) external {
        address next = council.execute(adminAddress);
        address old = adminAddress;

        // apply to host system
        require(handler.setAdmin(next), "handler/setAdmin failed");
        if (revokeOld) {
            // if host supports revocation and you want it
            handler.revokeAdmin(old);
        }

        adminAddress = next;
        emit AdminSet(old, next);
    }

    // -------- Resets & Params --------
    function resetAdminCouncil(address[] calldata guardians, uint8 threshold) external {
        if (council.locked()) {
            if (msg.sender != adminAddress) revert OnlyAdminCanResetWhileLocked();
        } else {
            // allow admin or any guardian in unlocked state (policy choice)
            if (msg.sender != adminAddress && !council.isGuardian(msg.sender)) revert OnlyAdminCanResetWhileLocked();
        }
        council.resetCouncil(guardians, threshold);
    }

    function emergencyResetByLastApprover(address[] calldata guardians, uint8 threshold) external {
        council.emergencyResetByLastApprover(guardians, threshold);
    }

    function setThreshold(uint8 newThreshold) external {
        if (msg.sender != adminAddress && !council.isGuardian(msg.sender)) revert OnlyAdminCanResetWhileLocked();
        council.setThreshold(newThreshold);
    }

    function setWindow(uint256 newWindow) external {
        if (msg.sender != adminAddress && !council.isGuardian(msg.sender)) revert OnlyAdminCanResetWhileLocked();
        council.setWindow(newWindow);
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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GuardianLib - lightweight guardian council library (propose/approve/execute/reset)
/// @notice Pluggable council logic with lock/warning signals and "last honest guardian" reset.

library GuardianLib {
    // -------- Custom Errors (gas/size friendly) --------
    error NotGuardian();
    error Locked();
    error NoActiveProposal();
    error AlreadyApproved();
    error WindowExpired();
    error NotEnoughApprovals(uint8 need, uint8 have);
    error BadGuardianCount();
    error BadThreshold();
    error ZeroAddress();
    error NotLastApprover();
    error SameTarget();
    error AlreadyLocked();
    error NotCouncilOwner(); // for external integrations deciding who can reset during lock

    // -------- Events --------
    event CouncilInitialized(uint8 size, uint8 threshold, uint256 window);
    event GuardianSet(uint8 indexed index, address guardian);
    event CouncilReset(uint8 newSize, uint8 newThreshold);
    event RecoveryProposed(address proposed, uint256 deadline);
    event RecoveryApproved(address indexed guardian, uint8 approvals);
    event WarningRaised(uint8 approvals);   // e.g., 4-of-7
    event LockedByUnanimity(uint8 approvals); // e.g., 7-of-7
    event RecoveryExecuted(address oldTarget, address newTarget);
    event ThresholdUpdated(uint8 oldThr, uint8 newThr);
    event WindowUpdated(uint256 oldWin, uint256 newWin);
    event LastApproverRecorded(address indexed guardian);

    // -------- Constants --------
    uint8 internal constant MAX_GUARDIANS = 10; // supports up to 10 without changing layout

    // -------- Storage Struct --------
    struct Council {
        // membership
        address[MAX_GUARDIANS] slots;    // fixed slots
        mapping(address => bool) isGuardian;
        uint8 size;                      // active guardian count (<= MAX_GUARDIANS)
        // params
        uint8 threshold;                 // e.g., 5 (for 5-of-7)
        uint256 window;                  // seconds to execute after propose
        // state
        bool locked;                     // unanimity lock (e.g., 7/7) -> requires privileged reset
        address proposed;                // proposed target (e.g., new deployer/admin)
        uint8 approvals;                 // live approvals on active proposal
        uint256 deadline;                // proposal deadline
        bool executed;                   // last proposal executed flag
        mapping(address => bool) hasApproved;
        address lastApprover;            // tracks final approver (for emergency reset option)
    }

    // -------- Internal Helpers --------
    function _clearApprovals(Council storage c) private {
        for (uint8 i = 0; i < c.size; i++) {
            address g = c.slots[i];
            if (g != address(0)) c.hasApproved[g] = false;
        }
        c.approvals = 0;
        c.lastApprover = address(0);
    }

    function _setGuardian(Council storage c, uint8 index, address guardian) private {
        address old = c.slots[index];
        if (old != address(0)) c.isGuardian[old] = false;
        c.slots[index] = guardian;
        if (guardian != address(0)) c.isGuardian[guardian] = true;
        emit GuardianSet(index, guardian);
    }

    // -------- Public (library) API --------

    /// @notice Initialize council with up to N guardians (N<=MAX_GUARDIANS), threshold, and window.
    function init(
        Council storage c,
        address[] memory guardians,
        uint8 threshold,
        uint256 windowSeconds
    ) internal {
        uint256 n = guardians.length;
        if (n == 0 || n > MAX_GUARDIANS) revert BadGuardianCount();
        if (threshold == 0 || threshold > n) revert BadThreshold();
        if (windowSeconds == 0) revert WindowExpired();

        // reset all
        for (uint8 i = 0; i < MAX_GUARDIANS; i++) {
            address prev = c.slots[i];
            if (prev != address(0)) c.isGuardian[prev] = false;
            c.slots[i] = address(0);
        }
        c.size = uint8(n);
        c.threshold = threshold;
        c.window = windowSeconds;
        c.locked = false;
        c.proposed = address(0);
        c.executed = false;
        _clearApprovals(c);

        for (uint8 i = 0; i < n; i++) {
            address g = guardians[i];
            if (g == address(0)) revert ZeroAddress();
            _setGuardian(c, i, g);
        }
        emit CouncilInitialized(c.size, c.threshold, c.window);
    }

    /// @notice Replace the entire guardian set (typically by privileged actor when locked).
    function resetCouncil(
        Council storage c,
        address[] memory guardians,
        uint8 threshold
    ) internal {
        uint256 n = guardians.length;
        if (n == 0 || n > MAX_GUARDIANS) revert BadGuardianCount();
        if (threshold == 0 || threshold > n) revert BadThreshold();

        // wipe
        for (uint8 i = 0; i < MAX_GUARDIANS; i++) {
            address prev = c.slots[i];
            if (prev != address(0)) c.isGuardian[prev] = false;
            c.slots[i] = address(0);
        }
        c.size = uint8(n);
        c.threshold = threshold;
        c.locked = false;
        c.proposed = address(0);
        c.executed = false;
        _clearApprovals(c);

        for (uint8 i = 0; i < n; i++) {
            address g = guardians[i];
            if (g == address(0)) revert ZeroAddress();
            _setGuardian(c, i, g);
        }
        emit CouncilReset(c.size, c.threshold);
    }

    /// @notice Update threshold.
    function setThreshold(Council storage c, uint8 newThreshold) internal {
        if (newThreshold == 0 || newThreshold > c.size) revert BadThreshold();
        uint8 old = c.threshold;
        c.threshold = newThreshold;
        emit ThresholdUpdated(old, newThreshold);
    }

    /// @notice Update window (seconds).
    function setWindow(Council storage c, uint256 newWindow) internal {
        if (newWindow == 0) revert WindowExpired();
        uint256 old = c.window;
        c.window = newWindow;
        emit WindowUpdated(old, newWindow);
    }

    /// @notice Propose a new target (e.g., new deployer/admin).
    function propose(Council storage c, address newTarget) internal {
        if (!c.isGuardian[msg.sender]) revert NotGuardian();
        if (c.locked) revert Locked();
        if (newTarget == address(0)) revert ZeroAddress();
        if (newTarget == c.proposed) revert SameTarget();

        c.proposed = newTarget;
        c.deadline = block.timestamp + c.window;
        c.executed = false;
        _clearApprovals(c);

        emit RecoveryProposed(newTarget, c.deadline);
    }

    /// @notice Approve the active proposal.
    function approve(Council storage c) internal returns (uint8 approvals, bool raisedWarning, bool becameLocked) {
        if (!c.isGuardian[msg.sender]) revert NotGuardian();
        if (c.locked) revert Locked();
        if (c.proposed == address(0)) revert NoActiveProposal();
        if (block.timestamp > c.deadline) revert WindowExpired();
        if (c.hasApproved[msg.sender]) revert AlreadyApproved();

        c.hasApproved[msg.sender] = true;
        c.approvals += 1;
        c.lastApprover = msg.sender;
        emit LastApproverRecorded(msg.sender);
        emit RecoveryApproved(msg.sender, c.approvals);

        // Early warning when approvals == size-1 (one short of unanimity).
        raisedWarning = (c.approvals == c.size - 1 && c.size > 2);
        if (raisedWarning) emit WarningRaised(c.approvals);

        // Lock if unanimity reached (hard safety against takeover).
        becameLocked = (c.approvals == c.size);
        if (becameLocked) {
            c.locked = true;
            emit LockedByUnanimity(c.approvals);
        }
        return (c.approvals, raisedWarning, becameLocked);
    }

    /// @notice Execute the recovery (returns proposed target for caller to apply).
    function execute(Council storage c, address currentTarget) internal returns (address newTarget) {
        if (c.locked) revert Locked();
        if (c.proposed == address(0)) revert NoActiveProposal();
        if (block.timestamp > c.deadline) revert WindowExpired();
        if (c.approvals < c.threshold) revert NotEnoughApprovals(c.threshold, c.approvals);

        address oldTarget = currentTarget;
        newTarget = c.proposed;

        c.executed = true;
        // Clear the proposal after execution
        c.proposed = address(0);
        _clearApprovals(c);

        emit RecoveryExecuted(oldTarget, newTarget);
        return newTarget;
    }

    /// @notice Emergency reset: only the last approver can reset if council is locked by unanimity.
    function emergencyResetByLastApprover(
        Council storage c,
        address[] memory guardians,
        uint8 threshold
    ) internal {
        if (!c.locked) revert AlreadyLocked(); // misuse: expects locked
        if (msg.sender != c.lastApprover) revert NotLastApprover();
        resetCouncil(c, guardians, threshold);
    }

    // -------- Views --------
    function isGuardian(Council storage c, address a) internal view returns (bool) {
        return c.isGuardian[a];
    }

    function getGuardians(Council storage c) internal view returns (address[] memory out) {
        out = new address[](c.size);
        for (uint8 i = 0; i < c.size; i++) out[i] = c.slots[i];
    }

    function status(Council storage c) internal view returns (
        uint8 size, uint8 threshold, bool locked, address proposed, uint8 approvals, uint256 deadline, address lastApprover
    ) {
        return (c.size, c.threshold, c.locked, c.proposed, c.approvals, c.deadline, c.lastApprover);
    }
}

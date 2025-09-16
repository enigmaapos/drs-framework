// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract CatalystGovernanceUpgradeable is Initializable, AccessControlUpgradeable {
    bytes32 public constant DEFAULT_ADMIN_ROLE_BYTES = 0x00;
    address public council;

    event AdminSwapped(address indexed oldAdmin, address indexed newAdmin);
    event CouncilSet(address indexed oldCouncil, address indexed newCouncil);

    modifier onlyCouncil() {
        require(msg.sender == council, "only council");
        _;
    }

    function initialize(address initialAdmin, address council_) external initializer {
        __AccessControl_init();
        require(initialAdmin != address(0), "initial admin zero");
        require(council_ != address(0), "council zero");
        _grantRole(DEFAULT_ADMIN_ROLE_BYTES, initialAdmin);
        council = council_;
    }

    function setCouncil(address newCouncil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCouncil != address(0), "zero");
        address old = council;
        council = newCouncil;
        emit CouncilSet(old, newCouncil);
    }

    function swapAdmin(address newAdmin, address oldAdmin) external onlyCouncil {
        require(newAdmin != address(0), "zero new");

        if (!hasRole(DEFAULT_ADMIN_ROLE_BYTES, newAdmin)) {
            _grantRole(DEFAULT_ADMIN_ROLE_BYTES, newAdmin);
        }
        if (oldAdmin != address(0) && hasRole(DEFAULT_ADMIN_ROLE_BYTES, oldAdmin)) {
            _revokeRole(DEFAULT_ADMIN_ROLE_BYTES, oldAdmin);
        }

        emit AdminSwapped(oldAdmin, newAdmin);
    }

    // Add governance logic here (proposals, voting, etc.)
}

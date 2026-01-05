// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./lib/Address.sol";
/**
 * @title TransparentUpgradeableProxy
 * @dev A minimal EIP1967 transparent upgradeable proxy:
 *      - Only the admin can call `upgradeTo()`
 *      - All other calls are delegated to the implementation
 */
contract TransparentUpgradeableProxy {
    // EIP1967 Slots
    bytes32 private constant _IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant _ADMIN_SLOT = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    event Upgraded(address indexed implementation);
    event AdminChanged(address oldAdmin, address newAdmin);


    /**
     * @dev Constructor: sets admin, implementation, and calls _data (initializer).
     * @param _logic The initial implementation contract.
     * @param admin_ The admin address controlling upgrades.
     * @param _data Data to delegatecall into the implementation (e.g., initialize()).
     */
    constructor(address _logic, address admin_, bytes memory _data) payable {
        _setAdmin(admin_);
        _setImplementation(_logic);

        if (_data.length > 0) {
            (bool success, ) = _logic.delegatecall(_data);
            require(success, "TransparentUpgradeableProxy: initialization failed");
        }
    }

     modifier onlyAdmin() {
        require(msg.sender == _admin(), "not admin");
        _;
    }

    // Optional: expose admin for external read
    function admin() external view returns (address) {
        return _admin();
    }

    function implementation() external view returns (address) {
        return _implementation();
    }

    function changeAdmin(address newAdmin) external virtual onlyAdmin {
        require(newAdmin != address(0), "zero admin");
        address old = _admin();
        _setAdmin(newAdmin);
        emit AdminChanged(old, newAdmin);
    }

    /**
     * @dev Admin-only function to upgrade the implementation.
     */
    function upgradeTo(address newImplementation) external onlyAdmin() {
        require(msg.sender == _admin(), "TransparentUpgradeableProxy: caller is not admin");
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Admin-only function to upgrade the implementation and call data.
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable onlyAdmin() {
        require(msg.sender == _admin(), "TransparentUpgradeableProxy: caller is not admin");
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

           // Step 2: If data is provided, call the function on the proxy
        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        }
    }

    /**
     * @dev Transparent proxy pattern:
     * - If caller is admin: block delegation to prevent function selector conflicts
     * - If caller is not admin: delegate all calls to implementation
     *
     * This prevents the admin from accidentally calling implementation functions
     * and
     */
    fallback() external payable {
        // Admin can only call the explicit management functions defined above
        // Admin cannot interact with the implementation contract
        require(msg.sender != _admin(), "TransparentUpgradeableProxy: admin cannot fallback");
        _delegate(_implementation());
    }

    receive() external payable {
        // Admin should not send TRX directly to the proxy
        require(msg.sender != _admin(), "TransparentUpgradeableProxy: admin cannot fallback");
        _delegate(_implementation());
    }

    function _delegate(address impl) internal {
        assembly {
            // Copy msg.data
            calldatacopy(0, 0, calldatasize())
            // Delegatecall to the implementation
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            // Retrieve return data
            returndatacopy(0, 0, returndatasize())

            switch result
            // If delegatecall fails, revert
            case 0 {
                revert(0, returndatasize())
            }
            // If delegatecall succeeds, return data
            default {
                return(0, returndatasize())
            }
        }
    }

    function _implementation() internal view returns (address impl) {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _admin() internal view returns (address adm) {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) private {
        bytes32 slot = _ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }
}

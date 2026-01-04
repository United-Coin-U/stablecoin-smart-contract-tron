// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ProxyAdmin
 * @dev A minimal admin contract to manage a TransparentUpgradeableProxy:
 *      - Upgrades to new implementations
 *      - Calls functions on the proxy (e.g., new initializer)
 */
contract ProxyAdmin is Ownable {
    /**
     * @dev Sets the deployer (msg.sender) as the initial owner 
     *      due to the older Ownable that needs a constructor parameter.
     */
    constructor(address initialOwner) Ownable(initialOwner) {}
    /**
     * @dev Returns the current implementation of `proxy`.
     *
     * NOTE: This function must use low-level staticcall because when ProxyAdmin
     * (as the admin) calls the proxy contract, the transparent proxy pattern
     * would normally prevent the call. We use staticcall with the exact function
     * selector to bypass this restriction.
     */
    function getProxyImplementation(address proxy) public view virtual returns (address) {
        // bytes4(keccak256("implementation()")) == 0x5c60da1b
        (bool success, bytes memory returndata) = proxy.staticcall(hex"5c60da1b");
        require(success, "ProxyAdmin: implementation call failed");
        return abi.decode(returndata, (address));
    }

    /**
     * @dev Returns the current admin of `proxy`.
     *
     * NOTE: This function must use low-level staticcall because when ProxyAdmin
     * (as the admin) calls the proxy contract, the transparent proxy pattern
     * would normally prevent the call. We use staticcall with the exact function
     * selector to bypass this restriction.
     */
    function getProxyAdmin(address proxy) public view virtual returns (address) {
        // bytes4(keccak256("admin()")) == 0xf851a440
        (bool success, bytes memory returndata) = proxy.staticcall(hex"f851a440");
        require(success, "ProxyAdmin: admin call failed");
        return abi.decode(returndata, (address));
    }

    /**
     * @dev Changes the admin of `proxy` to `newAdmin`.
     *
     * Requirements:
     *
     * - This contract must be the current admin of `proxy`.
     */
    function changeProxyAdmin(address proxy, address newAdmin) public virtual onlyOwner {
        // Call changeAdmin on the proxy using low-level call
        (bool success, ) = proxy.call(
            abi.encodeWithSignature("changeAdmin(address)", newAdmin)
        );
        require(success, "ProxyAdmin: changeAdmin call failed");
    }

    /**
     * @dev Upgrades `proxy` to `implementation`. See {TransparentUpgradeableProxy-upgradeTo}.
     *
     * Requirements:
     *
     * - This contract must be the admin of `proxy`.
     */
    function upgrade(address proxy, address implementation) public virtual onlyOwner {
        (bool success, ) = proxy.call(
            abi.encodeWithSignature("upgradeTo(address)", implementation)
        );
        require(success, "ProxyAdmin: upgradeTo call failed");
    }

    /**
     * @dev Upgrades `proxy` to `implementation` and calls a function on the new implementation.
     *
     * This function performs two steps:
     * 1. Upgrades the proxy to the new implementation
     * 2. If data is provided, calls the specified function on the proxy
     *
     * Requirements:
     *
     * - This contract must be the admin of `proxy`.
     */
    function upgradeAndCall(address proxy, address implementation, bytes memory data) public payable virtual onlyOwner {
          (bool success, ) = proxy.call(
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", implementation, data)
        );
        require(success, "ProxyAdmin: upgradeAndCall call failed");
    }
}

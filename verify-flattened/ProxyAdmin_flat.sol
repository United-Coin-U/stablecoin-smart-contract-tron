// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

// File: node_modules/@openzeppelin/contracts/utils/Context.sol

// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// File: node_modules/@openzeppelin/contracts/access/Ownable.sol

// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// File: contracts/ProxyAdmin.sol

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
     * @dev Allows the admin to call a function on the proxy (e.g. initializeV2()). Very unlikely.
     * @param proxyAddress The proxy that will receive the call.
     * @param data The encoded function call data.
     */
    function callProxy(address proxyAddress, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory)
    {
        (bool success, bytes memory result) = proxyAddress.call(data);
        require(success, "ProxyAdmin: callProxy failed");
        return result;
    }

    /**
     * @dev Explicit function for transferring the ownership
     *      of this ProxyAdmin contract to a new account.
     *      This calls the inherited Ownable's transferOwnership(...)
     *
     * @param newOwner The address of the new owner
     */
    function transferProxyAdminOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ProxyAdmin: new owner is the zero address");
        transferOwnership(newOwner);  // Inherited from Ownable
    }

    /**
     * @dev Upgrades the proxy to a new implementation.
     * @param proxyAddress The TransparentUpgradeableProxy address.
     * @param newImplementation The address of the new logic contract.
     */
    function upgrade(address proxyAddress, address newImplementation) external onlyOwner {
        (bool success, ) = proxyAddress.call(
            abi.encodeWithSignature("upgradeTo(address)", newImplementation)
        );
        require(success, "ProxyAdmin: upgrade call failed");
    }
    
     /*
     * @dev upgrade
     * @param proxy 
     * @param implementation 
     * @param data 
     */
    function upgradeAndCall(
        address proxy,
        address implementation,
        bytes memory data
    ) public payable virtual onlyOwner {
        (bool success, ) = proxy.call(
            abi.encodeWithSignature("upgradeTo(address)", implementation, data)
        );
        require(success, "ProxyAdmin: upgradeAndCall call failed");
    }
}


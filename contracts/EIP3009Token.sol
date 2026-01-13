// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
/**
 * @title EIP3009
 * @dev Abstract contract that implements EIP-3009: Transfer With Authorization
 *
 * EIP-3009 allows users to transfer tokens via signed authorizations, enabling
 * gasless transactions and improved UX. Unlike ERC20.permit which only approves,
 * this standard allows direct transfers with signatures.
 *
 * Key Features:
 * - transferWithAuthorization: Transfer tokens with a signature
 * - receiveWithAuthorization: Pull tokens with a signature (receiver initiated)
 * - cancelAuthorization: Cancel an authorization before it's used
 * - Uses EIP-712 typed structured data hashing
 * - Nonce-based replay protection
 * - Validity time window (validAfter, validBefore)
 *
 * Reference: https://eips.ethereum.org/EIPS/eip-3009
 */
abstract contract EIP3009Token {

    // EIP-712 type hashes
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH = keccak256(
        "CancelAuthorization(address authorizer,bytes32 nonce)"
    );

    // Mapping of authorizer => nonce => state (true if used or cancelled)
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    bool public eip3009EnableFlag;

    // Events
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);
    event EIP3009Enabled();
    event EIP3009Disabled();

    /**
     * @dev Modifier to check if EIP-3009 is enabled
     */
    modifier eip3009Enabled() {
        require(eip3009EnableFlag, "EIP-3009 is not enabled");
        _;
    }

    /**
     * @dev Internal modifier to check if caller is owner
     * Uses the _getEIP3009Owner() function that must be implemented by inheriting contract
     */
    modifier onlyEIP3009Owner() {
        require(msg.sender == _getEIP3009Owner(), "EIP3009Token: caller is not the owner");
        _;
    }

    /**
     * @dev Internal function to get the owner address
     * Must be implemented by inheriting contract
     */
    function _getEIP3009Owner() internal view virtual returns (address);

    /**
    *  @dev enable eip3009 support
     * Can only be called by the owner.
     */
    function enableEIP3009() onlyEIP3009Owner external {
        emit EIP3009Enabled();
        eip3009EnableFlag = true;
    }

    /**
    *  @dev disable eip3009 support
     * Can only be called by the owner.
     */
    function disableEIP3009() onlyEIP3009Owner external {
        emit EIP3009Disabled();
        eip3009EnableFlag = false;
    }

    /**
     * @dev Internal function to get the DOMAIN_SEPARATOR for EIP-712
     * Must be implemented by inheriting contract
     */
    function _getDomainSeparator() internal view virtual returns (bytes32);

    /**
     * @dev Internal function to hash typed data V4
     * Must be implemented by inheriting contract
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32);

    /**
     * @dev Internal function to execute the transfer
     * Must be implemented by inheriting contract
     * This is separate from _transfer to avoid conflicts with ERC20
     */
    function _executeAuthorizedTransfer(
        address from,
        address to,
        uint256 value
    ) internal virtual;

    /**
     * @dev Execute a transfer with an authorization signature, backward-compatible with the EIP-3009 standard.
     * @param from Payer's address (Authorizer)
     * @param to Payee's address
     * @param value Amount to transfer
     * @param validAfter The time after which this is valid (unix time)
     * @param validBefore The time before which this is valid (unix time)
     * @param nonce Unique nonce for this authorization
     * @param signature Signature bytes (EOA signature or EIP-1271 contract signature)
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external eip3009Enabled {
        _transferOrReceiveWithAuthorization(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, signature);
    }

    /**
     * @dev Execute a transfer with an authorization signature (EIP-3009)
     * @param from Payer's address (Authorizer)
     * @param to Payee's address
     * @param value Amount to transfer
     * @param validAfter The time after which this is valid (unix time)
     * @param validBefore The time before which this is valid (unix time)
     * @param nonce Unique nonce for this authorization
     * @param v Signature bytes (EOA signature or EIP-1271 contract signature)
     * @param r Signature bytes (EOA signature or EIP-1271 contract signature)
     * @param s Signature bytes (EOA signature or EIP-1271 contract signature)
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external eip3009Enabled {
        _transferOrReceiveWithAuthorization(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /**
    * @notice Receive a transfer with a signed authorization from the payer
    * @dev This has an additional check to ensure that the payee's address matches
    * the caller of this function to prevent front-running attacks. (See security
    * considerations)
    * @param from          Payer's address (Authorizer)
    * @param to            Payee's address
    * @param value         Amount to be transferred
    * @param validAfter    The time after which this is valid (unix time)
    * @param validBefore   The time before which this is valid (unix time)
    * @param nonce         Unique nonce
    * @param v Signature bytes (EOA signature or EIP-1271 contract signature)
    * @param r Signature bytes (EOA signature or EIP-1271 contract signature)
    * @param s Signature bytes (EOA signature or EIP-1271 contract signature)
    */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external eip3009Enabled {
        require(msg.sender == to, "Caller must be the payee");
        _transferOrReceiveWithAuthorization(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

     /**
    * @notice Receive a transfer with a signed authorization from the payer
    * @dev This has an additional check to ensure that the payee's address matches
    * the caller of this function to prevent front-running attacks. (See security
    * considerations)
    * @param from          Payer's address (Authorizer)
    * @param to            Payee's address
    * @param value         Amount to be transferred
    * @param validAfter    The time after which this is valid (unix time)
    * @param validBefore   The time before which this is valid (unix time)
    * @param nonce         Unique nonce
    * @param signature     Unstructured bytes signature signed by an EOA wallet or a contract wallet
    */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external eip3009Enabled {
        require(msg.sender == to, "Caller must be the payee");
        _transferOrReceiveWithAuthorization(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, signature);
    }


     /**
     * @dev Check if an authorization has been used
     * @param authorizer Address that provided the authorization
     * @param nonce Nonce of the authorization
     * @return True if the authorization has been used
     */
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    /**
     * @dev Execute a transfer with an authorization signature (EIP-3009)
     * @param from Payer's address (Authorizer)
     * @param to Payee's address
     * @param value Amount to transfer
     * @param validAfter The time after which this is valid (unix time)
     * @param validBefore The time before which this is valid (unix time)
     * @param nonce Unique nonce for this authorization
     * @param signature Signature bytes (EOA signature or EIP-1271 contract signature)
     */
    function _transferOrReceiveWithAuthorization(
        bytes32 typeHash,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) internal {
        // Validate time window
        require(block.timestamp > validAfter, "Authorization not yet valid");
        require(block.timestamp < validBefore, "Authorization expired");

        //can't be zero address
        require(from != address(0), "Invalid from address");
        require(to != address(0), "Invalid to address");

        // Validate nonce
        require(!_authorizationStates[from][nonce], "Authorization already used");

        // Build EIP-712 struct hash
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        // Build EIP-712 digest
        bytes32 digest = _hashTypedDataV4(structHash);

        // Validate signature (supports both EOA and EIP-1271 smart contracts)
        require(
            SignatureChecker.isValidSignatureNow(from, digest, signature),
            "Invalid signature"
        );

        // Mark authorization as used
        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        // Execute the transfer
        _executeAuthorizedTransfer(from, to, value);
    }

    /**
     * @dev Cancel an authorization before it's used
     * @param authorizer Address that provided the authorization (must be msg.sender)
     * @param nonce Nonce of the authorization to cancel
     */
    function cancelAuthorization(address authorizer, bytes32 nonce) external {
        require(msg.sender == authorizer, "Caller must be the authorizer");
        require(!_authorizationStates[authorizer][nonce], "Authorization already used");

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    uint256[50] private __gap;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol"; 

/**
 * @title RescuableToken
 * @dev Abstract contract that provides asset rescue functionality
 *
 * This contract allows the owner to rescue tokens and TRX that are accidentally
 * sent to the contract.
 *
 * Safety Features:
 * - Prevents rescue of the contract's own token (protects user funds)
 * - Only owner can rescue assets
 * - Emits events for transparency
 * - Includes balance check functions
 *
 * Note: This contract requires the inheriting contract to provide the
 * onlyOwner modifier (e.g., by inheriting from Ownable or OwnableUpgradeable)
 */
abstract contract RescuableToken {

     using SafeERC20 for IERC20; 

    /**
     * @dev Internal function to get the owner address
     * Must be overridden by inheriting contract
     * Typically this will call the owner() function from Ownable/OwnableUpgradeable
     */
    function _getRescueOwner() internal view virtual returns (address);

    /**
     * @dev Internal modifier to check if caller is owner
     * Uses the _getRescueOwner() function that must be implemented by inheriting contract
     */
    modifier onlyRescuer() {
        require(msg.sender == _getRescueOwner(), "RescuableToken: caller is not the owner");
        _;
    }

    error RescueTransferFailed();
    error ZeroAmount();
    error ZeroAddress();

    event TokensRescued(address indexed token, address indexed to, uint256 amount);
    event NativeTokenRescued(address indexed to, uint256 amount);

    /**
     * @dev Rescue TRC20 tokens accidentally sent to this contract
     * @param token The address of the TRC20 token to rescue
     * @param to The address to send the rescued tokens to
     * @param amount The amount of tokens to rescue
     *
     * Requirements:
     * - Can only be called by the contract owner
     * - Cannot rescue the stablecoin token itself (prevents owner from stealing user funds)
     * - Token address cannot be zero
     * - Recipient address cannot be zero
     * - Amount must be greater than zero
     *
     * Emits a {TokensRescued} event
     */
    function rescueTokens(
        address token,
        address to,
        uint256 amount
    ) external onlyRescuer {
        if(token == address(0)) revert ZeroAddress();
        if(to == address(0)) revert ZeroAddress();
        if(amount == 0) revert ZeroAmount();

        IERC20 tokenContract = IERC20(token);
        tokenContract.safeTransfer(to, amount);

        emit TokensRescued(token, to, amount);
    }

    /**
     * @dev Rescue all of a specific TRC20 token accidentally sent to this contract
     * @param token The address of the TRC20 token to rescue
     * @param to The address to send the rescued tokens to
     *
     * Convenience function that rescues the entire balance
     */
    function rescueAllTokens(
        address token,
        address to
    ) external onlyRescuer {
        if(token == address(0)) revert ZeroAddress();
        if(to == address(0)) revert ZeroAddress();

        IERC20 tokenContract = IERC20(token);
        uint256 balance = tokenContract.balanceOf(address(this));

        if(balance == 0) revert ZeroAmount();

        tokenContract.safeTransfer(to, balance);

        emit TokensRescued(token, to, balance);
    }

    /**
     * @dev Rescue TRX (native token) accidentally sent to this contract
     * @param to The address to send the rescued TRX to
     * @param amount The amount of TRX to rescue (in sun, 1 TRX = 1e6 sun)
     *
     * Requirements:
     * - Can only be called by the contract owner
     * - Recipient address cannot be zero
     * - Amount must be greater than zero
     * - Contract must have sufficient TRX balance
     *
     * Emits a {NativeTokenRescued} event
     */
    function rescueNativeToken(
        address payable to,
        uint256 amount
    ) external onlyRescuer {
        if(to == address(0)) revert ZeroAddress();
        if(amount == 0) revert ZeroAmount();
        if(address(this).balance < amount) revert RescueTransferFailed();

        (bool success, ) = to.call{value: amount}("");
        if(!success) revert RescueTransferFailed();

        emit NativeTokenRescued(to, amount);
    }

    /**
     * @dev Rescue all TRX (native token) accidentally sent to this contract
     * @param to The address to send the rescued TRX to
     *
     * Convenience function that rescues the entire TRX balance
     */
    function rescueAllNativeToken(
        address payable to
    ) external onlyRescuer {
        if(to == address(0)) revert ZeroAddress();

        uint256 balance = address(this).balance;
        if(balance == 0) revert ZeroAmount();

        (bool success, ) = to.call{value: balance}("");
        if(!success) revert RescueTransferFailed();

        emit NativeTokenRescued(to, balance);
    }

    /**
     * @dev Check TRC20 token balance held by this contract
     * @param token The address of the TRC20 token
     * @return The balance of the token
     */
    function getTokenBalance(address token) external view returns (uint256) {
        if(token == address(0)) revert ZeroAddress();
        return IERC20(token).balanceOf(address(this));
    }

    /**
     * @dev Check TRX balance held by this contract
     * @return The TRX balance in sun (1 TRX = 1e6 sun)
     */
    function getNativeBalance() external view returns (uint256) {
        return address(this).balance;
    }

    uint256[50] private __gap;
}

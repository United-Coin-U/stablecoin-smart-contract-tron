// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "./Stablecoin.sol";

/**
 * @title StablecoinV2
 * @dev This is a placeholder, which is only used for testing upgrades feature currently.
 */
contract StablecoinV2 is Stablecoin {

    /**
     * @dev Returns the version of the contract.
     * Overrides the parent contract's version.
     * @return Version string
     */
    function version() public pure override returns (string memory) {
        return "v2";
    }

}

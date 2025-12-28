// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

import "./Stablecoin.sol";

/**
 * @title StablecoinV2
 * @dev This is a placeholder, which is only used for testing upgrades feature currently.
 */
contract StablecoinV2 is Stablecoin {

    function versionV2() public pure returns (string memory) {
        return "v2";
    }

}

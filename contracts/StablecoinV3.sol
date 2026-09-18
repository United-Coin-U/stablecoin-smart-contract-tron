// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "./StablecoinV2.sol";

/**
 * @title StablecoinV3
 * @notice Adds Chainlink CCIP (Cross-Chain Token, Burn & Mint) support to the
 *         Stablecoin proxy. A CCIP token pool is granted permission to call
 *         `mint(address,uint256)` and `burn(uint256)` alongside the owner.
 *
 * Storage Layout for StablecoinV3 (verified against the TVM build of this repo):
 * - Slot 156: isCCIPMinterBurner (mapping)
 * - Slot 157: _ccipAdmin (address)
 * - Slot 158-205: __gapV3 (48 slots)
 *
 * Total new slots used: 2
 * Gap size: 48 (50 - 2 = 48)
 *
 * IMPORTANT: `Stablecoin`'s own `__gap` (slots 106-155) is deliberately left
 * untouched, so this contract appends at slot 156. Consuming that gap instead
 * would require editing Stablecoin.sol, which this upgrade explicitly avoids.
 *
 * NOTE ON SLOT NUMBERS: these differ from the EVM sibling repo, where V3 starts
 * at slot 409. That is expected and unavoidable — on EVM the EIP-3009 state and
 * its gap live in StablecoinV2, whereas here they live in the EIP3009Token base
 * class, and OpenZeppelin v5's upgradeable contracts use ERC-7201 namespaced
 * storage and therefore occupy no sequential slots. The layout *structure*
 * (append after the previous version's gap, reserve 48) is identical.
 *
 * When adding new state variables in a future upgrade (V4, etc.):
 * 1. Add new variables BEFORE `__gapV3`
 * 2. Reduce `__gapV3` by the number of slots used
 * 3. Re-derive the layout before deploying — this repo has no tool wired up for
 *    it, so compute it by hand from the inheritance chain above, or point a
 *    throwaway solc/foundry checkout at contracts/ and read its storage layout.
 */
contract StablecoinV3 is StablecoinV2 {

    error CallerNotOwnerOrCCIP(address caller);

    event CCIPRolesGranted(address indexed account);
    event CCIPRolesRevoked(address indexed account);
    event CCIPAdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    /// @dev Addresses permitted to mint and burn on behalf of CCIP — in practice
    ///      the Chainlink BurnMintTokenPool deployed for this token on this chain.
    mapping(address => bool) public isCCIPMinterBurner;

    /// @dev CCIP Token Administrator, decoupled from `owner()` so that routine
    ///      CCIP administration does not require the owner multisig.
    address private _ccipAdmin;

    uint256[48] private __gapV3;

    /**
     * @dev Throws if the caller is neither the owner nor a CCIP minter/burner.
     */
    modifier onlyOwnerOrCCIP() {
        if (msg.sender != owner() && !isCCIPMinterBurner[msg.sender]) {
            revert CallerNotOwnerOrCCIP(msg.sender);
        }
        _;
    }

    /**
     * @dev Disable initializers for the implementation contract.
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initialize the contract for the V3 upgrade. Seeds the CCIP
     *      administrator with the current owner so the token is registrable with
     *      Chainlink's TokenAdminRegistry immediately after the upgrade; the
     *      owner can decouple the two later via {setCCIPAdmin}.
     */
    function initializeV3() public reinitializer(3) {
        emit CCIPAdminTransferred(_ccipAdmin, owner());
        _ccipAdmin = owner();
    }

    /**
     * @dev Permit `pool` to mint and burn, in addition to the owner. Intended for
     *      the Chainlink BurnMintTokenPool deployed for this token on this chain.
     * @param pool Token pool address
     * Can only be called by the current owner.
     */
    function grantMintAndBurnRoles(address pool) external onlyOwner {
        if (pool == address(0)) revert NotAllowedAddress(pool);
        isCCIPMinterBurner[pool] = true;
        emit CCIPRolesGranted(pool);
    }

    /**
     * @dev Revoke a pool's permission to mint and burn. Required when rotating to
     *      a redeployed token pool, since a pool's allowlist mode cannot be
     *      changed in place.
     * @param pool Token pool address
     * Can only be called by the current owner.
     */
    function revokeMintAndBurnRoles(address pool) external onlyOwner {
        delete isCCIPMinterBurner[pool];
        emit CCIPRolesRevoked(pool);
    }

    /**
     * @dev See {Stablecoin-mint}. Widened to accept a CCIP token pool in addition
     *      to the owner; this is the function Chainlink's BurnMintTokenPool calls
     *      on the destination chain.
     *
     *      The freeze and pause checks are deliberately retained on this path: a
     *      regulated stablecoin must not mint to a frozen address or while
     *      paused, even though a revert here strands the in-flight CCIP message
     *      until it is manually re-executed.
     *
     *      `whenNotPaused` here is belt-and-braces on this chain, NOT a change of
     *      behaviour: Stablecoin inherits ERC20PausableUpgradeable and routes
     *      `_update` through it, so every balance change — `_mint` included — is
     *      already pause-gated one layer down. The modifier is kept to mirror the
     *      EVM sibling repo (which pauses only via explicit modifiers, because it
     *      uses plain PausableUpgradeable) and to make the intent legible at the
     *      call site. It only moves the revert earlier; the error is the same
     *      `EnforcedPause()` either way.
     * @param to Mint to address
     * @param amount Mint amount
     * @return True if successful
     */
    function mint(address to, uint256 amount)
        external
        virtual
        override
        whenNotPaused
        notFrozen(to)
        onlyOwnerOrCCIP
        returns (bool)
    {
        _mint(to, amount);
        emit Mint(_msgSender(), to, amount);
        return true;
    }

    /**
     * @dev See {Stablecoin-burn}. Widened to accept a CCIP token pool in addition
     *      to the owner; this is the function Chainlink's BurnMintTokenPool calls
     *      on the source chain, burning the tokens the Router just transferred
     *      into the pool.
     *
     *      `whenNotPaused` is deliberately omitted, matching V1 and the EVM
     *      sibling repo.
     *
     *      TVM DIVERGENCE: on the EVM side that omission means burn genuinely
     *      still works while paused, and pause blocks the outbound path only
     *      because moving tokens into the pool goes through `_transfer`. Here it
     *      makes no difference — ERC20PausableUpgradeable gates `_update`, so
     *      `_burn` reverts with `EnforcedPause()` while paused regardless of what
     *      this signature says. That is pre-existing V1/V2 behaviour on this
     *      chain, not something this upgrade introduces; it is stricter than EVM,
     *      and it means a paused token cannot service an in-flight CCIP burn.
     * @param amount Burn amount
     * @return True if successful
     */
    function burn(uint256 amount)
        external
        virtual
        override
        onlyOwnerOrCCIP
        returns (bool)
    {
        _burn(_msgSender(), amount);
        emit Burn(_msgSender(), _msgSender(), amount);
        return true;
    }

    /**
     * @dev Set the CCIP Token Administrator, the address Chainlink's
     *      RegistryModuleOwnerCustom.registerAdminViaGetCCIPAdmin accepts as the
     *      registrant. Keeping it separate from `owner()` means routine CCIP
     *      administration does not require the owner multisig.
     * @param admin New CCIP administrator
     * Can only be called by the current owner.
     */
    function setCCIPAdmin(address admin) external onlyOwner {
        if (admin == address(0)) revert NotAllowedAddress(admin);
        emit CCIPAdminTransferred(_ccipAdmin, admin);
        _ccipAdmin = admin;
    }

    /**
     * @dev Returns the CCIP Token Administrator, as required by Chainlink's
     *      TokenAdminRegistry registration flow. Falls back to `owner()` when
     *      unset so registration is never blocked by a zero address.
     * @return The CCIP administrator address
     */
    function getCCIPAdmin() external view returns (address) {
        address admin = _ccipAdmin;
        return admin == address(0) ? owner() : admin;
    }

    /**
     * @dev Returns the version of the contract.
     * Overrides the parent contract's version.
     * @return Version string
     */
    function version() public pure override returns (string memory) {
        return "v3";
    }
}

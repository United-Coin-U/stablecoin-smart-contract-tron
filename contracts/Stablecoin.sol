// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "./RescuableToken.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";

contract Stablecoin is RescuableToken, ERC20PermitUpgradeable, Ownable2StepUpgradeable, ERC20PausableUpgradeable {

    error CallerNotAutoOwner(address caller);
    error NotAllowedAddress(address addr);
    error FrozenAddress(address addr);
    error InvalidNonce(uint256 nonce);
    error InvalidChainId(uint256 chainId);
    error InvalidAmount(uint256 amount);
    error MintLimitExceeded(uint256 amount, uint256 limit);
   
    event Mint(address indexed caller, address indexed to, uint256 amount);
    event AutoMint(address indexed caller, address indexed to, uint256 indexed seq, uint256 amount);
    event Burn(address indexed caller, address indexed from, uint256 amount);
    event AutoBurn(address indexed caller, address indexed from, uint256 indexed seq, uint256 amount);
    event Freeze(address indexed caller, address indexed account);
    event Unfreeze(address indexed caller, address indexed account);
    event AutoOwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event SetAutoMintMaxLimit(uint256 previousLimit, uint256 newLimit);

    mapping(address => bool) public frozen;

    uint256 public nonce;
    uint256 public chainId;
    address public autoOwner;
    uint256 public autoMintMaxLimit;

    modifier onlyAutoOwner(){
        if(msg.sender != autoOwner) revert CallerNotAutoOwner(msg.sender);
        _;
    }

   /**
     * @dev Constructor
     */
    constructor() {
        _disableInitializers();
    }

   /**
     * @dev Initializer method
     */
    function initialize(string memory _name, string memory _symbol, address _initOwner) public initializer {
        __Context_init();
        __ERC20_init(_name, _symbol);
        __ERC20Permit_init(_name);
        __Ownable_init(_initOwner); // v5 requires initial owner address
        __Pausable_init();
        __AutoOwnerInit(_initOwner);

        chainId = block.chainid;
    }

   /**
     * @dev Implementation of RescuableToken's _getRescueOwner
     * Returns the contract owner from Ownable2StepUpgradeable
     */
    function _getRescueOwner() internal view override returns (address) {
        return owner();
    }

   /**
     * @dev Init auto owner
     */
    function __AutoOwnerInit(address _autoOwner) internal onlyInitializing {
        if(_autoOwner == address(0)) revert NotAllowedAddress(_autoOwner);
        emit AutoOwnerTransferred(autoOwner, _autoOwner);
        autoOwner = _autoOwner;
    }
    
    /**
     * @dev Transfer auto owner
     * @param _newAutoOwner new auto owner address
     */
    function transferAutoOwnership(address _newAutoOwner) external onlyOwner {
        if(_newAutoOwner == address(0)) revert NotAllowedAddress(_newAutoOwner);
        emit AutoOwnerTransferred(autoOwner, _newAutoOwner);
        autoOwner = _newAutoOwner;
    }

    
    /**
     * @dev Rennounce auto owner
     */
    function renounceAutoOwnership() external onlyOwner {
        emit AutoOwnerTransferred(autoOwner, address(0));
        autoOwner = address(0);
    }

    /**
     * @dev Throws if account is frozen.
     */
    modifier notFrozen(address account) {
        if(frozen[account]) revert FrozenAddress(account);
        _;
    }

    /**
    *  @dev set auto mint max limit
     * @param limit auto mint max limit
     * Can only be called by the auto owner.
     */
    function setAutoMintMaxLimit(uint256 limit) external onlyOwner {
        emit SetAutoMintMaxLimit(autoMintMaxLimit, limit);
        autoMintMaxLimit = limit;
    }

    /** 
     * @dev See {ERC20-_mint}.
     * @param amount Mint amount
     * @return True if successful
     * Can only be called by the current owner.
     */
    function mint(uint256 amount) external onlyOwner returns (bool) {
        _mint(_msgSender(), amount);
        emit Mint(_msgSender(), _msgSender(), amount);
        return true;
    }

    /** 
     * @dev See {ERC20-_mint}.
     * @param to Mint to address
     * @param amount Mint amount
     * @return True if successful
     * Can only be called by the current owner.
     */
    function mint(address to, uint256 amount) external notFrozen(to) onlyOwner returns (bool) {
        _mint(to, amount);
        emit Mint(_msgSender(), to, amount);
        return true;
    }

    /**
     * @dev See {ERC20-_mint}.
     * @param to Destination address
     * @param amount Mint amount
     * @param seq nonce
     * @param chainIdParam chain id
     * @return True if successful
     * Can only be called by the current auto owner.
     */
    function autoMint(address to, uint256 amount, uint256 seq, uint256 chainIdParam) external whenNotPaused() notFrozen(to) onlyAutoOwner returns (bool) {
        if(seq != nonce) revert InvalidNonce(seq);
        if(chainIdParam != chainId) revert InvalidChainId(chainIdParam);
        if(amount == 0) revert InvalidAmount(amount);
        if(amount > autoMintMaxLimit) revert MintLimitExceeded(amount, autoMintMaxLimit);
        nonce++;
        _mint(to, amount);
        emit Mint(_msgSender(), to, amount);
        emit AutoMint(_msgSender(), to, seq, amount);
        return true;
    }

    /**
     * @dev See {ERC20-_burn}.
     * @param amount Burn amount
     * @return True if successful
     * Can only be called by the current owner.
     */
    function burn(uint256 amount) external onlyOwner returns (bool) {
        _burn(_msgSender(), amount);
        emit Burn(_msgSender(), _msgSender(), amount);
        return true;
    }

    /**
     * @dev See {ERC20-_burn}.
     * @param amount Burn amount
     * @param seq nonce
     * @param chainIdParam chain id
     * @return True if successful
     * Can only be called by the current auto owner.
     */
    function autoBurn(uint256 amount, uint256 seq, uint256 chainIdParam) external whenNotPaused() onlyAutoOwner returns (bool) {
        if(seq != nonce) revert InvalidNonce(seq);
        if(chainIdParam != chainId) revert InvalidChainId(chainIdParam);
        if(amount == 0) revert InvalidAmount(amount);  
        nonce++;
        address owner = owner();
        _burn(owner, amount);
        emit Burn(autoOwner, owner, amount);
        emit AutoBurn(autoOwner,owner, seq, amount);
        return true;
    }
    
    /**
     * @dev Adds account to frozen state.
     * Can only be called by the current owner.
     */
    function freezeAccount(address account) external onlyOwner {
        frozen[account] = true;
        emit Freeze(_msgSender(), account);
    }

    /**
     * @dev Removes account from frozen state.
     * Can only be called by the current owner.
     */
    function unfreezeAccount(address account) external onlyOwner {
        delete frozen[account];
        emit Unfreeze(_msgSender(), account);
    }

    /**
     * @dev Triggers stopped state.
     * Can only be called by the current owner.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Returns to normal state.
     * Can only be called by the current owner.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Unsupported. Leaves the contract without owner.
     */
    function renounceOwnership() public view override onlyOwner {
        revert("Unsupported");
    }

    /**
     * @dev See {ERC20-_transfer}.
     * @param to Destination address
     * @param amount Transfer amount
     */
    function transfer(address to, uint256 amount) public override whenNotPaused notFrozen(_msgSender()) notFrozen(to) returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, amount);
        return true;
    }


    /**
     * @dev See {ERC20-_approve}.
     * @param spender Spender's address
     * @param amount Allowance amount
     */
    function approve(address spender, uint256 amount) public override whenNotPaused notFrozen(_msgSender()) notFrozen(spender) returns (bool){
        address owner = _msgSender();
        _approve(owner, spender, amount);
        return true;
    }

    /**
     * @dev See {ERC20-_transferFrom}.
     * @param from Source address
     * @param to Destination address
     * @param amount Transfer amount
     */
    function transferFrom(address from, address to, uint256 amount) public override whenNotPaused notFrozen(from) notFrozen(to) returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Hook that is called before any transfer of tokens.
     * This includes minting and burning.
     * Must override to resolve conflict between ERC20Upgradeable and ERC20PausableUpgradeable
     */
    function _update(address from, address to, uint256 value) internal virtual override(ERC20Upgradeable, ERC20PausableUpgradeable) {
        super._update(from, to, value);
    }

}

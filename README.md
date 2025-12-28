# Upgradable Smart Contracts Using the Transparent Proxy Pattern

$U is a next-generation stablecoin backed by fully fluid assets, designed to unify fragmented liquidity across trading, payments, DeFi, institutional settlement, and AI-driven autonomous systems. It is the embodiment of a "fluid" future where value flows seamlessly between humans and AI. 

## Contracts:

1. **Stablecoin.sol**

   - Stablecoin implementation smart contract

2. **ProxyAdmin.sol**

   - Minimal admin contract for `TransparentUpgradeableProxy`.
   - Only the `owner()` of `ProxyAdmin` can call `upgrade(proxy, newImplementation)`.
   - Also allows the admin to call arbitrary functions on the proxy (e.g. `initializeV2()`) and transfer ownership of the `ProxyAdmin` itself.

3. **TransparentUpgradeableProxy.sol**

   - Stores the implementation and admin addresses in EIP1967-defined slots.
   - Forwards all user calls (except those from the admin to `upgradeTo(...)`) to the implementation via `delegatecall`.
   - Ensures only the admin can perform upgrades, while normal users interact with token functions through the proxy address.
   - This contract's address acts as a permanent entry point for users, even if the underlying implementation is upgraded, making it the primary address that end users interact with.

## Migrations:

1. **1_initial_migration.js**

   - Standard TronBox migration that deploys the `Migrations` contract.
2. **2_deploy_upgradable_token.js**

   - Deploys and configures the entire upgradeable system:
     1. Deploys `ProxyAdmin`.
     2. Deploys `Stablecoin`.
     3. Deploys `TransparentUpgradeableProxy` pointing to `Stablecoin` and controlled by `ProxyAdmin`.
     4. Calls `Stablecoin.initialize(...)` via the proxy to set up initial token params (name, symbol, supply, owner).

**Important Note:** Update the .env file with your private key, Tron node host, and deployed contract addresses etc so they are properly used by tronbox.js, 2_deploy_upgradable_token.js.

## Contract Setup:

Before compiling & deploying, a few updates need to be done:

1. Modify your PRIVATE_KEY & FULL_NODE constants depending on your  network preferences.
2. Modify the 2_deploy_upgradable_token.js script with your own token information (line 56)
3. Make sure to run steps A to E form the 2_deploy_upgradable_token.js  when deploying your contract for the first time (Comment code as needed)
4. When upgrading implementation contract make sure to run ONLY steps F & G (optionally if you want to upgrade after deploying v2,v3, etc, Comment code as needed)

**Compile and Deploy:**

```bash
npx tronbox compile
npx tronbox migrate --network development // Deploy contract in your development network
npx tronbox migrate --network nile // Deploy your contract directly to nile testnet
```

```bash
npm run compile
npm run test
npm run clean
npm run deploy:nile
npm run deploy:prod
npm run flatten:all    
```

After deployment, you will see addresses of the deployed contracts:

1. ProxyAdmin at some Tron address
2. Stablecoin at some Tron address
3. TransparentUpgradeableProxy at some Tron address


## Test Contract :

### Test without deployment
```bash
  npm run test:stablecoin
  npm run test:proxy
  npm run test:all
```

### Test with deployment

```bash
  npm run test                     
  tronbox test
```
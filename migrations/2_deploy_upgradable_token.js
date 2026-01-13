const Stablecoin = artifacts.require("Stablecoin");
const ProxyAdmin = artifacts.require("ProxyAdmin");
const TransparentUpgradeableProxy = artifacts.require("TransparentUpgradeableProxy");

const tokenName = "United Stables";
const tokenSymbol = "U";

const fs = require('fs');
const path = require('path');
const TronWeb = require('tronweb').TronWeb || require('tronweb');

function saveDeployment(network, data) {
  const deploymentsDir = path.join(__dirname, '../deployments');

  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filePath = path.join(deploymentsDir, `${network}.json`);

  const deploymentData = {
    ...data,
    network: network,
    timestamp: new Date().toISOString(),
    date: new Date().toLocaleString()
  };

  fs.writeFileSync(filePath, JSON.stringify(deploymentData, null, 2));
  console.log(`\n💾 Deployment info saved: ${filePath}`);

  return filePath;
}

module.exports = async function (deployer, network, accounts) {
  console.log('\n🚀 Start Stablecoin deployment process...\n');
  console.log('=' .repeat(70));
  console.log('');

  try {
    // Init TronWeb instance
    const tronboxConfig = require('../tronbox.js');
    const networkConfig = tronboxConfig.networks[network];

    if (!networkConfig) {
      throw new Error(`Network ${network} is not found in tronbox.js`);
    }

    const localTronWeb = new TronWeb({
      fullHost: networkConfig.fullHost,
      privateKey: networkConfig.privateKey
    });

    // Get deployer address
    const deployerBase58 = accounts[0] && accounts[0].length >= 42
      ? localTronWeb.address.fromHex(accounts[0])
      : localTronWeb.address.fromPrivateKey(networkConfig.privateKey);

    console.log('📋 Deploy info:');
    console.log(`   Netwokr: ${network}`);
    console.log(`   Deployer: ${deployerBase58}`);
    console.log('');

    // ========================================
    // Step 1 : Deploy Stablecoin Impl smart contract
    // ========================================
    console.log('1️⃣  Deploy Stablecoin Implementation...');
    await deployer.deploy(Stablecoin);
    const implementation = await Stablecoin.deployed();
    const implBase58 = localTronWeb.address.fromHex(implementation.address);
    console.log(`   ✅ Implementation: ${implBase58}`);
    console.log('');

    // Sleep in case 429
    await new Promise(resolve => setTimeout(resolve, 6000));

    // ========================================
    // Step 2 : Deploy ProxyAdmin
    // ========================================
    console.log('2️⃣  Deploy ProxyAdmin...');

    await deployer.deploy(ProxyAdmin, deployerBase58);
    const proxyAdmin = await ProxyAdmin.deployed();
    const proxyAdminBase58 = localTronWeb.address.fromHex(proxyAdmin.address);

    console.log(`   ✅ ProxyAdmin: ${proxyAdminBase58}`);
    console.log('');

    // Sleep in case 429
    await new Promise(resolve => setTimeout(resolve, 6000));

    // Validate ProxyAdmin
    console.log('   Validate ProxyAdmin...');
    try {
      const adminOwner = await proxyAdmin.owner();
      const adminOwnerBase58 = localTronWeb.address.fromHex(adminOwner);
      console.log(`   Owner: ${adminOwnerBase58}`);

      const version = await proxyAdmin.version();
      console.log(`   Version: ${version}`);
    } catch (error) {
      console.log('   ⚠️  Cant validate ProxyAdmin:', error.message);
    }
    console.log('');

    // ========================================
    // Step 3: Prepare Stablecoin initialization data
    // ========================================
    console.log('3️⃣  Prepare Stablecoin initialization data...');

    const initializeSignature = 'initialize(string,string,address)';
    const functionSelector = localTronWeb.sha3(initializeSignature, false).slice(0, 8);

    const encodedParams = localTronWeb.utils.abi.encodeParams(
      ['string', 'string', 'address'],
      [tokenName, tokenSymbol, localTronWeb.address.toHex(deployerBase58)]
    );

    const initData = '0x' + functionSelector + encodedParams.replace('0x', '');

    console.log(`   Token Name: ${tokenName}`);
    console.log(`   Token Symbol: ${tokenSymbol}`);
    console.log(`   Initial Owner: ${deployerBase58}`);
    console.log(`   Initial Data: ${initData}`);
    console.log('   ✅ Initialization data is ready');
    console.log('');

    // ========================================
    // Step 4: Deploy TransparentUpgradeableProxy
    // ========================================
    console.log('4️⃣  Deploy TransparentUpgradeableProxy...');

    await deployer.deploy(
      TransparentUpgradeableProxy,
      implementation.address,    // _logic
      proxyAdmin.address,        // admin
      initData                   // _data
    );

    const proxy = await TransparentUpgradeableProxy.deployed();
    const proxyBase58 = localTronWeb.address.fromHex(proxy.address);

    console.log(`   ✅ Proxy (Stablecoin): ${proxyBase58}`);
    console.log(`   Admin: ${proxyAdminBase58}`);
    console.log(`   Implementation: ${implBase58}`);
    console.log('');

    // Sleep in case 429
    await new Promise(resolve => setTimeout(resolve, 6000));

    // ========================================
    // Step 5: Verify Deployment
    // ========================================
    console.log('5️⃣  Verify Stablecoin Deployment...');

    const proxyAsStablecoin = await localTronWeb.contract(
      Stablecoin.abi,
      proxyBase58
    );

    try {
      const name = await proxyAsStablecoin.name().call();
      const symbol = await proxyAsStablecoin.symbol().call();
      const owner = await proxyAsStablecoin.owner().call();
      const ownerBase58 = localTronWeb.address.fromHex(owner);

      console.log(`   Name: ${name}`);
      console.log(`   Symbol: ${symbol}`);
      console.log(`   Owner: ${ownerBase58}`);
      console.log('   ✅ Stablecoin Initialized correctly');
    } catch (error) {
      console.log('   ⚠️  Cant verify Stablecoin:', error.message);
    }
    console.log('');

    // ========================================
    // Step 6: Save Deployment Info
    // ========================================
    console.log('6️⃣   Save Deployment Info...');

    const deploymentData = {
      proxyAdmin: proxyAdminBase58,
      implementation: implBase58,
      proxy: proxyBase58,
      deployer: deployerBase58,
      tokenName: tokenName,
      tokenSymbol: tokenSymbol,
      proxyType: 'TransparentUpgradeableProxy + SafeProxyAdmin (OpenZeppelin)',
      version: 'v3.0.0',
      security: 'Based on OpenZeppelin v5.4.0'
    };

    const deploymentFile = saveDeployment(network, deploymentData);

  } catch (error) {
    console.error('\n❌ Deployment failed:', error.message);
    console.error(error);
    throw error;
  }
};

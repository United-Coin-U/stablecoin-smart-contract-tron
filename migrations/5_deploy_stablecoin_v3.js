const StablecoinV3 = artifacts.require("StablecoinV3");

const fs = require('fs');
const path = require('path');
const TronWeb = require('tronweb').TronWeb || require('tronweb');

const INITIALIZE_V3_SIGNATURE = 'initializeV3()';

function readDeployment(network) {
  const filePath = path.join(__dirname, '../deployments', `${network}.json`);
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function mergeDeployment(network, patch) {
  const deploymentsDir = path.join(__dirname, '../deployments');
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  const filePath = path.join(deploymentsDir, `${network}.json`);
  const existing = readDeployment(network) || {};
  const merged = {
    ...existing,
    ...patch,
    network,
    timestamp: new Date().toISOString(),
    date: new Date().toLocaleString()
  };
  fs.writeFileSync(filePath, JSON.stringify(merged, null, 2));
  console.log(`\n💾 Deployment info saved: ${filePath}`);
  return filePath;
}

module.exports = async function (deployer, network, accounts) {
  console.log('\n🚀 Start StablecoinV3 (Chainlink CCIP) implementation-only deployment...\n');
  console.log('='.repeat(70));
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
      privateKey: networkConfig.privateKey,
      headers: process.env.TRONGRID_API_KEY
        ? { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY }
        : undefined
    });

    // Get deployer address
    const deployerBase58 = accounts[0] && accounts[0].length >= 42
      ? localTronWeb.address.fromHex(accounts[0])
      : localTronWeb.address.fromPrivateKey(networkConfig.privateKey);

    console.log('📋 Deploy info:');
    console.log(`   Network:  ${network}`);
    console.log(`   Deployer: ${deployerBase58}`);
    console.log('');

    // ========================================
    // Step 1: Deploy StablecoinV3 implementation only
    // ========================================
    console.log('1️⃣  Deploy StablecoinV3 implementation...');
    await deployer.deploy(StablecoinV3);
    const implementation = await StablecoinV3.deployed();
    const implBase58 = localTronWeb.address.fromHex(implementation.address);
    console.log(`   ✅ StablecoinV3 implementation: ${implBase58}`);
    console.log('');

    // Sleep in case 429
    await new Promise(resolve => setTimeout(resolve, 6000));

    // ========================================
    // Step 2: Compute initializeV3() calldata
    // ========================================
    console.log('2️⃣  Compute initializeV3() calldata...');
    const initData = '0x' + localTronWeb.sha3(INITIALIZE_V3_SIGNATURE, false).slice(0, 8);
    console.log(`   Function Signature: ${INITIALIZE_V3_SIGNATURE}`);
    console.log(`   upgradeAndCall data: ${initData}`);
    console.log('');

    // ========================================
    // Step 3: Save Deployment Info
    // ========================================
    console.log('3️⃣  Save Deployment Info...');

    const prior = readDeployment(network) || {};
    mergeDeployment(network, {
      stablecoinV3: {
        implementation: implBase58,
        deployer: deployerBase58,
        initializeV3Data: initData,
        deployedAt: new Date().toISOString(),
        note: 'Implementation only — proxy NOT deployed and NOT upgraded. Upgrade existing proxy via ProxyAdmin.upgradeAndCall(proxy, impl, initializeV3Data).'
      }
    });

    // ========================================
    // Step 4: Print upgrade hint
    // ========================================
    console.log('');
    console.log('📝 Next steps to activate StablecoinV3:');
    if (prior.proxyAdmin && prior.proxy) {
      console.log(`   - Existing ProxyAdmin: ${prior.proxyAdmin}`);
      console.log(`   - Existing Proxy:      ${prior.proxy}`);
      console.log('   - As ProxyAdmin owner, call:');
      console.log('       ProxyAdmin.upgradeAndCall(');
      console.log(`         proxy   = ${prior.proxy},`);
      console.log(`         impl    = ${implBase58},`);
      console.log(`         data    = ${initData}   // initializeV3()`);
      console.log('       )');
    } else {
      console.log('   - No existing proxy info found in deployments/<network>.json.');
      console.log('   - As ProxyAdmin owner, call ProxyAdmin.upgradeAndCall(proxy, impl, data)');
      console.log(`     pointing the proxy at: ${implBase58}`);
      console.log(`     with data:             ${initData}   // initializeV3()`);
    }
    console.log('');
    console.log('   - Then, once the CCIP BurnMintTokenPool is deployed for this chain:');
    console.log('       StablecoinV3(proxy).grantMintAndBurnRoles(POOL)');
    console.log('');
    console.log('   ⚠️  initializeV3() seeds the CCIP admin with the current owner().');
    console.log('       Use setCCIPAdmin(admin) afterwards to decouple the two.');
    console.log('');
  } catch (error) {
    console.error('\n❌ Deployment failed:', error.message);
    console.error(error);
    throw error;
  }
};

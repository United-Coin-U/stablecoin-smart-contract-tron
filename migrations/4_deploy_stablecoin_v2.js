const StablecoinV2 = artifacts.require("StablecoinV2");

const fs = require('fs');
const path = require('path');
const TronWeb = require('tronweb').TronWeb || require('tronweb');

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
  console.log('\n🚀 Start StablecoinV2 implementation-only deployment...\n');
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
    // Step 1: Deploy StablecoinV2 implementation only
    // ========================================
    console.log('1️⃣  Deploy StablecoinV2 implementation...');
    await deployer.deploy(StablecoinV2);
    const implementation = await StablecoinV2.deployed();
    const implBase58 = localTronWeb.address.fromHex(implementation.address);
    console.log(`   ✅ StablecoinV2 implementation: ${implBase58}`);
    console.log('');

    // Sleep in case 429
    await new Promise(resolve => setTimeout(resolve, 6000));

    // ========================================
    // Step 2: Save Deployment Info
    // ========================================
    console.log('2️⃣  Save Deployment Info...');

    const prior = readDeployment(network) || {};
    mergeDeployment(network, {
      stablecoinV2: {
        implementation: implBase58,
        deployer: deployerBase58,
        deployedAt: new Date().toISOString(),
        note: 'Implementation only — proxy NOT deployed. Upgrade existing proxy via ProxyAdmin to point to this address.'
      }
    });

    // ========================================
    // Step 3: Print upgrade hint
    // ========================================
    console.log('');
    console.log('📝 Next steps to activate StablecoinV2:');
    if (prior.proxyAdmin && prior.proxy) {
      console.log(`   - Existing ProxyAdmin: ${prior.proxyAdmin}`);
      console.log(`   - Existing Proxy:      ${prior.proxy}`);
      console.log('   - As ProxyAdmin owner, call:');
      console.log(`       ProxyAdmin.upgradeAndCall(`);
      console.log(`         proxy   = ${prior.proxy},`);
      console.log(`         impl    = ${implBase58},`);
      console.log(`         data    = 0x   // or reinitializer call data if needed`);
      console.log(`       )`);
    } else {
      console.log('   - No existing proxy info found in deployments/<network>.json.');
      console.log('   - As ProxyAdmin owner, call ProxyAdmin.upgradeAndCall(proxy, impl, data)');
      console.log(`     pointing the proxy at: ${implBase58}`);
    }
    console.log('');
  } catch (error) {
    console.error('\n❌ Deployment failed:', error.message);
    console.error(error);
    throw error;
  }
};

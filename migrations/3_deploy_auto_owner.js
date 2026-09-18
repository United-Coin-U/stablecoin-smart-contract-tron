const StablecoinAutoOwner = artifacts.require("StablecoinAutoOwner");
const ERC1967Proxy = artifacts.require("ERC1967Proxy");

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

function envFor(network, key) {
  const suffix = network.toUpperCase();
  return process.env[`${key}_${suffix}`] || process.env[key] || '';
}

function toBase58(tronWeb, addr) {
  if (!addr) return addr;
  if (addr.startsWith('T') && addr.length === 34) return addr;
  return tronWeb.address.fromHex(addr);
}

module.exports = async function (deployer, network, accounts) {
  console.log('\n🚀 Start StablecoinAutoOwner deployment process...\n');
  console.log('='.repeat(70));
  console.log('');

  try {
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

    const deployerBase58 = accounts[0] && accounts[0].length >= 42
      ? localTronWeb.address.fromHex(accounts[0])
      : localTronWeb.address.fromPrivateKey(networkConfig.privateKey);

    console.log('📋 Deploy info:');
    console.log(`   Network: ${network}`);
    console.log(`   Deployer: ${deployerBase58}`);
    console.log('');

    // ========================================
    // Step 1: Resolve Stablecoin proxy address
    // ========================================
    console.log('1️⃣  Resolve Stablecoin proxy address...');
    const priorDeployment = readDeployment(network) || {};

    let stablecoinProxyBase58 = envFor(network, 'STABLECOIN_PROXY_ADDRESS')
      || priorDeployment.proxy
      || '';

    if (!stablecoinProxyBase58) {
      throw new Error(
        `Cannot resolve Stablecoin proxy address. ` +
        `Set STABLECOIN_PROXY_ADDRESS_${network.toUpperCase()} in .env ` +
        `or deploy the Stablecoin first (migration 2).`
      );
    }

    stablecoinProxyBase58 = toBase58(localTronWeb, stablecoinProxyBase58);
    const stablecoinProxyHex = localTronWeb.address.toHex(stablecoinProxyBase58);
    console.log(`   Stablecoin proxy: ${stablecoinProxyBase58}`);
    console.log('');

    // ========================================
    // Step 2: Resolve initial owner / operator
    // ========================================
    console.log('2️⃣  Resolve initial owner / operator...');

    const initialOwnerBase58 = toBase58(
      localTronWeb,
      envFor(network, 'AUTO_OWNER_INITIAL_OWNER') || deployerBase58
    );
    const initialOperatorBase58 = toBase58(
      localTronWeb,
      envFor(network, 'AUTO_OWNER_INITIAL_OPERATOR') || deployerBase58
    );

    console.log(`   Initial Owner:    ${initialOwnerBase58}`);
    console.log(`   Initial Operator: ${initialOperatorBase58}`);
    console.log('');

    // ========================================
    // Step 3: Deploy StablecoinAutoOwner Implementation
    // ========================================
    console.log('3️⃣  Deploy StablecoinAutoOwner Implementation...');
    await deployer.deploy(StablecoinAutoOwner);
    const implementation = await StablecoinAutoOwner.deployed();
    const implBase58 = localTronWeb.address.fromHex(implementation.address);
    console.log(`   ✅ Implementation: ${implBase58}`);
    console.log('');

    await new Promise(resolve => setTimeout(resolve, 6000));

    // ========================================
    // Step 4: Encode initialize(address,address,address) call data
    // ========================================
    console.log('4️⃣  Prepare StablecoinAutoOwner initialization data...');

    const initializeSignature = 'initialize(address,address,address)';
    const functionSelector = localTronWeb.sha3(initializeSignature, false).slice(0, 8);

    const encodedParams = localTronWeb.utils.abi.encodeParams(
      ['address', 'address', 'address'],
      [
        stablecoinProxyHex,
        localTronWeb.address.toHex(initialOwnerBase58),
        localTronWeb.address.toHex(initialOperatorBase58)
      ]
    );

    const initData = '0x' + functionSelector + encodedParams.replace('0x', '');

    console.log(`   Selector: 0x${functionSelector}`);
    console.log(`   Init data: ${initData}`);
    console.log('   ✅ Initialization data is ready');
    console.log('');

    // ========================================
    // Step 5: Deploy ERC1967Proxy
    // ========================================
    console.log('5️⃣  Deploy ERC1967Proxy...');

    await deployer.deploy(
      ERC1967Proxy,
      implementation.address,
      initData
    );

    const proxy = await ERC1967Proxy.deployed();
    const proxyBase58 = localTronWeb.address.fromHex(proxy.address);

    console.log(`   ✅ Proxy (StablecoinAutoOwner): ${proxyBase58}`);
    console.log(`   Implementation: ${implBase58}`);
    console.log('');

    await new Promise(resolve => setTimeout(resolve, 6000));

    // ========================================
    // Step 6: Verify Deployment
    // ========================================
    console.log('6️⃣  Verify StablecoinAutoOwner Deployment...');

    const proxyAsAutoOwner = await localTronWeb.contract(
      StablecoinAutoOwner.abi,
      proxyBase58
    );

    try {
      const ownerHex = await proxyAsAutoOwner.owner().call();
      const operatorHex = await proxyAsAutoOwner.operator().call();
      const stablecoinHex = await proxyAsAutoOwner.stablecoin().call();

      console.log(`   Owner:      ${localTronWeb.address.fromHex(ownerHex)}`);
      console.log(`   Operator:   ${localTronWeb.address.fromHex(operatorHex)}`);
      console.log(`   Stablecoin: ${localTronWeb.address.fromHex(stablecoinHex)}`);
      console.log('   ✅ StablecoinAutoOwner initialized correctly');
    } catch (error) {
      console.log('   ⚠️  Cant verify StablecoinAutoOwner:', error.message);
    }
    console.log('');

    // ========================================
    // Step 7: Save Deployment Info
    // ========================================
    console.log('7️⃣  Save Deployment Info...');

    mergeDeployment(network, {
      autoOwner: {
        proxy: proxyBase58,
        implementation: implBase58,
        stablecoin: stablecoinProxyBase58,
        owner: initialOwnerBase58,
        operator: initialOperatorBase58,
        proxyType: 'ERC1967Proxy + UUPSUpgradeable (OpenZeppelin v5.4.0)',
        version: 'v1.0.0'
      }
    });

    console.log('');
    console.log('📝 Next steps (run as Stablecoin owner):');
    console.log(`   1. Call Stablecoin.transferAutoOwnership("${proxyBase58}")`);
    console.log(`      on Stablecoin proxy ${stablecoinProxyBase58}`);
    console.log(`   2. Call StablecoinAutoOwner.setMaxMintLimit(to, limit) for each whitelisted recipient`);
    console.log('');
  } catch (error) {
    console.error('\n❌ Deployment failed:', error.message);
    console.error(error);
    throw error;
  }
};

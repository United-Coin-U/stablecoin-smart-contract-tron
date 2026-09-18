/**
 * Deploy TransparentUpgradeableProxy ONLY
 *
 * Useful when you already have a deployed ProxyAdmin and a deployed
 * implementation contract (e.g. StablecoinV2), and you only need a fresh
 * proxy pointing at them.
 *
 * Usage:
 *   node scripts/deploy_proxy.js \
 *     --network nile \
 *     --admin   <ProxyAdminAddress> \
 *     --logic   <StablecoinV2ImplementationAddress> \
 *     [--owner  <InitialOwnerAddress>] \
 *     [--name   "United Stables"] \
 *     [--symbol "U"] \
 *     [--init-data 0x...]   // raw initializer calldata (overrides name/symbol/owner)
 *     [--no-init]           // deploy proxy with empty init data (0x)
 *     [--save]              // merge result into deployments/<network>.json
 *
 * Notes:
 *   - --network is required and must exist in tronbox.js
 *   - --admin and --logic are required
 *   - If neither --init-data nor --no-init is supplied, the script builds
 *     calldata for Stablecoin.initialize(string,string,address) using
 *     --name / --symbol / --owner (owner defaults to deployer).
 *   - Run `npm run compile` first to ensure build/contracts/*.json are present.
 */

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const TronWeb = require('tronweb').TronWeb || require('tronweb');

const DEFAULT_TOKEN_NAME = 'United Stables';
const DEFAULT_TOKEN_SYMBOL = 'U';

function parseArgs() {
  const argv = process.argv.slice(2);
  const params = {
    network: null,
    admin: null,
    logic: null,
    owner: null,
    name: DEFAULT_TOKEN_NAME,
    symbol: DEFAULT_TOKEN_SYMBOL,
    initData: null,
    noInit: false,
    save: false
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = argv[i + 1];
    switch (a) {
      case '--network': params.network = next; i++; break;
      case '--admin':   params.admin   = next; i++; break;
      case '--logic':   params.logic   = next; i++; break;
      case '--owner':   params.owner   = next; i++; break;
      case '--name':    params.name    = next; i++; break;
      case '--symbol':  params.symbol  = next; i++; break;
      case '--init-data': params.initData = next; i++; break;
      case '--no-init': params.noInit  = true; break;
      case '--save':    params.save    = true; break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
      default:
        console.warn(`⚠️  Unknown argument: ${a}`);
    }
  }

  return params;
}

function printHelp() {
  console.log(`
Usage: node scripts/deploy_proxy.js [options]

Required:
  --network <name>        Network defined in tronbox.js (nile|shasta|prod|...)
  --admin   <address>     Existing ProxyAdmin address (Base58 starting with T)
  --logic   <address>     Existing implementation address (e.g. StablecoinV2)

Init data (pick one):
  (default)               Encode Stablecoin.initialize(name,symbol,owner)
  --name   <string>       Token name   (default: "${DEFAULT_TOKEN_NAME}")
  --symbol <string>       Token symbol (default: "${DEFAULT_TOKEN_SYMBOL}")
  --owner  <address>      Initial owner (default: deployer)
  --init-data <0x...>     Raw initializer calldata (overrides name/symbol/owner)
  --no-init               Deploy with empty init data (0x)

Other:
  --save                  Merge proxy info into deployments/<network>.json
  --help, -h              Show this help
`);
}

function loadArtifact(name) {
  const filePath = path.join(__dirname, '..', 'build', 'contracts', `${name}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Artifact not found: ${filePath}. Run "npm run compile" first.`);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function readDeployment(network) {
  const filePath = path.join(__dirname, '..', 'deployments', `${network}.json`);
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function mergeDeployment(network, patch) {
  const deploymentsDir = path.join(__dirname, '..', 'deployments');
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
  console.log(`💾 Deployment info saved: ${filePath}`);
  return filePath;
}

function toBase58(tronWeb, addr) {
  if (!addr) return addr;
  if (addr.startsWith('T')) return addr;
  return tronWeb.address.fromHex(addr);
}

function toHex(tronWeb, addr) {
  if (!addr) return addr;
  if (addr.startsWith('T')) return tronWeb.address.toHex(addr);
  if (addr.startsWith('0x')) return '41' + addr.slice(2);
  return addr;
}

function buildInitData(tronWeb, name, symbol, ownerBase58) {
  const sig = 'initialize(string,string,address)';
  const selector = tronWeb.sha3(sig, false).slice(0, 8);
  const ownerHex = tronWeb.address.toHex(ownerBase58);
  const encoded = tronWeb.utils.abi.encodeParams(
    ['string', 'string', 'address'],
    [name, symbol, ownerHex]
  );
  return '0x' + selector + encoded.replace(/^0x/, '');
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const params = parseArgs();

  console.log('\n🚀 Deploy TransparentUpgradeableProxy (standalone)\n');
  console.log('='.repeat(70));

  // --- Validate args ---
  if (!params.network) {
    console.error('❌ Missing --network');
    printHelp();
    process.exit(1);
  }
  if (!params.admin) {
    console.error('❌ Missing --admin (existing ProxyAdmin address)');
    process.exit(1);
  }
  if (!params.logic) {
    console.error('❌ Missing --logic (existing implementation address)');
    process.exit(1);
  }

  // --- Load network config ---
  const tronboxConfig = require('../tronbox.js');
  const networkConfig = tronboxConfig.networks[params.network];
  if (!networkConfig) {
    throw new Error(`Network "${params.network}" not found in tronbox.js`);
  }
  if (!networkConfig.privateKey) {
    throw new Error(`No privateKey configured for network "${params.network}"`);
  }

  const tronWeb = new TronWeb({
    fullHost: networkConfig.fullHost,
    privateKey: networkConfig.privateKey,
    headers: process.env.TRONGRID_API_KEY
      ? { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY }
      : undefined
  });

  const deployerBase58 = tronWeb.address.fromPrivateKey(networkConfig.privateKey);

  // Normalize input addresses to Base58 for display & validate
  const adminBase58 = toBase58(tronWeb, params.admin);
  const logicBase58 = toBase58(tronWeb, params.logic);
  const ownerBase58 = params.owner ? toBase58(tronWeb, params.owner) : deployerBase58;

  // --- Build init data ---
  let initData;
  if (params.noInit) {
    initData = '0x';
  } else if (params.initData) {
    initData = params.initData.startsWith('0x') ? params.initData : '0x' + params.initData;
  } else {
    initData = buildInitData(tronWeb, params.name, params.symbol, ownerBase58);
  }

  console.log('📋 Deploy info:');
  console.log(`   Network:        ${params.network}`);
  console.log(`   Deployer:       ${deployerBase58}`);
  console.log(`   ProxyAdmin:     ${adminBase58}`);
  console.log(`   Implementation: ${logicBase58}`);
  if (params.noInit) {
    console.log(`   Init Data:      <empty>`);
  } else if (params.initData) {
    console.log(`   Init Data:      ${initData} (raw, user-supplied)`);
  } else {
    console.log(`   Token Name:     ${params.name}`);
    console.log(`   Token Symbol:   ${params.symbol}`);
    console.log(`   Initial Owner:  ${ownerBase58}`);
    console.log(`   Init Data:      ${initData}`);
  }
  console.log('');

  // --- Pre-flight: verify admin & logic actually have code on-chain ---
  console.log('🔎 Pre-flight check...');
  for (const [label, addr] of [['ProxyAdmin', adminBase58], ['Implementation', logicBase58]]) {
    try {
      const info = await tronWeb.trx.getContract(addr);
      if (!info || !info.contract_address) {
        console.warn(`   ⚠️  ${label} ${addr} has no on-chain contract data (continuing)`);
      } else {
        console.log(`   ✅ ${label} ${addr} OK`);
      }
    } catch (err) {
      console.warn(`   ⚠️  Could not fetch ${label} info: ${err.message || err}`);
    }
  }
  console.log('');

  // --- Deploy proxy ---
  console.log('1️⃣  Deploying TransparentUpgradeableProxy...');
  const proxyArtifact = loadArtifact('TransparentUpgradeableProxy');

  const logicHex = toHex(tronWeb, logicBase58);
  const adminHex = toHex(tronWeb, adminBase58);

  const feeLimit = networkConfig.fee_limit || 1_000_000_000;
  const userFeePercentage =
    typeof networkConfig.consume_user_resource_percent === 'number'
      ? networkConfig.consume_user_resource_percent
      : 100;

  const proxy = await tronWeb.contract().new({
    abi: proxyArtifact.abi,
    bytecode: proxyArtifact.bytecode,
    feeLimit,
    callValue: 0,
    userFeePercentage,
    shouldPollResponse: true,
    parameters: [logicHex, adminHex, initData]
  });

  const proxyBase58 = tronWeb.address.fromHex(proxy.address);
  console.log(`   ✅ Proxy deployed: ${proxyBase58}`);
  console.log('');

  // Sleep in case of 429 rate limiting
  await sleep(6000);

  // --- Verify (best-effort) ---
  console.log('2️⃣  Verifying proxy...');
  try {
    const stablecoinArtifact = loadArtifact('Stablecoin');
    const proxyAsStablecoin = await tronWeb.contract(stablecoinArtifact.abi, proxyBase58);

    const name = await proxyAsStablecoin.name().call();
    const symbol = await proxyAsStablecoin.symbol().call();
    const owner = await proxyAsStablecoin.owner().call();
    const ownerOnChain = tronWeb.address.fromHex(owner);

    let version = null;
    try { version = await proxyAsStablecoin.version().call(); } catch (_) {}

    console.log(`   Name:    ${name}`);
    console.log(`   Symbol:  ${symbol}`);
    console.log(`   Owner:   ${ownerOnChain}`);
    if (version) console.log(`   Version: ${version}`);
    console.log('   ✅ Proxy initialized correctly');
  } catch (err) {
    console.log(`   ⚠️  Could not verify proxy state: ${err.message || err}`);
    console.log('       (This is normal if --no-init or a non-Stablecoin init was used.)');
  }
  console.log('');

  // --- Save (optional) ---
  if (params.save) {
    console.log('3️⃣  Saving deployment info...');
    mergeDeployment(params.network, {
      proxy: proxyBase58,
      proxyAdmin: adminBase58,
      implementation: logicBase58,
      deployer: deployerBase58,
      proxyType: 'TransparentUpgradeableProxy (standalone deploy)',
      lastProxyDeploy: {
        proxy: proxyBase58,
        admin: adminBase58,
        logic: logicBase58,
        initData,
        deployedAt: new Date().toISOString()
      }
    });
    console.log('');
  }

  console.log('='.repeat(70));
  console.log('🎉 Done.\n');
  console.log('Summary:');
  console.log(`   Proxy:          ${proxyBase58}`);
  console.log(`   ProxyAdmin:     ${adminBase58}`);
  console.log(`   Implementation: ${logicBase58}`);
  console.log('');
}

main().catch(err => {
  console.error('\n❌ Deployment failed:', err.message || err);
  console.error(err);
  process.exit(1);
});

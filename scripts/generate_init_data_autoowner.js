/**
 * Generate StablecoinAutoOwner initialization data (initData)
 *
 * This script generates the initialization data for the StablecoinAutoOwner
 * contract without deploying anything. The output is the ABI-encoded calldata
 * for `initialize(address,address,address)` — the `_data` argument of the
 * ERC1967Proxy constructor, or of `upgradeToAndCall` on an existing proxy.
 *
 * Usage:
 *   node scripts/generate_init_data_autoowner.js \
 *     --stablecoin TXxxxxxx \
 *     --owner      TYyyyyyy \
 *     --operator   TZzzzzzz
 *
 *   Addresses accept TRON base58 (T-prefixed, 34 chars)
 *   or hex (41-prefixed, 42 chars, or 0x-prefixed EVM-style 40-char body).
 */

const TronWeb = require('tronweb').TronWeb || require('tronweb');

const DEFAULT_HOST = 'https://api.trongrid.io'; // not used for I/O; TronWeb ctor needs it

function parseArgs() {
  const args = process.argv.slice(2);
  const params = {
    stablecoin: null,
    owner: null,
    operator: null
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const next = args[i + 1];
    if (a === '--stablecoin' && next) { params.stablecoin = next; i++; }
    else if (a === '--owner' && next) { params.owner = next; i++; }
    else if (a === '--operator' && next) { params.operator = next; i++; }
    else if (a === '--help' || a === '-h') {
      console.log(`
Usage: node scripts/generate_init_data_autoowner.js [options]

Options:
  --stablecoin <address>  Stablecoin proxy address (required)
  --owner      <address>  Initial owner of StablecoinAutoOwner (required)
  --operator   <address>  Initial operator (required)
  --help, -h              Show this help

Example:
  node scripts/generate_init_data_autoowner.js \\
    --stablecoin TKzxi7ifZF3XmJNBExcGnwJXkxQzKbHhY5 \\
    --owner      TY8E5j9omfjDp1TF9junUoKiGhLjJepSZe \\
    --operator   TY8E5j9omfjDp1TF9junUoKiGhLjJepSZe
      `);
      process.exit(0);
    }
  }
  return params;
}

// Accept base58 (T...) or hex (41... or 0x...), return 41-prefixed hex.
function normalizeAddressToHex(tronWeb, addr, label) {
  if (!addr) throw new Error(`${label} is required`);

  if (addr.startsWith('T') && addr.length === 34) {
    return tronWeb.address.toHex(addr);
  }
  if (addr.startsWith('41') && addr.length === 42) {
    return addr.toLowerCase();
  }
  if (addr.startsWith('0x') && addr.length === 42) {
    return ('41' + addr.slice(2)).toLowerCase();
  }
  throw new Error(`${label} has invalid TRON address format: ${addr}`);
}

function generateInitData(stablecoinHex, ownerHex, operatorHex) {
  const tronWeb = new TronWeb({ fullHost: DEFAULT_HOST });

  const signature = 'initialize(address,address,address)';
  const selector = tronWeb.sha3(signature, false).slice(0, 8);

  const encodedParams = tronWeb.utils.abi.encodeParams(
    ['address', 'address', 'address'],
    [stablecoinHex, ownerHex, operatorHex]
  );

  const initData = '0x' + selector + encodedParams.replace(/^0x/, '');

  return {
    signature,
    functionSelector: '0x' + selector,
    encodedParams,
    initData
  };
}

async function main() {
  console.log('\n🔧 Generate StablecoinAutoOwner Initialization Data\n');
  console.log('='.repeat(70));
  console.log('');

  const params = parseArgs();
  const missing = [];
  if (!params.stablecoin) missing.push('--stablecoin');
  if (!params.owner) missing.push('--owner');
  if (!params.operator) missing.push('--operator');
  if (missing.length) {
    console.error(`❌ Missing required argument(s): ${missing.join(', ')}`);
    console.error('   Use --help for more information.\n');
    process.exit(1);
  }

  const tronWeb = new TronWeb({ fullHost: DEFAULT_HOST });

  let stablecoinHex, ownerHex, operatorHex;
  try {
    stablecoinHex = normalizeAddressToHex(tronWeb, params.stablecoin, '--stablecoin');
    ownerHex = normalizeAddressToHex(tronWeb, params.owner, '--owner');
    operatorHex = normalizeAddressToHex(tronWeb, params.operator, '--operator');
  } catch (e) {
    console.error(`❌ ${e.message}\n`);
    process.exit(1);
  }

  const stablecoinB58 = tronWeb.address.fromHex(stablecoinHex);
  const ownerB58 = tronWeb.address.fromHex(ownerHex);
  const operatorB58 = tronWeb.address.fromHex(operatorHex);

  console.log('📋 Parameters:');
  console.log(`   _stablecoin       base58: ${stablecoinB58}`);
  console.log(`                     hex:    ${stablecoinHex}`);
  console.log(`   _initialOwner     base58: ${ownerB58}`);
  console.log(`                     hex:    ${ownerHex}`);
  console.log(`   _initialOperator  base58: ${operatorB58}`);
  console.log(`                     hex:    ${operatorHex}`);
  console.log('');

  const result = generateInitData(stablecoinHex, ownerHex, operatorHex);

  console.log('📦 Generated Data:');
  console.log(`   Function Signature: ${result.signature}`);
  console.log(`   Function Selector:  ${result.functionSelector}`);
  console.log('');
  console.log('✅ Init Data:');
  console.log('');
  console.log(result.initData);
  console.log('');
  console.log('='.repeat(70));
  console.log('');

  return result.initData;
}

main().catch(err => {
  console.error('❌ Error:', err.message);
  process.exit(1);
});

module.exports = { generateInitData };

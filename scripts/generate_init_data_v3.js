/**
 * Generate StablecoinV3 upgrade initialization data (initData)
 *
 * `initializeV3()` takes no arguments, so the calldata is just the 4-byte
 * function selector. This is the `data` argument for
 * ProxyAdmin.upgradeAndCall(proxy, implementation, data).
 *
 * Mirrors the EVM repo's script/UpgradeStablecoinV3.s.sol, which prints the same
 * calldata via abi.encodeWithSelector(StablecoinV3.initializeV3.selector).
 *
 * Usage:
 *   node scripts/generate_init_data_v3.js
 *   node scripts/generate_init_data_v3.js --proxy TProxy... --impl TImpl...
 */

const TronWeb = require('tronweb').TronWeb || require('tronweb');

const INITIALIZE_V3_SIGNATURE = 'initializeV3()';

function parseArgs() {
  const args = process.argv.slice(2);
  const params = { proxy: null, impl: null };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--proxy' && args[i + 1]) {
      params.proxy = args[i + 1];
      i++;
    } else if (args[i] === '--impl' && args[i + 1]) {
      params.impl = args[i + 1];
      i++;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Usage: node scripts/generate_init_data_v3.js [options]

Options:
  --proxy <address>   Proxy address (Base58), optional — only used to print the
                      exact upgradeAndCall invocation for the owner to execute
  --impl <address>    New StablecoinV3 implementation address (Base58), optional
  --help, -h          Show this help message
      `);
      process.exit(0);
    }
  }

  return params;
}

function generateInitDataV3() {
  // Minimal TronWeb instance — no network connection needed for sha3.
  const tronWeb = new TronWeb({ fullHost: 'https://api.trongrid.io' });

  const functionSelector = tronWeb.sha3(INITIALIZE_V3_SIGNATURE, false).slice(0, 8);

  return {
    functionSelector: '0x' + functionSelector,
    // No parameters, so initData === the selector.
    initData: '0x' + functionSelector
  };
}

function main() {
  console.log('\n🔧 Generate StablecoinV3 Upgrade Init Data\n');
  console.log('='.repeat(70));
  console.log('');

  const params = parseArgs();
  const result = generateInitDataV3();

  console.log('📦 Generated Data:');
  console.log(`   Function Signature: ${INITIALIZE_V3_SIGNATURE}`);
  console.log(`   Function Selector:  ${result.functionSelector}`);
  console.log('');
  console.log('✅ Init Data:');
  console.log(`   ${result.initData}`);
  console.log('');

  console.log('📝 Upgrade steps (executed by the ProxyAdmin owner, not by this script):');
  if (params.proxy && params.impl) {
    console.log('   ProxyAdmin.upgradeAndCall(');
    console.log(`     proxy          = ${params.proxy},`);
    console.log(`     implementation = ${params.impl},`);
    console.log(`     data           = ${result.initData}`);
    console.log('   )');
  } else {
    console.log('   ProxyAdmin.upgradeAndCall(');
    console.log('     proxy          = <existing proxy address>,');
    console.log('     implementation = <StablecoinV3 implementation address>,');
    console.log(`     data           = ${result.initData}`);
    console.log('   )');
    console.log('');
    console.log('   Pass --proxy and --impl to print the exact call.');
  }
  console.log('');
  console.log('   Then, once the CCIP BurnMintTokenPool is deployed for this chain:');
  console.log('     StablecoinV3(proxy).grantMintAndBurnRoles(POOL)');
  console.log('');
}

main();

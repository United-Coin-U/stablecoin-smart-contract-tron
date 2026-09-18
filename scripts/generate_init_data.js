/**
 * Generate Stablecoin initialization data (initData)
 * 
 * This script generates the initialization data for the Stablecoin contract
 * without deploying any contracts.
 * 
 * Usage:
 *   node scripts/generate_init_data.js
 *   
 *   Or with custom parameters:
 *   node scripts/generate_init_data.js --name "Token Name" --symbol "TKN" --owner "TAddress..."
 */

const TronWeb = require('tronweb').TronWeb || require('tronweb');

// Default values (same as in deployment script)
const DEFAULT_TOKEN_NAME = "United Stables";
const DEFAULT_TOKEN_SYMBOL = "U";

function parseArgs() {
  const args = process.argv.slice(2);
  const params = {
    tokenName: DEFAULT_TOKEN_NAME,
    tokenSymbol: DEFAULT_TOKEN_SYMBOL,
    ownerAddress: null
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--name' && args[i + 1]) {
      params.tokenName = args[i + 1];
      i++;
    } else if (args[i] === '--symbol' && args[i + 1]) {
      params.tokenSymbol = args[i + 1];
      i++;
    } else if (args[i] === '--owner' && args[i + 1]) {
      params.ownerAddress = args[i + 1];
      i++;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Usage: node scripts/generate_init_data.js [options]

Options:
  --name <string>     Token name (default: "${DEFAULT_TOKEN_NAME}")
  --symbol <string>   Token symbol (default: "${DEFAULT_TOKEN_SYMBOL}")
  --owner <address>   Owner address in Base58 format (required)
  --help, -h          Show this help message

Example:
  node scripts/generate_init_data.js --name "My Token" --symbol "MTK" --owner "TYourAddressHere..."
      `);
      process.exit(0);
    }
  }

  return params;
}

function generateInitData(tokenName, tokenSymbol, ownerAddressHex) {
  // Create a minimal TronWeb instance (no network connection needed)
  const tronWeb = new TronWeb({
    fullHost: 'https://api.trongrid.io' // Not actually used, just needed for initialization
  });

  // Generate function selector: initialize(string,string,address)
  const initializeSignature = 'initialize(string,string,address)';
  const functionSelector = tronWeb.sha3(initializeSignature, false).slice(0, 8);

  // Encode parameters
  const encodedParams = tronWeb.utils.abi.encodeParams(
    ['string', 'string', 'address'],
    [tokenName, tokenSymbol, ownerAddressHex]
  );

  // Combine function selector and encoded parameters
  const initData = '0x' + functionSelector + encodedParams.replace('0x', '');

  return {
    functionSelector: '0x' + functionSelector,
    encodedParams,
    initData
  };
}

async function main() {
  console.log('\n🔧 Generate Stablecoin Initialization Data\n');
  console.log('=' .repeat(70));
  console.log('');

  const params = parseArgs();

  // Validate owner address
  if (!params.ownerAddress) {
    console.error('❌ Error: Owner address is required.');
    console.error('   Use --owner <address> to specify the owner address.');
    console.error('   Use --help for more information.\n');
    process.exit(1);
  }

  // Create TronWeb instance for address conversion
  const tronWeb = new TronWeb({
    fullHost: 'https://api.trongrid.io'
  });

  // Validate and convert address
  let ownerAddressHex;
  try {
    if (params.ownerAddress.startsWith('T')) {
      // Base58 address
      ownerAddressHex = tronWeb.address.toHex(params.ownerAddress);
    } else if (params.ownerAddress.startsWith('41') || params.ownerAddress.startsWith('0x')) {
      // Already hex address
      ownerAddressHex = params.ownerAddress.startsWith('0x') 
        ? '41' + params.ownerAddress.slice(2)
        : params.ownerAddress;
    } else {
      throw new Error('Invalid address format');
    }
  } catch (error) {
    console.error('❌ Error: Invalid owner address format.');
    console.error('   Please provide a valid TRON address (Base58 starting with T).\n');
    process.exit(1);
  }

  const ownerBase58 = tronWeb.address.fromHex(ownerAddressHex);

  console.log('📋 Parameters:');
  console.log(`   Token Name:    ${params.tokenName}`);
  console.log(`   Token Symbol:  ${params.tokenSymbol}`);
  console.log(`   Owner Address: ${ownerBase58}`);
  console.log(`   Owner (Hex):   ${ownerAddressHex}`);
  console.log('');

  // Generate initData
  const result = generateInitData(params.tokenName, params.tokenSymbol, ownerAddressHex);

  console.log('📦 Generated Data:');
  console.log(`   Function Signature: initialize(string,string,address)`);
  console.log(`   Function Selector:  ${result.functionSelector}`);
  console.log('');
  console.log('✅ Init Data:');
  console.log('');
  console.log(result.initData);
  console.log('');
  console.log('=' .repeat(70));
  console.log('');

  return result.initData;
}

// Run if executed directly
main().catch(error => {
  console.error('❌ Error:', error.message);
  process.exit(1);
});

module.exports = { generateInitData };

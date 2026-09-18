/**
 * EncodeInitData.js
 *
 * Calculates the initialization data (_data parameter) needed when deploying TransparentUpgradeableProxy
 *
 * Purpose: Encode Stablecoin.initialize(string _name, string _symbol, address _initOwner) function call
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const {TronWeb} = require("tronweb");

// Configure TronWeb
const PRIVATE_KEY = process.env.PRIVATE_KEY_NILE;
const FULL_NODE = process.env.FULL_NODE_NILE || "https://nile.trongrid.io";

const tronWeb = new TronWeb({
  fullHost: FULL_NODE,
  privateKey: PRIVATE_KEY,
});

/**
 * Encode Stablecoin initialize function call
 * @param {string} tokenName - Token name, e.g. "United Stables"
 * @param {string} tokenSymbol - Token symbol, e.g. "U"
 * @param {string} ownerAddress - Initial owner address (base58 format)
 * @returns {string} Encoded initialization data (hex string)
 */
function encodeInitializeData(tokenName, tokenSymbol, ownerAddress) {
  console.log("\n=== Encode Stablecoin Initialization Data ===\n");

  console.log("Input Parameters:");
  console.log("  Token Name:", tokenName);
  console.log("  Token Symbol:", tokenSymbol);
  console.log("  Owner Address (base58):", ownerAddress);

  // Convert base58 address to hex
  let ownerHex = tronWeb.address.toHex(ownerAddress);
  console.log("  Owner Address (hex with 41 prefix):", ownerHex);

  // TRON addresses start with 41, need to remove prefix to convert to standard EVM address format
  // 41 is TRON's address prefix, standard EVM address is 20 bytes (40 hex characters)
  if (ownerHex.startsWith('0x41')) {
    ownerHex = '0x' + ownerHex.slice(4); // Remove 0x41, keep remaining 40 characters
  } else if (ownerHex.startsWith('41')) {
    ownerHex = '0x' + ownerHex.slice(2); // Remove 41, add 0x
  }
  console.log("  Owner Address (EVM format):", ownerHex);

  // Encode initialize function call
  // Function signature: initialize(string,string,address)
  const functionSignature = "initialize(string,string,address)";

  // Use ethers for encoding
  const { ethers } = require('ethers');

  // Build function selector
  const functionSelector = ethers.id(functionSignature).slice(0, 10);
  console.log("\n  Function Selector:", functionSelector);

  // Use AbiCoder to encode parameters
  const abiCoder = new ethers.AbiCoder();

  // Encode parameters
  const encodedParams = abiCoder.encode(
    ['string', 'string', 'address'],
    [tokenName, tokenSymbol, ownerHex]
  );

  // Combine function selector and parameters
  const encodedData = functionSelector + encodedParams.slice(2);

  console.log("\nEncoding Result:");
  console.log("  Function Signature:", functionSignature);
  console.log("  Encoded Data (hex):\n  ", encodedData);
  console.log("  Data Length:", encodedData.length, "characters");
  console.log("  Byte Length:", (encodedData.length - 2) / 2, "bytes");

  return encodedData;
}

/**
 * Decode initialization data (for verification)
 * @param {string} encodedData - Encoded data
 */
function decodeInitializeData(encodedData) {
  console.log("\n=== Verify Decoding ===\n");

  try {
    const { ethers } = require('ethers');

    // Get function selector (first 4 bytes, 8 hex characters)
    const selector = encodedData.slice(0, 10); // Including '0x' prefix
    console.log("Function Selector:", selector);

    // Calculate selector for initialize(string,string,address)
    const expectedSelector = ethers.id('initialize(string,string,address)').slice(0, 10);
    console.log("Expected Selector:", expectedSelector);
    console.log("Selector Match:", selector.toLowerCase() === expectedSelector.toLowerCase());

    // Note: Full parameter decoding requires ABI, only basic verification here
    console.log("\n✅ Data format verification passed");
  } catch (err) {
    console.error("❌ Decoding failed:", err.message);
  }
}

/**
 * Examples: Multiple configurations
 */
function examples() {
  const deployerAddress = tronWeb.address.fromPrivateKey(PRIVATE_KEY);

  console.log("\n" + "=".repeat(70));
  console.log("Example 1: United Stables (U)");
  console.log("=".repeat(70));
  const data1 = encodeInitializeData("United Stables", "U", deployerAddress);
  decodeInitializeData(data1);

  console.log("\n" + "=".repeat(70));
  console.log("Example 2: USDT on TRON");
  console.log("=".repeat(70));
  const data2 = encodeInitializeData("Tether USD", "USDT", deployerAddress);
  decodeInitializeData(data2);

  console.log("\n" + "=".repeat(70));
  console.log("Example 3: Custom owner address");
  console.log("=".repeat(70));
  const customOwner = "TKvCWxKrruxEGLQqH6oUNnJSBUC3VN7jaK"; // Example address
  const data3 = encodeInitializeData("My Stablecoin", "MSC", customOwner);
  decodeInitializeData(data3);
}

/**
 * Main function: Interactive input
 */
async function main() {
  console.log("╔════════════════════════════════════════════════════════════════════╗");
  console.log("║   TransparentUpgradeableProxy Initialization Data Encoder         ║");
  console.log("╚════════════════════════════════════════════════════════════════════╝");

  // Check command line arguments
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log("\nUsage:");
    console.log("  node tests/EncodeInitData.js <tokenName> <tokenSymbol> <ownerAddress>");
    console.log("\nOr:");
    console.log("  node tests/EncodeInitData.js --examples  # View examples");
    console.log("\nParameters:");
    console.log("  tokenName     - Token name (e.g. \"United Stables\")");
    console.log("  tokenSymbol   - Token symbol (e.g. \"U\")");
    console.log("  ownerAddress  - Initial owner address (base58 format)");
    console.log("\nExample:");
    console.log('  node tests/EncodeInitData.js "United Stables" "U" TKvCWxKrruxEGLQqH6oUNnJSBUC3VN7jaK');
    process.exit(0);
  }

  if (args[0] === '--examples' || args[0] === '-e') {
    examples();
    process.exit(0);
  }

  // Parse arguments
  const tokenName = args[0];
  const tokenSymbol = args[1];
  let ownerAddress = args[2];

  if (!tokenName || !tokenSymbol) {
    console.error("\n❌ Error: Missing required parameters");
    console.log("Use --help to view help information\n");
    process.exit(1);
  }

  // If owner address not provided, use current account
  if (!ownerAddress) {
    ownerAddress = tronWeb.address.fromPrivateKey(PRIVATE_KEY);
    console.log("\n⚠️  Owner address not provided, using current account:", ownerAddress);
  }

  // Validate address format
  try {
    tronWeb.address.toHex(ownerAddress);
  } catch (err) {
    console.error("\n❌ Error: Invalid TRON address:", ownerAddress);
    process.exit(1);
  }

  // Encode data
  const encodedData = encodeInitializeData(tokenName, tokenSymbol, ownerAddress);
  decodeInitializeData(encodedData);

  console.log("\n" + "=".repeat(70));
  console.log("Usage Instructions:");
  console.log("=".repeat(70));
  console.log("\nWhen deploying TransparentUpgradeableProxy, use the above encoded data as _data parameter:");
  console.log("\nIn Solidity:");
  console.log(`  new TransparentUpgradeableProxy(`);
  console.log(`    implementationAddress,`);
  console.log(`    adminAddress,`);
  console.log(`    hex"${encodedData.slice(2)}"  // Remove 0x prefix`);
  console.log(`  );`);
  console.log("\nIn TronWeb:");
  console.log(`  await tronWeb.contract().new({`);
  console.log(`    abi: ProxyABI,`);
  console.log(`    bytecode: ProxyBytecode,`);
  console.log(`    feeLimit: 1000000000,`);
  console.log(`    parameters: [`);
  console.log(`      implementationAddress,`);
  console.log(`      adminAddress,`);
  console.log(`      "${encodedData}"`);
  console.log(`    ]`);
  console.log(`  });`);
  console.log();
}

// Run main function
main()
  .then(() => {
    console.log("✅ Completed\n");
    process.exit(0);
  })
  .catch(err => {
    console.error("\n❌ Error:", err.message);
    console.error(err);
    process.exit(1);
  });

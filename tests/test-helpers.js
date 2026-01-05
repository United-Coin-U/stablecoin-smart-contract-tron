/**
 * Test Helpers - Common test helper functions
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const {TronWeb} = require("tronweb");
const fs = require('fs');
const path = require('path');

const StablecoinArtifact = require('../build/contracts/Stablecoin.json');

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  let network = 'nile'; // default network

  for (const arg of args) {
    if (arg.startsWith('--network=')) {
      network = arg.split('=')[1];
    }
  }

  return { network };
}

const { network } = parseArgs();

// Load network configuration
const tronboxConfig = require('../tronbox.js');
const networkConfig = tronboxConfig.networks[network];

if (!networkConfig) {
  console.error(`❌ Network '${network}' not found in tronbox.js`);
  console.error(`Available networks: ${Object.keys(tronboxConfig.networks).join(', ')}`);
  process.exit(1);
}

const PRIVATE_KEY = networkConfig.privateKey;
const FULL_NODE = networkConfig.fullHost;

if (!PRIVATE_KEY) {
  console.error(`❌ Private key not configured for network '${network}'`);
  process.exit(1);
}

const tronWeb = new TronWeb({
  fullHost: FULL_NODE,
  privateKey: PRIVATE_KEY,
  headers: { "TRON-PRO-API-KEY": process.env.TRONGRID_API_KEY || '' },
  timeout: 60000,
});

// Sleep function with network-specific optimization
async function sleep(ms) {
  const speedMultiplier = network === 'nile' ? 0.5 : 1;
  return new Promise(resolve => setTimeout(resolve, ms * speedMultiplier));
}

// Get contract instance
async function getContractInstance() {
  // Determine deployment file
  let deploymentPath = path.join(__dirname, `../deployments/${network}.json`);

  // Fallback to development.json if specific network deployment file doesn't exist
  if (!fs.existsSync(deploymentPath)) {
    deploymentPath = path.join(__dirname, '../deployments/development.json');
  }

  // Load deployment info
  let deployment;
  let proxyAddress;

  try {
    deployment = JSON.parse(fs.readFileSync(deploymentPath, 'utf8'));
    proxyAddress = deployment.proxy;
  } catch (err) {
    console.error("❌ Could not load deployment info.");
    console.error(`   Please run 'tronbox migrate --network=${network}' first.`);
    process.exit(1);
  }

  const deployerBase58 = tronWeb.address.fromPrivateKey(PRIVATE_KEY);
  const stablecoin = await tronWeb.contract(StablecoinArtifact.abi, proxyAddress);

  return {
    tronWeb,
    stablecoin,
    proxyAddress,
    deployerBase58,
    network,
    networkConfig
  };
}

// Test result tracking
class TestResults {
  constructor() {
    this.passed = 0;
    this.failed = 0;
    this.tests = [];
  }

  pass(testName) {
    this.passed++;
    this.tests.push({ name: testName, status: 'PASS' });
    console.log(`   ✅ ${testName} passed\n`);
  }

  fail(testName, error) {
    this.failed++;
    this.tests.push({ name: testName, status: 'FAIL', error: error.message });
    console.log(`   ❌ ${testName} failed: ${error.message}\n`);
  }

  summary() {
    console.log("\n" + "=".repeat(60));
    console.log("Test Summary");
    console.log("=".repeat(60));
    console.log(`Total: ${this.passed + this.failed}`);
    console.log(`✅ Passed: ${this.passed}`);
    console.log(`❌ Failed: ${this.failed}`);
    console.log("=".repeat(60) + "\n");

    if (this.failed > 0) {
      console.log("Failed tests:");
      this.tests.filter(t => t.status === 'FAIL').forEach(t => {
        console.log(`  - ${t.name}: ${t.error}`);
      });
      console.log();
    }

    return this.failed === 0;
  }
}

module.exports = {
  tronWeb,
  sleep,
  getContractInstance,
  network,
  networkConfig,
  StablecoinArtifact,
  TestResults,
  PRIVATE_KEY,
  FULL_NODE
};

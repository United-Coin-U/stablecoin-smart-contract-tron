/**
 * TestProxy.js
 *
 * Tests for ProxyAdmin and TransparentUpgradeableProxy
 *
 * Test Cases:
 * 1. Proxy deployment and initialization
 * 2. ProxyAdmin ownership
 * 3. Deploy StablecoinV2 implementation
 * 4. Get current implementation address
 * 5. Get proxy admin address
 * 6. Upgrade from V1 to V2 using upgrade()
 * 7. Verify V2 upgrade and data preservation
 * 8. Downgrade from V2 back to V1
 * 9. Test upgradeAndCall() method
 * 10. Cleanup - upgrade back to V1
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const {TronWeb} = require("tronweb");
const fs = require('fs');
const path = require('path');

const StablecoinArtifact = require('../build/contracts/Stablecoin.json');
const StablecoinV2Artifact = require('../build/contracts/StablecoinV2.json');
const ProxyAdminArtifact = require('../build/contracts/ProxyAdmin.json');
const ProxyArtifact = require('../build/contracts/TransparentUpgradeableProxy.json');

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

console.log(`Connecting to: ${FULL_NODE} (Network: ${network})`);

const tronWeb = new TronWeb({
  fullHost: FULL_NODE,
  privateKey: PRIVATE_KEY,
  headers: { "TRON-PRO-API-KEY": process.env.TRONGRID_API_KEY || '' },
  timeout: 60000,
});

// Determine deployment file based on network
let deploymentPath = path.join(__dirname, `../deployments/${network}.json`);

// Fallback to development.json if specific network deployment file doesn't exist
if (!fs.existsSync(deploymentPath)) {
  deploymentPath = path.join(__dirname, '../deployments/development.json');
}
let deployment;

try {
  deployment = JSON.parse(fs.readFileSync(deploymentPath, 'utf8'));
  console.log("✅ Loaded deployment info\n");
} catch (err) {
  console.error("❌ Could not load deployment info.");
  console.error(`   Please run 'tronbox migrate --network=${network}' first.`);
  process.exit(1);
}

const proxyAdminAddress = deployment.proxyAdmin;
let implementationV1Address = deployment.implementation;
const proxyAddress = deployment.proxy;

// For testing, we'll need to deploy V2 implementation
let implementationV2Address = null;

// We'll get the actual current implementation at runtime
let currentImplementationAddress = null;

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function deployStablecoinV2() {
  console.log("📦 Deploying StablecoinV2 implementation...");

  try {
    const StablecoinV2 = await tronWeb.contract().new({
      abi: StablecoinV2Artifact.abi,
      bytecode: StablecoinV2Artifact.bytecode,
      feeLimit: 1_000_000_000,
      callValue: 0,
      userFeePercentage: 100,
      shouldPollResponse: true
    });

    implementationV2Address = tronWeb.address.fromHex(StablecoinV2.address);
    console.log("   ✅ StablecoinV2 deployed at:", implementationV2Address);
    await sleep(3000);
    return implementationV2Address;
  } catch (err) {
    console.error("   ❌ Failed to deploy StablecoinV2:", err.message);
    throw err;
  }
}

async function main() {
  console.log("=== Proxy and ProxyAdmin Tests ===\n");

  const deployerBase58 = tronWeb.address.fromPrivateKey(PRIVATE_KEY);
  console.log("Deployer:", deployerBase58);
  console.log("Proxy:", proxyAddress);
  console.log("ProxyAdmin:", proxyAdminAddress);
  console.log("Implementation V1:", implementationV1Address);
  console.log();

  // Get contract instances
  const proxyAdmin = await tronWeb.contract(ProxyAdminArtifact.abi, proxyAdminAddress);

  // -----------------------------------------------------------
  // Test 1: Verify Proxy Deployment and Initialization
  // -----------------------------------------------------------
  console.log("📋 Test 1: Verify Proxy Deployment and Initialization");
  try {
    // Access proxy as Stablecoin
    const stablecoin = await tronWeb.contract(StablecoinArtifact.abi, proxyAddress);

    const name = await stablecoin.name().call();
    const symbol = await stablecoin.symbol().call();
    const ownerHex = await stablecoin.owner().call();
    const owner = tronWeb.address.fromHex(ownerHex);

    console.log("   Token Name:", name);
    console.log("   Token Symbol:", symbol);
    console.log("   Token Owner:", owner);

    if (name === "United Stables" && symbol === "U" && owner === deployerBase58) {
      console.log("   ✅ Proxy is correctly initialized\n");
    } else {
      console.log("   ⚠️  Unexpected initialization values\n");
    }
  } catch (err) {
    console.error("   ❌ Test 1 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 2: Verify ProxyAdmin Ownership
  // -----------------------------------------------------------
  console.log("📋 Test 2: Verify ProxyAdmin Ownership");
  try {
    const adminOwnerHex = await proxyAdmin.owner().call();
    const adminOwner = tronWeb.address.fromHex(adminOwnerHex);

    console.log("   ProxyAdmin Owner:", adminOwner);

    if (adminOwner === deployerBase58) {
      console.log("   ✅ ProxyAdmin owner is correct\n");
    } else {
      console.log("   ⚠️  ProxyAdmin owner mismatch\n");
    }
  } catch (err) {
    console.error("   ❌ Test 2 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 3: Deploy StablecoinV2
  // -----------------------------------------------------------
  console.log("📋 Test 3: Deploy StablecoinV2 Implementation");
  try {
    await deployStablecoinV2();
    console.log("   ✅ StablecoinV2 deployed successfully\n");
  } catch (err) {
    console.error("   ❌ Test 3 Failed:", err.message, "\n");
    console.log("   Skipping remaining upgrade tests\n");
    return;
  }

  // -----------------------------------------------------------
  // Test 4: Get Current Implementation Address
  // -----------------------------------------------------------
  console.log("📋 Test 4: Get Current Implementation Address (Before Upgrade)");
  try {
    // Call proxy.implementation() directly instead of through ProxyAdmin
    // because admin cannot call proxy functions due to transparent proxy pattern
    const proxy = await tronWeb.contract(ProxyArtifact.abi, proxyAddress);
    const implHex = await proxy.implementation().call();
    const implAddress = tronWeb.address.fromHex(implHex);

    // Save this as the current V1 implementation for later tests
    currentImplementationAddress = implAddress;
    implementationV1Address = implAddress;

    console.log("   Current Implementation:", implAddress);
    console.log("   Deployment file V1:", deployment.implementation);

    if (implAddress === deployment.implementation) {
      console.log("   ✅ Matches deployment file\n");
    } else {
      console.log("   ℹ️  Different from deployment file (proxy may have been redeployed)\n");
    }
  } catch (err) {
    console.error("   ❌ Test 4 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 5: Get Proxy Admin Address
  // -----------------------------------------------------------
  console.log("📋 Test 5: Get Proxy Admin Address");
  try {
    // Call proxy.admin() directly instead of through ProxyAdmin
    const proxy = await tronWeb.contract(ProxyArtifact.abi, proxyAddress);
    const adminHex = await proxy.admin().call();
    const adminAddress = tronWeb.address.fromHex(adminHex);

    console.log("   Proxy Admin:", adminAddress);
    console.log("   Expected:", proxyAdminAddress);

    if (adminAddress === proxyAdminAddress) {
      console.log("   ✅ Proxy admin is correct\n");
    } else {
      console.log("   ⚠️  Proxy admin mismatch\n");
    }
  } catch (err) {
    console.error("   ❌ Test 5 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 6: Upgrade Proxy to V2
  // -----------------------------------------------------------
  console.log("📋 Test 6: Upgrade Proxy from V1 to V2");
  try {
    console.log("   Upgrading to V2...");
    const upgradeTx = await proxyAdmin.upgrade(proxyAddress, implementationV2Address).send({
      feeLimit: 150_000_000,
      shouldPollResponse: true
    });

    console.log("   Upgrade transaction:", upgradeTx);
    await sleep(3000);

    console.log("   ✅ Upgrade transaction successful\n");
  } catch (err) {
    console.error("   ❌ Test 6 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 7: Verify V2 Upgrade
  // -----------------------------------------------------------
  console.log("📋 Test 7: Verify V2 Upgrade");
  try {
    const stablecoinV2 = await tronWeb.contract(StablecoinV2Artifact.abi, proxyAddress);

    // Check V2 specific function
    const version = await stablecoinV2.versionV2().call();
    console.log("   V2 Version:", version);

    // Verify old data is preserved
    const name = await stablecoinV2.name().call();
    const symbol = await stablecoinV2.symbol().call();
    const ownerHex = await stablecoinV2.owner().call();
    const owner = tronWeb.address.fromHex(ownerHex);
    console.log("   Name (preserved):", name);
    console.log("   Symbol (preserved):", symbol);

    // Verify implementation address changed
    const proxy1 = await tronWeb.contract(ProxyArtifact.abi, proxyAddress);
    const newImplHex = await proxy1.implementation().call();
    const newImplAddress = tronWeb.address.fromHex(newImplHex);
    console.log("   Current Implementation:", newImplAddress);

    if (version === "v2" && name === "United Stables" && owner === deployerBase58 && newImplAddress === implementationV2Address) {
      console.log("   ✅ Upgrade to V2 successful and data preserved\n");
    } else {
      console.log("   ⚠️  V2 verification incomplete\n");
    }
  } catch (err) {
    console.error("   ❌ Test 7 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 8: Downgrade Proxy from V2 to V1
  // -----------------------------------------------------------
  console.log("📋 Test 8: Downgrade Proxy from V2 to V1");
  try {
    console.log("   Downgrading to V1...");
    const downgradeTx = await proxyAdmin.upgrade(proxyAddress, implementationV1Address).send({
      feeLimit: 150_000_000,
      shouldPollResponse: true
    });

    console.log("   Downgrade transaction:", downgradeTx);
    await sleep(3000);

    // Verify we're back on V1
    const stablecoinV1 = await tronWeb.contract(StablecoinArtifact.abi, proxyAddress);
    const name = await stablecoinV1.name().call();

    // Verify implementation address changed back
    const proxy2 = await tronWeb.contract(ProxyArtifact.abi, proxyAddress);
    const implHex = await proxy2.implementation().call();
    const implAddress = tronWeb.address.fromHex(implHex);

    console.log("   Name after downgrade:", name);
    console.log("   Current Implementation:", implAddress);

    if (implAddress === implementationV1Address) {
      console.log("   ✅ Downgrade to V1 successful\n");
    } else {
      console.log("   ⚠️  Downgrade incomplete\n");
    }
  } catch (err) {
    console.error("   ❌ Test 8 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 9: Test upgradeAndCall() Method
  // -----------------------------------------------------------
  console.log("📋 Test 9: Test upgradeAndCall() Method");
  try {
    console.log("   Upgrading to V2 using upgradeAndCall...");

    // Prepare empty call data (can be used to call initialization function)
    const callData = "0x";

    const upgradeAndCallTx = await proxyAdmin.upgradeAndCall(
      proxyAddress,
      implementationV2Address,
      callData
    ).send({
      feeLimit: 200_000_000,
      shouldPollResponse: true
    });

    console.log("   UpgradeAndCall transaction:", upgradeAndCallTx);
    await sleep(3000);

    // Verify upgrade to V2
    const stablecoinV2 = await tronWeb.contract(StablecoinV2Artifact.abi, proxyAddress);
    const version = await stablecoinV2.versionV2().call();
    console.log("   V2 Version:", version);

    // Verify implementation address changed
    const proxy3 = await tronWeb.contract(ProxyArtifact.abi, proxyAddress);
    const newImplHex = await proxy3.implementation().call();
    const newImplAddress = tronWeb.address.fromHex(newImplHex);
    console.log("   New Implementation:", newImplAddress);
    console.log("   Expected (V2):", implementationV2Address);

    if (version === "v2" && newImplAddress === implementationV2Address) {
      console.log("   ✅ upgradeAndCall() successful\n");
    } else {
      console.log("   ⚠️  upgradeAndCall() verification incomplete\n");
    }
  } catch (err) {
    console.error("   ❌ Test 9 Failed:", err.message);
    console.log("   Note: upgradeAndCall may not be supported by current proxy implementation\n");
  }

  // -----------------------------------------------------------
  // Test 10: Cleanup - Upgrade back to V1
  // -----------------------------------------------------------
  console.log("📋 Test 10: Cleanup - Upgrade back to V1");
  try {
    console.log("   Upgrading back to V1...");
    const cleanupTx = await proxyAdmin.upgrade(proxyAddress, implementationV1Address).send({
      feeLimit: 150_000_000,
      shouldPollResponse: true
    });

    console.log("   Cleanup transaction:", cleanupTx);
    await sleep(3000);

    const proxy4 = await tronWeb.contract(ProxyArtifact.abi, proxyAddress);
    const finalImplHex = await proxy4.implementation().call();
    const finalImplAddress = tronWeb.address.fromHex(finalImplHex);
    console.log("   Final Implementation:", finalImplAddress);

    if (finalImplAddress === implementationV1Address) {
      console.log("   ✅ Cleanup successful\n");
    } else {
      console.log("   ⚠️  Cleanup incomplete\n");
    }
  } catch (err) {
    console.error("   ❌ Test 10 Failed:", err.message, "\n");
  }

  console.log("=== Proxy and ProxyAdmin Tests Completed ===\n");
}

main()
  .then(() => {
    console.log("✅ All proxy tests completed");
    process.exit(0);
  })
  .catch((err) => {
    console.error("❌ Test suite failed:", err);
    process.exit(1);
  });

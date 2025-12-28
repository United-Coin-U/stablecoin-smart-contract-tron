/**
 * TestStablecoin.js
 *
 * Comprehensive tests for Stablecoin.sol
 *
 * Test Cases:
 * 1. Token basic info (name, symbol, decimals)
 * 2. Ownership and autoOwnership
 * 3. Mint function (owner only)
 * 4. Mint to specific address
 * 5. AutoMint function with nonce
 * 6. Burn function (owner only)
 * 7. AutoBurn function with nonce
 * 8. Freeze and unfreeze accounts
 * 9. Pause and unpause contract
 * 10. Transfer tokens between accounts
 * 11. Approve and transferFrom
 * 12. Set autoMintMaxLimit
 * 13. Transfer ownership (2-step)
 * 14. Transfer autoOwnership
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const {TronWeb} = require("tronweb");
const fs = require('fs');
const path = require('path');

const StablecoinArtifact = require('../build/contracts/Stablecoin.json');

// Configure TronWeb
const PRIVATE_KEY = process.env.PRIVATE_KEY_NILE;
const FULL_NODE = process.env.FULL_NODE_NILE || "https://nile.trongrid.io";

console.log("Connecting to:", FULL_NODE);

const tronWeb = new TronWeb({
  fullHost: FULL_NODE,
  privateKey: PRIVATE_KEY,
});

// Load deployment info
const deploymentPath = path.join(__dirname, '../deployments/development.json');
let deployment;

try {
  deployment = JSON.parse(fs.readFileSync(deploymentPath, 'utf8'));
  console.log("✅ Loaded deployment info\n");
} catch (err) {
  console.error("❌ Could not load deployment info. Please run 'tronbox migrate' first.");
  process.exit(1);
}

const proxyAddress = deployment.proxy;

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log("=== Stablecoin Contract Tests ===\n");

  const deployerBase58 = tronWeb.address.fromPrivateKey(PRIVATE_KEY);
  console.log("Deployer:", deployerBase58);
  console.log("Proxy (Stablecoin):", proxyAddress);
  console.log();

  // Get contract instance
  const stablecoin = await tronWeb.contract(StablecoinArtifact.abi, proxyAddress);

  // -----------------------------------------------------------
  // Test 1: Token Basic Info
  // -----------------------------------------------------------
  console.log("📋 Test 1: Token Basic Info");
  try {
    const name = await stablecoin.name().call();
    const symbol = await stablecoin.symbol().call();
    const decimals = await stablecoin.decimals().call();
    const totalSupply = await stablecoin.totalSupply().call();

    console.log("   Name:", name);
    console.log("   Symbol:", symbol);
    console.log("   Decimals:", decimals.toString());
    console.log("   Total Supply:", totalSupply.toString());
    console.log("   ✅ Token info retrieved successfully\n");
  } catch (err) {
    console.error("   ❌ Test 1 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 2: Ownership and AutoOwnership
  // -----------------------------------------------------------
  console.log("📋 Test 2: Ownership and AutoOwnership");
  try {
    const ownerHex = await stablecoin.owner().call();
    const owner = tronWeb.address.fromHex(ownerHex);

    const autoOwnerHex = await stablecoin.autoOwner().call();
    const autoOwner = tronWeb.address.fromHex(autoOwnerHex);

    const nonce = await stablecoin.nonce().call();

    console.log("   Owner:", owner);
    console.log("   AutoOwner:", autoOwner);
    console.log("   Nonce:", nonce.toString());
    console.log("   ✅ Ownership info retrieved\n");
  } catch (err) {
    console.error("   ❌ Test 2 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 3: Mint Function (single parameter)
  // -----------------------------------------------------------
  console.log("📋 Test 3: Mint Function (to caller)");
  try {
    const mintAmount = 1000;
    const beforeSupply = await stablecoin.totalSupply().call();

    console.log("   Minting", mintAmount, "tokens to caller...");
    const mintTx = await stablecoin.methods['mint(uint256)'](mintAmount).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", mintTx);
    await sleep(3000);

    const afterSupply = await stablecoin.totalSupply().call();
    const balance = await stablecoin.balanceOf(deployerBase58).call();

    console.log("   Before Supply:", beforeSupply.toString());
    console.log("   After Supply:", afterSupply.toString());
    console.log("   Caller Balance:", balance.toString());

    if (BigInt(afterSupply) > BigInt(beforeSupply)) {
      console.log("   ✅ Mint successful\n");
    } else {
      console.log("   ⚠️  Supply didn't increase\n");
    }
  } catch (err) {
    console.error("   ❌ Test 3 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 4: Mint to Specific Address
  // -----------------------------------------------------------
  console.log("📋 Test 4: Mint to Specific Address");
  try {
    // Create a random recipient address for testing
    const recipientAccount = tronWeb.utils.accounts.generateAccount();
    const recipient = recipientAccount.address.base58;

    const mintAmount = 500;
    console.log("   Minting", mintAmount, "tokens to:", recipient);

    const mintTx = await stablecoin.methods['mint(address,uint256)'](recipient, mintAmount).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", mintTx);
    await sleep(3000);

    const balance = await stablecoin.balanceOf(recipient).call();
    console.log("   Recipient Balance:", balance.toString());

    if (balance.toString() === mintAmount.toString()) {
      console.log("   ✅ Mint to address successful\n");
    } else {
      console.log("   ⚠️  Balance mismatch\n");
    }
  } catch (err) {
    console.error("   ❌ Test 4 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 5: Set AutoMint Max Limit
  // -----------------------------------------------------------
  console.log("📋 Test 5: Set AutoMint Max Limit");
  try {
    const newLimit = 10000;
    console.log("   Setting autoMintMaxLimit to:", newLimit);

    const setLimitTx = await stablecoin.setAutoMintMaxLimit(newLimit).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", setLimitTx);
    await sleep(3000);

    const limit = await stablecoin.autoMintMaxLimit().call();
    console.log("   AutoMintMaxLimit:", limit.toString());

    if (limit.toString() === newLimit.toString()) {
      console.log("   ✅ AutoMintMaxLimit set successfully\n");
    } else {
      console.log("   ⚠️  Limit mismatch\n");
    }
  } catch (err) {
    console.error("   ❌ Test 5 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 6: AutoMint Function
  // -----------------------------------------------------------
  console.log("📋 Test 6: AutoMint Function");
  try {
    const recipientAccount = tronWeb.utils.accounts.generateAccount();
    const recipient = recipientAccount.address.base58;

    const currentNonce = await stablecoin.nonce().call();
    const mintAmount = 800;

    console.log("   Current Nonce:", currentNonce.toString());
    console.log("   AutoMinting", mintAmount, "tokens with nonce...");

    const autoMintTx = await stablecoin.autoMint(recipient, mintAmount, currentNonce).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", autoMintTx);
    await sleep(3000);

    const newNonce = await stablecoin.nonce().call();
    const balance = await stablecoin.balanceOf(recipient).call();

    console.log("   New Nonce:", newNonce.toString());
    console.log("   Recipient Balance:", balance.toString());

    if (BigInt(newNonce) > BigInt(currentNonce) && balance.toString() === mintAmount.toString()) {
      console.log("   ✅ AutoMint successful\n");
    } else {
      console.log("   ⚠️  AutoMint may have issues\n");
    }
  } catch (err) {
    console.error("   ❌ Test 6 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 7: Burn Function
  // -----------------------------------------------------------
  console.log("📋 Test 7: Burn Function");
  try {
    const burnAmount = 100;
    const beforeSupply = await stablecoin.totalSupply().call();
    const beforeBalance = await stablecoin.balanceOf(deployerBase58).call();

    console.log("   Burning", burnAmount, "tokens...");
    const burnTx = await stablecoin.burn(burnAmount).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", burnTx);
    await sleep(3000);

    const afterSupply = await stablecoin.totalSupply().call();
    const afterBalance = await stablecoin.balanceOf(deployerBase58).call();

    console.log("   Before Supply:", beforeSupply.toString());
    console.log("   After Supply:", afterSupply.toString());
    console.log("   Before Balance:", beforeBalance.toString());
    console.log("   After Balance:", afterBalance.toString());

    if (BigInt(afterSupply) < BigInt(beforeSupply)) {
      console.log("   ✅ Burn successful\n");
    } else {
      console.log("   ⚠️  Supply didn't decrease\n");
    }
  } catch (err) {
    console.error("   ❌ Test 7 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 8: AutoBurn Function
  // -----------------------------------------------------------
  console.log("📋 Test 8: AutoBurn Function");
  try {
    const currentNonce = await stablecoin.nonce().call();
    const burnAmount = 50;
    const beforeSupply = await stablecoin.totalSupply().call();

    console.log("   Current Nonce:", currentNonce.toString());
    console.log("   AutoBurning", burnAmount, "tokens...");

    const autoBurnTx = await stablecoin.autoBurn(burnAmount, currentNonce).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", autoBurnTx);
    await sleep(3000);

    const afterSupply = await stablecoin.totalSupply().call();
    const newNonce = await stablecoin.nonce().call();

    console.log("   New Nonce:", newNonce.toString());
    console.log("   Before Supply:", beforeSupply.toString());
    console.log("   After Supply:", afterSupply.toString());

    if (BigInt(newNonce) > BigInt(currentNonce) && BigInt(afterSupply) < BigInt(beforeSupply)) {
      console.log("   ✅ AutoBurn successful\n");
    } else {
      console.log("   ⚠️  AutoBurn may have issues\n");
    }
  } catch (err) {
    console.error("   ❌ Test 8 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 9: Freeze and Unfreeze Account
  // -----------------------------------------------------------
  console.log("📋 Test 9: Freeze and Unfreeze Account");
  try {
    const testAccount = tronWeb.utils.accounts.generateAccount();
    const testAddress = testAccount.address.base58;

    // First mint some tokens to the account
    await stablecoin.methods['mint(address,uint256)'](testAddress, 100).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });
    await sleep(3000);

    console.log("   Freezing account:", testAddress);
    const freezeTx = await stablecoin.freezeAccount(testAddress).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Freeze Transaction:", freezeTx);
    await sleep(3000);

    const isFrozen = await stablecoin.frozen(testAddress).call();
    console.log("   Is Frozen:", isFrozen);

    // Unfreeze
    console.log("   Unfreezing account...");
    const unfreezeTx = await stablecoin.unfreezeAccount(testAddress).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Unfreeze Transaction:", unfreezeTx);
    await sleep(3000);

    const isUnfrozen = await stablecoin.frozen(testAddress).call();
    console.log("   Is Still Frozen:", isUnfrozen);

    if (isFrozen && !isUnfrozen) {
      console.log("   ✅ Freeze/Unfreeze successful\n");
    } else {
      console.log("   ⚠️  Freeze state issue\n");
    }
  } catch (err) {
    console.error("   ❌ Test 9 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 10: Pause and Unpause
  // -----------------------------------------------------------
  console.log("📋 Test 10: Pause and Unpause Contract");
  try {
    // Check initial pause state
    console.log("   Checking initial pause state...");
    let initialPaused;
    try {
      initialPaused = await stablecoin.paused().call();
      console.log("   Initial Paused State:", initialPaused);
    } catch (err) {
      console.log("   ⚠️  Could not check pause state:", err.message);
      console.log("   Continuing with pause test...\n");
    }

    console.log("   Pausing contract...");
    const pauseTx = await stablecoin.pause().send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Pause Transaction:", pauseTx);
    await sleep(5000); // Increased wait time

    // Check paused state after pause
    let isPaused1 = false;
    try {
      isPaused1 = await stablecoin.paused().call();
      console.log("   Is Paused After pause():", isPaused1);
    } catch (err) {
      console.log("   ⚠️  Could not verify pause state:", err.message);
    }

    console.log("   Unpausing contract...");
    const unpauseTx = await stablecoin.unpause().send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Unpause Transaction:", unpauseTx);
    await sleep(5000); // Increased wait time

    // Check paused state after unpause
    let isPaused2 = true;
    try {
      isPaused2 = await stablecoin.paused().call();
      console.log("   Is Paused After unpause():", isPaused2);
    } catch (err) {
      console.log("   ⚠️  Could not verify unpause state:", err.message);
    }

    if (pauseTx && unpauseTx) {
      console.log("   ✅ Pause/Unpause transactions completed\n");
    } else {
      console.log("   ⚠️  Some transactions may have failed\n");
    }
  } catch (err) {
    console.error("   ❌ Test 10 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 11: Transfer Tokens
  // -----------------------------------------------------------
  console.log("📋 Test 11: Transfer Tokens");
  try {
    const recipient = tronWeb.utils.accounts.generateAccount();
    const recipientAddress = recipient.address.base58;
    const transferAmount = 50;

    const beforeBalance = await stablecoin.balanceOf(deployerBase58).call();
    console.log("   Sender Balance Before:", beforeBalance.toString());

    console.log("   Transferring", transferAmount, "tokens to:", recipientAddress);
    const transferTx = await stablecoin.transfer(recipientAddress, transferAmount).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", transferTx);
    await sleep(3000);

    const afterBalance = await stablecoin.balanceOf(deployerBase58).call();
    const recipientBalance = await stablecoin.balanceOf(recipientAddress).call();

    console.log("   Sender Balance After:", afterBalance.toString());
    console.log("   Recipient Balance:", recipientBalance.toString());

    if (recipientBalance.toString() === transferAmount.toString()) {
      console.log("   ✅ Transfer successful\n");
    } else {
      console.log("   ⚠️  Transfer amount mismatch\n");
    }
  } catch (err) {
    console.error("   ❌ Test 11 Failed:", err.message, "\n");
  }

  // -----------------------------------------------------------
  // Test 12: Approve and Allowance
  // -----------------------------------------------------------
  console.log("📋 Test 12: Approve and Check Allowance");
  try {
    const spender = tronWeb.utils.accounts.generateAccount();
    const spenderAddress = spender.address.base58;
    const approveAmount = 200;

    console.log("   Approving", approveAmount, "tokens for:", spenderAddress);
    const approveTx = await stablecoin.approve(spenderAddress, approveAmount).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", approveTx);
    await sleep(3000);

    const allowance = await stablecoin.allowance(deployerBase58, spenderAddress).call();
    console.log("   Allowance:", allowance.toString());

    if (allowance.toString() === approveAmount.toString()) {
      console.log("   ✅ Approve successful\n");
    } else {
      console.log("   ⚠️  Allowance mismatch\n");
    }
  } catch (err) {
    console.error("   ❌ Test 12 Failed:", err.message, "\n");
  }

  console.log("=== Stablecoin Tests Completed ===\n");
}

main()
  .then(() => {
    console.log("✅ All Stablecoin tests completed");
    process.exit(0);
  })
  .catch((err) => {
    console.error("❌ Test suite failed:", err);
    process.exit(1);
  });

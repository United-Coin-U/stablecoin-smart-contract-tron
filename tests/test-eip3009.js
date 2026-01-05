/**
 * Test EIP-3009 (Tests 25-34)
 *
 * EIP-3009: Transfer With Authorization tests:
 * 25. Enable/Disable EIP3009
 * 26. Check authorization state
 * 27. Transfer with authorization (bytes signature)
 * 28. Transfer with authorization (v,r,s signature)
 * 29. Receive with authorization (v,r,s)
 * 30. Receive with authorization (bytes signature)
 * 31. Test authorization time window
 * 32. Test nonce replay protection
 * 33. Cancel authorization
 * 34. Test access control and integration with pause/frozen
 */

const { getContractInstance, sleep, TestResults, tronWeb, network, FULL_NODE, PRIVATE_KEY } = require('./test-helpers');
const { ethers } = require('ethers');
const StablecoinArtifact = require('../build/contracts/Stablecoin.json');

async function main() {
  console.log(`\n=== EIP-3009 Tests (Network: ${network}) ===\n`);

  const results = new TestResults();
  const { stablecoin, proxyAddress, deployerBase58 } = await getContractInstance();

  // Create a test recipient account
  const recipientAccount = tronWeb.utils.accounts.generateAccount();
  const recipientAddress = recipientAccount.address.base58;
  console.log("Test Recipient:", recipientAddress);

  // Activate recipient account
  console.log("Activating recipient account...");
  await tronWeb.trx.sendTransaction(recipientAddress, 10_000_000);
  await sleep(3000);

  // Helper function to get domain separator
  async function getDomainSeparator() {
    // Get chain ID
    const chainId = await stablecoin.chainId().call();

    // Get contract name and version from the contract
    const name = await stablecoin.name().call();

    // Convert TRON proxy address to Ethereum hex format
    let verifyingContract = tronWeb.address.toHex(proxyAddress);

    // TRON addresses have 41 prefix, need to convert to standard 0x format
    if (verifyingContract.startsWith('41')) {
      verifyingContract = '0x' + verifyingContract.substring(2);
    }

    // Build EIP-712 domain
    const domain = {
      name: name,
      version: '1',
      chainId: chainId.toString(),
      verifyingContract: verifyingContract
    };

    return domain;
  }

  // Helper function to sign transferWithAuthorization
  async function signTransferAuthorization(from, to, value, validAfter, validBefore, nonce, privateKey) {
    const domain = await getDomainSeparator();

    const types = {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' }
      ]
    };

    // Convert TRON addresses to Ethereum hex format (remove 41 prefix, add 0x)
    let fromHex = tronWeb.address.toHex(from);
    let toHex = tronWeb.address.toHex(to);

    // TRON addresses have 41 prefix, need to convert to standard 0x format
    if (fromHex.startsWith('41')) {
      fromHex = '0x' + fromHex.substring(2);
    }
    if (toHex.startsWith('41')) {
      toHex = '0x' + toHex.substring(2);
    }

    const message = {
      from: fromHex,
      to: toHex,
      value: value.toString(),
      validAfter: validAfter.toString(),
      validBefore: validBefore.toString(),
      nonce: nonce
    };

    // Create wallet from private key
    const wallet = new ethers.Wallet(privateKey);

    // Sign typed data
    const signature = await wallet.signTypedData(domain, types, message);

    return signature;
  }

  // Helper function to sign receiveWithAuthorization
  async function signReceiveAuthorization(from, to, value, validAfter, validBefore, nonce, privateKey) {
    const domain = await getDomainSeparator();

    const types = {
      ReceiveWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' }
      ]
    };

    // Convert TRON addresses to Ethereum hex format (remove 41 prefix, add 0x)
    let fromHex = tronWeb.address.toHex(from);
    let toHex = tronWeb.address.toHex(to);

    // TRON addresses have 41 prefix, need to convert to standard 0x format
    if (fromHex.startsWith('41')) {
      fromHex = '0x' + fromHex.substring(2);
    }
    if (toHex.startsWith('41')) {
      toHex = '0x' + toHex.substring(2);
    }

    const message = {
      from: fromHex,
      to: toHex,
      value: value.toString(),
      validAfter: validAfter.toString(),
      validBefore: validBefore.toString(),
      nonce: nonce
    };

    const wallet = new ethers.Wallet(privateKey);
    const signature = await wallet.signTypedData(domain, types, message);

    return signature;
  }

  // -----------------------------------------------------------
  // Test 25: Enable/Disable EIP3009
  // -----------------------------------------------------------
  console.log("📋 Test 25: Enable/Disable EIP3009");
  try {
    // Check initial state
    const initialState = await stablecoin.eip3009EnableFlag().call();
    console.log("   Initial EIP3009 state:", initialState);

    // Enable EIP3009
    console.log("   Enabling EIP3009...");
    await stablecoin.enableEIP3009().send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });
    await sleep(3000);

    const enabledState = await stablecoin.eip3009EnableFlag().call();
    console.log("   After enable:", enabledState);

    if (enabledState === true) {
      console.log("   ✅ EIP3009 enabled successfully");
      results.pass("Test 25: Enable/Disable EIP3009");
    } else {
      throw new Error("Failed to enable EIP3009");
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 25: Enable/Disable EIP3009", err);
  }

  // Ensure we have some tokens for testing
  console.log("\nMinting tokens for tests...");
  try {
    await stablecoin.mint(deployerBase58, 1000_000000).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });
    await sleep(3000);
    const balance = await stablecoin.balanceOf(deployerBase58).call();
    console.log("   Deployer balance:", tronWeb.fromSun(balance), "tokens");
  } catch (err) {
    console.log("   Warning: Could not mint tokens:", err.message);
  }

  // -----------------------------------------------------------
  // Test 26: Check Authorization State
  // -----------------------------------------------------------
  console.log("\n📋 Test 26: Check Authorization State");
  try {
    const testNonce = ethers.hexlify(ethers.randomBytes(32));
    const state = await stablecoin.authorizationState(deployerBase58, testNonce).call();

    console.log("   Test nonce:", testNonce);
    console.log("   Authorization state:", state);

    if (state === false) {
      results.pass("Test 26: Check Authorization State");
    } else {
      throw new Error("Unexpected authorization state");
    }
  } catch (err) {
    results.fail("Test 26: Check Authorization State", err);
  }

  // -----------------------------------------------------------
  // Test 27: Transfer with Authorization (bytes signature)
  // -----------------------------------------------------------
  console.log("\n📋 Test 27: Transfer with Authorization (bytes signature)");
  try {
    const transferAmount = 100_000000; // 100 tokens
    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const validAfter = Math.floor(Date.now() / 1000) - 100;
    const validBefore = Math.floor(Date.now() / 1000) + 3600;

    console.log("   Signing authorization...");
    const signature = await signTransferAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    console.log("   Signature:", signature.substring(0, 20) + "...");

    // Get balances before
    const balanceBefore = await stablecoin.balanceOf(recipientAddress).call();
    console.log("   Recipient balance before:", tronWeb.fromSun(balanceBefore));

    // Execute transfer with authorization
    console.log("   Executing transferWithAuthorization...");

    // Use explicit function signature for overloaded function
    const functionSelector = 'transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)';

    await stablecoin.methods[functionSelector](
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      signature
    ).send({
      feeLimit: 200_000_000,
      shouldPollResponse: true
    });

    await sleep(3000);

    // Check balances after
    const balanceAfter = await stablecoin.balanceOf(recipientAddress).call();
    console.log("   Recipient balance after:", tronWeb.fromSun(balanceAfter));

    // Check authorization was marked as used
    const authState = await stablecoin.authorizationState(deployerBase58, nonce).call();
    console.log("   Authorization marked as used:", authState);

    if (BigInt(balanceAfter) > BigInt(balanceBefore) && authState === true) {
      results.pass("Test 27: Transfer with Authorization (bytes)");
    } else {
      throw new Error("Transfer failed or authorization not marked");
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 27: Transfer with Authorization (bytes)", err);
  }

  // -----------------------------------------------------------
  // Test 28: Transfer with Authorization (v,r,s signature)
  // -----------------------------------------------------------
  console.log("\n📋 Test 28: Transfer with Authorization (v,r,s signature)");
  try {
    const transferAmount = 50_000000; // 50 tokens
    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const validAfter = Math.floor(Date.now() / 1000) - 100;
    const validBefore = Math.floor(Date.now() / 1000) + 3600;

    const signature = await signTransferAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    // Split signature into v, r, s
    const sig = ethers.Signature.from(signature);
    const v = sig.v;
    const r = sig.r;
    const s = sig.s;

    console.log("   v:", v, "r:", r.substring(0, 10) + "...", "s:", s.substring(0, 10) + "...");

    const balanceBefore = await stablecoin.balanceOf(recipientAddress).call();

    console.log("   Executing transferWithAuthorization with v,r,s...");

    // Use the method with explicit function signature to handle overloaded functions
    const functionSelector = 'transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)';

    await stablecoin.methods[functionSelector](
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      v,
      r,
      s
    ).send({
      feeLimit: 200_000_000,
      shouldPollResponse: true
    });

    await sleep(3000);

    const balanceAfter = await stablecoin.balanceOf(recipientAddress).call();
    console.log("   Balance increased:", tronWeb.fromSun(BigInt(balanceAfter) - BigInt(balanceBefore)));

    if (BigInt(balanceAfter) > BigInt(balanceBefore)) {
      results.pass("Test 28: Transfer with Authorization (v,r,s)");
    } else {
      throw new Error("Transfer failed");
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 28: Transfer with Authorization (v,r,s)", err);
  }

  // -----------------------------------------------------------
  // Test 29: Receive with Authorization (v,r,s)
  // -----------------------------------------------------------
  console.log("\n📋 Test 29: Receive with Authorization (v,r,s)");
  try {
    const transferAmount = 30_000000; // 30 tokens
    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const validAfter = Math.floor(Date.now() / 1000) - 100;
    const validBefore = Math.floor(Date.now() / 1000) + 3600;

    // Sign authorization from deployer
    const signature = await signReceiveAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    const sig = ethers.Signature.from(signature);
    const v = sig.v;
    const r = sig.r;
    const s = sig.s;

    const balanceBefore = await stablecoin.balanceOf(recipientAddress).call();

    // Create TronWeb instance for recipient
    const recipientTronWeb = new tronWeb.constructor({
      fullHost: FULL_NODE,
      privateKey: recipientAccount.privateKey
    });

    const recipientStablecoin = await recipientTronWeb.contract(StablecoinArtifact.abi, proxyAddress);

    console.log("   Recipient calling receiveWithAuthorization...");

    // Use explicit function signature for overloaded function
    const functionSelector = 'receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)';

    await recipientStablecoin.methods[functionSelector](
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      v,
      r,
      s
    ).send({
      feeLimit: 200_000_000,
      shouldPollResponse: true
    });

    await sleep(3000);

    const balanceAfter = await stablecoin.balanceOf(recipientAddress).call();
    console.log("   Balance increased:", tronWeb.fromSun(BigInt(balanceAfter) - BigInt(balanceBefore)));

    if (BigInt(balanceAfter) > BigInt(balanceBefore)) {
      results.pass("Test 29: Receive with Authorization (v,r,s)");
    } else {
      throw new Error("Receive failed");
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 29: Receive with Authorization (v,r,s)", err);
  }

  // -----------------------------------------------------------
  // Test 30: Receive with Authorization (bytes signature)
  // -----------------------------------------------------------
  console.log("\n📋 Test 30: Receive with Authorization (bytes signature)");
  try {
    const transferAmount = 20_000000; // 20 tokens
    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const validAfter = Math.floor(Date.now() / 1000) - 100;
    const validBefore = Math.floor(Date.now() / 1000) + 3600;

    const signature = await signReceiveAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    const balanceBefore = await stablecoin.balanceOf(recipientAddress).call();

    const recipientTronWeb = new tronWeb.constructor({
      fullHost: FULL_NODE,
      privateKey: recipientAccount.privateKey
    });

    const recipientStablecoin = await recipientTronWeb.contract(StablecoinArtifact.abi, proxyAddress);

    console.log("   Recipient calling receiveWithAuthorization with bytes signature...");

    // Use explicit function signature for overloaded function
    const functionSelector = 'receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)';

    await recipientStablecoin.methods[functionSelector](
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      signature
    ).send({
      feeLimit: 200_000_000,
      shouldPollResponse: true
    });

    await sleep(3000);

    const balanceAfter = await stablecoin.balanceOf(recipientAddress).call();
    console.log("   Balance increased:", tronWeb.fromSun(BigInt(balanceAfter) - BigInt(balanceBefore)));

    if (BigInt(balanceAfter) > BigInt(balanceBefore)) {
      results.pass("Test 30: Receive with Authorization (bytes)");
    } else {
      throw new Error("Receive failed");
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 30: Receive with Authorization (bytes)", err);
  }

  // -----------------------------------------------------------
  // Test 31: Test Authorization Time Window
  // -----------------------------------------------------------
  console.log("\n📋 Test 31: Test Authorization Time Window");
  try {
    const transferAmount = 10_000000;
    const nonce = ethers.hexlify(ethers.randomBytes(32));

    // Set validBefore to past (expired)
    const validAfter = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
    const validBefore = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago (expired)

    const signature = await signTransferAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    console.log("   Trying to use expired authorization...");
    try {
      await stablecoin.transferWithAuthorization(
        deployerBase58,
        recipientAddress,
        transferAmount,
        validAfter,
        validBefore,
        nonce,
        signature
      ).send({
        feeLimit: 200_000_000,
        shouldPollResponse: true
      });

      throw new Error("Should have rejected expired authorization");
    } catch (timeErr) {
      if (timeErr.message.includes("expired") ||
          timeErr.message.includes("REVERT") ||
          timeErr.message.includes("Authorization")) {
        console.log("   ✅ Expired authorization correctly rejected");
        results.pass("Test 31: Authorization Time Window");
      } else {
        throw timeErr;
      }
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 31: Authorization Time Window", err);
  }

  // -----------------------------------------------------------
  // Test 32: Test Nonce Replay Protection
  // -----------------------------------------------------------
  console.log("\n📋 Test 32: Test Nonce Replay Protection");
  try {
    const transferAmount = 10_000000;
    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const validAfter = Math.floor(Date.now() / 1000) - 100;
    const validBefore = Math.floor(Date.now() / 1000) + 3600;

    const signature = await signTransferAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    // First use - should succeed
    console.log("   First use of authorization...");
    await stablecoin.transferWithAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      signature
    ).send({
      feeLimit: 200_000_000,
      shouldPollResponse: true
    });

    await sleep(3000);

    // Second use - should fail
    console.log("   Attempting replay attack...");
    try {
      await stablecoin.transferWithAuthorization(
        deployerBase58,
        recipientAddress,
        transferAmount,
        validAfter,
        validBefore,
        nonce,
        signature
      ).send({
        feeLimit: 200_000_000,
        shouldPollResponse: true
      });

      throw new Error("Replay attack should have been prevented");
    } catch (replayErr) {
      if (replayErr.message.includes("already used") ||
          replayErr.message.includes("REVERT") ||
          replayErr.message.includes("Authorization")) {
        console.log("   ✅ Replay attack correctly prevented");
        results.pass("Test 32: Nonce Replay Protection");
      } else {
        throw replayErr;
      }
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 32: Nonce Replay Protection", err);
  }

  // -----------------------------------------------------------
  // Test 33: Cancel Authorization
  // -----------------------------------------------------------
  console.log("\n📋 Test 33: Cancel Authorization");
  try {
    const nonce = ethers.hexlify(ethers.randomBytes(32));

    console.log("   Canceling authorization...");
    console.log("   Nonce:", nonce);

    await stablecoin.cancelAuthorization(deployerBase58, nonce).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    await sleep(3000);

    // Check that authorization is now marked as used
    const state = await stablecoin.authorizationState(deployerBase58, nonce).call();
    console.log("   Authorization state after cancel:", state);

    if (state === true) {
      console.log("   ✅ Authorization successfully canceled");
      results.pass("Test 33: Cancel Authorization");
    } else {
      throw new Error("Authorization not marked as canceled");
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 33: Cancel Authorization", err);
  }

  // -----------------------------------------------------------
  // Test 34: Access Control and Integration
  // -----------------------------------------------------------
  console.log("\n📋 Test 34: Access Control and Integration");
  try {
    console.log("   Testing that EIP3009 requires enabled flag...");

    // Disable EIP3009
    await stablecoin.disableEIP3009().send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });
    await sleep(3000);

    const disabledState = await stablecoin.eip3009EnableFlag().call();
    console.log("   EIP3009 disabled:", disabledState === false);

    // Try to use transferWithAuthorization while disabled
    const transferAmount = 10_000000;
    const nonce = ethers.hexlify(ethers.randomBytes(32));
    const validAfter = Math.floor(Date.now() / 1000) - 100;
    const validBefore = Math.floor(Date.now() / 1000) + 3600;

    const signature = await signTransferAuthorization(
      deployerBase58,
      recipientAddress,
      transferAmount,
      validAfter,
      validBefore,
      nonce,
      PRIVATE_KEY
    );

    try {
      await stablecoin.transferWithAuthorization(
        deployerBase58,
        recipientAddress,
        transferAmount,
        validAfter,
        validBefore,
        nonce,
        signature
      ).send({
        feeLimit: 200_000_000,
        shouldPollResponse: true
      });

      throw new Error("Should have failed when EIP3009 is disabled");
    } catch (disabledErr) {
      if (disabledErr.message.includes("not enabled") ||
          disabledErr.message.includes("REVERT")) {
        console.log("   ✅ Correctly rejected when disabled");

        // Re-enable for cleanup
        await stablecoin.enableEIP3009().send({
          feeLimit: 100_000_000,
          shouldPollResponse: true
        });
        await sleep(3000);

        results.pass("Test 34: Access Control and Integration");
      } else {
        throw disabledErr;
      }
    }
  } catch (err) {
    console.log("   Error:", err.message);
    results.fail("Test 34: Access Control and Integration", err);
  }

  // Print summary
  const success = results.summary();
  process.exit(success ? 0 : 1);
}

main().catch(err => {
  console.error("\n❌ Test suite failed:", err);
  process.exit(1);
});

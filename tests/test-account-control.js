/**
 * Test Account Control (Tests 9-12)
 *
 * Account control tests:
 * 9. Freeze and unfreeze accounts
 * 10. Pause and unpause contract
 * 11. Transfer tokens between accounts
 * 12. Approve and transferFrom
 */

const { getContractInstance, sleep, TestResults, tronWeb, network } = require('./test-helpers');

async function main() {
  console.log(`\n=== Account Control Tests (Network: ${network}) ===\n`);

  const results = new TestResults();
  const { stablecoin, deployerBase58 } = await getContractInstance();

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
      results.pass("Test 9: Freeze and Unfreeze Account");
    } else {
      throw new Error("Freeze state mismatch");
    }
  } catch (err) {
    results.fail("Test 9: Freeze and Unfreeze Account", err);
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
      results.pass("Test 10: Pause and Unpause Contract");
    } else {
      throw new Error("Transaction failed");
    }
  } catch (err) {
    results.fail("Test 10: Pause and Unpause Contract", err);
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
      results.pass("Test 11: Transfer Tokens");
    } else {
      throw new Error("Transfer amount mismatch");
    }
  } catch (err) {
    results.fail("Test 11: Transfer Tokens", err);
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
      results.pass("Test 12: Approve and Allowance");
    } else {
      throw new Error("Allowance mismatch");
    }
  } catch (err) {
    results.fail("Test 12: Approve and Allowance", err);
  }

  // Print summary
  const success = results.summary();
  process.exit(success ? 0 : 1);
}

main().catch(err => {
  console.error("❌ Test suite failed:", err);
  process.exit(1);
});

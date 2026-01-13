/**
 * Test Mint Functions - Mint function tests
 *
 * Tests:
 * - Mint to caller
 * - Mint to specific address
 * - Set autoMintMaxLimit
 * - AutoMint with nonce and chainId
 */

const { getContractInstance, sleep, TestResults, tronWeb, network } = require('./test-helpers');

async function main() {
  console.log(`\n🪙 Mint Function Tests (Network: ${network})\n`);
  console.log("=".repeat(60) + "\n");

  const results = new TestResults();
  const { stablecoin, deployerBase58 } = await getContractInstance();

  // Test 1: Mint to Caller
  console.log("Test 1: Mint to Caller");
  try {
    const mintAmount = 1000;
    const beforeSupply = await stablecoin.totalSupply().call();

    console.log(`   Minting ${mintAmount} tokens to caller...`);
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
      results.pass("Mint to Caller");
    } else {
      throw new Error("Supply didn't increase");
    }
  } catch (err) {
    results.fail("Mint to Caller", err);
  }

  // Test 2: Mint to Specific Address
  console.log("Test 2: Mint to Specific Address");
  try {
    const recipientAccount = tronWeb.utils.accounts.generateAccount();
    const recipient = recipientAccount.address.base58;
    const mintAmount = 500;

    console.log(`   Minting ${mintAmount} tokens to:`, recipient);
    const mintTx = await stablecoin.methods['mint(address,uint256)'](recipient, mintAmount).send({
      feeLimit: 100_000_000,
      shouldPollResponse: true
    });

    console.log("   Transaction:", mintTx);
    await sleep(3000);

    const balance = await stablecoin.balanceOf(recipient).call();
    console.log("   Recipient Balance:", balance.toString());

    if (balance.toString() === mintAmount.toString()) {
      results.pass("Mint to Specific Address");
    } else {
      throw new Error("Balance mismatch");
    }
  } catch (err) {
    results.fail("Mint to Specific Address", err);
  }

  // Test 3: Set AutoMint Max Limit
  console.log("Test 3: Set AutoMint Max Limit");
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
      results.pass("Set AutoMint Max Limit");
    } else {
      throw new Error("Limit mismatch");
    }
  } catch (err) {
    results.fail("Set AutoMint Max Limit", err);
  }

  // Test 4: AutoMint Function
  console.log("Test 4: AutoMint Function");
  try {
    const recipientAccount = tronWeb.utils.accounts.generateAccount();
    const recipient = recipientAccount.address.base58;

    const currentNonce = await stablecoin.nonce().call();
    const currentChainId = await stablecoin.chainId().call();
    const mintAmount = 800;

    console.log("   Current Nonce:", currentNonce.toString());
    console.log("   Current ChainID:", currentChainId.toString());
    console.log(`   AutoMinting ${mintAmount} tokens...`);

    const autoMintTx = await stablecoin.autoMint(recipient, mintAmount, currentNonce, currentChainId).send({
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
      results.pass("AutoMint Function");
    } else {
      throw new Error("AutoMint validation failed");
    }
  } catch (err) {
    results.fail("AutoMint Function", err);
  }

  // Print summary
  const success = results.summary();
  process.exit(success ? 0 : 1);
}

main().catch(err => {
  console.error("❌ Test suite failed:", err);
  process.exit(1);
});

/**
 * Test Basic Functions (Tests 1-8)
 *
 * Basic function tests:
 * 1. Token basic info (name, symbol, decimals)
 * 2. Ownership and autoOwnership
 * 3. Mint function (owner only)
 * 4. Mint to specific address
 * 5. Set autoMintMaxLimit
 * 6. AutoMint function with nonce and chainId
 * 7. Burn function (owner only)
 * 8. AutoBurn function with nonce and chainId
 */

const { getContractInstance, sleep, TestResults, tronWeb, network } = require('./test-helpers');

async function main() {
  console.log(`\n=== Basic Functions Tests (Network: ${network}) ===\n`);

  const results = new TestResults();
  const { stablecoin, deployerBase58 } = await getContractInstance();

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
    results.pass("Test 1: Token Basic Info");
  } catch (err) {
    results.fail("Test 1: Token Basic Info", err);
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
    results.pass("Test 2: Ownership and AutoOwnership");
  } catch (err) {
    results.fail("Test 2: Ownership and AutoOwnership", err);
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
      results.pass("Test 3: Mint Function");
    } else {
      throw new Error("Supply didn't increase");
    }
  } catch (err) {
    results.fail("Test 3: Mint Function", err);
  }

  // -----------------------------------------------------------
  // Test 4: Mint to Specific Address
  // -----------------------------------------------------------
  console.log("📋 Test 4: Mint to Specific Address");
  try {
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
      results.pass("Test 4: Mint to Specific Address");
    } else {
      throw new Error("Balance mismatch");
    }
  } catch (err) {
    results.fail("Test 4: Mint to Specific Address", err);
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
      results.pass("Test 5: Set AutoMint Max Limit");
    } else {
      throw new Error("Limit mismatch");
    }
  } catch (err) {
    results.fail("Test 5: Set AutoMint Max Limit", err);
  }

  // -----------------------------------------------------------
  // Test 6: AutoMint Function
  // -----------------------------------------------------------
  console.log("📋 Test 6: AutoMint Function");
  try {
    const recipientAccount = tronWeb.utils.accounts.generateAccount();
    const recipient = recipientAccount.address.base58;

    const currentNonce = await stablecoin.nonce().call();
    const currentChainId = await stablecoin.chainId().call();
    const mintAmount = 800;

    console.log("   Current Nonce:", currentNonce.toString());
    console.log("   Current ChainID:", currentChainId.toString());
    console.log("   AutoMinting", mintAmount, "tokens with nonce...");

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
      results.pass("Test 6: AutoMint Function");
    } else {
      throw new Error("AutoMint validation failed");
    }
  } catch (err) {
    results.fail("Test 6: AutoMint Function", err);
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
      results.pass("Test 7: Burn Function");
    } else {
      throw new Error("Supply didn't decrease");
    }
  } catch (err) {
    results.fail("Test 7: Burn Function", err);
  }

  // -----------------------------------------------------------
  // Test 8: AutoBurn Function
  // -----------------------------------------------------------
  console.log("📋 Test 8: AutoBurn Function");
  try {
    const currentNonce = await stablecoin.nonce().call();
    const currentChainId = await stablecoin.chainId().call();
    const burnAmount = 50;
    const beforeSupply = await stablecoin.totalSupply().call();

    console.log("   Current Nonce:", currentNonce.toString());
    console.log("   Current ChainID:", currentChainId.toString());
    console.log("   AutoBurning", burnAmount, "tokens...");

    const autoBurnTx = await stablecoin.autoBurn(burnAmount, currentNonce, currentChainId).send({
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
      results.pass("Test 8: AutoBurn Function");
    } else {
      throw new Error("AutoBurn validation failed");
    }
  } catch (err) {
    results.fail("Test 8: AutoBurn Function", err);
  }

  // Print summary
  const success = results.summary();
  process.exit(success ? 0 : 1);
}

main().catch(err => {
  console.error("❌ Test suite failed:", err);
  process.exit(1);
});

/**
 * Test CCIP (StablecoinV3) - Chainlink Cross-Chain Token burn & mint role tests
 *
 * Runs against a proxy already upgraded to StablecoinV3. Covers the authorization
 * surface a real Chainlink BurnMintTokenPool depends on:
 * - grantMintAndBurnRoles / revokeMintAndBurnRoles
 * - role-holder mint (destination chain) and burn (source chain)
 * - calls rejected after the role is revoked
 * - freeze still blocks a role-holder mint
 * - setCCIPAdmin / getCCIPAdmin
 *
 * The role-holder here is a plain EOA rather than a pool contract. That exercises
 * the same `onlyOwnerOrCCIP` branch — the part that could plausibly behave
 * differently on TVM — without putting a test-only contract in contracts/.
 *
 * NOT COVERED: the contract-caller case, i.e. a pool calling through Chainlink's
 * returnless IBurnMintERC20 interface while our mint/burn return bool. There is
 * no test double for it in this repo, so verify that against the real
 * BurnMintTokenPool before relying on a CCIP lane.
 *
 * The role-holder account needs TRX to pay for energy. Either supply a funded one
 * via POOL_PRIVATE_KEY, or let this script generate one and fund it from the
 * deployer (swept back at the end).
 *
 * ⚠️  This test MUTATES token state (mints, burns, grants roles, freezes). It
 *     refuses to run against `prod` unless --force-prod is passed.
 *
 * Usage:
 *   node tests/test-ccip.js
 *   node tests/test-ccip.js --network=shasta --fund=500
 *   POOL_PRIVATE_KEY=<hex> node tests/test-ccip.js
 */

const { TronWeb } = require('tronweb');
const {
  getContractInstance,
  sleep,
  TestResults,
  tronWeb,
  network,
  networkConfig
} = require('./test-helpers');

const StablecoinV3Artifact = require('../build/contracts/StablecoinV3.json');

const SEND_OPTS = { feeLimit: 1_000_000_000, shouldPollResponse: true };
const SUN = 1_000_000;
const DEFAULT_FUND_TRX = 300;
// Left behind when sweeping, so the sweep transaction itself can pay its way.
const SWEEP_RESERVE_TRX = 1;

function parseFundAmount() {
  const arg = process.argv.find(a => a.startsWith('--fund='));
  if (!arg) return DEFAULT_FUND_TRX;
  const value = Number(arg.split('=')[1]);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid --fund value: ${arg}`);
  }
  return value;
}

/** Asserts that `fn` reverts. Returns the error message for logging. */
async function expectRevert(label, fn) {
  try {
    await fn();
  } catch (err) {
    return err.message || String(err);
  }
  throw new Error(`${label}: expected a revert, but the call succeeded`);
}

async function main() {
  console.log(`\n🔗 CCIP (StablecoinV3) Tests (Network: ${network})\n`);
  console.log('='.repeat(60) + '\n');

  if (network === 'prod' && !process.argv.includes('--force-prod')) {
    console.error('❌ Refusing to run on prod: this test mints, burns, grants roles and freezes.');
    console.error('   Re-run with --force-prod only if you really mean it.\n');
    process.exit(1);
  }

  const results = new TestResults();
  const { proxyAddress, deployerBase58 } = await getContractInstance();

  // Bind the V3 ABI to the existing proxy — test-helpers binds the V1 ABI, which
  // has none of the CCIP functions.
  const token = await tronWeb.contract(StablecoinV3Artifact.abi, proxyAddress);

  console.log('📋 Context:');
  console.log(`   Proxy:    ${proxyAddress}`);
  console.log(`   Deployer: ${deployerBase58}`);
  console.log('');

  // Test 1: Proxy is actually on V3
  console.log('Test 1: Proxy reports version v3');
  try {
    const version = await token.version().call();
    console.log('   version():', version);
    if (version !== 'v3') {
      throw new Error(`expected "v3", got "${version}" — upgrade the proxy first (npm run deploy:v3:${network})`);
    }
    results.pass('Proxy reports version v3');
  } catch (err) {
    results.fail('Proxy reports version v3', err);
    results.summary();
    process.exit(1);
  }

  // Test 2: getCCIPAdmin is seeded (initializeV3 ran, or it falls back to owner)
  console.log('Test 2: getCCIPAdmin returns a usable address');
  try {
    const adminHex = await token.getCCIPAdmin().call();
    const adminBase58 = tronWeb.address.fromHex(adminHex);
    const ownerHex = await token.owner().call();
    console.log('   getCCIPAdmin():', adminBase58);
    console.log('   owner():       ', tronWeb.address.fromHex(ownerHex));
    if (/^(41)?0{40}$/i.test(String(adminHex).replace(/^0x/, ''))) {
      throw new Error('getCCIPAdmin() returned the zero address');
    }
    results.pass('getCCIPAdmin returns a usable address');
  } catch (err) {
    results.fail('getCCIPAdmin returns a usable address', err);
  }

  // ------------------------------------------------------------------
  // Setup: the EOA that will stand in for the CCIP token pool.
  // ------------------------------------------------------------------
  console.log('Setup: Prepare CCIP role-holder account');
  let poolKey = process.env.POOL_PRIVATE_KEY;
  let generated = false;
  if (!poolKey) {
    const account = tronWeb.utils.accounts.generateAccount();
    poolKey = account.privateKey.replace(/^0x/, '');
    generated = true;
  }

  const poolTronWeb = new TronWeb({
    fullHost: networkConfig.fullHost,
    privateKey: poolKey,
    headers: { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY || '' },
    timeout: 60000
  });
  const poolBase58 = poolTronWeb.address.fromPrivateKey(poolKey);
  console.log('   Role-holder:', poolBase58, generated ? '(generated)' : '(from POOL_PRIVATE_KEY)');

  if (generated) {
    const fundTrx = parseFundAmount();
    console.log(`   Funding it with ${fundTrx} TRX for energy...`);
    try {
      await tronWeb.trx.sendTransaction(poolBase58, fundTrx * SUN);
      await sleep(4000);
      const bal = await tronWeb.trx.getBalance(poolBase58);
      console.log(`   Balance: ${bal / SUN} TRX`);
      if (bal <= 0) throw new Error('funding did not arrive');
    } catch (err) {
      console.log(`   ❌ Could not fund role-holder: ${err.message}`);
      console.log('      Supply a pre-funded account via POOL_PRIVATE_KEY instead.\n');
      results.fail('Fund CCIP role-holder', err);
      results.summary();
      process.exit(1);
    }
  }
  console.log('');

  const poolToken = await poolTronWeb.contract(StablecoinV3Artifact.abi, proxyAddress);

  // Test 3: grantMintAndBurnRoles
  console.log('Test 3: grantMintAndBurnRoles sets the flag');
  try {
    await token.grantMintAndBurnRoles(poolBase58).send(SEND_OPTS);
    await sleep(3000);

    const granted = await token.isCCIPMinterBurner(poolBase58).call();
    console.log('   isCCIPMinterBurner(role-holder):', granted);
    if (granted !== true) throw new Error('flag not set');
    results.pass('grantMintAndBurnRoles sets the flag');
  } catch (err) {
    results.fail('grantMintAndBurnRoles sets the flag', err);
  }

  // Test 4: role-holder mint (destination-chain path)
  console.log('Test 4: Role-holder can mint (destination-chain releaseOrMint)');
  const receiver = tronWeb.utils.accounts.generateAccount().address.base58;
  const mintAmount = 1000;
  try {
    const supplyBefore = await token.totalSupply().call();

    console.log(`   Role-holder minting ${mintAmount} to ${receiver}...`);
    await poolToken.methods['mint(address,uint256)'](receiver, mintAmount).send(SEND_OPTS);
    await sleep(3000);

    const supplyAfter = await token.totalSupply().call();
    const balance = await token.balanceOf(receiver).call();
    console.log('   Receiver balance:', balance.toString());
    console.log('   Supply delta:    ', (BigInt(supplyAfter) - BigInt(supplyBefore)).toString());

    if (BigInt(balance) !== BigInt(mintAmount)) {
      throw new Error(`receiver balance ${balance} != ${mintAmount}`);
    }
    if (BigInt(supplyAfter) - BigInt(supplyBefore) !== BigInt(mintAmount)) {
      throw new Error('totalSupply did not increase by the minted amount');
    }
    results.pass('Role-holder can mint (destination-chain releaseOrMint)');
  } catch (err) {
    results.fail('Role-holder can mint (destination-chain releaseOrMint)', err);
  }

  // Test 5: role-holder burn (source-chain path)
  console.log('Test 5: Role-holder can burn its own balance (source-chain lockOrBurn)');
  const burnAmount = 500;
  try {
    // The Router would move tokens into the pool; here the deployer funds it.
    await token.transfer(poolBase58, burnAmount).send(SEND_OPTS);
    await sleep(3000);

    const poolBalance = await token.balanceOf(poolBase58).call();
    console.log('   Role-holder token balance before burn:', poolBalance.toString());
    if (BigInt(poolBalance) < BigInt(burnAmount)) {
      throw new Error('role-holder was not funded with tokens');
    }

    const supplyBefore = await token.totalSupply().call();
    await poolToken.burn(burnAmount).send(SEND_OPTS);
    await sleep(3000);

    const supplyAfter = await token.totalSupply().call();
    const poolAfter = await token.balanceOf(poolBase58).call();
    console.log('   Role-holder token balance after burn: ', poolAfter.toString());
    console.log('   Supply delta:                         ', (BigInt(supplyAfter) - BigInt(supplyBefore)).toString());

    if (BigInt(supplyBefore) - BigInt(supplyAfter) !== BigInt(burnAmount)) {
      throw new Error('totalSupply did not decrease by the burned amount');
    }
    results.pass('Role-holder can burn its own balance (source-chain lockOrBurn)');
  } catch (err) {
    results.fail('Role-holder can burn its own balance (source-chain lockOrBurn)', err);
  }

  // Test 6: freeze still blocks a role-holder mint
  console.log('Test 6: Freeze blocks a role-holder mint');
  const frozenReceiver = tronWeb.utils.accounts.generateAccount().address.base58;
  try {
    await token.freezeAccount(frozenReceiver).send(SEND_OPTS);
    await sleep(3000);

    const msg = await expectRevert('role-holder mint to frozen address', () =>
      poolToken.methods['mint(address,uint256)'](frozenReceiver, 1).send(SEND_OPTS)
    );
    console.log('   Reverted as expected:', msg.slice(0, 120));

    // Clean up so the address is not left frozen on chain.
    await token.unfreezeAccount(frozenReceiver).send(SEND_OPTS);
    await sleep(3000);

    results.pass('Freeze blocks a role-holder mint');
  } catch (err) {
    results.fail('Freeze blocks a role-holder mint', err);
  }

  // Test 7: revokeMintAndBurnRoles, then the role-holder is rejected
  console.log('Test 7: revokeMintAndBurnRoles blocks the role-holder');
  try {
    await token.revokeMintAndBurnRoles(poolBase58).send(SEND_OPTS);
    await sleep(3000);

    const granted = await token.isCCIPMinterBurner(poolBase58).call();
    console.log('   isCCIPMinterBurner(role-holder):', granted);
    if (granted !== false) throw new Error('flag not cleared');

    const msg = await expectRevert('role-holder mint after revoke', () =>
      poolToken.methods['mint(address,uint256)'](receiver, 1).send(SEND_OPTS)
    );
    console.log('   Reverted as expected:', msg.slice(0, 120));

    results.pass('revokeMintAndBurnRoles blocks the role-holder');
  } catch (err) {
    results.fail('revokeMintAndBurnRoles blocks the role-holder', err);
  }

  // Test 8: setCCIPAdmin / getCCIPAdmin round trip
  console.log('Test 8: setCCIPAdmin updates getCCIPAdmin');
  try {
    const ownerBase58 = tronWeb.address.fromHex(await token.owner().call());
    const newAdmin = tronWeb.utils.accounts.generateAccount().address.base58;

    await token.setCCIPAdmin(newAdmin).send(SEND_OPTS);
    await sleep(3000);

    const afterSet = tronWeb.address.fromHex(await token.getCCIPAdmin().call());
    console.log('   getCCIPAdmin() after set:', afterSet);
    if (afterSet !== newAdmin) {
      throw new Error(`expected ${newAdmin}, got ${afterSet}`);
    }

    // Restore the owner as CCIP admin so the chain is left as we found it.
    await token.setCCIPAdmin(ownerBase58).send(SEND_OPTS);
    await sleep(3000);
    const restored = tronWeb.address.fromHex(await token.getCCIPAdmin().call());
    console.log('   getCCIPAdmin() restored: ', restored);
    if (restored !== ownerBase58) {
      throw new Error(`failed to restore CCIP admin to ${ownerBase58}, it is ${restored}`);
    }

    results.pass('setCCIPAdmin updates getCCIPAdmin');
  } catch (err) {
    results.fail('setCCIPAdmin updates getCCIPAdmin', err);
  }

  // Test 9: zero address is rejected
  console.log('Test 9: grantMintAndBurnRoles rejects the zero address');
  try {
    const zero = tronWeb.address.fromHex('41' + '0'.repeat(40));
    const msg = await expectRevert('grant zero address', () =>
      token.grantMintAndBurnRoles(zero).send(SEND_OPTS)
    );
    console.log('   Reverted as expected:', msg.slice(0, 120));
    results.pass('grantMintAndBurnRoles rejects the zero address');
  } catch (err) {
    results.fail('grantMintAndBurnRoles rejects the zero address', err);
  }

  // ------------------------------------------------------------------
  // Cleanup: return the role-holder's TRX, and report leftover tokens.
  // ------------------------------------------------------------------
  console.log('');
  console.log('Cleanup:');
  try {
    const leftoverTokens = await token.balanceOf(poolBase58).call();
    if (BigInt(leftoverTokens) > 0n) {
      console.log(`   ℹ️  Role-holder still holds ${leftoverTokens.toString()} tokens at ${poolBase58}`);
      console.log('      Its roles were revoked in Test 7, so it can no longer mint or burn.');
    }
  } catch (_) { /* reporting only */ }

  if (generated) {
    try {
      const bal = await tronWeb.trx.getBalance(poolBase58);
      const sweep = bal - SWEEP_RESERVE_TRX * SUN;
      if (sweep > 0) {
        await poolTronWeb.trx.sendTransaction(deployerBase58, sweep);
        await sleep(3000);
        console.log(`   ✅ Swept ${(sweep / SUN).toFixed(2)} TRX back to ${deployerBase58}`);
      } else {
        console.log('   ℹ️  Nothing worth sweeping back.');
      }
    } catch (err) {
      console.log(`   ⚠️  Could not sweep TRX back: ${err.message}`);
      console.log(`      Throwaway key for ${poolBase58}: ${poolKey}`);
    }
  }

  const ok = results.summary();
  process.exit(ok ? 0 : 1);
}

main().catch(err => {
  console.error('\n❌ Test run failed:', err);
  process.exit(1);
});

/**
 * StablecoinAutoOwner Tests (live network)
 *
 * Ports U/test/StablecoinAutoOwner.t.sol (Foundry) to TronBox/TronWeb style,
 * adapted for the whitelist-only design (no per-address mint limit).
 *
 * Prerequisites:
 *   - Stablecoin proxy and StablecoinAutoOwner proxy both deployed.
 *     (migrations/2_deploy_upgradable_token.js + migrations/3_deploy_auto_owner.js)
 *   - Stablecoin.transferAutoOwnership(<autoOwner proxy>) has been called.
 *   - Stablecoin.autoMintMaxLimit() > 0.
 *   - Deployer private key in .env is both the Stablecoin owner AND the
 *     AutoOwner owner AND the AutoOwner operator (default deployment).
 *
 * Usage:
 *   node tests/test-auto-owner.js --network=nile
 */

const fs = require('fs');
const path = require('path');
const {
  tronWeb,
  sleep,
  network,
  networkConfig,
  TestResults
} = require('./test-helpers');

const AutoOwnerArtifact = require('../build/contracts/StablecoinAutoOwner.json');
const StablecoinArtifact = require('../build/contracts/Stablecoin.json');

const FEE_LIMIT = 200_000_000; // 200 TRX

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadAutoOwnerAddress() {
  const file = path.join(__dirname, `../deployments/${network}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(
      `deployments/${network}.json not found. ` +
      `Run migrations 2 + 3 (deploy:nile + deploy:autoowner:nile) first.`
    );
  }
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!data.autoOwner || !data.autoOwner.proxy) {
    throw new Error(
      `autoOwner.proxy missing in ${file}. ` +
      `Run migration 3 (deploy:autoowner:${network}) first.`
    );
  }
  return {
    autoOwnerProxy: data.autoOwner.proxy,
    stablecoinProxy: data.proxy || data.autoOwner.stablecoin
  };
}

async function expectRevert(promise, label) {
  try {
    await promise;
    throw new Error(`Expected revert, but call succeeded (${label})`);
  } catch (err) {
    const msg = (err && err.message) || String(err);
    if (/REVERT|revert|Expected revert/.test(msg) && !msg.startsWith('Expected revert, but call succeeded')) {
      return msg;
    }
    if (msg.startsWith('Expected revert, but call succeeded')) throw err;
    return msg;
  }
}

async function simulateConstant(contractAddress, methodSig, params, fromBase58) {
  const paramTypes = methodSig.match(/\((.*)\)/)[1].split(',').filter(Boolean);
  const parameter = paramTypes.map((t, i) => ({ type: t.trim(), value: params[i] }));

  const result = await tronWeb.transactionBuilder.triggerConstantContract(
    tronWeb.address.toHex(contractAddress),
    methodSig,
    {},
    parameter,
    tronWeb.address.toHex(fromBase58)
  );

  const ok = result && result.result && result.result.result === true;
  let message = '';
  if (result && Array.isArray(result.constant_result) && result.constant_result[0]) {
    message = result.constant_result[0];
  }
  return { ok, message, raw: result };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`\n🧪 StablecoinAutoOwner Tests (Network: ${network})\n`);
  console.log('='.repeat(70) + '\n');

  const results = new TestResults();
  const { autoOwnerProxy, stablecoinProxy } = loadAutoOwnerAddress();

  const deployerBase58 = tronWeb.address.fromPrivateKey(networkConfig.privateKey);
  const autoOwner = await tronWeb.contract(AutoOwnerArtifact.abi, autoOwnerProxy);
  const stablecoin = await tronWeb.contract(StablecoinArtifact.abi, stablecoinProxy);

  console.log('📋 Addresses:');
  console.log(`   Deployer:          ${deployerBase58}`);
  console.log(`   Stablecoin proxy:  ${stablecoinProxy}`);
  console.log(`   AutoOwner proxy:   ${autoOwnerProxy}`);
  console.log('');

  // -------------------------------------------------------------------
  // Pre-flight: confirm roles line up for a full test run
  // -------------------------------------------------------------------
  const ownerHex = await autoOwner.owner().call();
  const operatorHex = await autoOwner.operator().call();
  const stablecoinHex = await autoOwner.stablecoin().call();
  const ownerBase58 = tronWeb.address.fromHex(ownerHex);
  const operatorBase58 = tronWeb.address.fromHex(operatorHex);
  const stablecoinCfgBase58 = tronWeb.address.fromHex(stablecoinHex);

  console.log('📋 AutoOwner state:');
  console.log(`   owner:      ${ownerBase58}`);
  console.log(`   operator:   ${operatorBase58}`);
  console.log(`   stablecoin: ${stablecoinCfgBase58}`);
  console.log('');

  if (ownerBase58 !== deployerBase58) {
    console.log(`⚠️  Deployer is not AutoOwner.owner — owner-gated tests will be skipped.\n`);
  }
  if (operatorBase58 !== deployerBase58) {
    console.log(`⚠️  Deployer is not AutoOwner.operator — operator-gated write tests will be skipped.\n`);
  }
  const deployerIsOwner = ownerBase58 === deployerBase58;
  const deployerIsOperator = operatorBase58 === deployerBase58;

  const tokenAutoOwnerHex = await stablecoin.autoOwner().call();
  const tokenAutoOwnerBase58 = tronWeb.address.fromHex(tokenAutoOwnerHex);
  if (tokenAutoOwnerBase58 !== autoOwnerProxy) {
    throw new Error(
      `Stablecoin.autoOwner() = ${tokenAutoOwnerBase58}, expected ${autoOwnerProxy}. ` +
      `Call Stablecoin.transferAutoOwnership("${autoOwnerProxy}") first.`
    );
  }

  const globalCap = BigInt(await stablecoin.autoMintMaxLimit().call());
  if (globalCap === 0n) {
    throw new Error(
      `Stablecoin.autoMintMaxLimit() is 0. ` +
      `Call setAutoMintMaxLimit(<nonzero>) first.`
    );
  }

  const aliceAcct = tronWeb.utils.accounts.generateAccount();
  const bobAcct = tronWeb.utils.accounts.generateAccount();
  const charlieAcct = tronWeb.utils.accounts.generateAccount();
  const strangerAcct = tronWeb.utils.accounts.generateAccount();

  const MINT_AMOUNT = 100n; // any value within Stablecoin.autoMintMaxLimit

  console.log('📋 Test actors:');
  console.log(`   alice:    ${aliceAcct.address.base58} (to be whitelisted)`);
  console.log(`   bob:      ${bobAcct.address.base58} (to be whitelisted then removed)`);
  console.log(`   charlie:  ${charlieAcct.address.base58} (batch-whitelisted)`);
  console.log(`   stranger: ${strangerAcct.address.base58} (never whitelisted)`);
  console.log('');

  // -------------------------------------------------------------------
  // (1) Views reflect Stablecoin
  // -------------------------------------------------------------------
  console.log('▶ Views reflect Stablecoin');
  try {
    const autoNonce = BigInt(await autoOwner.nonce().call());
    const tokenNonce = BigInt(await stablecoin.nonce().call());
    const autoChain = BigInt(await autoOwner.chainId().call());
    const tokenChain = BigInt(await stablecoin.chainId().call());

    if (autoNonce !== tokenNonce) throw new Error(`nonce mismatch ${autoNonce} vs ${tokenNonce}`);
    if (autoChain !== tokenChain) throw new Error(`chainId mismatch ${autoChain} vs ${tokenChain}`);
    results.pass('Views reflect Stablecoin (nonce, chainId)');
  } catch (err) {
    results.fail('Views reflect Stablecoin', err);
  }

  // -------------------------------------------------------------------
  // (2) setWhitelist: add alice & bob
  // -------------------------------------------------------------------
  if (deployerIsOwner) {
    console.log('▶ setWhitelist: add alice & bob');
    try {
      await autoOwner
        .setWhitelist(aliceAcct.address.base58, true)
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);
      await autoOwner
        .setWhitelist(bobAcct.address.base58, true)
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);

      const aliceOk = await autoOwner.isWhitelisted(aliceAcct.address.base58).call();
      const bobOk = await autoOwner.isWhitelisted(bobAcct.address.base58).call();
      if (!aliceOk) throw new Error('alice not whitelisted after setWhitelist(true)');
      if (!bobOk) throw new Error('bob not whitelisted after setWhitelist(true)');
      results.pass('setWhitelist: add alice & bob');
    } catch (err) {
      results.fail('setWhitelist: add alice & bob', err);
    }
  } else {
    console.log('⏭  setWhitelist: skipped (deployer not owner)\n');
  }

  // -------------------------------------------------------------------
  // (3) setWhitelist reverts
  // -------------------------------------------------------------------
  if (deployerIsOwner) {
    console.log('▶ setWhitelist reverts on ZeroAddress');
    try {
      await expectRevert(
        autoOwner.setWhitelist('0x0000000000000000000000000000000000000000', true)
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'ZeroAddress'
      );
      results.pass('setWhitelist reverts on ZeroAddress');
    } catch (err) {
      results.fail('setWhitelist reverts on ZeroAddress', err);
    }
  }

  // -------------------------------------------------------------------
  // (4) setWhitelistBatch happy + LengthMismatch
  // -------------------------------------------------------------------
  if (deployerIsOwner) {
    console.log('▶ setWhitelistBatch: success');
    try {
      await autoOwner
        .setWhitelistBatch(
          [charlieAcct.address.base58, aliceAcct.address.base58],
          [true, true] // re-asserting alice is fine
        )
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);

      const c = await autoOwner.isWhitelisted(charlieAcct.address.base58).call();
      const a = await autoOwner.isWhitelisted(aliceAcct.address.base58).call();
      if (!c) throw new Error('charlie not whitelisted');
      if (!a) throw new Error('alice not whitelisted');
      results.pass('setWhitelistBatch: success');
    } catch (err) {
      results.fail('setWhitelistBatch: success', err);
    }

    console.log('▶ setWhitelistBatch reverts on LengthMismatch');
    try {
      await expectRevert(
        autoOwner.setWhitelistBatch(
          [charlieAcct.address.base58, aliceAcct.address.base58],
          [true]
        ).send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'LengthMismatch'
      );
      results.pass('setWhitelistBatch reverts on LengthMismatch');
    } catch (err) {
      results.fail('setWhitelistBatch reverts on LengthMismatch', err);
    }
  }

  // -------------------------------------------------------------------
  // (4b) Enumerate whitelist: length, at(i), getWhitelist()
  // -------------------------------------------------------------------
  if (deployerIsOwner) {
    console.log('▶ enumerate whitelist (length/at/getWhitelist)');
    try {
      const len = BigInt(await autoOwner.whitelistLength().call());
      if (len < 3n) throw new Error(`expected >=3 whitelisted, got ${len}`);

      const collected = [];
      for (let i = 0n; i < len; i++) {
        const hex = await autoOwner.whitelistAt(i.toString()).call();
        collected.push(tronWeb.address.fromHex(hex));
      }

      const expected = [aliceAcct.address.base58, bobAcct.address.base58, charlieAcct.address.base58];
      for (const e of expected) {
        if (!collected.includes(e)) throw new Error(`whitelistAt enumeration missing ${e}`);
      }

      const bulkHex = await autoOwner.getWhitelist().call();
      const bulk = bulkHex.map(h => tronWeb.address.fromHex(h));
      for (const e of expected) {
        if (!bulk.includes(e)) throw new Error(`getWhitelist() missing ${e}`);
      }
      if (BigInt(bulk.length) !== len) throw new Error(`getWhitelist length ${bulk.length} !== ${len}`);

      results.pass('enumerate whitelist (length/at/getWhitelist)');
    } catch (err) {
      results.fail('enumerate whitelist', err);
    }

    console.log('▶ whitelistAt reverts on IndexOutOfBounds');
    try {
      const len = BigInt(await autoOwner.whitelistLength().call());
      await expectRevert(
        autoOwner.whitelistAt(len.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'IndexOutOfBounds'
      );
      results.pass('whitelistAt reverts on IndexOutOfBounds');
    } catch (err) {
      results.fail('whitelistAt reverts on IndexOutOfBounds', err);
    }
  }

  // -------------------------------------------------------------------
  // (5) autoMint happy path
  // -------------------------------------------------------------------
  if (deployerIsOperator) {
    console.log('▶ autoMint success (whitelisted recipient)');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());

      await autoOwner
        .autoMint(aliceAcct.address.base58, MINT_AMOUNT.toString(), seq.toString(), chain.toString())
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);

      const bal = BigInt(await stablecoin.balanceOf(aliceAcct.address.base58).call());
      const newNonce = BigInt(await stablecoin.nonce().call());
      if (bal !== MINT_AMOUNT) throw new Error(`alice balance ${bal} !== ${MINT_AMOUNT}`);
      if (newNonce !== seq + 1n) throw new Error(`nonce ${newNonce} !== ${seq + 1n}`);
      results.pass('autoMint success (whitelisted recipient)');
    } catch (err) {
      results.fail('autoMint success (whitelisted recipient)', err);
    }
  }

  // -------------------------------------------------------------------
  // (6) autoMint business-logic reverts
  // -------------------------------------------------------------------
  if (deployerIsOperator) {
    console.log('▶ autoMint reverts on NotWhitelisted');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoMint(strangerAcct.address.base58, '1', seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'NotWhitelisted'
      );
      results.pass('autoMint reverts on NotWhitelisted');
    } catch (err) {
      results.fail('autoMint reverts on NotWhitelisted', err);
    }

    console.log('▶ autoMint reverts on ZeroAmount');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoMint(aliceAcct.address.base58, '0', seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'ZeroAmount'
      );
      results.pass('autoMint reverts on ZeroAmount');
    } catch (err) {
      results.fail('autoMint reverts on ZeroAmount', err);
    }

    console.log('▶ autoMint reverts on ZeroAddress');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoMint('0x0000000000000000000000000000000000000000', '1', seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'ZeroAddress'
      );
      results.pass('autoMint reverts on ZeroAddress');
    } catch (err) {
      results.fail('autoMint reverts on ZeroAddress', err);
    }

    console.log('▶ autoMint propagates Stablecoin.InvalidChainId');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      await expectRevert(
        autoOwner.autoMint(aliceAcct.address.base58, '1', seq.toString(), '999999')
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'InvalidChainId'
      );
      results.pass('autoMint propagates Stablecoin.InvalidChainId');
    } catch (err) {
      results.fail('autoMint propagates Stablecoin.InvalidChainId', err);
    }

    console.log('▶ autoMint propagates Stablecoin.InvalidNonce');
    try {
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoMint(aliceAcct.address.base58, '1', '999999', chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'InvalidNonce'
      );
      results.pass('autoMint propagates Stablecoin.InvalidNonce');
    } catch (err) {
      results.fail('autoMint propagates Stablecoin.InvalidNonce', err);
    }

    console.log('▶ autoMint propagates Stablecoin.MintLimitExceeded (amount > globalCap)');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      const tooMuch = (globalCap + 1n).toString();
      await expectRevert(
        autoOwner.autoMint(aliceAcct.address.base58, tooMuch, seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'MintLimitExceeded'
      );
      results.pass('autoMint propagates Stablecoin.MintLimitExceeded');
    } catch (err) {
      results.fail('autoMint propagates Stablecoin.MintLimitExceeded', err);
    }
  }

  // -------------------------------------------------------------------
  // (7) autoMint CallerNotOperator (simulate from stranger, no gas)
  // -------------------------------------------------------------------
  console.log('▶ autoMint from non-operator reverts (constant-call simulation)');
  try {
    const seq = BigInt(await stablecoin.nonce().call());
    const chain = BigInt(await stablecoin.chainId().call());
    const sim = await simulateConstant(
      autoOwnerProxy,
      'autoMint(address,uint256,uint256,uint256)',
      [aliceAcct.address.base58, '1', seq.toString(), chain.toString()],
      strangerAcct.address.base58
    );
    if (sim.ok) throw new Error('Expected non-operator simulation to revert');
    results.pass('autoMint from non-operator reverts');
  } catch (err) {
    results.fail('autoMint from non-operator reverts', err);
  }

  // -------------------------------------------------------------------
  // (8) autoBurn happy path (owner must hold balance)
  // -------------------------------------------------------------------
  if (deployerIsOperator && deployerIsOwner) {
    console.log('▶ autoBurn success');
    try {
      const ownerBal = BigInt(await stablecoin.balanceOf(deployerBase58).call());
      if (ownerBal < 100n) {
        await stablecoin.methods['mint(uint256)'](200).send({
          feeLimit: FEE_LIMIT,
          shouldPollResponse: true
        });
        await sleep(3000);
      }

      const before = BigInt(await stablecoin.balanceOf(deployerBase58).call());
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      const burnAmt = 100n;

      await autoOwner
        .autoBurn(burnAmt.toString(), seq.toString(), chain.toString())
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);

      const after = BigInt(await stablecoin.balanceOf(deployerBase58).call());
      const newSeq = BigInt(await stablecoin.nonce().call());
      if (before - after !== burnAmt) throw new Error(`delta ${before - after} !== ${burnAmt}`);
      if (newSeq !== seq + 1n) throw new Error(`nonce ${newSeq} !== ${seq + 1n}`);
      results.pass('autoBurn success');
    } catch (err) {
      results.fail('autoBurn success', err);
    }
  }

  // -------------------------------------------------------------------
  // (8b) autoBurn reverts on ZeroAmount / AmountExceedsMaxLimit
  // -------------------------------------------------------------------
  if (deployerIsOperator) {
    console.log('▶ autoBurn reverts on ZeroAmount');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoBurn('0', seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'ZeroAmount'
      );
      results.pass('autoBurn reverts on ZeroAmount');
    } catch (err) {
      results.fail('autoBurn reverts on ZeroAmount', err);
    }

    console.log('▶ autoBurn reverts on AmountExceedsMaxLimit');
    try {
      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      const tooMuch = (globalCap + 1n).toString();
      await expectRevert(
        autoOwner.autoBurn(tooMuch, seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'AmountExceedsMaxLimit'
      );
      results.pass('autoBurn reverts on AmountExceedsMaxLimit');
    } catch (err) {
      results.fail('autoBurn reverts on AmountExceedsMaxLimit', err);
    }
  }

  // -------------------------------------------------------------------
  // (9) autoBurn CallerNotOperator (constant-call simulation)
  // -------------------------------------------------------------------
  console.log('▶ autoBurn from non-operator reverts (constant-call simulation)');
  try {
    const seq = BigInt(await stablecoin.nonce().call());
    const chain = BigInt(await stablecoin.chainId().call());
    const sim = await simulateConstant(
      autoOwnerProxy,
      'autoBurn(uint256,uint256,uint256)',
      ['1', seq.toString(), chain.toString()],
      strangerAcct.address.base58
    );
    if (sim.ok) throw new Error('Expected non-operator simulation to revert');
    results.pass('autoBurn from non-operator reverts');
  } catch (err) {
    results.fail('autoBurn from non-operator reverts', err);
  }

  // -------------------------------------------------------------------
  // (10) pause / unpause + autoMint blocked while paused
  // -------------------------------------------------------------------
  if (deployerIsOwner && deployerIsOperator) {
    console.log('▶ pause blocks autoMint; unpause restores');
    try {
      await autoOwner.pause().send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);

      const paused = await autoOwner.paused().call();
      if (!paused) throw new Error('paused() returned false after pause()');

      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoMint(aliceAcct.address.base58, '1', seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'Paused'
      );

      await autoOwner.unpause().send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);

      const unpaused = await autoOwner.paused().call();
      if (unpaused) throw new Error('paused() still true after unpause()');

      results.pass('pause blocks autoMint; unpause restores');
    } catch (err) {
      results.fail('pause blocks autoMint; unpause restores', err);

      try {
        await autoOwner.unpause().send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
        await sleep(3000);
      } catch (_) { /* ignore */ }
    }
  }

  // -------------------------------------------------------------------
  // (11) pause / unpause owner-only (simulated from stranger)
  // -------------------------------------------------------------------
  console.log('▶ pause from non-owner reverts (constant-call simulation)');
  try {
    const sim = await simulateConstant(
      autoOwnerProxy,
      'pause()',
      [],
      strangerAcct.address.base58
    );
    if (sim.ok) throw new Error('Expected stranger pause() to revert');
    results.pass('pause from non-owner reverts');
  } catch (err) {
    results.fail('pause from non-owner reverts', err);
  }

  // -------------------------------------------------------------------
  // (12) setOperator happy path + rotate back
  // -------------------------------------------------------------------
  if (deployerIsOwner) {
    console.log('▶ setOperator: rotate & restore');
    let rotated = false;
    try {
      const placeholder = tronWeb.utils.accounts.generateAccount().address.base58;
      await autoOwner
        .setOperator(placeholder)
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      rotated = true;
      await sleep(3000);
      const newOp = tronWeb.address.fromHex(await autoOwner.operator().call());
      if (newOp !== placeholder) throw new Error(`operator ${newOp} !== ${placeholder}`);

      await autoOwner
        .setOperator(operatorBase58)
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      rotated = false;
      await sleep(3000);

      const restored = tronWeb.address.fromHex(await autoOwner.operator().call());
      if (restored !== operatorBase58) throw new Error(`operator not restored: ${restored}`);
      results.pass('setOperator: rotate & restore');
    } catch (err) {
      results.fail('setOperator: rotate & restore', err);

      if (rotated) {
        try {
          await autoOwner
            .setOperator(operatorBase58)
            .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
          await sleep(3000);
        } catch (_) { /* ignore */ }
      }
    }

    console.log('▶ setOperator reverts on ZeroAddress');
    try {
      await expectRevert(
        autoOwner.setOperator('0x0000000000000000000000000000000000000000')
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'ZeroAddress'
      );
      results.pass('setOperator reverts on ZeroAddress');
    } catch (err) {
      results.fail('setOperator reverts on ZeroAddress', err);
    }
  }

  // -------------------------------------------------------------------
  // (13) setWhitelist from non-owner reverts (simulated)
  // -------------------------------------------------------------------
  console.log('▶ setWhitelist from non-owner reverts (constant-call simulation)');
  try {
    const sim = await simulateConstant(
      autoOwnerProxy,
      'setWhitelist(address,bool)',
      [charlieAcct.address.base58, true],
      strangerAcct.address.base58
    );
    if (sim.ok) throw new Error('Expected non-owner setWhitelist to revert');
    results.pass('setWhitelist from non-owner reverts');
  } catch (err) {
    results.fail('setWhitelist from non-owner reverts', err);
  }

  // -------------------------------------------------------------------
  // (14) Removing from whitelist blocks subsequent autoMint
  // -------------------------------------------------------------------
  if (deployerIsOwner && deployerIsOperator) {
    console.log('▶ setWhitelist(bob, false) removes whitelist');
    try {
      await autoOwner
        .setWhitelist(bobAcct.address.base58, false)
        .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true });
      await sleep(3000);
      const flag = await autoOwner.isWhitelisted(bobAcct.address.base58).call();
      if (flag) throw new Error(`expected false, got ${flag}`);

      const seq = BigInt(await stablecoin.nonce().call());
      const chain = BigInt(await stablecoin.chainId().call());
      await expectRevert(
        autoOwner.autoMint(bobAcct.address.base58, '1', seq.toString(), chain.toString())
          .send({ feeLimit: FEE_LIMIT, shouldPollResponse: true }),
        'NotWhitelisted'
      );
      results.pass('setWhitelist(bob, false) removes whitelist');
    } catch (err) {
      results.fail('setWhitelist(bob, false) removes whitelist', err);
    }
  }

  // -------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------
  const ok = results.summary();
  process.exit(ok ? 0 : 1);
}

main().catch(err => {
  console.error('❌ Test suite failed:', err);
  process.exit(1);
});

/**
 * Run All Tests - Run all test modules
 *
 * Run all test files in sequence
 */

const { exec } = require('child_process');
const path = require('path');

const testFiles = [
  'test-mint.js',
  'test-basic-functions.js',
  'test-account-control.js',
  'test-rescuable.js',
  'test-tip712.js',
  'test-eip3009.js'
];

const network = process.argv.find(arg => arg.startsWith('--network=')) || '--network=nile';

console.log('\n' + '='.repeat(80));
console.log('  Running All Stablecoin Tests');
console.log('  Network:', network.split('=')[1] || 'nile');
console.log('='.repeat(80) + '\n');

let currentTest = 0;
let passedTests = 0;
let failedTests = 0;

function runNextTest() {
  if (currentTest >= testFiles.length) {
    // All tests completed
    console.log('\n' + '='.repeat(80));
    console.log('  All Test Suites Completed');
    console.log('='.repeat(80));
    console.log(`  Total Suites: ${testFiles.length}`);
    console.log(`  ✅ Passed: ${passedTests}`);
    console.log(`  ❌ Failed: ${failedTests}`);
    console.log('='.repeat(80) + '\n');

    process.exit(failedTests > 0 ? 1 : 0);
    return;
  }

  const testFile = testFiles[currentTest];
  const testPath = path.join(__dirname, testFile);

  console.log(`\n${'='.repeat(80)}`);
  console.log(`  Running: ${testFile}`);
  console.log(`${'='.repeat(80)}\n`);

  const child = exec(`node "${testPath}" ${network}`, {
    cwd: __dirname
  });

  child.stdout.on('data', (data) => {
    process.stdout.write(data);
  });

  child.stderr.on('data', (data) => {
    process.stderr.write(data);
  });

  child.on('exit', (code) => {
    if (code === 0) {
      passedTests++;
      console.log(`\n✅ ${testFile} PASSED\n`);
    } else {
      failedTests++;
      console.log(`\n❌ ${testFile} FAILED\n`);
    }

    currentTest++;
    runNextTest();
  });

  child.on('error', (err) => {
    console.error(`❌ Error running ${testFile}:`, err);
    failedTests++;
    currentTest++;
    runNextTest();
  });
}

// Start running tests
runNextTest();

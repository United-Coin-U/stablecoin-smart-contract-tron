/**
 * Solidity Contract Flattener
 *
 * Flattens Solidity contracts by recursively resolving all imports
 * and combining them into a single file for verification.
 */

const fs = require('fs');
const path = require('path');

class SolidityFlattener {
  constructor() {
    this.processedFiles = new Set();
    this.flattenedContent = [];
    this.spdxLicenses = new Set();
    this.pragmaVersions = new Set();
  }

  /**
   * Resolve import path
   */
  resolveImport(importPath, currentDir) {
    // Handle @openzeppelin imports
    if (importPath.startsWith('@openzeppelin')) {
      return path.join(process.cwd(), 'node_modules', importPath);
    }

    // Handle relative imports
    if (importPath.startsWith('.')) {
      return path.join(currentDir, importPath);
    }

    // Handle absolute imports from contracts/
    return path.join(process.cwd(), 'contracts', importPath);
  }

  /**
   * Extract imports from source code
   */
  extractImports(source) {
    const importRegex = /import\s+(?:(?:"([^"]+)"|'([^']+)')|(?:{[^}]+}\s+from\s+(?:"([^"]+)"|'([^']+)')))\s*;/g;
    const imports = [];
    let match;

    while ((match = importRegex.exec(source)) !== null) {
      const importPath = match[1] || match[2] || match[3] || match[4];
      imports.push({
        statement: match[0],
        path: importPath
      });
    }

    return imports;
  }

  /**
   * Extract SPDX license
   */
  extractSPDX(source) {
    const spdxRegex = /\/\/\s*SPDX-License-Identifier:\s*(.+)/;
    const match = source.match(spdxRegex);
    if (match) {
      this.spdxLicenses.add(match[1].trim());
      return match[0];
    }
    return null;
  }

  /**
   * Extract pragma directive
   */
  extractPragma(source) {
    const pragmaRegex = /pragma\s+solidity\s+([^;]+);/;
    const match = source.match(pragmaRegex);
    if (match) {
      this.pragmaVersions.add(match[0]);
      return match[0];
    }
    return null;
  }

  /**
   * Process a single file
   */
  processFile(filePath, currentDir) {
    // Check if already processed
    const normalizedPath = path.normalize(filePath);
    if (this.processedFiles.has(normalizedPath)) {
      return;
    }

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.error(`Warning: File not found: ${filePath}`);
      return;
    }

    this.processedFiles.add(normalizedPath);
    console.log(`Processing: ${path.relative(process.cwd(), filePath)}`);

    // Read file content
    let source = fs.readFileSync(filePath, 'utf8');

    // Extract and save SPDX and pragma
    this.extractSPDX(source);
    this.extractPragma(source);

    // Extract imports
    const imports = this.extractImports(source);

    // Process each import first (depth-first)
    for (const imp of imports) {
      const importFilePath = this.resolveImport(imp.path, currentDir);
      const importDir = path.dirname(importFilePath);
      this.processFile(importFilePath, importDir);
    }

    // Remove SPDX, pragma, and import statements from source
    source = source
      .replace(/\/\/\s*SPDX-License-Identifier:[^\n]*/g, '')
      .replace(/pragma\s+solidity\s+[^;]+;/g, '')
      .replace(/import\s+(?:(?:"[^"]+"|'[^']')|(?:{[^}]+}\s+from\s+(?:"[^"]+"|'[^']+')))\s*;/g, '');

    // Clean up extra blank lines
    source = source.replace(/\n{3,}/g, '\n\n');

    // Add to flattened content
    this.flattenedContent.push({
      file: path.relative(process.cwd(), filePath),
      content: source.trim()
    });
  }

  /**
   * Generate flattened output
   */
  generateOutput() {
    let output = '';

    // Add SPDX (use the first one found, typically MIT)
    if (this.spdxLicenses.size > 0) {
      const license = Array.from(this.spdxLicenses)[0];
      output += `// SPDX-License-Identifier: ${license}\n\n`;
    }

    // Add pragma (use the most specific one)
    if (this.pragmaVersions.size > 0) {
      const pragma = Array.from(this.pragmaVersions)[0];
      output += `${pragma}\n\n`;
    }

    // Add file separator comments and content
    for (const item of this.flattenedContent) {
      output += `// File: ${item.file}\n\n`;
      output += item.content + '\n\n';
    }

    return output;
  }

  /**
   * Flatten a contract
   */
  flatten(contractPath) {
    this.processedFiles.clear();
    this.flattenedContent = [];
    this.spdxLicenses.clear();
    this.pragmaVersions.clear();

    const absolutePath = path.isAbsolute(contractPath)
      ? contractPath
      : path.join(process.cwd(), 'contracts', contractPath);

    const contractDir = path.dirname(absolutePath);

    console.log(`\n🔄 Flattening ${contractPath}...\n`);

    this.processFile(absolutePath, contractDir);

    const output = this.generateOutput();

    console.log(`\n✅ Processed ${this.processedFiles.size} files`);
    console.log(`📝 SPDX License: ${Array.from(this.spdxLicenses).join(', ')}`);
    console.log(`📝 Solidity Version: ${Array.from(this.pragmaVersions).join(', ')}\n`);

    return output;
  }
}

/**
 * Main execution
 */
function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║              Solidity Contract Flattener                          ║
║     Combine all imports into a single verifiable file            ║
╚═══════════════════════════════════════════════════════════════════╝

Usage:
  node scripts/flatten.js <contract-name>
  node scripts/flatten.js <contract-path>

Examples:
  node scripts/flatten.js Stablecoin
  node scripts/flatten.js ProxyAdmin
  node scripts/flatten.js contracts/Stablecoin.sol

Output:
  Flattened files are saved to: verify-flattened/
    `);
    process.exit(0);
  }

  const contractInput = args[0];

  // Determine contract name and path
  let contractPath = contractInput;
  let contractName = contractInput;

  if (!contractInput.endsWith('.sol')) {
    contractPath = `${contractInput}.sol`;
    contractName = contractInput;
  } else {
    contractName = path.basename(contractInput, '.sol');
  }

  try {
    const flattener = new SolidityFlattener();
    const flattenedCode = flattener.flatten(contractPath);

    // Create output directory
    const outputDir = path.join(process.cwd(), 'verify-flattened');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Save flattened file
    const outputFile = path.join(outputDir, `${contractName}_flat.sol`);
    fs.writeFileSync(outputFile, flattenedCode);

    console.log(`✅ Flattened contract saved to: ${outputFile}`);
    console.log(`\n📋 File size: ${(flattenedCode.length / 1024).toFixed(2)} KB`);
    console.log(`📋 Lines: ${flattenedCode.split('\n').length}`);

    console.log(`\n📝 Next steps:`);
    console.log(`1. Open the flattened file:`);
    console.log(`   cat ${outputFile}`);
    console.log(`\n2. Copy the content and paste into TronScan verification`);
    console.log(`   or`);
    console.log(`   pbcopy < ${outputFile}  # macOS`);
    console.log(`   cat ${outputFile} | clip  # Windows\n`);

  } catch (error) {
    console.error(`\n❌ Error: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { SolidityFlattener };

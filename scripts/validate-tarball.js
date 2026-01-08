#!/usr/bin/env node

/**
 * Tarball Validation Script
 *
 * Creates a dry-run npm pack and validates that all runtime-required files
 * are present in the tarball. This catches issues that static analysis misses.
 *
 * Validates:
 * 1. Workspace package.json files are included (v1.25.7 regression)
 * 2. Import resolutions work within tarball structure (v1.25.8 regression)
 * 3. All bin entries have corresponding files
 *
 * Usage:
 *   npm run validate:tarball
 *   node scripts/validate-tarball.js
 *
 * Exit codes:
 *   0 - All validations passed
 *   1 - Validation failed
 */

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

let hasErrors = false;

function error(message) {
  console.error(`  \x1b[31m✗\x1b[0m ${message}`);
  hasErrors = true;
}

function success(message) {
  console.log(`  \x1b[32m✓\x1b[0m ${message}`);
}

function warn(message) {
  console.warn(`  \x1b[33m⚠\x1b[0m ${message}`);
}

console.log("\n=== Tarball Validation ===\n");
console.log("Creating dry-run tarball...");

// Debug mode: set DEBUG=1 to see raw output
const DEBUG = process.env.DEBUG === "1";

// Get tarball contents without actually creating it
let output;
try {
  output = execSync("npm pack --dry-run 2>&1", {
    encoding: "utf-8",
    cwd: projectRoot,
    maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large package listings
  });
} catch (err) {
  console.error("Failed to run npm pack --dry-run");
  console.error(err.message);
  process.exit(1);
}

// Parse npm notice lines to get file list
// Note: Output may contain ANSI color codes, so we need to strip them
const stripAnsi = (str) => str.replace(/\x1b\[[0-9;]*m/g, "");
const cleanOutput = stripAnsi(output);

if (DEBUG) {
  console.log(`\nDEBUG: Raw output length: ${output.length}`);
  console.log(`DEBUG: Clean output length: ${cleanOutput.length}`);
}

const lines = cleanOutput
  .split("\n")
  .filter((line) => line.includes("npm notice"));

if (DEBUG) {
  console.log(`DEBUG: Total lines with 'npm notice': ${lines.length}`);
  console.log("DEBUG: First 5 lines:");
  lines.slice(0, 5).forEach((l) => console.log(`  ${l}`));
  console.log("DEBUG: Last 5 lines:");
  lines.slice(-5).forEach((l) => console.log(`  ${l}`));
}

const tarballFiles = lines
  .map((line) => {
    // Match lines like "npm notice 1.9kB cli/package.json"
    // Size can be like "1.2kB", "14.3kB", "1.8MB", "474B"
    // Note: npm uses lowercase 'k' for kilobytes
    const match = line.match(/npm notice\s+[\d.]+[kKMG]?B\s+(.+)$/);
    return match ? match[1].trim() : null;
  })
  .filter(Boolean);

// Debug: show sample of what we found
if (tarballFiles.length === 0) {
  console.log("WARNING: No files parsed from npm pack output");
  console.log("Sample output lines:");
  lines.slice(0, 5).forEach((l) => console.log(`  ${l}`));
}

console.log(`\nFound ${tarballFiles.length} files in tarball\n`);

// Check 1: Required runtime dependencies
console.log("1. Checking workspace package.json files...\n");

const requiredFiles = [
  "client/package.json",
  "server/package.json",
  "cli/package.json",
];

for (const file of requiredFiles) {
  if (tarballFiles.includes(file)) {
    success(file);
  } else {
    error(`Missing: ${file}`);
  }
}

// Check 2: Import resolution validation
console.log("\n2. Validating import resolution paths...\n");

const importChecks = [
  {
    file: "client/lib/lib/moduleScoring.js",
    imports: "../../package.json",
    resolves: "client/package.json",
    description: "moduleScoring.js → client/package.json",
  },
  {
    file: "cli/build/index.js",
    imports: "../package.json",
    resolves: "cli/package.json",
    description: "cli/index.js → cli/package.json",
  },
];

for (const check of importChecks) {
  const hasSource = tarballFiles.includes(check.file);
  const hasTarget = tarballFiles.includes(check.resolves);

  if (!hasSource) {
    warn(`Source file not found: ${check.file}`);
    continue;
  }

  if (hasTarget) {
    success(check.description);
  } else {
    error(
      `Import broken: ${check.file} imports ${check.imports} but ${check.resolves} is missing`,
    );
  }
}

// Check 3: Binary entries have corresponding files
console.log("\n3. Checking binary entry points...\n");

const rootPkg = JSON.parse(
  fs.readFileSync(path.join(projectRoot, "package.json"), "utf-8"),
);

for (const [binName, binPath] of Object.entries(rootPkg.bin || {})) {
  if (tarballFiles.includes(binPath)) {
    success(`${binName} → ${binPath}`);
  } else {
    error(`Binary missing: ${binName} → ${binPath}`);
  }
}

// Check 4: ESM import attributes in built files
console.log("\n4. Checking ESM import attributes in tarball files...\n");

const moduleScoringPath = path.join(
  projectRoot,
  "client/lib/lib/moduleScoring.js",
);

if (fs.existsSync(moduleScoringPath)) {
  const content = fs.readFileSync(moduleScoringPath, "utf-8");

  // Check for JSON imports with proper attributes
  const jsonImportWithAttr =
    /import\s+\w+\s+from\s+["'][^"']+\.json["']\s+with\s*\{\s*type:\s*["']json["']\s*\}/;
  const jsonImportWithoutAttr =
    /import\s+\w+\s+from\s+["'][^"']+\.json["'](?!\s+with)/;

  if (jsonImportWithAttr.test(content)) {
    success("moduleScoring.js has ESM import attributes");
  } else if (jsonImportWithoutAttr.test(content)) {
    error("moduleScoring.js missing ESM import attribute for JSON import");
  } else {
    success("moduleScoring.js has no JSON imports (OK)");
  }
} else {
  warn("client/lib not built - skipping ESM check");
}

// Summary
console.log("\n=== Summary ===\n");

if (hasErrors) {
  console.error(
    "\x1b[31mValidation FAILED\x1b[0m - Tarball missing required runtime files\n",
  );
  console.log("Common fixes:");
  console.log("  - Add missing files to 'files' array in package.json");
  console.log("  - Add 'with { type: \"json\" }' to JSON imports in source");
  console.log("  - Run 'npm run build' before validation\n");
  process.exit(1);
} else {
  console.log(
    "\x1b[32mValidation PASSED\x1b[0m - All runtime dependencies present in tarball\n",
  );
  process.exit(0);
}

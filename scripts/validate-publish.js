#!/usr/bin/env node

/**
 * Pre-Publish Validation Script
 *
 * Validates package.json structure before publishing to npm to prevent
 * the workspace dependency bug (commit 09d8198) from recurring.
 *
 * Checks:
 * 1. No workspace packages listed as dependencies
 * 2. All workspace versions match root version
 * 3. Files array includes workspace build directories
 *
 * Usage:
 *   node scripts/validate-publish.js
 *
 * Exit codes:
 *   0 - All validations passed
 *   1 - Validation failed
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

const WORKSPACE_PACKAGE_PREFIXES = [
  "@bryan-thompson/inspector-assessment-",
  "@modelcontextprotocol/inspector-",
];

let hasErrors = false;

function error(message) {
  console.error(`\x1b[31m ERROR \x1b[0m ${message}`);
  hasErrors = true;
}

function warn(message) {
  console.warn(`\x1b[33m WARN \x1b[0m ${message}`);
}

function success(message) {
  console.log(`\x1b[32m PASS \x1b[0m ${message}`);
}

function info(message) {
  console.log(`\x1b[36m INFO \x1b[0m ${message}`);
}

// Load root package.json
const rootPkgPath = path.join(projectRoot, "package.json");
const rootPkg = JSON.parse(fs.readFileSync(rootPkgPath, "utf-8"));

console.log("\n=== Pre-Publish Validation ===\n");
info(`Package: ${rootPkg.name}@${rootPkg.version}`);
console.log("");

// Check 1: No workspace packages as dependencies
console.log("1. Checking for workspace packages in dependencies...");

const allDeps = {
  ...rootPkg.dependencies,
  ...rootPkg.devDependencies,
};

const workspaceDeps = Object.keys(allDeps).filter((dep) =>
  WORKSPACE_PACKAGE_PREFIXES.some((prefix) => dep.startsWith(prefix)),
);

if (workspaceDeps.length > 0) {
  error(
    `Found workspace packages in dependencies: ${workspaceDeps.join(", ")}`,
  );
  console.log("");
  console.log("   WHY THIS IS A PROBLEM:");
  console.log(
    "   Workspace packages are bundled via the 'files' array, not installed from npm.",
  );
  console.log(
    "   When users run 'npx', npm tries to fetch these packages from the registry.",
  );
  console.log(
    "   If versions mismatch, installation fails with ETARGET errors.",
  );
  console.log("");
  console.log(
    "   FIX: Remove these entries from dependencies/devDependencies in package.json",
  );
} else {
  success("No workspace packages in dependencies");
}

// Check 2: Version consistency across workspaces
console.log("\n2. Checking version consistency across workspaces...");

const workspaces = rootPkg.workspaces || [];
let versionMismatches = [];

for (const workspace of workspaces) {
  const workspacePkgPath = path.join(projectRoot, workspace, "package.json");
  if (fs.existsSync(workspacePkgPath)) {
    const workspacePkg = JSON.parse(fs.readFileSync(workspacePkgPath, "utf-8"));
    if (workspacePkg.version !== rootPkg.version) {
      versionMismatches.push({
        workspace,
        version: workspacePkg.version,
        expected: rootPkg.version,
      });
    }
  }
}

if (versionMismatches.length > 0) {
  for (const mismatch of versionMismatches) {
    error(
      `${mismatch.workspace}: version ${mismatch.version} != root ${mismatch.expected}`,
    );
  }
  console.log("");
  console.log("   FIX: Run 'npm version patch' to sync all workspace versions");
} else {
  success(`All ${workspaces.length} workspaces at version ${rootPkg.version}`);
}

// Check 3: Files array includes workspace builds
console.log("\n3. Checking files array includes workspace builds...");

const files = rootPkg.files || [];
const requiredPatterns = [
  { pattern: /cli/, name: "cli" },
  { pattern: /client/, name: "client" },
  { pattern: /server/, name: "server" },
];

const missingPatterns = requiredPatterns.filter(
  ({ pattern }) => !files.some((f) => pattern.test(f)),
);

if (missingPatterns.length > 0) {
  for (const { name } of missingPatterns) {
    error(`Missing '${name}' directory in files array`);
  }
} else {
  success("All workspace build directories included in files array");
}

// Check 4: Build directories exist
console.log("\n4. Checking build directories exist...");

const buildDirs = ["cli/build", "server/build", "client/dist"];

const missingBuilds = buildDirs.filter(
  (dir) => !fs.existsSync(path.join(projectRoot, dir)),
);

if (missingBuilds.length > 0) {
  for (const dir of missingBuilds) {
    warn(`Build directory missing: ${dir} (run 'npm run build' first)`);
  }
} else {
  success("All build directories exist");
}

// Summary
console.log("\n=== Summary ===\n");

if (hasErrors) {
  console.error(
    "\x1b[31mValidation FAILED\x1b[0m - Fix errors before publishing",
  );
  process.exit(1);
} else {
  console.log("\x1b[32mValidation PASSED\x1b[0m - Safe to publish");
  process.exit(0);
}

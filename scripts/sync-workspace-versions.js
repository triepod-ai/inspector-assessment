#!/usr/bin/env node
/**
 * Sync Workspace Versions
 *
 * Automatically syncs all workspace package versions and shared dependencies
 * when npm version is called. This prevents CI failures from version mismatches.
 *
 * Usage:
 *   node scripts/sync-workspace-versions.js
 *
 * Automatically called by npm version lifecycle hook.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rootDir = path.join(__dirname, "..");
const rootPkgPath = path.join(rootDir, "package.json");
const rootPkg = JSON.parse(fs.readFileSync(rootPkgPath, "utf8"));
const version = rootPkg.version;

// Shared dependencies that should be synced from root to all workspaces
// Add dependencies here that must stay consistent across the monorepo
const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk"];

const workspaces = ["client", "server", "cli"];

console.log(`Syncing all workspace versions to ${version}...`);

// Update workspace package.json files
for (const ws of workspaces) {
  const pkgPath = path.join(rootDir, ws, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  pkg.version = version;
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
  console.log(`  ✓ ${ws}/package.json → ${version}`);
}

// Sync shared dependencies from root to workspaces
console.log("\nSyncing shared dependencies...");
let depsSynced = 0;

for (const dep of SHARED_DEPENDENCIES) {
  const rootVersion = rootPkg.dependencies?.[dep];
  if (!rootVersion) {
    console.log(`  ⚠ ${dep} not found in root dependencies, skipping`);
    continue;
  }

  for (const ws of workspaces) {
    const pkgPath = path.join(rootDir, ws, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

    if (pkg.dependencies?.[dep]) {
      if (pkg.dependencies[dep] !== rootVersion) {
        pkg.dependencies[dep] = rootVersion;
        fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
        console.log(`  ✓ ${ws}: ${dep} → ${rootVersion}`);
        depsSynced++;
      }
    }
  }
}

if (depsSynced === 0) {
  console.log("  (all shared dependencies already in sync)");
}

console.log("\n✓ All versions and dependencies synced");

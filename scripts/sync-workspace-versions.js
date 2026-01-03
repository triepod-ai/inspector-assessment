#!/usr/bin/env node
/**
 * Sync Workspace Versions
 *
 * Automatically syncs all workspace package versions and root dependencies
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

console.log(`Syncing all workspace versions to ${version}...`);

// Update workspace package.json files
const workspaces = ["client", "server", "cli"];
for (const ws of workspaces) {
  const pkgPath = path.join(rootDir, ws, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  pkg.version = version;
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
  console.log(`  ✓ ${ws}/package.json → ${version}`);
}

// Note: Workspace packages are bundled directly via relative imports,
// not listed as npm dependencies. The root package.json only contains
// actual external dependencies like @modelcontextprotocol/sdk.

console.log("✓ All versions synced");

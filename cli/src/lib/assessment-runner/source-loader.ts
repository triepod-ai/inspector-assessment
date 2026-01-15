/**
 * Source File Loading
 *
 * Handles recursive source file discovery with gitignore support.
 *
 * @module cli/lib/assessment-runner/source-loader
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import type { SourceFiles } from "./types.js";

/** Maximum file size (in characters) to include in source code analysis */
const MAX_SOURCE_FILE_SIZE = 100_000;

/**
 * Load optional files from source code path
 *
 * @param sourcePath - Path to source code directory
 * @param debug - Enable debug logging for path resolution troubleshooting
 * @returns Object containing loaded source files
 */
export function loadSourceFiles(
  sourcePath: string,
  debug: boolean = false,
): SourceFiles {
  const result: Record<string, unknown> = {};

  // Debug logging helper - masks home directory for privacy in logs
  const log = (msg: string) => {
    if (!debug) return;
    const maskedMsg = msg.replace(os.homedir(), "~");
    console.log(`[source-loader] ${maskedMsg}`);
  };

  log(`Starting source file loading from: ${sourcePath}`);

  // Search for README in source directory and parent directories (up to 3 levels)
  // This handles cases where --source points to a subdirectory but README is at repo root
  // Extended patterns to handle various README naming conventions
  const readmePaths = [
    "README.md",
    "readme.md",
    "Readme.md",
    "README.markdown",
    "readme.markdown",
    "README.txt",
    "readme.txt",
    "README",
    "Readme",
  ];
  let readmeFound = false;

  log(`Searching for README variants: ${readmePaths.join(", ")}`);

  // First try the source directory itself
  for (const readmePath of readmePaths) {
    const fullPath = path.join(sourcePath, readmePath);
    const exists = fs.existsSync(fullPath);
    log(`  Checking: ${fullPath} - exists: ${exists}`);
    if (exists) {
      result.readmeContent = fs.readFileSync(fullPath, "utf-8");
      log(
        `  ✓ Found README: ${fullPath} (${(result.readmeContent as string).length} bytes)`,
      );
      readmeFound = true;
      break;
    }
  }

  // If not found, search parent directories (up to 3 levels)
  if (!readmeFound) {
    log(
      `README not found in source directory, searching parent directories...`,
    );
    let currentDir = sourcePath;
    for (let i = 0; i < 3; i++) {
      const parentDir = path.dirname(currentDir);
      if (parentDir === currentDir) {
        log(`  Reached filesystem root, stopping parent search`);
        break; // Reached filesystem root
      }

      log(`  Searching parent level ${i + 1}: ${parentDir}`);
      for (const readmePath of readmePaths) {
        const fullPath = path.join(parentDir, readmePath);
        const exists = fs.existsSync(fullPath);
        log(`    Checking: ${fullPath} - exists: ${exists}`);
        if (exists) {
          result.readmeContent = fs.readFileSync(fullPath, "utf-8");
          log(
            `    ✓ Found README: ${fullPath} (${(result.readmeContent as string).length} bytes)`,
          );
          readmeFound = true;
          break;
        }
      }
      if (readmeFound) break;
      currentDir = parentDir;
    }
  }

  if (!readmeFound) {
    log(`✗ No README found in source directory or parent directories`);
  }

  const packagePath = path.join(sourcePath, "package.json");
  if (fs.existsSync(packagePath)) {
    result.packageJson = JSON.parse(fs.readFileSync(packagePath, "utf-8"));
  }

  const manifestPath = path.join(sourcePath, "manifest.json");
  if (fs.existsSync(manifestPath)) {
    result.manifestRaw = fs.readFileSync(manifestPath, "utf-8");
    try {
      result.manifestJson = JSON.parse(result.manifestRaw as string);
    } catch {
      console.warn("[Assessment] Failed to parse manifest.json");
    }
  }

  // Issue #172: Load server.json for transport configuration
  const serverJsonPath = path.join(sourcePath, "server.json");
  if (fs.existsSync(serverJsonPath)) {
    try {
      result.serverJson = JSON.parse(fs.readFileSync(serverJsonPath, "utf-8"));
      log(`  ✓ Found server.json`);
    } catch {
      console.warn("[Assessment] Failed to parse server.json");
    }
  }

  result.sourceCodeFiles = new Map<string, string>();
  // Include config files for portability analysis
  const sourceExtensions = [
    ".ts",
    ".js",
    ".py",
    ".go",
    ".rs",
    ".json",
    ".sh",
    ".yaml",
    ".yml",
  ];

  // Parse .gitignore patterns
  const gitignorePatterns: RegExp[] = [];
  const gitignorePath = path.join(sourcePath, ".gitignore");
  if (fs.existsSync(gitignorePath)) {
    const gitignoreContent = fs.readFileSync(gitignorePath, "utf-8");
    for (const line of gitignoreContent.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      // Convert gitignore pattern to regex
      const pattern = trimmed
        .replace(/\./g, "\\.")
        .replace(/\*\*/g, ".*")
        .replace(/\*/g, "[^/]*")
        .replace(/\?/g, ".");
      try {
        gitignorePatterns.push(new RegExp(pattern));
      } catch {
        // Skip invalid patterns
      }
    }
  }

  const isGitignored = (relativePath: string): boolean => {
    return gitignorePatterns.some((pattern) => pattern.test(relativePath));
  };

  const loadSourceDir = (dir: string, prefix: string = "") => {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith(".") || entry.name === "node_modules") continue;

      const fullPath = path.join(dir, entry.name);
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;

      // Skip gitignored files
      if (isGitignored(relativePath)) continue;

      if (entry.isDirectory()) {
        loadSourceDir(fullPath, relativePath);
      } else if (sourceExtensions.some((ext) => entry.name.endsWith(ext))) {
        try {
          const content = fs.readFileSync(fullPath, "utf-8");
          if (content.length < MAX_SOURCE_FILE_SIZE) {
            (result.sourceCodeFiles as Map<string, string>).set(
              relativePath,
              content,
            );
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  };

  try {
    loadSourceDir(sourcePath);
  } catch (e) {
    console.warn("[Assessment] Could not load source files:", e);
  }

  // Summary logging
  const sourceCodeFiles = result.sourceCodeFiles as Map<string, string>;
  log(`Source loading complete:`);
  log(`  - README: ${result.readmeContent ? "found" : "not found"}`);
  log(`  - package.json: ${result.packageJson ? "found" : "not found"}`);
  log(`  - manifest.json: ${result.manifestJson ? "found" : "not found"}`);
  log(`  - Source files loaded: ${sourceCodeFiles.size}`);

  return result as SourceFiles;
}

/**
 * Source File Loading
 *
 * Handles recursive source file discovery with gitignore support.
 *
 * @module cli/lib/assessment-runner/source-loader
 */

import * as fs from "fs";
import * as path from "path";

import type { SourceFiles } from "./types.js";

/**
 * Load optional files from source code path
 *
 * @param sourcePath - Path to source code directory
 * @returns Object containing loaded source files
 */
export function loadSourceFiles(sourcePath: string): SourceFiles {
  const result: Record<string, unknown> = {};

  // Search for README in source directory and parent directories (up to 3 levels)
  // This handles cases where --source points to a subdirectory but README is at repo root
  const readmePaths = ["README.md", "readme.md", "Readme.md"];
  let readmeFound = false;

  // First try the source directory itself
  for (const readmePath of readmePaths) {
    const fullPath = path.join(sourcePath, readmePath);
    if (fs.existsSync(fullPath)) {
      result.readmeContent = fs.readFileSync(fullPath, "utf-8");
      readmeFound = true;
      break;
    }
  }

  // If not found, search parent directories (up to 3 levels)
  if (!readmeFound) {
    let currentDir = sourcePath;
    for (let i = 0; i < 3; i++) {
      const parentDir = path.dirname(currentDir);
      if (parentDir === currentDir) break; // Reached filesystem root

      for (const readmePath of readmePaths) {
        const fullPath = path.join(parentDir, readmePath);
        if (fs.existsSync(fullPath)) {
          result.readmeContent = fs.readFileSync(fullPath, "utf-8");
          readmeFound = true;
          break;
        }
      }
      if (readmeFound) break;
      currentDir = parentDir;
    }
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
          if (content.length < 100000) {
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

  return result as SourceFiles;
}

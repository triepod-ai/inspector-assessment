/**
 * Path Resolution Utilities
 *
 * Handles path normalization for source code paths including:
 * - Home directory (~) expansion
 * - Relative path resolution
 * - Symlink resolution (for MCPB temp extraction paths)
 *
 * @module cli/lib/assessment-runner/path-resolver
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/**
 * Resolve a source code path to an absolute, real path
 *
 * Handles:
 * - Tilde (~) expansion to home directory
 * - Relative paths resolved to absolute
 * - Symlinks followed to real paths (important for MCPB temp extraction)
 *
 * @param sourcePath - The source path to resolve (may be relative, contain ~, or be a symlink)
 * @returns The resolved absolute path, or the original path if resolution fails
 *
 * @example
 * resolveSourcePath("~/project") // => "/home/user/project"
 * resolveSourcePath("./src") // => "/current/working/dir/src"
 * resolveSourcePath("/tmp/symlink") // => "/actual/target/path"
 */
export function resolveSourcePath(sourcePath: string): string {
  let resolved = sourcePath;

  // Expand home directory (~)
  if (resolved.startsWith("~")) {
    resolved = path.join(os.homedir(), resolved.slice(1));
  }

  // Resolve to absolute path
  resolved = path.resolve(resolved);

  // Follow symlinks if path exists (handles MCPB temp extraction paths)
  try {
    if (fs.existsSync(resolved)) {
      resolved = fs.realpathSync(resolved);
    }
  } catch {
    // realpathSync can fail on broken symlinks, continue with resolved path
  }

  return resolved;
}

/**
 * Package Structure Validation Tests
 *
 * Prevents regression of the workspace dependency bug (commit 09d8198).
 *
 * Background: The root package.json incorrectly listed workspace packages
 * (@bryan-thompson/inspector-assessment-cli, -client, -server) as npm
 * dependencies. This caused installation failures because:
 * 1. Workspace packages are bundled via the `files` array, not installed from npm
 * 2. Version mismatches caused npm ETARGET errors
 *
 * These tests ensure workspace architecture remains correct.
 */

import * as fs from "fs";
import * as path from "path";

// Find project root by looking for package.json with workspaces
const findProjectRoot = (): string => {
  let dir = __dirname;
  let iterations = 0;
  const maxIterations = 20; // Prevent infinite loops on edge cases
  while (dir !== "/" && iterations < maxIterations) {
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
      if (pkg.workspaces) {
        return dir;
      }
    }
    dir = path.dirname(dir);
    iterations++;
  }
  throw new Error("Could not find project root with workspaces");
};

describe("Package Structure Validation", () => {
  const projectRoot = findProjectRoot();
  const rootPkg = JSON.parse(
    fs.readFileSync(path.join(projectRoot, "package.json"), "utf-8"),
  );

  describe("Workspace Dependencies", () => {
    it("should NOT have workspace packages as npm dependencies", () => {
      // This is the critical test that prevents the bug from recurring
      const deps = Object.keys(rootPkg.dependencies || {});
      const workspaceDeps = deps.filter(
        (d) =>
          d.startsWith("@bryan-thompson/inspector-assessment-") ||
          d.startsWith("@modelcontextprotocol/inspector-"),
      );

      expect(workspaceDeps).toHaveLength(0);

      if (workspaceDeps.length > 0) {
        throw new Error(
          `Found workspace packages in dependencies: ${workspaceDeps.join(", ")}.\n` +
            `Workspace packages are bundled via the 'files' array, not installed from npm.\n` +
            `Remove these dependencies to fix installation errors.`,
        );
      }
    });

    it("should NOT have workspace packages as devDependencies", () => {
      const devDeps = Object.keys(rootPkg.devDependencies || {});
      const workspaceDeps = devDeps.filter(
        (d) =>
          d.startsWith("@bryan-thompson/inspector-assessment-") ||
          d.startsWith("@modelcontextprotocol/inspector-"),
      );

      expect(workspaceDeps).toHaveLength(0);
    });
  });

  describe("Workspace Configuration", () => {
    it("should have workspaces defined", () => {
      expect(rootPkg.workspaces).toBeDefined();
      expect(Array.isArray(rootPkg.workspaces)).toBe(true);
      expect(rootPkg.workspaces).toContain("client");
      expect(rootPkg.workspaces).toContain("server");
      expect(rootPkg.workspaces).toContain("cli");
    });

    it("should have files array for bundling workspace content", () => {
      expect(rootPkg.files).toBeDefined();
      expect(Array.isArray(rootPkg.files)).toBe(true);

      // Verify key workspace directories are in files
      const hasClientBuild =
        rootPkg.files.some((f: string) => f.includes("client/")) ||
        rootPkg.files.includes("client");
      const hasServerBuild =
        rootPkg.files.some((f: string) => f.includes("server/")) ||
        rootPkg.files.includes("server");
      const hasCliBuild =
        rootPkg.files.some((f: string) => f.includes("cli/")) ||
        rootPkg.files.includes("cli");

      expect(hasClientBuild).toBe(true);
      expect(hasServerBuild).toBe(true);
      expect(hasCliBuild).toBe(true);
    });
  });

  describe("Version Consistency", () => {
    it("should have workspace packages at matching versions", () => {
      const rootVersion = rootPkg.version;

      for (const workspace of rootPkg.workspaces || []) {
        const workspacePkgPath = path.join(
          projectRoot,
          workspace,
          "package.json",
        );
        if (fs.existsSync(workspacePkgPath)) {
          const workspacePkg = JSON.parse(
            fs.readFileSync(workspacePkgPath, "utf-8"),
          );
          expect(workspacePkg.version).toBe(rootVersion);
        }
      }
    });
  });

  describe("Binary Configuration", () => {
    it("should have bin entries pointing to workspace builds", () => {
      expect(rootPkg.bin).toBeDefined();

      // Verify bin entries point to local files, not node_modules
      for (const [_name, binPath] of Object.entries(rootPkg.bin || {})) {
        expect(binPath).not.toContain("node_modules");
        expect(
          (binPath as string).startsWith("cli/") ||
            (binPath as string).startsWith("client/") ||
            (binPath as string).startsWith("server/"),
        ).toBe(true);
      }
    });
  });
});

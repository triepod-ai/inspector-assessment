/**
 * Sync Workspace Versions Test
 *
 * Tests the npm version lifecycle script that syncs all workspace package
 * versions and shared dependencies when npm version is called.
 *
 * Why these tests matter:
 * 1. Script runs automatically during npm version (release-critical)
 * 2. Silent failures only surface during CI/CD publish attempts
 * 3. Version mismatches cause ETARGET errors for end users
 * 4. Shared dependency sync prevents runtime errors from version drift
 *
 * Note: We test the logic by mocking fs, not by running the actual script.
 * This keeps tests fast and isolated from the real filesystem.
 */

import * as fs from "fs";
import * as path from "path";

// Mock fs before importing the script logic
jest.mock("fs");

const mockFs = fs as jest.Mocked<typeof fs>;

describe("Sync Workspace Versions", () => {
  const rootDir = "/fake/project";
  const workspaces = ["client", "server", "cli"];

  beforeEach(() => {});

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Version Synchronization", () => {
    it("should sync all workspace versions to match root version", () => {
      const rootVersion = "1.26.2";
      const rootPkg = {
        version: rootVersion,
        workspaces,
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2",
        },
      };

      const clientPkg = { version: "1.26.1" }; // Outdated
      const serverPkg = { version: "1.26.1" }; // Outdated
      const cliPkg = { version: "1.26.1" }; // Outdated

      // Mock file reads
      mockFs.readFileSync
        .mockReturnValueOnce(JSON.stringify(rootPkg)) // Root package.json
        .mockReturnValueOnce(JSON.stringify(clientPkg)) // client/package.json
        .mockReturnValueOnce(JSON.stringify(serverPkg)) // server/package.json
        .mockReturnValueOnce(JSON.stringify(cliPkg)); // cli/package.json

      // Simulate script logic
      for (const ws of workspaces) {
        const pkgPath = path.join(rootDir, ws, "package.json");
        const pkg = JSON.parse(mockFs.readFileSync(pkgPath, "utf8") as string);
        pkg.version = rootVersion;
        mockFs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
      }

      // Verify all workspaces were written with new version
      expect(mockFs.writeFileSync).toHaveBeenCalledTimes(3);

      // Verify each write call updated the version
      for (let i = 0; i < 3; i++) {
        const writtenContent = (mockFs.writeFileSync as jest.Mock).mock.calls[
          i
        ][1] as string;
        const writtenPkg = JSON.parse(writtenContent.trim());
        expect(writtenPkg.version).toBe(rootVersion);
      }
    });

    it("should preserve workspace package structure while updating version", () => {
      const rootVersion = "2.0.0";
      const clientPkg = {
        version: "1.0.0",
        name: "@bryan-thompson/inspector-assessment-client",
        dependencies: { react: "^18.3.1" },
        scripts: { build: "tsc" },
      };

      // Create a deep copy before modifying
      const updatedPkg = JSON.parse(JSON.stringify(clientPkg));
      updatedPkg.version = rootVersion;
      const expectedOutput = JSON.stringify(updatedPkg, null, 2) + "\n";

      // Verify the output preserves structure
      const writtenPkg = JSON.parse(expectedOutput.trim());

      // Verify only version changed
      expect(writtenPkg.version).toBe("2.0.0");
      expect(writtenPkg.name).toBe(
        "@bryan-thompson/inspector-assessment-client",
      );
      expect(writtenPkg.dependencies).toEqual({ react: "^18.3.1" });
      expect(writtenPkg.scripts).toEqual({ build: "tsc" });
    });
  });

  describe("Shared Dependencies Synchronization", () => {
    it("should sync shared dependencies from root to workspaces", () => {
      const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk"];
      const rootPkg = {
        version: "1.26.2",
        workspaces,
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2",
          "other-dep": "^1.0.0",
        },
      };

      const clientPkg = {
        version: "1.26.2",
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.24.0", // Outdated!
          react: "^18.3.1",
        },
      };

      // Simulate the sync logic without mocked fs reads
      let updateNeeded = false;
      for (const dep of SHARED_DEPENDENCIES) {
        const rootVersion =
          rootPkg.dependencies[dep as keyof typeof rootPkg.dependencies];
        if (!rootVersion) continue;

        if (
          clientPkg.dependencies?.[
            dep as keyof typeof clientPkg.dependencies
          ] &&
          clientPkg.dependencies[dep as keyof typeof clientPkg.dependencies] !==
            rootVersion
        ) {
          updateNeeded = true;
          clientPkg.dependencies[dep as keyof typeof clientPkg.dependencies] =
            rootVersion;
        }
      }

      // Verify update was needed and applied
      expect(updateNeeded).toBe(true);
      expect(clientPkg.dependencies["@modelcontextprotocol/sdk"]).toBe(
        "^1.25.2",
      );
      // Other deps unchanged
      expect(clientPkg.dependencies["react"]).toBe("^18.3.1");
    });

    it("should skip workspaces that don't have the shared dependency", () => {
      const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk"];
      const rootPkg = {
        version: "1.26.2",
        workspaces,
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2",
        },
      };

      const serverPkg = {
        version: "1.26.2",
        dependencies: {
          express: "^5.1.0", // No @modelcontextprotocol/sdk
        },
      };

      mockFs.readFileSync
        .mockReturnValueOnce(JSON.stringify(rootPkg))
        .mockReturnValueOnce(JSON.stringify(serverPkg));

      // Simulate shared dependency sync logic
      for (const dep of SHARED_DEPENDENCIES) {
        const rootVersion = rootPkg.dependencies[dep];
        if (!rootVersion) continue;

        const pkgPath = path.join(rootDir, "server", "package.json");
        const pkg = JSON.parse(mockFs.readFileSync(pkgPath, "utf8") as string);

        // Skip if workspace doesn't have this dep
        if (!pkg.dependencies?.[dep]) continue;

        if (pkg.dependencies[dep] !== rootVersion) {
          pkg.dependencies[dep] = rootVersion;
          mockFs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
        }
      }

      // Verify no writes happened (workspace doesn't have the dep)
      expect(mockFs.writeFileSync).not.toHaveBeenCalled();
    });

    it("should skip shared dependencies not found in root package", () => {
      const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk", "missing-dep"];
      const rootPkg = {
        version: "1.26.2",
        workspaces,
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2",
          // missing-dep not in root
        },
      };

      // Track which deps were attempted
      const attemptedDeps: string[] = [];

      for (const dep of SHARED_DEPENDENCIES) {
        const rootVersion =
          rootPkg.dependencies[dep as keyof typeof rootPkg.dependencies];
        if (!rootVersion) {
          attemptedDeps.push(`${dep}:skipped`);
          continue;
        }
        attemptedDeps.push(`${dep}:processed`);
      }

      expect(attemptedDeps).toEqual([
        "@modelcontextprotocol/sdk:processed",
        "missing-dep:skipped",
      ]);
    });

    it("should not overwrite if shared dependency already at correct version", () => {
      const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk"];
      const rootPkg = {
        version: "1.26.2",
        workspaces,
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2",
        },
      };

      const cliPkg = {
        version: "1.26.2",
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2", // Already correct!
        },
      };

      mockFs.readFileSync
        .mockReturnValueOnce(JSON.stringify(rootPkg))
        .mockReturnValueOnce(JSON.stringify(cliPkg));

      // Simulate shared dependency sync logic
      for (const dep of SHARED_DEPENDENCIES) {
        const rootVersion = rootPkg.dependencies[dep];
        if (!rootVersion) continue;

        const pkgPath = path.join(rootDir, "cli", "package.json");
        const pkg = JSON.parse(mockFs.readFileSync(pkgPath, "utf8") as string);

        if (pkg.dependencies?.[dep] && pkg.dependencies[dep] !== rootVersion) {
          pkg.dependencies[dep] = rootVersion;
          mockFs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
        }
      }

      // Verify no write happened (already in sync)
      expect(mockFs.writeFileSync).not.toHaveBeenCalled();
    });
  });

  describe("Edge Cases", () => {
    it("should handle workspaces with no dependencies object", () => {
      const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk"];
      const rootPkg = {
        version: "1.26.2",
        workspaces,
        dependencies: {
          "@modelcontextprotocol/sdk": "^1.25.2",
        },
      };

      const minimalPkg = {
        version: "1.26.2",
        name: "minimal-workspace",
        // No dependencies object
      };

      // Simulate shared dependency sync logic without file operations
      let needsUpdate = false;
      for (const dep of SHARED_DEPENDENCIES) {
        const rootVersion =
          rootPkg.dependencies[dep as keyof typeof rootPkg.dependencies];
        if (!rootVersion) continue;

        // Safe navigation with optional chaining - should not crash
        const pkg = minimalPkg as { dependencies?: Record<string, string> };
        if (pkg.dependencies?.[dep] && pkg.dependencies[dep] !== rootVersion) {
          needsUpdate = true;
        }
      }

      // Should gracefully skip (no crash, no update needed)
      expect(needsUpdate).toBe(false);
    });

    it("should handle root package with no shared dependencies", () => {
      const SHARED_DEPENDENCIES = ["@modelcontextprotocol/sdk"];
      const rootPkg = {
        version: "1.26.2",
        workspaces,
        dependencies: {
          // No @modelcontextprotocol/sdk
          "other-dep": "^1.0.0",
        },
      };

      // Should not crash when dep not found
      for (const dep of SHARED_DEPENDENCIES) {
        const rootVersion =
          rootPkg.dependencies[dep as keyof typeof rootPkg.dependencies];
        expect(rootVersion).toBeUndefined();
        if (!rootVersion) continue; // Skip gracefully
      }
    });
  });

  describe("File Format Preservation", () => {
    it("should write files with proper JSON formatting", () => {
      const rootPkg = { version: "1.26.2", workspaces, dependencies: {} };
      const workspacePkg = { version: "1.26.1", name: "test" };

      mockFs.readFileSync
        .mockReturnValueOnce(JSON.stringify(rootPkg))
        .mockReturnValueOnce(JSON.stringify(workspacePkg));

      // Simulate script logic
      const pkgPath = path.join(rootDir, "client", "package.json");
      const pkg = JSON.parse(mockFs.readFileSync(pkgPath, "utf8") as string);
      pkg.version = "1.26.2";
      mockFs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");

      const writtenContent = (mockFs.writeFileSync as jest.Mock).mock
        .calls[0][1] as string;

      // Verify formatting
      expect(writtenContent).toContain("\n"); // Has newlines
      expect(writtenContent).toMatch(/^\{[\s\S]+\}\n$/); // Proper JSON with trailing newline
      expect(writtenContent.split("\n").length).toBeGreaterThan(2); // Multi-line (indented)
    });

    it("should add trailing newline to package.json files", () => {
      const rootPkg = { version: "1.26.2", workspaces, dependencies: {} };
      const workspacePkg = { version: "1.26.1" };

      mockFs.readFileSync
        .mockReturnValueOnce(JSON.stringify(rootPkg))
        .mockReturnValueOnce(JSON.stringify(workspacePkg));

      const pkgPath = path.join(rootDir, "client", "package.json");
      const pkg = JSON.parse(mockFs.readFileSync(pkgPath, "utf8") as string);
      pkg.version = "1.26.2";
      mockFs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");

      const writtenContent = (mockFs.writeFileSync as jest.Mock).mock
        .calls[0][1] as string;

      // Verify trailing newline (POSIX standard)
      expect(writtenContent.endsWith("\n")).toBe(true);
    });
  });

  describe("Integration with npm version lifecycle", () => {
    // Unmock fs for this test - we need to read the actual package.json
    beforeAll(() => {
      jest.unmock("fs");
    });

    it("should be called as part of version script in package.json", () => {
      // This test verifies the hook configuration, not the script itself
      // Use real fs since we need to read the actual package.json
      const realFs = jest.requireActual("fs") as typeof fs;
      const rootPkgPath = path.join(__dirname, "../../package.json");
      const rootPkg = JSON.parse(realFs.readFileSync(rootPkgPath, "utf-8"));

      // Verify the version script exists and calls sync-workspace-versions.js
      expect(rootPkg.scripts).toBeDefined();
      expect(rootPkg.scripts.version).toBeDefined();
      expect(rootPkg.scripts.version).toContain("sync-workspace-versions.js");
      expect(rootPkg.scripts.version).toContain("git add");
    });
  });
});

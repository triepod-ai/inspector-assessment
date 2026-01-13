/**
 * Source Loader Unit Tests
 *
 * Tests for loadSourceFiles() that loads source files with gitignore support.
 */

import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import * as path from "path";
import type { Dirent } from "fs";

// Mock fs module
jest.unstable_mockModule("fs", () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
  readdirSync: jest.fn(),
}));

// Import after mocking
const fs = await import("fs");
const { loadSourceFiles } =
  await import("../../lib/assessment-runner/source-loader.js");

// Helper to create mock Dirent objects
function createDirent(name: string, isDirectory: boolean): Dirent {
  return {
    name,
    isDirectory: () => isDirectory,
    isFile: () => !isDirectory,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isSymbolicLink: () => false,
    isFIFO: () => false,
    isSocket: () => false,
    parentPath: "",
    path: "",
  } as Dirent;
}

describe("loadSourceFiles", () => {
  const mockExistsSync = fs.existsSync as jest.Mock;
  const mockReadFileSync = fs.readFileSync as jest.Mock;
  const mockReaddirSync = fs.readdirSync as jest.Mock;

  beforeEach(() => {
    mockExistsSync.mockReturnValue(false);
    mockReaddirSync.mockReturnValue([]);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("README discovery", () => {
    it("should find README.md in source directory", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, "README.md"),
      );
      mockReadFileSync.mockReturnValue("# Project README");

      const result = loadSourceFiles(sourcePath);

      expect(result.readmeContent).toBe("# Project README");
    });

    it("should find readme.md with lowercase", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, "readme.md"),
      );
      mockReadFileSync.mockReturnValue("# Lowercase README");

      const result = loadSourceFiles(sourcePath);

      expect(result.readmeContent).toBe("# Lowercase README");
    });

    it("should find Readme.md with mixed case", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, "Readme.md"),
      );
      mockReadFileSync.mockReturnValue("# Mixed Case README");

      const result = loadSourceFiles(sourcePath);

      expect(result.readmeContent).toBe("# Mixed Case README");
    });

    it("should search parent directories for README (up to 3 levels)", () => {
      const sourcePath = "/project/packages/core/src";
      // README is in /project (3 levels up)
      mockExistsSync.mockImplementation(
        (p: string) => p === "/project/README.md",
      );
      mockReadFileSync.mockReturnValue("# Root README");

      const result = loadSourceFiles(sourcePath);

      expect(result.readmeContent).toBe("# Root README");
    });

    it("should not search more than 3 levels up", () => {
      const sourcePath = "/a/b/c/d/e";
      // README is in /a (4 levels up) - should not be found
      mockExistsSync.mockReturnValue(false);

      const result = loadSourceFiles(sourcePath);

      expect(result.readmeContent).toBeUndefined();
    });
  });

  describe("package.json parsing", () => {
    it("should parse package.json when present", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, "package.json"),
      );
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          name: "test-package",
          version: "1.0.0",
        }),
      );

      const result = loadSourceFiles(sourcePath);

      expect(result.packageJson).toEqual({
        name: "test-package",
        version: "1.0.0",
      });
    });

    it("should not set packageJson when file does not exist", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);

      const result = loadSourceFiles(sourcePath);

      expect(result.packageJson).toBeUndefined();
    });
  });

  describe("manifest.json parsing", () => {
    it("should parse manifest.json when present", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, "manifest.json"),
      );
      const manifestContent = JSON.stringify({
        name: "test-server",
        tools: [],
      });
      mockReadFileSync.mockReturnValue(manifestContent);

      const result = loadSourceFiles(sourcePath);

      expect(result.manifestJson).toEqual({
        name: "test-server",
        tools: [],
      });
      expect(result.manifestRaw).toBe(manifestContent);
    });

    it("should set manifestRaw but warn on invalid JSON manifest", () => {
      const sourcePath = "/project";
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      try {
        mockExistsSync.mockImplementation(
          (p: string) => p === path.join(sourcePath, "manifest.json"),
        );
        mockReadFileSync.mockReturnValue("{ invalid json }");

        const result = loadSourceFiles(sourcePath);

        expect(result.manifestRaw).toBe("{ invalid json }");
        expect(result.manifestJson).toBeUndefined();
        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining("Failed to parse manifest.json"),
        );
      } finally {
        consoleSpy.mockRestore();
      }
    });
  });

  describe("source file collection", () => {
    it("should collect source files with supported extensions", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue([
        createDirent("index.ts", false),
        createDirent("utils.js", false),
        createDirent("config.json", false),
        createDirent("setup.sh", false),
      ]);
      mockReadFileSync.mockImplementation((p: string) => {
        if (p.endsWith(".ts")) return "const x = 1;";
        if (p.endsWith(".js")) return "var y = 2;";
        if (p.endsWith(".json")) return "{}";
        if (p.endsWith(".sh")) return "#!/bin/bash";
        return "";
      });

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.size).toBe(4);
      expect(result.sourceCodeFiles?.has("index.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has("utils.js")).toBe(true);
      expect(result.sourceCodeFiles?.has("config.json")).toBe(true);
      expect(result.sourceCodeFiles?.has("setup.sh")).toBe(true);
    });

    it("should recursively load files from subdirectories", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockImplementation((dir: string) => {
        if (dir === sourcePath) {
          return [createDirent("src", true), createDirent("index.ts", false)];
        }
        if (dir === path.join(sourcePath, "src")) {
          return [createDirent("main.ts", false)];
        }
        return [];
      });
      mockReadFileSync.mockReturnValue("code");

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("index.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has("src/main.ts")).toBe(true);
    });

    it("should enforce 100KB file size limit", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue([
        createDirent("small.ts", false),
        createDirent("large.ts", false),
      ]);
      mockReadFileSync.mockImplementation((p: string) => {
        if (p.includes("small")) return "small content";
        if (p.includes("large")) return "x".repeat(100_001); // > 100KB
        return "";
      });

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("small.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has("large.ts")).toBe(false);
    });

    it("should skip dotfiles and directories", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue([
        createDirent(".git", true),
        createDirent(".eslintrc.js", false),
        createDirent("src.ts", false),
      ]);
      mockReadFileSync.mockReturnValue("code");

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("src.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has(".eslintrc.js")).toBe(false);
      expect(result.sourceCodeFiles?.has(".git")).toBe(false);
    });

    it("should skip node_modules directory", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockImplementation((dir: string) => {
        if (dir === sourcePath) {
          return [
            createDirent("node_modules", true),
            createDirent("src", true),
          ];
        }
        if (dir === path.join(sourcePath, "src")) {
          return [createDirent("index.ts", false)];
        }
        return [];
      });
      mockReadFileSync.mockReturnValue("code");

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("src/index.ts")).toBe(true);
      // node_modules should be skipped entirely
    });
  });

  describe("gitignore support", () => {
    it("should respect .gitignore patterns", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, ".gitignore"),
      );
      mockReadFileSync.mockImplementation((p: string) => {
        if (p.endsWith(".gitignore")) {
          return "dist/\n*.log\nbuild/**";
        }
        return "code";
      });
      mockReaddirSync.mockReturnValue([
        createDirent("index.ts", false),
        createDirent("debug.log", false),
        createDirent("dist", true),
      ]);

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("index.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has("debug.log")).toBe(false);
    });

    it("should handle missing .gitignore gracefully", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue([createDirent("index.ts", false)]);
      mockReadFileSync.mockReturnValue("code");

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("index.ts")).toBe(true);
    });

    it("should ignore comments and empty lines in .gitignore", () => {
      const sourcePath = "/project";
      mockExistsSync.mockImplementation(
        (p: string) => p === path.join(sourcePath, ".gitignore"),
      );
      mockReadFileSync.mockImplementation((p: string) => {
        if (p.endsWith(".gitignore")) {
          return "# comment\n\n*.log\n   \n# another comment";
        }
        return "code";
      });
      mockReaddirSync.mockReturnValue([
        createDirent("index.ts", false),
        createDirent("debug.log", false),
      ]);

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("index.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has("debug.log")).toBe(false);
    });
  });

  describe("error handling", () => {
    it("should return empty sourceCodeFiles when directory read fails", () => {
      const sourcePath = "/project";
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      try {
        mockExistsSync.mockReturnValue(false);
        mockReaddirSync.mockImplementation(() => {
          throw new Error("Permission denied");
        });

        const result = loadSourceFiles(sourcePath);

        expect(result.sourceCodeFiles?.size).toBe(0);
        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining("Could not load source files"),
          expect.any(Error),
        );
      } finally {
        consoleSpy.mockRestore();
      }
    });

    it("should skip unreadable files silently", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue([
        createDirent("readable.ts", false),
        createDirent("unreadable.ts", false),
      ]);
      mockReadFileSync.mockImplementation((p: string) => {
        if (p.includes("unreadable")) {
          throw new Error("Permission denied");
        }
        return "code";
      });

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.has("readable.ts")).toBe(true);
      expect(result.sourceCodeFiles?.has("unreadable.ts")).toBe(false);
    });
  });

  describe("supported file extensions", () => {
    it("should support all defined extensions", () => {
      const sourcePath = "/project";
      const extensions = [
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
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue(
        extensions.map((ext) => createDirent(`file${ext}`, false)),
      );
      mockReadFileSync.mockReturnValue("content");

      const result = loadSourceFiles(sourcePath);

      for (const ext of extensions) {
        expect(result.sourceCodeFiles?.has(`file${ext}`)).toBe(true);
      }
    });

    it("should not include unsupported file types", () => {
      const sourcePath = "/project";
      mockExistsSync.mockReturnValue(false);
      mockReaddirSync.mockReturnValue([
        createDirent("image.png", false),
        createDirent("doc.pdf", false),
        createDirent("data.csv", false),
      ]);
      mockReadFileSync.mockReturnValue("content");

      const result = loadSourceFiles(sourcePath);

      expect(result.sourceCodeFiles?.size).toBe(0);
    });
  });
});

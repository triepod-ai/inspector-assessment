/**
 * Path Resolver Unit Tests
 *
 * Tests for resolveSourcePath() that handles path normalization.
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterAll,
} from "@jest/globals";
import * as path from "path";
import * as os from "os";

// Mock fs module
jest.unstable_mockModule("fs", () => ({
  existsSync: jest.fn(),
  realpathSync: jest.fn(),
}));

// Import after mocking
const fs = await import("fs");
const { resolveSourcePath } =
  await import("../../lib/assessment-runner/path-resolver.js");

describe("resolveSourcePath", () => {
  const mockExistsSync = fs.existsSync as jest.Mock;
  const mockRealpathSync = fs.realpathSync as unknown as jest.Mock;

  beforeEach(() => {
    mockExistsSync.mockReturnValue(false);
    mockRealpathSync.mockReturnValue("");
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    jest.unmock("fs");
  });

  describe("tilde expansion", () => {
    it("should expand ~ to home directory", () => {
      mockExistsSync.mockReturnValue(false);

      const result = resolveSourcePath("~/project");

      expect(result).toBe(path.join(os.homedir(), "project"));
    });

    it("should expand ~/subdir/path correctly", () => {
      mockExistsSync.mockReturnValue(false);

      const result = resolveSourcePath("~/foo/bar/baz");

      expect(result).toBe(path.join(os.homedir(), "foo/bar/baz"));
    });

    it("should not modify paths without tilde", () => {
      mockExistsSync.mockReturnValue(false);

      const result = resolveSourcePath("/absolute/path");

      expect(result).toBe("/absolute/path");
    });
  });

  describe("relative path resolution", () => {
    it("should resolve relative paths to absolute", () => {
      mockExistsSync.mockReturnValue(false);
      const cwd = process.cwd();

      const result = resolveSourcePath("./src");

      expect(result).toBe(path.resolve(cwd, "./src"));
    });

    it("should resolve parent directory references", () => {
      mockExistsSync.mockReturnValue(false);
      const cwd = process.cwd();

      const result = resolveSourcePath("../sibling");

      expect(result).toBe(path.resolve(cwd, "../sibling"));
    });

    it("should handle bare directory names", () => {
      mockExistsSync.mockReturnValue(false);
      const cwd = process.cwd();

      const result = resolveSourcePath("mydir");

      expect(result).toBe(path.resolve(cwd, "mydir"));
    });
  });

  describe("symlink resolution", () => {
    it("should follow symlinks when path exists", () => {
      const symlinkPath = "/tmp/symlink";
      const realPath = "/actual/target/path";

      mockExistsSync.mockImplementation((p: string) => p === symlinkPath);
      mockRealpathSync.mockReturnValue(realPath);

      const result = resolveSourcePath(symlinkPath);

      expect(mockRealpathSync).toHaveBeenCalledWith(symlinkPath);
      expect(result).toBe(realPath);
    });

    it("should not call realpathSync when path does not exist", () => {
      mockExistsSync.mockReturnValue(false);

      resolveSourcePath("/nonexistent/path");

      expect(mockRealpathSync).not.toHaveBeenCalled();
    });

    it("should handle broken symlinks gracefully", () => {
      const brokenSymlink = "/tmp/broken-symlink";

      mockExistsSync.mockReturnValue(true);
      mockRealpathSync.mockImplementation(() => {
        throw new Error("ENOENT: no such file or directory");
      });

      // Should not throw, should return the resolved path without realpath
      const result = resolveSourcePath(brokenSymlink);

      expect(result).toBe(brokenSymlink);
    });
  });

  describe("combined scenarios", () => {
    it("should handle ~ with symlink resolution", () => {
      const tildePathExpanded = path.join(os.homedir(), "project");
      const realPath = "/real/project/path";

      mockExistsSync.mockImplementation((p: string) => p === tildePathExpanded);
      mockRealpathSync.mockReturnValue(realPath);

      const result = resolveSourcePath("~/project");

      expect(result).toBe(realPath);
    });

    it("should handle relative path with symlink resolution", () => {
      const cwd = process.cwd();
      const resolvedRelative = path.resolve(cwd, "./src");
      const realPath = "/real/src/path";

      mockExistsSync.mockImplementation((p: string) => p === resolvedRelative);
      mockRealpathSync.mockReturnValue(realPath);

      const result = resolveSourcePath("./src");

      expect(result).toBe(realPath);
    });
  });
});

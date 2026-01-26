/**
 * Native Module Detection Tests
 *
 * Tests for the native module detection utilities that identify
 * problematic native dependencies in package.json.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/212
 */

import { describe, it, expect } from "@jest/globals";
import {
  checkNativeModule,
  checkPackageJsonNativeModules,
  getNativeModulesBySeverity,
  getNativeModulesByCategory,
  NATIVE_MODULES,
  ALL_NATIVE_MODULES,
  type NativeModule,
} from "../nativeModules";

describe("nativeModules", () => {
  describe("checkNativeModule", () => {
    it("should detect canvas module", () => {
      const result = checkNativeModule("canvas");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("canvas");
      expect(result?.category).toBe("image");
      expect(result?.severity).toBe("HIGH");
    });

    it("should detect node-canvas variant", () => {
      const result = checkNativeModule("node-canvas");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("canvas");
    });

    it("should detect sharp module", () => {
      const result = checkNativeModule("sharp");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("sharp");
      expect(result?.category).toBe("image");
      expect(result?.severity).toBe("HIGH");
      expect(result?.suggestedEnvVars).toEqual({
        SHARP_IGNORE_GLOBAL_LIBVIPS: "1",
      });
    });

    it("should detect better-sqlite3 module", () => {
      const result = checkNativeModule("better-sqlite3");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("better-sqlite3");
      expect(result?.category).toBe("database");
      expect(result?.severity).toBe("HIGH");
    });

    it("should detect maplibre-gl-native module", () => {
      const result = checkNativeModule("maplibre-gl-native");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("maplibre-gl-native");
      expect(result?.category).toBe("graphics");
      expect(result?.suggestedEnvVars).toEqual({
        ENABLE_DYNAMIC_MAPS: "false",
      });
    });

    it("should detect @maplibre scoped native modules", () => {
      const result = checkNativeModule("@maplibre/maplibre-native");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("maplibre-gl-native");
    });

    it("should detect bcrypt module", () => {
      const result = checkNativeModule("bcrypt");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("bcrypt");
      expect(result?.category).toBe("crypto");
      expect(result?.severity).toBe("MEDIUM");
    });

    it("should detect sqlite3 module", () => {
      const result = checkNativeModule("sqlite3");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("sqlite3");
      expect(result?.category).toBe("database");
    });

    it("should detect leveldown module", () => {
      const result = checkNativeModule("leveldown");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("leveldown");
    });

    it("should detect leveldb module", () => {
      const result = checkNativeModule("leveldb");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("leveldown");
    });

    it("should detect node-gyp module", () => {
      const result = checkNativeModule("node-gyp");
      expect(result).not.toBeNull();
      expect(result?.name).toBe("node-gyp");
      expect(result?.category).toBe("system");
    });

    it("should not match non-native modules", () => {
      expect(checkNativeModule("express")).toBeNull();
      expect(checkNativeModule("lodash")).toBeNull();
      expect(checkNativeModule("react")).toBeNull();
      expect(checkNativeModule("typescript")).toBeNull();
    });

    it("should not match partial matches", () => {
      // Should not match "canvas" within a longer name
      expect(checkNativeModule("my-canvas-wrapper")).toBeNull();
      expect(checkNativeModule("canvas-polyfill")).toBeNull();
    });
  });

  describe("checkPackageJsonNativeModules", () => {
    it("should detect canvas in dependencies", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(1);
      expect(result[0].module.name).toBe("canvas");
      expect(result[0].dependencyType).toBe("dependencies");
      expect(result[0].version).toBe("^2.11.0");
    });

    it("should detect modules in devDependencies", () => {
      const packageJson = {
        devDependencies: { sharp: "^0.32.0" },
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(1);
      expect(result[0].module.name).toBe("sharp");
      expect(result[0].dependencyType).toBe("devDependencies");
    });

    it("should detect modules in optionalDependencies", () => {
      const packageJson = {
        optionalDependencies: { "better-sqlite3": "^9.0.0" },
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(1);
      expect(result[0].module.name).toBe("better-sqlite3");
      expect(result[0].dependencyType).toBe("optionalDependencies");
    });

    it("should detect multiple native modules", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0", sharp: "^0.32.0" },
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(2);
      const names = result.map((r) => r.module.name);
      expect(names).toContain("canvas");
      expect(names).toContain("sharp");
    });

    it("should scan all dependency types", () => {
      const packageJson = {
        dependencies: { canvas: "1.0.0" },
        devDependencies: { sharp: "1.0.0" },
        optionalDependencies: { "better-sqlite3": "1.0.0" },
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(3);
      const depTypes = result.map((r) => r.dependencyType);
      expect(depTypes).toContain("dependencies");
      expect(depTypes).toContain("devDependencies");
      expect(depTypes).toContain("optionalDependencies");
    });

    it("should return empty array for no native modules", () => {
      const packageJson = {
        dependencies: {
          express: "^4.18.0",
          lodash: "^4.17.21",
          react: "^18.2.0",
        },
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(0);
    });

    it("should handle empty package.json", () => {
      const result = checkPackageJsonNativeModules({});
      expect(result).toHaveLength(0);
    });

    it("should handle missing dependency sections", () => {
      const packageJson = {
        name: "test-package",
        version: "1.0.0",
      };
      const result = checkPackageJsonNativeModules(packageJson);
      expect(result).toHaveLength(0);
    });
  });

  describe("getNativeModulesBySeverity", () => {
    it("should return HIGH severity modules", () => {
      const highSeverity = getNativeModulesBySeverity("HIGH");
      expect(highSeverity.length).toBeGreaterThan(0);
      expect(highSeverity.every((m) => m.severity === "HIGH")).toBe(true);
      // Check known HIGH severity modules
      const names = highSeverity.map((m) => m.name);
      expect(names).toContain("canvas");
      expect(names).toContain("sharp");
      expect(names).toContain("better-sqlite3");
    });

    it("should return MEDIUM severity modules", () => {
      const mediumSeverity = getNativeModulesBySeverity("MEDIUM");
      expect(mediumSeverity.length).toBeGreaterThan(0);
      expect(mediumSeverity.every((m) => m.severity === "MEDIUM")).toBe(true);
      // Check known MEDIUM severity modules
      const names = mediumSeverity.map((m) => m.name);
      expect(names).toContain("bcrypt");
      expect(names).toContain("node-gyp");
    });
  });

  describe("getNativeModulesByCategory", () => {
    it("should return image category modules", () => {
      const imageModules = getNativeModulesByCategory("image");
      expect(imageModules.length).toBeGreaterThan(0);
      expect(imageModules.every((m) => m.category === "image")).toBe(true);
      const names = imageModules.map((m) => m.name);
      expect(names).toContain("canvas");
      expect(names).toContain("sharp");
    });

    it("should return database category modules", () => {
      const dbModules = getNativeModulesByCategory("database");
      expect(dbModules.length).toBeGreaterThan(0);
      expect(dbModules.every((m) => m.category === "database")).toBe(true);
      const names = dbModules.map((m) => m.name);
      expect(names).toContain("better-sqlite3");
      expect(names).toContain("sqlite3");
    });

    it("should return crypto category modules", () => {
      const cryptoModules = getNativeModulesByCategory("crypto");
      expect(cryptoModules.length).toBeGreaterThan(0);
      expect(cryptoModules.every((m) => m.category === "crypto")).toBe(true);
      const names = cryptoModules.map((m) => m.name);
      expect(names).toContain("bcrypt");
    });
  });

  describe("NATIVE_MODULES constant", () => {
    it("should have at least 8 modules", () => {
      expect(NATIVE_MODULES.length).toBeGreaterThanOrEqual(8);
    });

    it("should have required fields for all modules", () => {
      for (const mod of NATIVE_MODULES) {
        expect(mod.name).toBeTruthy();
        expect(mod.patterns.length).toBeGreaterThan(0);
        expect(["image", "database", "graphics", "system", "crypto"]).toContain(
          mod.category,
        );
        expect(["HIGH", "MEDIUM"]).toContain(mod.severity);
        expect(mod.warningMessage).toBeTruthy();
      }
    });

    it("should have documentation URLs where provided", () => {
      const modulesWithDocs = NATIVE_MODULES.filter((m) => m.documentation);
      expect(modulesWithDocs.length).toBeGreaterThan(0);
      for (const mod of modulesWithDocs) {
        expect(mod.documentation).toMatch(/^https?:\/\//);
      }
    });
  });

  describe("ALL_NATIVE_MODULES alias", () => {
    it("should be identical to NATIVE_MODULES", () => {
      expect(ALL_NATIVE_MODULES).toBe(NATIVE_MODULES);
    });
  });
});

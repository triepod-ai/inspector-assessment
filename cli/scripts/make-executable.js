/**
 * Cross-platform script to make a file executable
 */
import { promises as fs } from "fs";
import { platform } from "os";
import { execSync } from "child_process";
import path from "path";

const TARGET_FILES = [
  path.resolve("build/cli.js"),
  path.resolve("build/assess-full.js"),
  path.resolve("build/assess-security.js"),
];

async function makeExecutable() {
  try {
    // On Unix-like systems (Linux, macOS), use chmod
    if (platform() !== "win32") {
      for (const file of TARGET_FILES) {
        execSync(`chmod +x "${file}"`);
      }
      console.log("Made file executable with chmod");
    } else {
      // On Windows, no need to make files "executable" in the Unix sense
      // Just ensure the files exist
      for (const file of TARGET_FILES) {
        await fs.access(file);
      }
      console.log("File exists and is accessible on Windows");
    }
  } catch (error) {
    console.error("Error making file executable:", error);
    process.exit(1);
  }
}

makeExecutable();

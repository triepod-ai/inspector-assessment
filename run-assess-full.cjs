#!/usr/bin/env node
/**
 * Wrapper script to run the TypeScript assessment via tsx
 * This enables annotation events (annotation_missing, annotation_aligned, etc.)
 * that are emitted by run-security-assessment.ts but not the compiled CLI
 */

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

// Get the tsx binary from node_modules
const tsxPath = path.join(__dirname, "node_modules", ".bin", "tsx");
const scriptPath = path.join(
  __dirname,
  "scripts",
  "run-security-assessment.ts",
);

// Transform args: --json --full -> remove (tsx script handles differently)
// and map args to what run-security-assessment.ts expects
const args = process.argv.slice(2);

// Filter out --json and --full flags that the TS script doesn't use
// and transform to use --module all instead
const transformedArgs = [];
let skipNext = false;
let configPath = null;
let serverName = null;

for (let i = 0; i < args.length; i++) {
  if (skipNext) {
    skipNext = false;
    continue;
  }
  const arg = args[i];
  if (arg === "--json" || arg === "--full") {
    // Skip these - TS script handles output differently
    continue;
  }
  if (arg === "--source") {
    // Skip --source and its value - reserved for future deep analysis
    i++;  // Skip the next arg (the source path)
    continue;
  }
  if (arg === "--config" || arg === "-c") {
    // Capture config path for transformation
    configPath = args[++i];
    transformedArgs.push(arg, configPath);
    continue;
  }
  if (arg === "--server" || arg === "-s") {
    // Capture server name
    serverName = args[++i];
    transformedArgs.push(arg, serverName);
    continue;
  }
  if (arg === "--output" || arg === "-o") {
    // Keep output path
    transformedArgs.push(arg, args[++i]);
    continue;
  }
  transformedArgs.push(arg);
}

// Transform config if it's in mcpServers format (used by audit-worker)
// to transport/url format (used by run-security-assessment.ts)
if (configPath && fs.existsSync(configPath)) {
  try {
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    // Check if it's in mcpServers format with mcp-remote command
    if (config.mcpServers && serverName && config.mcpServers[serverName]) {
      const serverConfig = config.mcpServers[serverName];
      // Extract URL from mcp-remote args: ['mcp-remote', 'http://...', '--allow-http']
      if (serverConfig.args && serverConfig.args.length >= 2) {
        const url = serverConfig.args.find((a) => a.startsWith("http"));
        if (url) {
          // Create transformed config in transport/url format
          const transformedConfig = { transport: "http", url };
          const transformedConfigPath = configPath.replace(
            ".json",
            "-transformed.json",
          );
          fs.writeFileSync(
            transformedConfigPath,
            JSON.stringify(transformedConfig, null, 2),
          );
          // Update args to use transformed config
          const configIndex = transformedArgs.indexOf(configPath);
          if (configIndex >= 0) {
            transformedArgs[configIndex] = transformedConfigPath;
          }
        }
      }
    }
  } catch (err) {
    // Config transformation failed, continue with original
    console.error(`Config transformation warning: ${err.message}`);
  }
}

// Add --module with all modules except temporal (rug pull testing takes too long)
// Available: security, aupCompliance, functionality, documentation, errorHandling,
// usability, mcpSpec, toolAnnotations, prohibitedLibraries, manifestValidation,
// portability, externalAPIScanner, temporal
if (!transformedArgs.includes("--module")) {
  // Skip temporal for faster assessments (temporal takes 25+ invocations per tool)
  const modules =
    "security,aupCompliance,functionality,documentation,errorHandling,usability,mcpSpec,toolAnnotations,prohibitedLibraries,manifestValidation,portability";
  transformedArgs.push("--module", modules);
}

// Run tsx with the TypeScript assessment script
const proc = spawn(
  tsxPath,
  [
    "--tsconfig",
    path.join(__dirname, "client", "tsconfig.app.json"),
    scriptPath,
    ...transformedArgs,
  ],
  {
    stdio: "inherit",
    cwd: __dirname,
  },
);

proc.on("exit", (code) => {
  process.exit(code || 0);
});

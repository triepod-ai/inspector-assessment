#!/usr/bin/env node

import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);
const MAIN_PORT = 6274;
const PROXY_PORT = 6277;

async function killServerOnPort(port) {
  try {
    // Find process using the port
    const { stdout } = await execAsync(`lsof -ti:${port}`);

    if (stdout.trim()) {
      const pids = stdout.trim().split("\n");

      console.log(`Found ${pids.length} process(es) on port ${port}`);

      // Kill each process
      for (const pid of pids) {
        try {
          await execAsync(`kill -9 ${pid}`);
          console.log(`✅ Killed process ${pid}`);
        } catch (error) {
          console.error(`❌ Failed to kill process ${pid}:`, error.message);
        }
      }

      console.log(`\n🎯 Server on port ${port} has been stopped`);
    } else {
      console.log(`ℹ️  No process found running on port ${port}`);
    }
  } catch (error) {
    // lsof returns error if no process found, which is fine
    if (error.code === 1) {
      console.log(`ℹ️  No process found running on port ${port}`);
    } else {
      console.error("Error finding process:", error.message);
      console.log("\nTrying alternative method...");

      // Try alternative method using netstat/ss
      try {
        const { stdout } = await execAsync(
          `ss -lptn 'sport = :${port}' | grep -oP '(?<=pid=)\\d+' | head -1`,
        );
        if (stdout.trim()) {
          await execAsync(`kill -9 ${stdout.trim()}`);
          console.log(`✅ Killed process ${stdout.trim()} using ss command`);
        } else {
          console.log(`ℹ️  No process found on port ${port}`);
        }
      } catch (altError) {
        console.log(`ℹ️  Could not find process on port ${port}`);
      }
    }
  }
}

// Run the script
async function killAllServers() {
  console.log(`🔍 Checking for MCP Inspector servers...`);

  // Kill both server ports
  await killServerOnPort(MAIN_PORT);
  await killServerOnPort(PROXY_PORT);

  console.log("\n✨ All MCP Inspector processes have been cleaned up");
}

killAllServers().catch(console.error);

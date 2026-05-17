import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import app from "./app";
import { logger } from "./lib/logger";
import { startMonitor } from "./lib/monitor";
import { isOnChainEnabled } from "./lib/onchain";
import { prisma } from "@workspace/db";

// Load .env from root directory
// CWD is /artifacts/api-server, so we need to go up 2 levels to reach root
const rootEnvPath = path.resolve(process.cwd(), "../../.env");
dotenv.config({ path: rootEnvPath });

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
  const REAL_ONCHAIN = (process.env["REAL_ONCHAIN"] ?? "false").toLowerCase() === "true";
  logger.info({ REAL_ONCHAIN, onChainEnabled: isOnChainEnabled() }, "On-chain configuration");
  (async () => {
    // Validate DB connection early so misconfigured DATABASE_URL fails fast.
    try {
      const connectPromise = prisma.$connect();
      const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("DB connect timeout")), 5000));
      await Promise.race([connectPromise, timeout]);
      logger.info("Database connection validated");
    } catch (dbErr) {
      logger.error({ err: dbErr }, "Failed to connect to database. Check DATABASE_URL and credentials. Exiting.");
      try {
        await prisma.$disconnect();
      } catch (_) {}
      process.exit(1);
    }

    // Start the Sui blockchain monitor in the background.
    // Failures here are logged but never crash the API server.
    startMonitor().catch((monitorErr) => {
      logger.warn({ err: monitorErr }, "Sui monitor failed to start — running without live monitoring");
    });
  })();
});

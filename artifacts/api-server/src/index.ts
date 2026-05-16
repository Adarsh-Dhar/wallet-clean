import app from "./app";
import { logger } from "./lib/logger";
import { startMonitor } from "./lib/monitor";

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

  // Start the Sui blockchain monitor in the background.
  // Failures here are logged but never crash the API server.
  startMonitor().catch((monitorErr) => {
    logger.warn({ err: monitorErr }, "Sui monitor failed to start — running without live monitoring");
  });
});

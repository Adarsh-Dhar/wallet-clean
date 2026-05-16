import { Router, type IRouter } from "express";
import { HealthCheckResponse } from "@workspace/api-zod";
import { getMonitorStatus } from "../lib/monitor";

const router: IRouter = Router();

router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json({ ...data, monitor: getMonitorStatus(), timestamp: new Date().toISOString() });
});

export default router;

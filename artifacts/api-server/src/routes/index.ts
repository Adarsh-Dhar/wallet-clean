import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import threatsRouter from "./threats";
import walletsRouter from "./wallets";
import statsRouter from "./stats";
import populateRouter from "./populate";
import { requireAuth, isAuthEnabled } from "../lib/auth";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);

if (isAuthEnabled()) {
	router.use(requireAuth);
}

router.use(threatsRouter);
router.use(walletsRouter);
router.use(statsRouter);
router.use(populateRouter);

export default router;

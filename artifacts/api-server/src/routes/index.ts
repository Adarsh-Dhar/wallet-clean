import { Router, type IRouter } from "express";
import healthRouter from "./health";
import threatsRouter from "./threats";
import walletsRouter from "./wallets";
import statsRouter from "./stats";
import populateRouter from "./populate";

const router: IRouter = Router();

router.use(healthRouter);
router.use(threatsRouter);
router.use(walletsRouter);
router.use(statsRouter);
router.use(populateRouter);

export default router;

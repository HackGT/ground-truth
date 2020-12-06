import express from "express";

import { appsRouter } from "./api/apps";
import { membersRouter } from "./api/members";
import { scopesRouter } from "./api/scopes";

import { clientRouter } from "./api/client";
import { userRouter } from "./api/user";

export let apiRouter = express.Router();

// Routes for admin page
apiRouter.use("/apps", appsRouter);
apiRouter.use("/members", membersRouter);
apiRouter.use("/scopes", scopesRouter);

apiRouter.use("/client", clientRouter);
apiRouter.use("/user", userRouter);

import express from "express";
import csrf from "csurf";

import { User } from "../../schema";
import { isAdmin } from "../middleware";

export let membersRouter = express.Router();

membersRouter.use(isAdmin);
membersRouter.use(csrf());

membersRouter.post("/", async (request, response) => {
    try {
        const emails = (request.body.email as string || "").replace(/\s/g, "").split(",");

        // Only allow updating these two fields if provided
        const updateOptions = {
            ...request.body.member && { member: request.body.member },
            ...request.body.admin && { admin: request.body.admin }
        }

        await User.updateMany({ email: { $in: emails } }, updateOptions)

        response.json({ success: true });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while updating user"
        });
    }
});

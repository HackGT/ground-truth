import express from "express";

import { User } from "../../schema";
import { isAdmin, postParser } from "../middleware";

export let membersRouter = express.Router();

membersRouter.use(isAdmin);
membersRouter.use(postParser);

membersRouter.post("/", async (request, response) => {
    try {
        const emails = (request.body.email as string || "").replace(/\s/g, "").split(",");

        let users = await User.find({ email: { $in: emails } });

        if (users.length != emails.length) {
            response.status(400).json({
                error: "Error finding user with email(s) provided"
            });
            return;
        }

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

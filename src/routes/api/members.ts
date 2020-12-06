import express from "express";

import { User } from "../../schema";
import { isAdmin, postParser } from "../middleware";

export let membersRouter = express.Router();

membersRouter.use(isAdmin);
membersRouter.use(postParser);

membersRouter.post("/", async (request, response) => {
    try {
        let user = await User.findOne({ email: request.body.email });

        if (!user) {
            response.status(400).json({
                error: "No existing user found"
            });
            return;
        }

        // Only allow updating these two fields
        user.member = request.body.member || user.member;
        user.admin = request.body.admin || user.admin;

        await user.save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while updating user"
        });
    }
});

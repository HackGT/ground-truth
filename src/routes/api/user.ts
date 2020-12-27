import express from "express";
import passport from "passport";

import { IUser, User, AccessToken } from "../../schema";
import { formatName } from "../../email";

export let userRouter = express.Router();

userRouter.get("/", passport.authenticate("bearer", { session: false }), async (request, response) => {
    let user = request.user as IUser;
    response.json({
        uuid: user.uuid,
        name: formatName(user),
        nameParts: user.name,
        email: user.email,
        admin: user.admin,
        member: user.member,
        scopes: (user.scopes && Object.keys(user.scopes).length > 0) ? user.scopes : null
    });
});

userRouter.post("/logout", passport.authenticate("bearer", { session: false }), async (request, response) => {
    let user = request.user as IUser;
    let existingTokens = await AccessToken.find({ "uuid": user.uuid });
    for (let token of existingTokens) {
        await token.remove();
    }

    let userDB = await User.findOne({ uuid: user.uuid });
    if (userDB) {
        userDB.forceLogOut = true;
        await userDB.save();
    }

    response.json({
        success: true
    });
});

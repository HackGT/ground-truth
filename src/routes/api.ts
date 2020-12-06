import express from "express";
import passport from "passport";

import { IUser, User, AccessToken } from "../schema";
import { postParser, bestLoginMethod } from "./middleware";
import { UserSessionData } from "../auth/strategies/types";
import { formatName } from "../email";
import { adminRoutes } from "./admin";

export let apiRoutes = express.Router();

apiRoutes.get("/user", passport.authenticate("bearer", { session: false }), async (request, response) => {
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

apiRoutes.post("/user/logout", passport.authenticate("bearer", { session: false }), postParser, async (request, response) => {
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

apiRoutes.get("/login-type", async (request, response) => {
    let email = request.query.email as string | undefined;
    response.json({
        type: await bestLoginMethod(email)
    });
});

apiRoutes.post("/signup-data", postParser, (request, response) => {
    function attachToSession(bodyProperty: keyof UserSessionData) {
        if (!request.session) return;

        let value = request.body[bodyProperty] as string | undefined;
        if (value) {
            request.session[bodyProperty] = value;
        }
    }

    attachToSession("email");
    attachToSession("firstName");
    attachToSession("preferredName");
    attachToSession("lastName");

    response.send();
});

apiRoutes.use("/admin", adminRoutes);

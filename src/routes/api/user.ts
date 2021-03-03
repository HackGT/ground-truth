import express from "express";
import passport from "passport";

import { IUser, User, AccessToken } from "../../schema";
import { formatName } from "../../email";
import { rateLimit } from "../middleware";

export const userRouter = express.Router();

userRouter.use(rateLimit["api-user"]);

userRouter.get(
  "/",
  passport.authenticate("bearer", { session: false }),
  async (request, response) => {
    const user = request.user as IUser;
    response.json({
      uuid: user.uuid,
      name: formatName(user),
      nameParts: user.name,
      email: user.email,
      admin: user.admin,
      member: user.member,
      scopes: user.scopes && Object.keys(user.scopes).length > 0 ? user.scopes : null,
    });
  }
);

userRouter.post(
  "/logout",
  passport.authenticate("bearer", { session: false }),
  async (request, response) => {
    const user = request.user as IUser;
    const existingTokens = await AccessToken.find({ uuid: user.uuid });
    for (const token of existingTokens) {
      await token.remove();
    }

    const userDB = await User.findOne({ uuid: user.uuid });
    if (userDB) {
      userDB.forceLogOut = true;
      await userDB.save();
    }

    response.json({
      success: true,
    });
  }
);

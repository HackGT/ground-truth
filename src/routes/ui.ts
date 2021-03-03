import * as express from "express";
import csrf from "csurf";

import { config } from "../common";
import { authenticateWithRedirect, isAdmin, bestLoginMethod, rateLimit } from "./middleware";
import { User, IUser, OAuthClient, AccessToken, Scope } from "../schema";
import {
  AdminTemplate,
  ChangePasswordTemplate,
  ForgotPasswordTemplate,
  IndexTemplate,
  LoginTemplate,
  ErrorTemplate,
  ResetPasswordTemplate,
} from "../templates";

export const uiRoutes = express.Router();

uiRoutes.use(rateLimit.ui);

uiRoutes.route("/").get(authenticateWithRedirect, async (request, response) => {
  if (request.session) {
    const url = request.session.returnTo;
    if (url && url !== "/") {
      request.session.returnTo = undefined;
      response.redirect(url);
      return;
    }
  }

  const templateData = {
    title: "Home",

    // @ts-ignore
    user: request.user.toObject(),
    loginMethod: await bestLoginMethod(request.user?.email),
  };

  response.send(IndexTemplate.render(templateData));
});

uiRoutes.route("/login").get(csrf(), async (request, response) => {
  if (request.isAuthenticated() && request.user && (request.user as IUser).verifiedEmail) {
    response.redirect("/");
    return;
  }

  const templateData = {
    title: "Log in",
    includeJS: "login",

    error: request.flash("error"),
    success: request.flash("success"),
    loginMethods: config.loginMethods,
    localOnly:
      config.loginMethods && config.loginMethods.length === 1 && config.loginMethods[0] === "local",
    email: request.session ? request.session.email : null,

    csrfToken: request.csrfToken(),
    recaptchaSiteKey: config.secrets.recaptcha.siteKey,
  };

  response.send(LoginTemplate.render(templateData));
});

uiRoutes.route("/login/forgot").get(csrf(), (request, response) => {
  const templateData = {
    title: "Forgot Password",

    error: request.flash("error"),
    success: request.flash("success"),

    csrfToken: request.csrfToken(),
    recaptchaSiteKey: config.secrets.recaptcha.siteKey,
  };

  response.send(ForgotPasswordTemplate.render(templateData));
});

uiRoutes.route("/login/forgot/:code").get(csrf(), async (request, response) => {
  const user = await User.findOne({ "local.resetCode": request.params.code });

  if (!user) {
    request.flash("error", "Invalid password reset code");
    response.redirect("/login");
    return;
  }
  if (
    !user.local ||
    !user.local.resetCode ||
    Date.now() - user.local.resetRequestedTime!.valueOf() > config.server.passwordResetExpiration
  ) {
    request.flash("error", "Your password reset link has expired. Please request a new one.");
    if (user.local) {
      user.local.resetCode = undefined;
    }
    await user.save();
    response.redirect("/login");
    return;
  }

  const templateData = {
    title: "Reset Password",

    error: request.flash("error"),
    success: request.flash("success"),
    resetCode: user.local!.resetCode!,

    csrfToken: request.csrfToken(),
    recaptchaSiteKey: config.secrets.recaptcha.siteKey,
  };

  response.send(ResetPasswordTemplate.render(templateData));
});

uiRoutes
  .route("/login/changepassword")
  .get(authenticateWithRedirect, csrf(), async (request, response) => {
    const user = request.user as IUser;
    if (!user.local || !user.local.hash) {
      response.redirect("/");
      return;
    }

    const templateData = {
      title: "Change Password",

      error: request.flash("error"),
      success: request.flash("success"),

      csrfToken: request.csrfToken(),
      recaptchaSiteKey: config.secrets.recaptcha.siteKey,
    };

    response.send(ChangePasswordTemplate.render(templateData));
  });

uiRoutes.route("/admin").get(isAdmin, csrf(), async (request, response) => {
  const templateData = {
    title: "Admin",
    includeJS: "admin",

    uuid: request.user?.uuid,

    apps: await Promise.all(
      (await OAuthClient.find().lean()).map(async (client: any) => {
        client.tokens = await AccessToken.countDocuments({ clientID: client.clientID });
        return client;
      })
    ),

    scopes: await Scope.find().lean(),

    adminDomains: config.server.adminDomains,
    admins: config.server.admins,
    currentMembers: await User.find({ $or: [{ member: true }, { admin: true }] })
      .lean()
      .sort("name.first"),

    csrfToken: request.csrfToken(),
  };

  response.send(AdminTemplate.render(templateData));
});

uiRoutes.route("*").all(async (request, response) => {
  const templateData = {
    title: "404 Not Found",
    errorTitle: "404 Error - Page Not Found",
    errorSubtitle: "Sorry, we couldn't find what you were looking for.",
    button: true,
  };

  response.status(404).send(ErrorTemplate.render(templateData));
});

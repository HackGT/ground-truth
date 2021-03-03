import * as crypto from "crypto";
import * as express from "express";
import csrf from "csurf";

import { config } from "../common";
import { User } from "../schema";
import { strategies } from "../auth/strategies/index";
import { RegistrationStrategy } from "../auth/strategies/types";
import { validateAndCacheHostName } from "../auth/strategies/util";
import { sendVerificationEmail, resendVerificationEmailLink } from "../email";
import { rateLimit } from "./middleware";

export const authRouter = express.Router();

authRouter.use(rateLimit["auth-general"]);
authRouter.use(csrf());

const authenticationMethods: RegistrationStrategy[] = [];
console.info(`Using authentication methods: ${config.loginMethods.join(", ")}`);

for (const methodName of config.loginMethods) {
  if (!strategies[methodName]) {
    console.error(
      `Authentication method "${methodName}" is not available. Did you add it to the exported list of strategies?`
    );
  } else {
    const method = new strategies[methodName]();
    authenticationMethods.push(method);
    method.use(authRouter);
  }
}

authRouter.get("/validatehost/:nonce", (request, response) => {
  const nonce: string = request.params.nonce || "";
  response.send(
    crypto.createHmac("sha256", config.secrets.session).update(nonce).digest().toString("hex")
  );
});

authRouter.get("/verify/:code", rateLimit["verify-code"], async (request, response) => {
  const user = await User.findOne({ emailVerificationCode: request.params.code });
  if (!user) {
    request.flash("error", "Invalid email verification code");
  } else {
    user.verifiedEmail = true;
    user.emailVerificationCode = undefined;
    await user.save();
    request.flash("success", "Thanks for verifying your email. You can now log in.");
  }
  response.redirect("/login");
});

authRouter.get(
  "/resend/:uuid",
  rateLimit["send-email-verify"],
  validateAndCacheHostName,
  async (request, response) => {
    const user = await User.findOne({ uuid: request.params.uuid || "" });
    if (user) {
      await sendVerificationEmail(request, user);
      const email = user.email.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/&/g, "&amp;");
      request.flash(
        "success",
        `Resent a verification email to ${email}. ${resendVerificationEmailLink(
          request,
          user.uuid
        )}`
      );
    }
    response.redirect("/login");
  }
);

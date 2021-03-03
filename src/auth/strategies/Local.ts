import * as util from "util";
import * as crypto from "crypto";
import * as path from "path";
import moment from "moment";
import passport from "passport";
import { Request, Router } from "express";
import { Strategy as LocalStrategy } from "passport-local";
import passwordValidator from "password-validator";

import { config } from "../../common";
import { authenticateWithRedirect, rateLimit, verifyRecaptcha } from "../../routes/middleware";
import { User, createNew, IUser } from "../../schema";
import { checkAndSetAdmin, createLink, validateAndCacheHostName } from "./util";
import { OAuthStrategy } from "./OAuthStrategy";
import { PassportDone, RegistrationStrategy, StrategyOptions, Strategy } from "./types";
import {
  sendVerificationEmail,
  resendVerificationEmailLink,
  sendMailAsync,
  renderEmailHTML,
  renderEmailText,
} from "../../email";

export const PBKDF2_ROUNDS = 300000;

const pbkdf2Async = async (
  password: string | Buffer,
  salt: string | Buffer,
  rounds: number
): Promise<Buffer> =>
  util.promisify(crypto.pbkdf2).call(null, password, salt, rounds, 128, "sha256");

// There is also frontend validation that should be changed accordingly
const passwordSchema = new passwordValidator();
passwordSchema
  .is()
  .min(8) // Minimum length 8
  .has()
  .uppercase() // Must have uppercase letters
  .has()
  .lowercase() // Must have lowercase letters
  .has()
  .digits(); // Must have digits

interface LocalStrategyOptions extends StrategyOptions {
  usernameField: string;
  passwordField: string;
}

export class Local implements RegistrationStrategy {
  public readonly passportStrategy: Strategy;
  public readonly name = "local";

  constructor() {
    const options: LocalStrategyOptions = {
      usernameField: "email",
      passwordField: "password",
      passReqToCallback: true,
    };
    this.passportStrategy = new LocalStrategy(options, this.passportCallback.bind(this));
  }

  protected async passportCallback(
    request: Request,
    email: string,
    password: string,
    done: PassportDone
  ) {
    email = email.trim().toLowerCase();
    let user = await User.findOne({ email });

    if (user && request.path.match(/\/signup$/i)) {
      done(null, false, { message: "That email address is already in use" });
    } else if (user && (!user.local || !user.local.hash)) {
      done(null, false, { message: "Please log back in with an external provider" });
    } else if (!user || !user.local) {
      // User hasn't signed up yet
      if (!request.path.match(/\/signup$/i)) {
        // Only create the user when targeting /signup
        done(null, false, { message: "Incorrect email or password" });
        return;
      }

      const firstName: string = request.body.firstName || "";
      const { preferredName } = request.body;
      const lastName: string = request.body.lastName || "";

      if (!email) {
        done(null, false, { message: "Missing email" });
        return;
      }
      if (!password) {
        done(null, false, { message: "Missing password" });
        return;
      }
      if (!firstName || !lastName) {
        done(null, false, { message: "Missing first or last name" });
        return;
      }
      if (!passwordSchema.validate(password)) {
        done(null, false, {
          message:
            "Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one number",
        });
        return;
      }

      const salt = crypto.randomBytes(32);
      const hash = await pbkdf2Async(password, salt, PBKDF2_ROUNDS);
      user = createNew<IUser>(User, {
        ...OAuthStrategy.defaultUserProperties,
        email,
        name: {
          first: firstName,
          preferred: preferredName,
          last: lastName,
        },
        local: {
          hash: hash.toString("hex"),
          salt: salt.toString("hex"),
          rounds: PBKDF2_ROUNDS,
        },
      });

      try {
        await user.save();
      } catch (err) {
        done(err);
        return;
      }

      if (!user.verifiedEmail && !user.emailVerificationCode) {
        await sendVerificationEmail(request, user);
      }
      if (!user.verifiedEmail) {
        request.flash(
          "success",
          `Account created successfully. Please verify your email before signing in. ${resendVerificationEmailLink(
            request,
            user.uuid
          )}`
        );
        done(null, false);
        return;
      }
      await checkAndSetAdmin(user);

      done(null, user);
    } else {
      // Log the user in
      const hash = await pbkdf2Async(
        password,
        Buffer.from(user.local.salt || "", "hex"),
        PBKDF2_ROUNDS
      );
      if (hash.toString("hex") === user.local.hash) {
        if (user.verifiedEmail) {
          await checkAndSetAdmin(user);

          if (request.session) {
            request.session.email = undefined;
            request.session.firstName = undefined;
            request.session.preferredName = undefined;
            request.session.lastName = undefined;
          }
          done(null, user);
        } else {
          done(null, false, {
            message: `You must verify your email before you can sign in. ${resendVerificationEmailLink(
              request,
              user.uuid
            )}`,
          });
        }
      } else {
        done(null, false, { message: "Incorrect email or password" });
      }
    }
  }

  public use(authRoutes: Router) {
    passport.use(this.passportStrategy);

    authRoutes.post(
      "/signup",
      rateLimit["local-signup"],
      validateAndCacheHostName,
      verifyRecaptcha(),
      passport.authenticate("local", { failureFlash: true }),
      (request, response) => {
        // This works because the client just reloads the page once the requests completes
        // which displays the flash message (if error) or redirects to the next page (if success)
        response.json({ success: true });
      }
    );

    authRoutes.post(
      "/login",
      rateLimit["local-login-slow"],
      rateLimit["local-login"],
      passport.authenticate("local", { failureFlash: true }),
      (request, response) => {
        // Same as comment above
        response.json({ success: true });
      }
    );

    authRoutes.post(
      "/forgot",
      rateLimit["send-email-forgot"],
      validateAndCacheHostName,
      verifyRecaptcha("/login/forgot"),
      async (request, response) => {
        let { email } = request.body;
        if (!email || !email.toString().trim()) {
          request.flash("error", "Invalid email");
          response.redirect("/login/forgot");
          return;
        }
        email = email.toString().trim().toLowerCase();

        const user = await User.findOne({ email });
        if (!user) {
          request.flash("error", "No account matching the email that you submitted was found");
          response.redirect("/login/forgot");
          return;
        }
        if (!user.verifiedEmail) {
          request.flash(
            "error",
            `Please verify your email first. ${resendVerificationEmailLink(request, user.uuid)}`
          );
          response.redirect("/login");
          return;
        }
        if (!user.local || !user.local.hash) {
          request.flash(
            "error",
            "The account with the email that you submitted has no password set. Please log in with an external service like GitHub, Google, or Facebook instead."
          );
          response.redirect("/login");
          return;
        }

        user.local.resetRequestedTime = new Date();
        user.local.resetCode = crypto.randomBytes(32).toString("hex");

        // Send reset email (hostname validated by previous middleware)
        const link = createLink(request, `/login/forgot/${user.local.resetCode}`);
        const markdown = `Hi {{name}},

You (or someone who knows your email address) recently asked to reset the password for this account: {{email}}.

You can update your password by [clicking here](${link}).

If you don't use this link within ${moment
          .duration(config.server.passwordResetExpiration, "milliseconds")
          .humanize()}, it will expire and you will have to [request a new one](${createLink(
          request,
          "/login/forgot"
        )}).

If you didn't request a password reset, you can safely disregard this email and no changes will be made to your account.

Sincerely,

The ${config.server.name} Team.`;
        try {
          await user.save();
          await sendMailAsync({
            from: config.email.from,
            to: email,
            subject: `[${config.server.name}] - Password reset request`,
            html: await renderEmailHTML(markdown, user),
            text: await renderEmailText(markdown, user),
          });
          request.flash(
            "success",
            "Please check your email for a link to reset your password. If it doesn't appear within a few minutes, check your spam folder."
          );
          response.redirect("/login/forgot");
        } catch (err) {
          console.error(err);
          request.flash("error", "An error occurred while sending you a password reset email");
          response.redirect("/login/forgot");
        }
      }
    );

    authRoutes.post(
      "/forgot/:code",
      rateLimit["forgot-code"],
      validateAndCacheHostName,
      verifyRecaptcha("/login/forgot/:code"),
      async (request, response) => {
        const user = await User.findOne({ "local.resetCode": request.params.code });
        if (!user) {
          request.flash("error", "Invalid password reset code");
          response.redirect("/login");
          return;
        }

        const expirationDuration = moment.duration(
          config.server.passwordResetExpiration,
          "milliseconds"
        );
        if (
          !user.local!.resetCode ||
          moment().isAfter(moment(user.local!.resetRequestedTime).add(expirationDuration))
        ) {
          request.flash("error", "Your password reset link has expired. Please request a new one.");
          user.local!.resetCode = undefined;
          await user.save();
          response.redirect("/login");
          return;
        }

        const { password1 } = request.body;
        const { password2 } = request.body;

        if (!password1 || !password2) {
          request.flash("error", "Missing new password or confirm password");
          response.redirect(`/login/forgot/${request.params.code}`);
          return;
        }
        if (password1 !== password2) {
          request.flash("error", "Passwords must match");
          response.redirect(`/login/forgot/${request.params.code}`);
          return;
        }
        if (!passwordSchema.validate(password1)) {
          request.flash(
            "error",
            "Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one number"
          );
          response.redirect(`/login/forgot/${request.params.code}`);
          return;
        }

        const salt = crypto.randomBytes(32);
        const hash = await pbkdf2Async(password1, salt, PBKDF2_ROUNDS);

        try {
          user.local!.salt = salt.toString("hex");
          user.local!.hash = hash.toString("hex");
          user.local!.resetCode = undefined;
          await user.save();

          request.flash("success", "Password reset successfully. You can now log in.");
          response.redirect("/login");
        } catch (err) {
          console.error(err);
          request.flash("error", "An error occurred while saving your new password");
          response.redirect(path.join("/auth", request.url));
        }
      }
    );

    authRoutes.post(
      "/changepassword",
      rateLimit["local-change-password"],
      validateAndCacheHostName,
      verifyRecaptcha("/login/changepassword"),
      authenticateWithRedirect,
      async (request, response) => {
        const user = await User.findOne({ uuid: request.user!.uuid });
        if (!user) {
          request.flash("error", "User not logged in");
          response.redirect("/login");
          return;
        }
        if (!user.local || !user.local.hash) {
          response.redirect("/");
          return;
        }

        const oldPassword: string = request.body.oldpassword || "";
        const currentHash = await pbkdf2Async(
          oldPassword,
          Buffer.from(user.local.salt || "", "hex"),
          PBKDF2_ROUNDS
        );
        if (currentHash.toString("hex") !== user.local.hash) {
          request.flash("error", "Incorrect current password");
          response.redirect("/login/changepassword");
          return;
        }

        const { password1 } = request.body;
        const { password2 } = request.body;

        if (!password1 || !password2) {
          request.flash("error", "Missing new password or confirm password");
          response.redirect(`/login/changepassword`);
          return;
        }
        if (password1 !== password2) {
          request.flash("error", "New passwords must match");
          response.redirect(`/login/changepassword`);
          return;
        }
        if (!passwordSchema.validate(password1)) {
          request.flash(
            "error",
            "New password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one number"
          );
          response.redirect(`/login/changepassword`);
          return;
        }

        const salt = crypto.randomBytes(32);
        const hash = await pbkdf2Async(password1, salt, PBKDF2_ROUNDS);

        try {
          user.local!.salt = salt.toString("hex");
          user.local!.hash = hash.toString("hex");
          user.local!.resetCode = undefined;
          await user.save();

          response.redirect("/");
        } catch (err) {
          console.error(err);
          request.flash("error", "An error occurred while saving your new password");
          response.redirect("/login/changepassword");
        }
      }
    );
  }
}

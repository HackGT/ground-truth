import express from "express";
import moment from "moment";

import { createLink } from "../auth/strategies/util";
import { config } from "../common";

export const verifyEmailMarkdown = (request: express.Request, emailVerificationCode: string) => {
  const emailVerificationLink = createLink(request, `/auth/verify/${emailVerificationCode}`);

  return `Hi {{name}},

Thanks for creating an account with ${config.server.name}! To verify your email, please [click here](${emailVerificationLink}).

If you are registering for a ${config.server.name} event, please note that this does **not** complete your registration. After verifying your email, you will be directed to the event registration portal to submit an application.

Sincerely,

The ${config.server.name} Team.`;
};

export const passwordResetMarkdown = (request: express.Request, resetCode: string) => {
  const passwordResetLink = createLink(request, `/login/forgot/${resetCode}`);
  const expirationTime = moment
    .duration(config.server.passwordResetExpiration, "milliseconds")
    .humanize();
  const forgotEmailLink = createLink(request, "/login/forgot");

  return `Hi {{name}},

You (or someone who knows your email address) recently asked to reset the password for this account: {{email}}.

You can update your password by [clicking here](${passwordResetLink}).

If you don't use this link within ${expirationTime}, it will expire and you will have to [request a new one](${forgotEmailLink}).

If you didn't request a password reset, you can safely disregard this email and no changes will be made to your account.

Sincerely,

The ${config.server.name} Team.`;
};

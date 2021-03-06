import * as crypto from "crypto";
import * as http from "http";
import * as https from "https";
import { Request, Response, NextFunction } from "express";

import { config, IConfig } from "../../common";
import { createNew, IUser, Model, User } from "../../schema";
import { sendVerificationEmail, resendVerificationEmailLink } from "../../email/email";
import { OAuthStrategy } from "./OAuthStrategy";
import { PassportDone } from "./types";

/* eslint-disable no-param-reassign */
export async function checkAndSetAdmin(user: Model<IUser>) {
  if (!user.verifiedEmail) return;

  const domain = user.email.split("@").pop();
  if (!domain) return;

  if (config.server.adminDomains.includes(domain) || config.server.admins.includes(user.email)) {
    user.member = true;
    user.admin = true;
    await user.save();
  }
}

export async function ExternalServiceCallback(
  request: Request,
  serviceName: IConfig.OAuthServices | IConfig.CASServices,
  id: string,
  username: string | undefined,
  serviceEmail: string | undefined,
  done: PassportDone
) {
  if (request.user) {
    request.logout();
  }

  // If `user` exists, the user has already logged in with this service and is good-to-go
  let user = await User.findOne({ [`services.${serviceName}.id`]: id });

  if (
    request.session &&
    request.session.email &&
    request.session.firstName &&
    request.session.lastName
  ) {
    const signupEmail = request.session.email.trim().toLowerCase();
    // Only create / modify user account if email and name exist on the session (set by login page)
    const existingUser = await User.findOne({ email: signupEmail });

    if (
      !user &&
      serviceEmail &&
      existingUser &&
      existingUser.verifiedEmail &&
      existingUser.email === serviceEmail
    ) {
      user = existingUser;
      // Add new service
      if (!user.services) {
        user.services = {};
      }
      if (!user.services[serviceName]) {
        user.services[serviceName] = {
          id,
          email: serviceEmail,
          username,
        };
      }
      try {
        user.markModified("services");
        await user.save();
      } catch (err) {
        done(err);
        return;
      }
    } else if (!user && !existingUser) {
      // Create an account
      user = createNew<IUser>(User, {
        ...OAuthStrategy.defaultUserProperties,
        email: signupEmail,
        name: {
          first: request.session.firstName,
          preferred: request.session.preferredName,
          last: request.session.lastName,
        },
      });

      user.services = {};
      user.services[serviceName] = {
        id,
        email: serviceEmail,
        username,
      };

      try {
        user.markModified("services");
        await user.save();
      } catch (err) {
        done(err);
        return;
      }
    }
  }

  if (!user) {
    done(null, false, { message: "Could not match login to existing account" });
    return;
  }

  if (!user.verifiedEmail && !user.emailVerificationCode) {
    await sendVerificationEmail(request, user);
  }

  if (!user.verifiedEmail) {
    request.logout();
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

  if (request.session) {
    request.session.email = undefined;
    request.session.firstName = undefined;
    request.session.preferredName = undefined;
    request.session.lastName = undefined;
  }

  done(null, user);
}

// Authentication helpers
export function getExternalPort(request: Request): number {
  function defaultPort(): number {
    // Default ports for HTTP and HTTPS
    return request.protocol === "http" ? 80 : 443;
  }

  const { host } = request.headers;
  if (!host || Array.isArray(host)) {
    return defaultPort();
  }

  // IPv6 literal support
  const offset = host[0] === "[" ? host.indexOf("]") + 1 : 0;
  const index = host.indexOf(":", offset);
  if (index !== -1) {
    return parseInt(host.substring(index + 1));
  }
  return defaultPort();
}

const validatedHostNames: string[] = [];
export function validateAndCacheHostName(request: Request, response: Response, next: NextFunction) {
  // Basically checks to see if the server behind the hostname has the same session key by HMACing a random nonce
  if (validatedHostNames.find(hostname => hostname === request.hostname)) {
    next();
    return;
  }

  const nonce = crypto.randomBytes(64).toString("hex");
  function callback(message: http.IncomingMessage) {
    if (message.statusCode !== 200) {
      console.error(`Got non-OK status code when validating hostname: ${request.hostname}`);
      message.resume();
      return;
    }
    message.setEncoding("utf8");
    let data = "";
    message.on("data", chunk => {
      data += chunk;
    });
    message.on("end", () => {
      const localHMAC = crypto
        .createHmac("sha256", config.secrets.session)
        .update(nonce)
        .digest()
        .toString("hex");
      if (localHMAC === data) {
        validatedHostNames.push(request.hostname);
        next();
      } else {
        console.error(`Got invalid HMAC when validating hostname: ${request.hostname}`);
      }
    });
  }
  function onError(err: Error) {
    console.error(`Error when validating hostname: ${request.hostname}`, err);
  }
  if (request.protocol === "http") {
    http
      .get(
        `http://${request.hostname}:${getExternalPort(request)}/auth/validatehost/${nonce}`,
        callback
      )
      .on("error", onError);
  } else {
    https
      .get(
        `https://${request.hostname}:${getExternalPort(request)}/auth/validatehost/${nonce}`,
        callback
      )
      .on("error", onError);
  }
}

export function createLink(request: Request, link: string): string {
  const cleanedLink = link[0] === "/" ? link.substring(1) : link;

  if (
    (request.secure && getExternalPort(request) === 443) ||
    (!request.secure && getExternalPort(request) === 80)
  ) {
    return `http${request.secure ? "s" : ""}://${request.hostname}/${cleanedLink}`;
  }
  return `http${request.secure ? "s" : ""}://${request.hostname}:${getExternalPort(
    request
  )}/${cleanedLink}`;
}

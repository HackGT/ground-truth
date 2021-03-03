import { Request, Router } from "express";
import passport from "passport";

import { config } from "../../common";
import { PassportDone, RegistrationStrategy, StrategyOptions, Strategy, Profile } from "./types";
import { ExternalServiceCallback } from "./util";

interface CASStrategyConstructor {
  new (
    options: CASStrategyOptions,
    cb: (request: Request, username: string, profile: Profile, done: PassportDone) => Promise<void>
  ): Strategy;
}

// eslint-disable-next-line camelcase, @typescript-eslint/no-var-requires
const CASStrategy: CASStrategyConstructor = require("passport-cas2").Strategy;

interface CASStrategyOptions extends StrategyOptions {
  casURL: string;
  pgtURL?: string;
  sessionKey?: string;
  propertyMap?: any;
  sslCA?: any[];
}

// Registration must be hosted on a *.hack.gt domain for this to work
export class GeorgiaTechCAS implements RegistrationStrategy {
  public readonly passportStrategy: Strategy;
  public readonly name = "gatech";

  constructor() {
    const options: CASStrategyOptions = {
      casURL: config.secrets.gatech.url,
      passReqToCallback: true,
    };
    this.passportStrategy = new CASStrategy(options, this.passportCallback.bind(this));
  }

  private async passportCallback(
    request: Request,
    username: string,
    profile: Profile,
    done: PassportDone
  ) {
    // GT login will pass long invalid usernames of different capitalizations
    const trimmedUsername = username.toLowerCase().trim();

    // Reject username@gatech.edu usernames because the CAS allows those for some reason
    // Bonus fact: using a @gatech.edu username bypasses 2FA and the OIT team in charge refuses to fix this
    if (trimmedUsername.indexOf("@") !== -1) {
      done(null, false, {
        message: `Usernames of the format ${trimmedUsername} with an email domain are insecure and therefore disallowed. Please log in with <strong>${
          trimmedUsername.split("@")[0]
        }</strong> instead. <a href="${
          config.secrets.gatech.logoutLink
        }" target="_blank">Click here</a> to do this.`,
      });
      return;
    }

    const serviceEmail = `${trimmedUsername}@${config.secrets.gatech.emailDomain}`;

    ExternalServiceCallback(
      request,
      this.name,
      trimmedUsername,
      trimmedUsername,
      serviceEmail,
      done
    );
  }

  public use(authRoutes: Router) {
    passport.use(this.name, this.passportStrategy);

    authRoutes.get(
      `/${this.name}`,
      passport.authenticate(this.name, {
        failureRedirect: "/login",
        successReturnToOrRedirect: "/",
        failureFlash: true,
      })
    );
  }
}

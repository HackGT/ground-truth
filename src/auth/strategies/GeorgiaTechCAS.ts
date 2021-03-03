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

// No type definitions available yet
// tslint:disable:no-var-requires
const CASStrategy: CASStrategyConstructor = require("passport-cas2").Strategy;

interface CASStrategyOptions extends StrategyOptions {
  casURL: string;
  pgtURL?: string;
  sessionKey?: string;
  propertyMap?: object;
  sslCA?: any[];
}

// Registration must be hosted on a *.hack.gt domain for this to work
export class GeorgiaTechCAS implements RegistrationStrategy {
  public readonly passportStrategy: Strategy;
  public readonly name = "gatech";

  constructor() {
    let options: CASStrategyOptions = {
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
    username = username.toLowerCase().trim();

    // Reject username@gatech.edu usernames because the CAS allows those for some reason
    // Bonus fact: using a @gatech.edu username bypasses 2FA and the OIT team in charge refuses to fix this
    if (username.indexOf("@") !== -1) {
      done(null, false, {
        message: `Usernames of the format ${username} with an email domain are insecure and therefore disallowed. Please log in with <strong>${
          username.split("@")[0]
        }</strong> instead. <a href="${
          config.secrets.gatech.logoutLink
        }" target="_blank">Click here</a> to do this.`,
      });
      return;
    }

    let serviceEmail = `${username}@${config.secrets.gatech.emailDomain}`;

    ExternalServiceCallback(request, this.name, username, username, serviceEmail, done);
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

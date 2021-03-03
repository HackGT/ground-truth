/* eslint-disable @typescript-eslint/no-namespace, @typescript-eslint/no-empty-interface */
import { Request, Response, Router } from "express";
import passport from "passport";

import { Model, IUser } from "../../schema";

export type Strategy = passport.Strategy & {
  logout?(request: Request, response: Response, returnURL: string): void;
};
export type Profile = passport.Profile & {
  profileUrl?: string;
  _json: any;
};

export type PassportDone = (
  err: Error | null,
  user?: Model<IUser> | false,
  errMessage?: { message: string }
) => void;

export interface StrategyOptions {
  passReqToCallback: true; // Forced to true for our usecase
}

// Because the passport typedefs don't include this for some reason
// Defined: https://github.com/jaredhanson/passport-oauth2/blob/9ddff909a992c3428781b7b2957ce1a97a924367/lib/strategy.js#L135
export type AuthenticateOptions = passport.AuthenticateOptions & {
  callbackURL: string;
};

export interface RegistrationStrategy {
  readonly name: string;
  readonly passportStrategy: Strategy;
  use(authRoutes: Router, scope?: string[]): void;
}

declare module "express-session" {
  interface Session {
    email?: string;
    firstName?: string;
    preferredName?: string;
    lastName?: string;
    authorizeURL?: string;
    scope?: string[];
    returnTo?: string;
    passport: any;
  }
}

declare global {
  namespace Express {
    interface User extends IUser {}
  }
}

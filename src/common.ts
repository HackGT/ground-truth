/* eslint-disable @typescript-eslint/no-namespace */
import * as fs from "fs";
import * as path from "path";
import mongoose from "mongoose";

//
// Config
//

// Secrets JSON file schema
export namespace IConfig {
  export type OAuthServices = "github" | "google" | "facebook";
  export type CASServices = "gatech";
  export type Services = "local" | OAuthServices | CASServices;

  export interface Secrets {
    session: string;
    recaptcha: {
      siteKey: string;
      secretKey: string;
    };
    oauth: {
      [Service in OAuthServices]: {
        id: string;
        secret: string;
      };
    };
    gatech: {
      url: string;
      emailDomain: string;
      logoutLink: string;
    };
    sentryDSN: string;
  }
  export interface Email {
    from: string;
    key: string;
    headerImage: string;
    twitterHandle: string;
    facebookHandle: string;
    contactAddress: string;
  }
  export interface Server {
    name: string;
    isProduction: boolean;
    port: number;
    cookieMaxAge: number;
    cookieSecureOnly: boolean;
    passwordResetExpiration: number;
    defaultTimezone: string;
    adminDomains: string[];
    admins: string[];
  }
  export interface Database {
    mongoURL: string;
    rateLimitCollection: string;
  }

  export interface Main {
    secrets: Secrets;
    email: Email;
    server: Server;
    database: Database;
    loginMethods: Services[];
  }
}

class Config implements IConfig.Main {
  public secrets = <IConfig.Secrets>{};
  public email = <IConfig.Email>{};
  public server = <IConfig.Server>{};
  public database = <IConfig.Database>{};
  public loginMethods = [] as IConfig.Services[];

  protected addLoginMethod(method: IConfig.Services) {
    if (this.loginMethods.indexOf(method) === -1) {
      this.loginMethods.push(method);
    }
  }

  constructor() {
    this.loadFromJSON("default.json");
    this.loadFromJSON("development.json");
    this.loadFromEnv();
  }

  protected loadFromJSON(fileName: string) {
    // tslint:disable-next-line:no-shadowed-variable
    let config: IConfig.Main | null = null;
    try {
      config = JSON.parse(fs.readFileSync(path.resolve(__dirname, "./config", fileName), "utf8"));
    } catch (err) {
      if (err.code !== "ENOENT") {
        throw err;
      }
    }

    if (!config) {
      return;
    }

    if (config.secrets) {
      for (const key of Object.keys(config.secrets) as (keyof IConfig.Secrets)[]) {
        (this.secrets as any)[key] = config.secrets[key];
      }
    }
    if (config.email) {
      for (const key of Object.keys(config.email) as (keyof IConfig.Email)[]) {
        this.email[key] = config.email[key];
      }
    }
    if (config.server) {
      for (const key of Object.keys(config.server) as (keyof IConfig.Server)[]) {
        (this.server as any)[key] = config.server[key];
      }
    }
    if (config.database) {
      for (const key of Object.keys(config.database) as (keyof IConfig.Database)[]) {
        (this.database as any)[key] = config.database[key];
      }
    }
    if (config.loginMethods) {
      this.loginMethods = config.loginMethods;
    }
  }

  protected loadFromEnv() {
    // Secrets
    if (process.env.SESSION_SECRET) {
      this.secrets.session = process.env.SESSION_SECRET;
    }
    if (process.env.RECAPTCHA_SITE_KEY) {
      this.secrets.recaptcha.siteKey = process.env.RECAPTCHA_SITE_KEY;
    }
    if (process.env.RECAPTCHA_SECRET_KEY) {
      this.secrets.recaptcha.secretKey = process.env.RECAPTCHA_SECRET_KEY;
    }
    if (process.env.GT_CAS) {
      this.addLoginMethod("gatech");
    }
    if (process.env.GITHUB_CLIENT_ID) {
      this.secrets.oauth.github.id = process.env.GITHUB_CLIENT_ID;
      this.addLoginMethod("github");
    }
    if (process.env.GITHUB_CLIENT_SECRET) {
      this.secrets.oauth.github.secret = process.env.GITHUB_CLIENT_SECRET;
    }
    if (process.env.GOOGLE_CLIENT_ID) {
      this.secrets.oauth.google.id = process.env.GOOGLE_CLIENT_ID;
      this.addLoginMethod("google");
    }
    if (process.env.GOOGLE_CLIENT_SECRET) {
      this.secrets.oauth.google.secret = process.env.GOOGLE_CLIENT_SECRET;
    }
    if (process.env.FACEBOOK_CLIENT_ID) {
      this.secrets.oauth.facebook.id = process.env.FACEBOOK_CLIENT_ID;
      this.addLoginMethod("facebook");
    }
    if (process.env.FACEBOOK_CLIENT_SECRET) {
      this.secrets.oauth.facebook.secret = process.env.FACEBOOK_CLIENT_SECRET;
    }
    if (process.env.SENTRY_DSN) {
      this.secrets.sentryDSN = process.env.SENTRY_DSN;
    }
    // Email
    if (process.env.EMAIL_FROM) {
      this.email.from = process.env.EMAIL_FROM;
    }
    if (process.env.EMAIL_KEY) {
      this.email.key = process.env.EMAIL_KEY;
    }
    if (process.env.EMAIL_HEADER_IMAGE) {
      this.email.headerImage = process.env.EMAIL_HEADER_IMAGE;
    }
    if (process.env.EMAIL_TWITTER_HANDLE) {
      this.email.twitterHandle = process.env.EMAIL_TWITTER_HANDLE;
    }
    if (process.env.EMAIL_FACEBOOK_HANDLE) {
      this.email.facebookHandle = process.env.EMAIL_FACEBOOK_HANDLE;
    }
    if (process.env.EMAIL_CONTACT_ADDRESS) {
      this.email.contactAddress = process.env.EMAIL_CONTACT_ADDRESS;
    }
    // Server
    if (process.env.NAME) {
      this.server.name = process.env.NAME;
    }
    if (process.env.PRODUCTION && process.env.PRODUCTION.toLowerCase() === "true") {
      this.server.isProduction = true;
    }
    if (process.env.PORT) {
      const port = parseInt(process.env.PORT, 10);
      if (!isNaN(port) && port > 0) {
        this.server.port = port;
      }
    }
    if (process.env.COOKIE_MAX_AGE) {
      const maxAge = parseInt(process.env.COOKIE_MAX_AGE, 10);
      if (!isNaN(maxAge) && maxAge > 0) {
        this.server.cookieMaxAge = maxAge;
      }
    }
    if (process.env.COOKIE_SECURE_ONLY && process.env.COOKIE_SECURE_ONLY.toLowerCase() === "true") {
      this.server.cookieSecureOnly = true;
    }
    if (process.env.PASSWORD_RESET_EXPIRATION) {
      const expirationTime = parseInt(process.env.PASSWORD_RESET_EXPIRATION, 10);
      if (!isNaN(expirationTime) && expirationTime > 0) {
        this.server.passwordResetExpiration = expirationTime;
      }
    }
    if (process.env.DEFAULT_TIMEZONE) {
      this.server.defaultTimezone = process.env.DEFAULT_TIMEZONE;
    }
    if (process.env.ADMIN_DOMAINS) {
      this.server.adminDomains = process.env.ADMIN_DOMAINS.split(",");
    }
    if (process.env.ADMINS) {
      this.server.admins = process.env.ADMINS.split(",");
    }
    // Database
    if (process.env.MONGO_URL) {
      this.database.mongoURL = process.env.MONGO_URL;
    }
    if (process.env.RATE_LIMIT_COLLECTION) {
      this.database.rateLimitCollection = process.env.RATE_LIMIT_COLLECTION;
    }
  }
}

export const config = new Config();

//
// Constants
//
export const PORT = config.server.port;
export const VERSION_NUMBER = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../package.json"), "utf8")
).version;
export const VERSION_HASH = fs.existsSync(".git") ? require("git-rev-sync").short() : "";

export const COOKIE_OPTIONS = {
  path: "/",
  maxAge: config.server.cookieMaxAge,
  secure: config.server.cookieSecureOnly,
  httpOnly: true,
};

//
// Database connection
//
mongoose
  .connect(config.database.mongoURL, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
  })
  .catch(err => {
    throw err;
  });
export { mongoose };

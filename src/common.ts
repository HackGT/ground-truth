// Needed so that common.ts <-> schema.ts cyclical dependencies don't cause problems
/* tslint:disable:no-duplicate-imports */
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";

//
// Config
//

// Secrets JSON file schema
export namespace IConfig {
    export type OAuthServices = "github" | "google" | "facebook";
    export type CASServices = "gatech";
    export type Services = "local" | OAuthServices | CASServices;
    export interface Secrets {
        adminKey: string;
        session: string;
        oauth: {
            [Service in OAuthServices]: {
                id: string;
                secret: string;
            }
        };
        gatech: {
            url: string;
            emailDomain: string;
            logoutLink: string;
        }
        bugsnag: string | null;
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
        isProduction: boolean;
        port: number;
        versionHash: string;
        cookieMaxAge: number;
        cookieSecureOnly: boolean;
        mongoURL: string;
        passwordResetExpiration: number;
        defaultTimezone: string;
        name: string;
        adminDomains: string[];
        admins: string[];
    }

    export interface Main {
        secrets: Secrets;
        email: Email;
        server: Server;
        loginMethods: Services[];
    }
}

class Config implements IConfig.Main {
    public secrets: IConfig.Secrets = {
        adminKey: crypto.randomBytes(32).toString("hex"),
        session: crypto.randomBytes(32).toString("hex"),
        oauth: {
            github: {
                id: "",
                secret: ""
            },
            google: {
                id: "",
                secret: ""
            },
            facebook: {
                id: "",
                secret: ""
            }
        },
        gatech: {
            url: "https://login.gatech.edu/cas",
            emailDomain: "gatech.edu",
            logoutLink: "https://login.gatech.edu/cas/logout"
        },
        bugsnag: null
    };
    public email: IConfig.Email = {
        from: "HackGT Team <hello@hackgt.com>",
        key: "",
        headerImage: "",
        twitterHandle: "TheHackGT",
        facebookHandle: "thehackgt",
        contactAddress: "hello@hack.gt"
    };
    public server: IConfig.Server = {
        isProduction: false,
        port: 3000,
        versionHash: fs.existsSync(".git") ? require("git-rev-sync").short() : "",
        cookieMaxAge: 1000 * 60 * 60 * 24 * 30 * 6, // 6 months
        cookieSecureOnly: false,
        mongoURL: "mongodb://localhost/auth",
        passwordResetExpiration: 1000 * 60 * 60, // 1 hour
        defaultTimezone: "America/New_York",
        name: "HackGT",
        adminDomains: ["hack.gt"],
        admins: [],
    };

    public loginMethods = ["local"] as IConfig.Services[];
    protected addLoginMethod(method: IConfig.Services) {
        if (this.loginMethods.indexOf(method) === -1) {
            this.loginMethods.push(method);
        }
    }

    public sessionSecretSet: boolean = false;

    constructor(fileName: string = "config.json") {
        this.loadFromJSON(fileName);
        this.loadFromEnv();
    }
    protected loadFromJSON(fileName: string): void {
        // tslint:disable-next-line:no-shadowed-variable
        let config: IConfig.Main | null = null;
        try {
            config = JSON.parse(fs.readFileSync(path.resolve(__dirname, "./config", fileName), "utf8"));
        }
        catch (err) {
            if (err.code !== "ENOENT") {
                throw err;
            }
        }
        if (!config) {
            return;
        }
        if (config.secrets) {
            for (let key of Object.keys(config.secrets) as (keyof IConfig.Secrets)[]) {
                (this.secrets as any)[key] = config.secrets[key];
            }
        }
        if (config.secrets && config.secrets.session) {
            this.sessionSecretSet = true;
        }
        if (config.email) {
            for (let key of Object.keys(config.email) as (keyof IConfig.Email)[]) {
                this.email[key] = config.email[key];
            }
        }
        if (config.server) {
            for (let key of Object.keys(config.server) as (keyof IConfig.Server)[]) {
                (this.server as any)[key] = config.server[key];
            }
        }
        if (config.loginMethods) {
            this.loginMethods = config.loginMethods;
        }
    }
    protected loadFromEnv(): void {
        // Secrets
        if (process.env.ADMIN_KEY_SECRET) {
            this.secrets.adminKey = process.env.ADMIN_KEY_SECRET;
        }
        else {
            console.warn("Setting random admin key! Cannot use the service-to-service APIs.");
        }
        if (process.env.SESSION_SECRET) {
            this.secrets.session = process.env.SESSION_SECRET;
            this.sessionSecretSet = true;
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
        if (process.env.BUGSNAG) {
            this.secrets.bugsnag = process.env.BUGSNAG;
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
        if (process.env.PRODUCTION && process.env.PRODUCTION.toLowerCase() === "true") {
            this.server.isProduction = true;
        }
        if (process.env.PORT) {
            let port = parseInt(process.env.PORT, 10);
            if (!isNaN(port) && port > 0) {
                this.server.port = port;
            }
        }
        if (process.env.VERSION_HASH) {
            this.server.versionHash = process.env.VERSION_HASH;
        }
        if (process.env.SOURCE_REV) {
            this.server.versionHash = process.env.SOURCE_REV;
        }
        if (process.env.SOURCE_VERSION) {
            this.server.versionHash = process.env.SOURCE_VERSION;
        }
        if (process.env.COOKIE_MAX_AGE) {
            let maxAge = parseInt(process.env.COOKIE_MAX_AGE, 10);
            if (!isNaN(maxAge) && maxAge > 0) {
                this.server.cookieMaxAge = maxAge;
            }
        }
        if (process.env.COOKIE_SECURE_ONLY && process.env.COOKIE_SECURE_ONLY.toLowerCase() === "true") {
            this.server.cookieSecureOnly = true;
        }
        if (process.env.MONGO_URL) {
            this.server.mongoURL = process.env.MONGO_URL;
        }
        if (process.env.DEFAULT_TIMEZONE) {
            this.server.defaultTimezone = process.env.DEFAULT_TIMEZONE;
        }
        if (process.env.NAME) {
            this.server.name = process.env.NAME;
        }
        if (process.env.PASSWORD_RESET_EXPIRATION) {
            let expirationTime = parseInt(process.env.PASSWORD_RESET_EXPIRATION, 10);
            if (!isNaN(expirationTime) && expirationTime > 0) {
                this.server.passwordResetExpiration = expirationTime;
            }
        }
        if (process.env.ADMIN_DOMAINS) {
            this.server.adminDomains = process.env.ADMIN_DOMAINS.split(",");
        }
        if (process.env.ADMINS) {
            this.server.admins = process.env.ADMINS.split(",");
        }
    }
}
export let config = new Config();

//
// Constants
//
export const PORT = config.server.port;
export const VERSION_NUMBER = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../package.json"), "utf8")).version;
export const VERSION_HASH = config.server.versionHash;
export const COOKIE_OPTIONS = {
    "path": "/",
    "maxAge": config.server.cookieMaxAge,
    "secure": config.server.cookieSecureOnly,
    "httpOnly": true
};

//
// Database connection
//
import mongoose from "mongoose";
mongoose.connect(config.server.mongoURL, { useNewUrlParser: true }).catch(err => {
    throw err;
});
export { mongoose };

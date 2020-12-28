import passport from "passport";
import { v4 as uuidv4 } from "uuid";
import { Request, Router } from "express";

import { config, IConfig } from "../../common";
import { validateAndCacheHostName, getExternalPort, ExternalServiceCallback } from "./util";
import { AuthenticateOptions, PassportDone, RegistrationStrategy, StrategyOptions, Strategy, Profile } from "./types";

interface OAuthStrategyOptions extends StrategyOptions {
    clientID: string;
    clientSecret: string;
    profileFields?: string[];
}

interface StrategyConstructor {
    new(options: OAuthStrategyOptions, cb: (request: Request, accessToken: string, refreshToken: string, profile: Profile, done: PassportDone) => Promise<void>): Strategy;
}

export abstract class OAuthStrategy implements RegistrationStrategy {
    public readonly passportStrategy: Strategy;

    public static get defaultUserProperties() {
        return {
            "uuid": uuidv4(),
            "verifiedEmail": false,
            "admin": false,
            "member": false,
            "forceLogOut": false,

            "services": {},
            "scopes": {},
        };
    }

    constructor(public readonly name: IConfig.OAuthServices, strategy: StrategyConstructor, profileFields?: string[]) {
        const secrets = config.secrets.oauth[name];

        if (!secrets || !secrets.id || !secrets.secret) {
            throw new Error(`Client ID or secret not configured in config.json or environment variables for strategy "${this.name}"`);
        }

        let options: OAuthStrategyOptions = {
            clientID: secrets.id,
            clientSecret: secrets.secret,
            profileFields,
            passReqToCallback: true
        };
        this.passportStrategy = new strategy(options, this.passportCallback.bind(this));
    }

    protected async passportCallback(request: Request, accessToken: string, refreshToken: string, profile: Profile, done: PassportDone) {
        let serviceName = this.name as IConfig.OAuthServices;
        let serviceEmail: string | undefined = undefined;

        if (profile.emails && profile.emails.length > 0) {
            serviceEmail = profile.emails[0].value.trim();
        }

        ExternalServiceCallback(request, serviceName, profile.id, profile.username, serviceEmail, done);
    }

    public use(authRoutes: Router, scope: string[]) {
        passport.use(this.passportStrategy);

        const callbackHref = `auth/${this.name}/callback`;

        authRoutes.get(`/${this.name}`, validateAndCacheHostName, (request, response, next) => {
            let callbackURL = `${request.protocol}://${request.hostname}:${getExternalPort(request)}/${callbackHref}`;

            passport.authenticate(
                this.name,
                { scope, callbackURL } as AuthenticateOptions
            )(request, response, next);
        });

        authRoutes.get(`/${this.name}/callback`, validateAndCacheHostName, (request, response, next) => {
            let callbackURL = `${request.protocol}://${request.hostname}:${getExternalPort(request)}/${callbackHref}`;

            passport.authenticate(
                this.name,
                {
                    failureRedirect: "/login",
                    successReturnToOrRedirect: "/",
                    failureFlash: true,
                    callbackURL
                } as AuthenticateOptions
            )(request, response, next);
        });
    }
}

import passport from "passport";
import uuid from "uuid";
import { Request, Router } from "express";

import { config, IConfig } from "../../common";
import { checkAndSetAdmin, validateAndCacheHostName, getExternalPort } from "./util";
import { User, createNew, IUser } from "../../schema";
import { AuthenticateOptions, PassportDone, RegistrationStrategy, StrategyOptions, Strategy, Profile, UserSessionData } from "./types";
import { sendVerificationEmail, resendVerificationEmailLink } from "../../email";

interface OAuthStrategyOptions extends StrategyOptions {
    clientID: string;
    clientSecret: string;
    profileFields?: string[];
}

interface StrategyConstructor {
    new(options: OAuthStrategyOptions, cb: (request: Request, accessToken: string, refreshToken: string, profile: Profile, done: PassportDone) => Promise<void>): Strategy;
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
    let session = request.session as Partial<UserSessionData>;

    // If `user` exists, the user has already logged in with this service and is good-to-go
    let user = await User.findOne({ [`services.${serviceName}.id`]: id });

    if (session && session.email && session.firstName && session.lastName) {
        let signupEmail = session.email.trim().toLowerCase();
        // Only create / modify user account if email and name exist on the session (set by login page)
        let existingUser = await User.findOne({ email: signupEmail });

        if (!user && serviceEmail && existingUser && existingUser.verifiedEmail && existingUser.email === serviceEmail) {
            user = existingUser;
            // Add new service
            if (!user.services) {
                user.services = {};
            }
            if (!user.services[serviceName]) {
                user.services[serviceName] = {
                    id,
                    email: serviceEmail,
                    username
                };
            }
            try {
                user.markModified("services");
                await user.save();
            }
            catch (err) {
                done(err);
                return;
            }
        } else if (!user && !existingUser) {
            // Create an account
            user = createNew<IUser>(User, {
                ...OAuthStrategy.defaultUserProperties,
                email: signupEmail,
                name: {
                    first: session.firstName,
                    preferred: session.preferredName,
                    last: session.lastName,
                },
            });

            user.services = {};
            user.services[serviceName] = {
                id,
                email: serviceEmail,
                username
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
        done(null, false, { "message": "Could not match login to existing account" });
        return;
    }

    if (!user.verifiedEmail && !user.emailVerificationCode) {
        await sendVerificationEmail(request, user);
    }

    if (!user.verifiedEmail) {
        request.logout();
        request.flash("success", `Account created successfully. Please verify your email before signing in. ${resendVerificationEmailLink(request, user.uuid)}`);
        done(null, false);
        return;
    }

    await checkAndSetAdmin(user);

    if (session) {
        session.email = undefined;
        session.firstName = undefined;
        session.preferredName = undefined;
        session.lastName = undefined;
    }

    done(null, user);
}

export abstract class OAuthStrategy implements RegistrationStrategy {
    public readonly passportStrategy: Strategy;

    public static get defaultUserProperties() {
        return {
            "uuid": uuid(),
            "verifiedEmail": false,
            "admin": false,
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

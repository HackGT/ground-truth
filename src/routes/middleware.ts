import express from "express";
import { IRateLimiterMongoOptions, RateLimiterMongo } from "rate-limiter-flexible";
import fetch from "node-fetch";

import { IUser, User } from "../schema";
import { config, IConfig, mongoose } from "../common";
import { ErrorTemplate } from "../templates";

export async function bestLoginMethod(email?: string): Promise<IConfig.Services | "unknown"> {
    let type: IConfig.Services | "unknown" = "unknown";
    if (email) {
        let user = await User.findOne({ email: email.trim().toLowerCase() });
        if (user) {
            // Least important first
            if (user.local && user.local.hash) {
                type = "local";
            }
            if (user.services) {
                if (user.services.facebook) {
                    type = "facebook";
                }
                if (user.services.github) {
                    type = "github";
                }
                if (user.services.google) {
                    type = "google";
                }
                if (user.services.gatech) {
                    type = "gatech";
                }
            }
        }
    }
    return type;
}

export async function authenticateWithRedirect(request: express.Request, response: express.Response, next: express.NextFunction) {
    response.setHeader("Cache-Control", "private");
    let user = request.user as IUser | undefined;

    if (!request.isAuthenticated() || !user || !user.verifiedEmail) {
        if (request.session) {
            request.session.returnTo = request.originalUrl;
        }
        response.redirect("/login");
    } else if (user && user.forceLogOut) {
        let userModel = await User.findOne({ uuid: user.uuid });
        if (userModel) {
            userModel.forceLogOut = false;
            await userModel.save();
        }

        if (request.session) {
            request.session.passport = undefined;
            request.session.returnTo = request.originalUrl;
        }
        response.redirect("/login");
    } else {
        next();
    }
}

export function isAdmin(request: express.Request, response: express.Response, next: express.NextFunction) {
    authenticateWithRedirect(request, response, (err?: any) => {
        if (err) {
            next(err);
            return;
        }
        if (!request.user?.admin) {
            response.redirect("/");
            return;
        }
        next();
    });
}


const createRateLimit = (options: Partial<IRateLimiterMongoOptions>, setHeaders = true): express.RequestHandler => {
    const rateLimiter = new RateLimiterMongo({
        storeClient: mongoose.connection,
        tableName: config.server.rateLimitCollection,
        ...options
    });

    return (request, response, next) => {
        rateLimiter.consume(request.ip)
            .then((rateLimitRes) => {
                if (setHeaders) {
                    response.set("X-RateLimit-Limit", options.points?.toString());
                    response.set("X-RateLimit-Remaining", rateLimitRes.remainingPoints.toString());
                    response.set("X-RateLimit-Reset", (rateLimitRes.msBeforeNext / 1000).toString());
                }

                next();
            })
            .catch(() => {
                let templateData = {
                    title: "Too Many Requests",
                    errorTitle: "429 - An Error Occurred",
                    errorSubtitle: "Sorry, too many requests have been sent. Please try again later.",
                    button: true
                };

                response.status(429).send(ErrorTemplate.render(templateData));
            });
    }
};

export const rateLimit = {
    "local-signup": createRateLimit({ points: 30, duration: 60 * 60, keyPrefix: "local-signup" }),                      // 30 per 60 min
    "local-login-slow": createRateLimit({ points: 200, duration: 60 * 60 * 24, keyPrefix: "local-login-slow" }),        // 200 per 1 day
    "local-login": createRateLimit({ points: 40, duration: 60 * 15, keyPrefix: "local-login" }),                        // 40 per 15 min
    "verify-code": createRateLimit({ points: 100, duration: 60 * 60 * 24, keyPrefix: "verify-code" }),                  // 100 per 1 day
    "send-email-verify": createRateLimit({ points: 50, duration: 60 * 60 * 6, keyPrefix: "send-email-verify" }),        // 50 per 6 hours
    "forgot-code": createRateLimit({ points: 100, duration: 60 * 60 * 24, keyPrefix: "forgot-code" }),                  // 100 per 1 day
    "send-email-forgot": createRateLimit({ points: 50, duration: 60 * 60 * 6, keyPrefix: "send-email-forgot" }),        // 50 per 6 hours
    "local-change-password": createRateLimit({ points: 20, duration: 60 * 60, keyPrefix: "local-change-password" }),    // 20 per 60 min
    "api-admin": createRateLimit({ points: 500, duration: 60 * 30, keyPrefix: "api-admin" }),                           // 500 per 30 min
    "api-user": createRateLimit({ points: 3000, duration: 60 * 2, keyPrefix: "api-user" }),                             // 3000 per 2 min
    "api-client": createRateLimit({ points: 500, duration: 60 * 5, keyPrefix: "api-client" }),                          // 500 per 5 min
    "ui": createRateLimit({ points: 1000, duration: 60 * 2, keyPrefix: "ui" }),                                         // 1000 per 2 min
    "oauth-authorize": createRateLimit({ points: 200, duration: 60 * 30, keyPrefix: "oauth-authorize" }),               // 200 per 30 min
    "oauth-token": createRateLimit({ points: 2000, duration: 60 * 5, keyPrefix: "oauth-token" }),                       // 2000 per 5 min
    "auth-general": createRateLimit({ points: 10000, duration: 60 * 1, keyPrefix: "auth-general" }),                    // 10000 per 1 min
}


export const verifyRecaptcha = (redirectIfFailUrl: string = ""): express.RequestHandler => {
    return async (request, response, next) => {
        try {
            const opt = {
                secret: config.secrets.recaptcha.secretKey,
                response: request.body["g-recaptcha-response"] || "",
                remoteip: request.ip
            }

            const res = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${opt.secret}&response=${opt.response}&remoteip=${opt.remoteip}`, {
                method: "POST"
            });

            const json = await res.json();

            if (json.success) {
                next();
            } else {
                request.flash("error", "Please complete the recaptcha validation.");

                if (redirectIfFailUrl === "") {
                    response.end(); // Used for login endpoint
                } else {
                    response.redirect(redirectIfFailUrl.replace(":code", request.params.code)); // Used for forgot password reset endpoint
                }
            }
        } catch (err) {
            next(err);
        }
    }
}

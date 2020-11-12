import express from "express";
import bodyParser from "body-parser";

import { IUser, User } from "../schema";
import { IConfig } from "../common";

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

export const postParser = bodyParser.urlencoded({
    extended: false
});

export async function authenticateWithRedirect(request: express.Request, response: express.Response, next: express.NextFunction) {
    response.setHeader("Cache-Control", "private");
    let user = request.user as IUser | undefined;
    if (!request.isAuthenticated() || !user || !user.verifiedEmail) {
        if (request.session) {
            request.session.returnTo = request.originalUrl;
        }
        response.redirect("/login");
    }
    else if (user && user.forceLogOut) {
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
    }
    else {
        next();
    }
}

export function isAdmin(request: express.Request, response: express.Response, next: express.NextFunction) {
    authenticateWithRedirect(request, response, (err?: any) => {
        if (err) {
            next(err);
            return;
        }
        if (!request.user.admin) {
            response.redirect("/");
            return;
        }
        next();
    });
}

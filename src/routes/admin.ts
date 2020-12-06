import crypto from "crypto";
import express from "express";
import uuid from "uuid";

import { createNew, User, IOAuthClient, OAuthClient, AccessToken, Scope, IScope } from "../schema";
import { isAdmin, postParser } from "./middleware";

export let adminRoutes = express.Router();

adminRoutes.use(isAdmin);
adminRoutes.use(postParser);

adminRoutes.post("/app", async (request, response) => {
    let name: string = (request.body.name || "").trim();
    let rawRedirectURIs: string = (request.body.redirectURIs || "").trim();
    let redirectURIs: string[] = rawRedirectURIs.split(/, ?/);
    if (!name || !rawRedirectURIs) {
        response.status(400).json({
            error: "Missing name or redirect URI(s)"
        });
        return;
    }

    try {
        await createNew<IOAuthClient>(OAuthClient, {
            uuid: uuid.v4(),
            clientID: crypto.randomBytes(32).toString("hex"),
            clientSecret: crypto.randomBytes(64).toString("hex"),
            name,
            redirectURIs,
            public: request.body.clientType === "public"
        }).save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while creating app"
        });
    }
});

adminRoutes.post("/app/:id/rename", async (request, response) => {
    let app = await OAuthClient.findOne({ uuid: request.params.id });
    if (!app) {
        response.status(400).json({
            error: "Invalid app ID"
        });
        return;
    }

    let name: string = (request.body.name || "").trim();
    if (!name) {
        response.status(400).json({
            error: "Invalid name"
        });
        return;
    }

    try {
        app.name = name;
        await app.save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while updating the app name"
        });
    }
});

adminRoutes.post("/app/:id/redirects", async (request, response) => {
    let app = await OAuthClient.findOne({ uuid: request.params.id });
    if (!app) {
        response.status(400).json({
            error: "Invalid app ID"
        });
        return;
    }

    let URIs = (request.body.redirectURIs as string || "").trim().split(/, ?/);

    try {
        app.redirectURIs = URIs;
        await app.save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while updating the app's redirect URIs"
        });
    }
});

adminRoutes.post("/app/:id/regenerate", async (request, response) => {
    let app = await OAuthClient.findOne({ uuid: request.params.id });
    if (!app) {
        response.status(400).json({
            error: "Invalid app ID"
        });
        return;
    }

    let secret = crypto.randomBytes(64).toString("hex");
    try {
        app.clientSecret = secret;
        await app.save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while regenerating the client secret"
        });
    }
});

adminRoutes.post("/app/:id/delete", async (request, response) => {
    let app = await OAuthClient.findOne({ uuid: request.params.id });
    if (!app) {
        response.status(400).json({
            error: "Invalid app ID"
        });
        return;
    }

    try {
        await AccessToken.deleteMany({ clientID: app.clientID });
        await app.remove();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while deleting this app"
        });
    }
});

adminRoutes.post("/scope", async (request, response) => {
    function getParam(name: string): string {
        return (request.body[name] || "").trim();
    }
    let name = getParam("name").toLowerCase().replace(/ /g, "-").replace(/,/, "");
    let question = getParam("question");
    let type = getParam("type");
    let validatorCode: string | undefined = request.body.validatorCode;
    let errorMessage: string | undefined = request.body.errorMessage;
    let icon: string | undefined = getParam("icon") || undefined;

    if (!name || !question || !type) {
        response.status(400).json({
            error: "Missing name, question, or type"
        });
        return;
    }

    if ((validatorCode && !errorMessage) || (!validatorCode && errorMessage)) {
        response.status(400).json({
            error: "Validator code and corresponding error message cannot appear individually"
        });
        return;
    }

    try {
        await createNew<IScope>(Scope, {
            name,
            question,
            type,
            validator: validatorCode ? {
                code: validatorCode,
                errorMessage: errorMessage!
            } : undefined,
            icon
        }).save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while creating scope"
        });
    }
});

adminRoutes.post("/scope/delete", async (request, response) => {
    let scope = await Scope.findOne({ name: request.body.name });
    if (!scope) {
        response.status(400).json({
            error: "Invalid scope name"
        });
        return;
    }

    try {
        await scope.remove();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while deleting this scope"
        });
    }
});

async function changeUserStatus(fields: ("admin" | "member")[], newStatus: boolean, request: express.Request, response: express.Response) {
    let user = await User.findOne({ email: (request.body.email || "").trim().toLowerCase() });
    if (!user) {
        response.status(400).json({
            error: "No existing user found with that email"
        });
        return;
    }

    try {
        fields.forEach(field => user![field] = newStatus);
        await user.save();
        response.json({
            success: true
        });
    } catch (err) {
        console.error(err);
        response.status(500).json({
            error: "An error occurred while setting new status"
        });
    }
}

adminRoutes.post("/add-admin", changeUserStatus.bind(null, ["admin"], true));
adminRoutes.post("/remove-admin", changeUserStatus.bind(null, ["admin"], false));

adminRoutes.post("/add-member", changeUserStatus.bind(null, ["member"], true));
adminRoutes.post("/remove-member", changeUserStatus.bind(null, ["member", "admin"], false)); // Set both to false when removing member

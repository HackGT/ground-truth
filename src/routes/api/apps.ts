import crypto from "crypto";
import express from "express";
import uuid from "uuid";

import { createNew, IOAuthClient, OAuthClient, AccessToken } from "../../schema";
import { isAdmin, postParser } from "../middleware";

export let appsRouter = express.Router();

appsRouter.use(isAdmin);
appsRouter.use(postParser);

appsRouter.post("/", async (request, response) => {
    try {
        let name: string = (request.body.name || "").trim();
        let rawRedirectURIs: string = (request.body.redirectURIs || "").trim();
        let redirectURIs: string[] = rawRedirectURIs.split(/, ?/);
        if (!name || !rawRedirectURIs) {
            response.status(400).json({
                error: "Missing name or redirect URI(s)"
            });
            return;
        }

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

appsRouter.put("/:id/rename", async (request, response) => {
    try {
        let app = await OAuthClient.findById(request.params.id);
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

appsRouter.put("/:id/redirects", async (request, response) => {
    try {
        let app = await OAuthClient.findById(request.params.id);
        if (!app) {
            response.status(400).json({
                error: "Invalid app ID"
            });
            return;
        }

        let URIs = (request.body.redirectURIs as string || "").trim().split(/, ?/);

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

appsRouter.put("/:id/regenerate", async (request, response) => {
    try {
        let app = await OAuthClient.findById(request.params.id);
        if (!app) {
            response.status(400).json({
                error: "Invalid app ID"
            });
            return;
        }

        let secret = crypto.randomBytes(64).toString("hex");
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

appsRouter.delete("/:id", async (request, response) => {
    try {
        let app = await OAuthClient.findById(request.params.id);
        if (!app) {
            response.status(400).json({
                error: "Invalid app ID"
            });
            return;
        }

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

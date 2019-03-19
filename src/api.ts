import crypto from "crypto";
import express from "express";
import passport from "passport";

import { IConfig, IUser, User, OAuthClient } from "./schema";
import { postParser, isAdmin } from "./common";

export let apiRoutes = express.Router();

apiRoutes.get("/user", passport.authenticate("bearer", { session: false }), async (request, response) => {
	let user = request.user as IUser;
	response.json({
		"uuid": user.uuid,
		"name": user.name,
		"email": user.email,
	});
});

export async function bestLoginMethod(email?: string): Promise<IConfig.Services | "unknown"> {
	let type: IConfig.Services | "unknown" = "unknown";
	if (email) {
		let user = await User.findOne({ email });
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

apiRoutes.get("/login-type", async (request, response) => {
	let email = request.query.email as string | undefined;
	response.json({ type: await bestLoginMethod(email) });
});

apiRoutes.post("/signup-data", postParser, (request, response) => {
	if (!request.session) return;

	let email = request.body.email as string | undefined;
	let name = request.body.name as string | undefined;
	if (email) {
		request.session.email = email;
	}
	if (name) {
		request.session.name = name;
	}
	response.send();
});

let adminRoutes = express.Router();
apiRoutes.use("/admin", isAdmin, postParser, adminRoutes);

adminRoutes.post("/app/:id/rename", async (request, response) => {
	let app = await OAuthClient.findOne({ uuid: request.params.id });
	if (!app) {
		response.status(400).json({
			"error": "Invalid app ID"
		});
		return;
	}
	let name: string = (request.body.name || "").trim();
	if (!name) {
		response.status(400).json({
			"error": "Invalid name"
		});
		return;
	}

	try {
		app.name = name;
		await app.save();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while updating the app name"
		});
	}
});

adminRoutes.post("/app/:id/redirects", async (request, response) => {
	let app = await OAuthClient.findOne({ uuid: request.params.id });
	if (!app) {
		response.status(400).json({
			"error": "Invalid app ID"
		});
		return;
	}
	let URIs = (request.body.redirectURIs as string || "").trim().split(/, ?/);

	try {
		app.redirectURIs = URIs;
		await app.save();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while updating the app's redirect URIs"
		});
	}
});

adminRoutes.post("/app/:id/regenerate", async (request, response) => {
	let app = await OAuthClient.findOne({ uuid: request.params.id });
	if (!app) {
		response.status(400).json({
			"error": "Invalid app ID"
		});
		return;
	}
	let secret = crypto.randomBytes(64).toString("hex");
	try {
		app.clientSecret = secret;
		await app.save();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while regenerating the client secret"
		});
	}
});

adminRoutes.post("/app/:id/delete", async (request, response) => {
	let app = await OAuthClient.findOne({ uuid: request.params.id });
	if (!app) {
		response.status(400).json({
			"error": "Invalid app ID"
		});
		return;
	}
	try {
		await app.remove();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while deleting this app"
		});
	}
});

import crypto from "crypto";
import express from "express";
import passport from "passport";
import uuid from "uuid";

import {
	createNew, IConfig,
	IUser, User,
	IOAuthClient, OAuthClient, AccessToken, Scope, IScope
} from "./schema";
import { formatName } from "./common";
import { postParser, isAdmin } from "./middleware";
import { UserSessionData } from "./auth/strategies";

export let apiRoutes = express.Router();

apiRoutes.get("/user", passport.authenticate("bearer", { session: false }), async (request, response) => {
	let user = request.user as IUser;
	response.json({
		"uuid": user.uuid,
		"name": formatName(user),
		"nameParts": user.name,
		"email": user.email,
		"scopes": (user.scopes && Object.keys(user.scopes).length > 0) ? user.scopes : null
	});
});

apiRoutes.post("/user/logout", passport.authenticate("bearer", { session: false }), postParser, async (request, response) => {
	let user = request.user as IUser;
	let existingTokens = await AccessToken.find({ "uuid": user.uuid });
	for (let token of existingTokens) {
		await token.remove();
	}
	let userDB = await User.findOne({ uuid: user.uuid });
	if (userDB) {
		userDB.forceLogOut = true;
		await userDB.save();
	}

	response.json({ "success": true });
});

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
				if (user.services.fido2) {
					type = "fido2";
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
	function attachToSession(bodyProperty: keyof UserSessionData) {
		if (!request.session) return;

		let value = request.body[bodyProperty] as string | undefined;
		if (value) {
			request.session[bodyProperty] = value;
		}
	}

	attachToSession("email");
	attachToSession("firstName");
	attachToSession("preferredName");
	attachToSession("lastName");

	response.send();
});

let adminRoutes = express.Router();
apiRoutes.use("/admin", isAdmin, postParser, adminRoutes);

adminRoutes.post("/app", async (request, response) => {
	let name: string = (request.body.name || "").trim();
	let rawRedirectURIs: string = (request.body.redirectURIs || "").trim();
	let redirectURIs: string[] = rawRedirectURIs.split(/, ?/);
	if (!name || !rawRedirectURIs) {
		response.status(400).json({
			"error": "Missing name or redirect URI(s)"
		});
		return;
	}
	let clientType: "private" | "public" = request.body.clientType;
	if (clientType !== "private" && clientType !== "public") {
		clientType = "private";
	}

	try {
		await createNew<IOAuthClient>(OAuthClient, {
			uuid: uuid.v4(),
			clientID: crypto.randomBytes(32).toString("hex"),
			clientSecret: crypto.randomBytes(64).toString("hex"),
			name,
			redirectURIs,
			public: clientType === "public"
		}).save();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while creating app"
		});
	}
});

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
		await AccessToken.deleteMany({ clientID: app.clientID });
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
			"error": "Missing name, question, or type"
		});
		return;
	}
	if ((validatorCode && !errorMessage) || (!validatorCode && errorMessage)) {
		response.status(400).json({
			"error": "Validator code and corresponding error message cannot appear individually"
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
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while creating scope"
		});
	}
});

adminRoutes.post("/scope/delete", async (request, response) => {
	let scope = await Scope.findOne({ name: request.body.name });
	if (!scope) {
		response.status(400).json({
			"error": "Invalid scope name"
		});
		return;
	}
	try {
		await scope.remove();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while deleting this scope"
		});
	}
});

async function changeAdminStatus(isAdmin: boolean, request: express.Request, response: express.Response) {
	let user = await User.findOne({ email: (request.body.email || "").trim().toLowerCase() });
	if (!user) {
		response.status(400).json({
			"error": "No existing user found with that email"
		});
		return;
	}

	try {
		user.admin = isAdmin;
		await user.save();
		response.json({
			"success": true
		});
	}
	catch (err) {
		console.error(err);
		response.status(500).json({
			"error": "An error occurred while setting admin status"
		});
	}
}

adminRoutes.post("/add", changeAdminStatus.bind(null, true));
adminRoutes.post("/remove", changeAdminStatus.bind(null, false));

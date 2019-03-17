import * as crypto from "crypto";
import * as express from "express";
import { URL } from "url";
import session from "express-session";
import bodyParser from "body-parser";
import connectMongo from "connect-mongo";
const MongoStore = connectMongo(session);
import passport from "passport";
import * as oauth2orize from "oauth2orize";
import { BasicStrategy } from "passport-http";
import { Strategy as BearerStrategy } from "passport-http-bearer";
import { Strategy as ClientPasswordStrategy } from "passport-oauth2-client-password";

import {
	config, mongoose, COOKIE_OPTIONS, postParser, authenticateWithRedirect
} from "../common";
import {
	createNew, Model,
	IUser, User,
	IAuthorizationCode, AuthorizationCode,
	IAccessToken, AccessToken, IOAuthClient, OAuthClient, TemplateContent, IConfig,
} from "../schema";
import { Template } from "../templates";
import {
	RegistrationStrategy, strategies, validateAndCacheHostName, sendVerificationEmail
} from "./strategies";

// Passport authentication
import { app } from "../app";

if (!config.server.isProduction) {
	console.warn("OAuth callback(s) running in development mode");
}
else {
	app.enable("trust proxy");
}
if (!config.sessionSecretSet) {
	console.warn("No session secret set; sessions won't carry over server restarts");
}
app.use(session({
	secret: config.secrets.session,
	cookie: COOKIE_OPTIONS,
	resave: false,
	store: new MongoStore({
		mongooseConnection: mongoose.connection,
		touchAfter: 24 * 60 * 60 // Check for TTL every 24 hours at minimum
	}),
	saveUninitialized: false
}));
passport.serializeUser<IUser, string>((user, done) => {
	done(null, user._id.toString());
});
passport.deserializeUser<IUser, string>((id, done) => {
	User.findById(id, (err, user) => {
		done(err, user!);
	});
});

export let authRouter = express.Router();

let authenticationMethods: RegistrationStrategy[] = [];
console.info(`Using authentication methods: ${config.loginMethods.join(", ")}`);
for (let methodName of config.loginMethods) {
	if (!strategies[methodName]) {
		console.error(`Authentication method "${methodName}" is not available. Did you add it to the exported list of strategies?`);
		continue;
	}
	let method = new strategies[methodName]();
	authenticationMethods.push(method);
	method.use(authRouter);
}

authRouter.get("/validatehost/:nonce", (request, response) => {
	let nonce: string = request.params.nonce || "";
	response.send(crypto.createHmac("sha256", config.secrets.session).update(nonce).digest().toString("hex"));
});

app.all("/logout", (request, response) => {
	request.logout();
	if (request.session) {
		request.session.destroy(() => {
			response.redirect("/login");
		});
	}
	else {
		response.redirect("/login");
	}
});

app.use(passport.initialize());
app.use(passport.session());

// OAuth server stuff
export let OAuthRouter = express.Router();
OAuthRouter.use(postParser);

/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients. They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens. The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate. Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header). While this approach is not recommended by
 * the specification, in practice it is quite common.
 */
async function verifyClient(clientID: string, clientSecret: string, done: (err: Error | null, client?: IOAuthClient | false) => void) {
	try {
		let client = await OAuthClient.findOne({ clientID });
		if (!client || client.clientSecret !== clientSecret) {
			done(null, false);
			return;
		}
		done(null, client);
	}
	catch (err) {
		done(err);
	}
}
passport.use(new BasicStrategy(verifyClient));
passport.use(new ClientPasswordStrategy(verifyClient));
/**
 * BearerStrategy
 *
 * This strategy is used to authenticate either users or clients based on an access token
 * (aka a bearer token). If a user, they must have previously authorized a client
 * application, which is issued an access token to make requests on behalf of
 * the authorizing user.
 */
passport.use(new BearerStrategy(async (rawToken, done) => {
	try {
		let token = await AccessToken.findOne({ token: rawToken });
		if (!token) {
			done(null, false);
			return;
		}
		let user = await User.findOne({ uuid: token.uuid });
		if (!user) {
			done(null, false);
			return;
		}
		// TODO: implement scopes
		done(null, user, { scope: "*", message: "" });
	}
	catch (err) {
		done(err);
	}
}));

const server = oauth2orize.createServer();
server.serializeClient((client: IOAuthClient, done) => {
	done(null, client.uuid)
});
server.deserializeClient(async (uuid, done) => {
	try {
		let client = await OAuthClient.findOne({ uuid });
		done(null, client || false);
	}
	catch (err) {
		done(err);
	}
});

server.grant(oauth2orize.grant.code(async (client: IOAuthClient, redirectURI, user: IUser, ares, done) => {
	const code = crypto.randomBytes(16).toString("hex");
	try {
		await createNew<IAuthorizationCode>(AuthorizationCode, {
			clientID: client.clientID,
			code,
			redirectURI,
			uuid: user.uuid,
		}).save();
		done(null, code);
	}
	catch (err) {
		done(err);
	}
}));

server.exchange(oauth2orize.exchange.code(async (client: IOAuthClient, code, redirectURI, done) => {
	try {
		let authCode = await AuthorizationCode.findOne({ code });
		if (!authCode || client.clientID !== authCode.clientID || redirectURI !== authCode.redirectURI) {
			done(null, false);
			return;
		}
		const token = crypto.randomBytes(128).toString("hex");
		await createNew<IAccessToken>(AccessToken, {
			token,
			clientID: authCode.clientID,
			uuid: authCode.uuid,
		}).save();
		await authCode.remove();
		const params = {};
		done(null, token, undefined, params);
	}
	catch (err) {
		done(err);
	}
}));

interface IAuthorizationTemplate extends TemplateContent {
	name: string;
	email: string;
	appName: string;
	redirect: string;
	transactionID: string;
}
const AuthorizeTemplate = new Template<IAuthorizationTemplate>("authorize.hbs");
OAuthRouter.get("/authorize", authenticateWithRedirect, server.authorization(async (clientID, redirectURI, done) => {
	try {
		let client = await OAuthClient.findOne({ clientID });
		// Redirect URIs are allowed on a same-origin basis
		// This is so that changing example.com/endpoint to example.com/other_endpoint doesn't result in failure
		let redirectOrigin = new URL(redirectURI).origin;
		if (!client || !client.redirectURIs.includes(redirectOrigin)) {
			done(null, false);
			return;
		}
		done(null, client, redirectURI);
	}
	catch (err) {
		done(err);
	}
}, async (client, user, scope, type, areq, done) => {
	try {
		let token = await AccessToken.findOne({ clientID: client.clientID, uuid: user.uuid })
		done(null, !!token, null, null);
	}
	catch (err) {
		done(err, false, null, null);
	}
}), authenticateWithRedirect, (request, response) => {
	let transactionID = request.oauth2.transactionID as string;
	let user = request.user as IUser;
	let client = request.oauth2.client as IOAuthClient;

	response.send(AuthorizeTemplate.render({
		siteTitle: config.server.name,
		title: "Authorize",
		includeJS: false,

		name: user.name,
		email: user.email,
		redirect: new URL(request.oauth2.redirectURI).origin,
		appName: client.name,
		transactionID,
	}));
});

OAuthRouter.post("/authorize/decision", authenticateWithRedirect, server.decision());

OAuthRouter.post("/token", passport.authenticate(["basic", "oauth2-client-password"], { session: false }), server.token(), server.errorHandler());

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

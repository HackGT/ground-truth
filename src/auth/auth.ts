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
	config, mongoose, COOKIE_OPTIONS, postParser
} from "../common";
import {
	createNew, Model,
	IUser, User,
	IAuthorizationCode, AuthorizationCode,
	IAccessToken, AccessToken, IOAuthClient, OAuthClient,
} from "../schema";
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

authRouter.post("/confirm", validateAndCacheHostName, postParser, async (request, response) => {
	let user = request.user as Model<IUser>;
	let name = request.body.name as string;
	if (!name || !name.trim()) {
		request.flash("error", "Invalid name");
		response.redirect("/login/confirm");
		return;
	}
	if (!request.isAuthenticated() || !user) {
		request.flash("error", "Must be logged in");
		response.redirect("/login");
		return;
	}
	user.name = name.trim();

	let email = request.body.email as string | undefined;
	if (email && email !== user.email) {
		if (!email.trim()) {
			request.flash("error", "Invalid email");
			response.redirect("/login/confirm");
			return;
		}
		if (await User.count({ email }) > 0) {
			request.flash("error", "That email address is already in use. You may already have an account from another login service.");
			response.redirect("/login/confirm");
			return;
		}
		user.verifiedEmail = false;
		user.email = email;
	}
	user.accountConfirmed = true;

	try {
		await user.save();
		if (!user.verifiedEmail && !user.emailVerificationCode) {
			await sendVerificationEmail(request, user);
		}
		if (!user.verifiedEmail) {
			request.logout();
			request.flash("success", "Account created successfully. Please verify your email before logging in.");
			response.redirect("/login");
			return;
		}
		response.redirect("/");
	}
	catch (err) {
		console.error(err);
		request.flash("error", "An error occurred while creating your account");
		response.redirect("/login/confirm");
	}
});

authRouter.get("/validatehost/:nonce", (request, response) => {
	let nonce: string = request.params.nonce || "";
	response.send(crypto.createHmac("sha256", config.secrets.session).update(nonce).digest().toString("hex"));
});

app.all("/logout", (request, response) => {
	request.logout();
	response.redirect("/login");
});

app.use(passport.initialize());
app.use(passport.session());

// OAuth server stuff
export let OAuthRouter = express.Router();
OAuthRouter.use(bodyParser.urlencoded({ extended: true }));

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

server.grant(oauth2orize.grant.code(async (client, redirectURI, user: IUser, ares, done) => {
	const code = crypto.randomBytes(16).toString("hex");
	try {
		await createNew<IAuthorizationCode>(AuthorizationCode, {
			clientID: client.id,
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

server.exchange(oauth2orize.exchange.code(async (client, code, redirectURI, done) => {
	try {
		let authCode = await AuthorizationCode.findOne({ code });
		if (!authCode || client.id !== authCode.clientID || redirectURI !== authCode.redirectURI) {
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

export function authenticateWithRedirect(request: express.Request, response: express.Response, next: express.NextFunction) {
	response.setHeader("Cache-Control", "private");
	if (!request.isAuthenticated() || !request.user || !request.user.verifiedEmail || !request.user.accountConfirmed) {
		if (request.session) {
			request.session.returnTo = request.originalUrl;
		}
		response.redirect("/login");
	}
	else {
		next();
	}
}

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
}), (request, response) => {
	let oauth2 = (request as any).oauth2;
	response.json({ transactionId: oauth2.transactionID, user: request.user, client: oauth2.client })
});

OAuthRouter.post("/authorize/decision", authenticateWithRedirect, server.decision());

OAuthRouter.post("/token", passport.authenticate(["basic", "oauth2-client-password"], { session: false }), server.token(), server.errorHandler());

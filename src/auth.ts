import * as crypto from "crypto";
import * as path from "path";
import * as express from "express";
import session from "express-session";
import connectMongo from "connect-mongo";
import * as bodyParser from "body-parser";
const MongoStore = connectMongo(session);
import * as passport from "passport";

import {
	config, mongoose, COOKIE_OPTIONS, postParser
} from "./common";
import {
	IUser, User, IUserMongoose
} from "./schema";
import {
	RegistrationStrategy, strategies, validateAndCacheHostName, sendVerificationEmail
} from "./strategies";

// Passport authentication
import { app } from "./app";

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
	let user = request.user as IUserMongoose;
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

authRouter.all("/logout", (request, response) => {
	request.logout();
	response.redirect("/login");
});

app.use(passport.initialize());
app.use(passport.session());

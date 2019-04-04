import express from "express";
import compression from "compression";
import cookieParser from "cookie-parser";
import * as cookieSignature from "cookie-signature";
import * as chalk from "chalk";
import morgan from "morgan";
import flash from "connect-flash";

import {
	// Constants
	PORT, VERSION_NUMBER, VERSION_HASH, COOKIE_OPTIONS,
	// Configuration
	config
} from "./common";

// Set up Express and its middleware
export let app = express();

import bugsnag from "@bugsnag/js";
import bugsnagExpress from "@bugsnag/plugin-express";
let bugsnagMiddleware: any | null = null;
if (config.secrets.bugsnag) {
	const bugsnagClient = bugsnag({
		apiKey: config.secrets.bugsnag,
		appVersion: VERSION_NUMBER
	});
	bugsnagClient.use(bugsnagExpress);
	bugsnagMiddleware = bugsnagClient.getPlugin("express");
	// Must come first to capture errors downstream
	app.use(bugsnagMiddleware.requestHandler);
}
else {
	console.info("Bugsnag API key not set");
}

app.use(compression());
let cookieParserInstance = cookieParser(undefined, COOKIE_OPTIONS as cookieParser.CookieParseOptions);
app.use(cookieParserInstance);
morgan.token("sessionid", (request, response) => {
	const FAILURE_MESSAGE = "Unknown session";
	if (!request.cookies["groundtruthid"]) {
		return FAILURE_MESSAGE;
	}
	let rawID: string = request.cookies["groundtruthid"].slice(2);
	let id = cookieSignature.unsign(rawID, config.secrets.session);
	if (typeof id === "string") {
		return id;
	}
	return FAILURE_MESSAGE;
});
morgan.format("hackgt", (tokens, request, response) => {
	let statusColorizer: (input: string) => string = input => input; // Default passthrough function
	if (response.statusCode >= 500) {
		statusColorizer = chalk.default.red;
	}
	else if (response.statusCode >= 400) {
		statusColorizer = chalk.default.yellow;
	}
	else if (response.statusCode >= 300) {
		statusColorizer = chalk.default.cyan;
	}
	else if (response.statusCode >= 200) {
		statusColorizer = chalk.default.green;
	}

	return [
		tokens.date(request, response, "iso"),
		tokens["remote-addr"](request, response),
		tokens.sessionid(request, response),
		tokens.method(request, response),
		tokens.url(request, response),
		statusColorizer(tokens.status(request, response)),
		tokens["response-time"](request, response), "ms", "-",
		tokens.res(request, response, "content-length")
	].join(" ");
});
app.use(morgan("hackgt"));
app.use(flash());

// Throw and show a stack trace on an unhandled Promise rejection instead of logging an unhelpful warning
process.on("unhandledRejection", err => {
	throw err;
});

// Auth needs to be the first route configured or else requests handled before it will always be unauthenticated
import { authRouter, OAuthRouter } from "./auth/auth";
app.use("/auth", authRouter);
app.use("/oauth", OAuthRouter);

import { apiRoutes } from "./api";
app.use("/api", apiRoutes);

import { uiRoutes } from "./templates";
app.use("/", uiRoutes);

app.route("/version").get((request, response) => {
	response.json({
		"version": VERSION_NUMBER,
		"hash": VERSION_HASH,
		"node": process.version
	});
});

if (bugsnagMiddleware) {
	app.use(bugsnagMiddleware.errorHandler);
}

app.listen(PORT, () => {
	console.log(`Ground Truth system v${VERSION_NUMBER} @ ${VERSION_HASH} started on port ${PORT}`);
});

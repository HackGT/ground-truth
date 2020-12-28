import express from "express";
import compression from "compression";
import cookieParser from "cookie-parser";
import * as cookieSignature from "cookie-signature";
import * as chalk from "chalk";
import * as path from "path";
import morgan from "morgan";
import flash from "connect-flash";
import * as Sentry from "@sentry/node";
import * as Tracing from "@sentry/tracing";
import helmet from "helmet";

import {
    // Constants
    PORT, VERSION_NUMBER, VERSION_HASH, COOKIE_OPTIONS,
    // Configuration
    config
} from "./common";
import { ErrorTemplate } from "./templates";

// Set up Express and its middleware
export let app = express();

// Sentry setup
if (config.secrets.sentryDSN) {
    Sentry.init({
        dsn: config.secrets.sentryDSN,
        integrations: [
            new Sentry.Integrations.Http({ tracing: true }), // Enable HTTP calls tracing
            new Tracing.Integrations.Express({ app }) // Enable Express.js middleware tracing
        ],
        tracesSampleRate: 1.0,
    });

    app.use(Sentry.Handlers.requestHandler({
        user: ["id", "uuid", "email"],
        ip: true
    }));
    app.use(Sentry.Handlers.tracingHandler());
}

morgan.token("sessionid", (request: express.Request, response) => {
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
    let statusColorizer: (input?: string) => string | undefined = input => input; // Default passthrough function

    if (response.statusCode >= 500) {
        statusColorizer = chalk.default.red;
    } else if (response.statusCode >= 400) {
        statusColorizer = chalk.default.yellow;
    } else if (response.statusCode >= 300) {
        statusColorizer = chalk.default.cyan;
    } else if (response.statusCode >= 200) {
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

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"],
            "frame-src": ["https://www.google.com/recaptcha/"]
        }
    }
}));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(undefined, COOKIE_OPTIONS as cookieParser.CookieParseOptions));
app.use(morgan("hackgt"));
app.use(flash());

// Throw and show a stack trace on an unhandled Promise rejection instead of logging an unhelpful warning
process.on("unhandledRejection", err => {
    throw err;
});

import "./auth/auth";

// Auth needs to be the first route configured or else requests handled before it will always be unauthenticated
import { authRouter } from "./routes/auth";
app.use("/auth", authRouter);

import { OAuthRouter } from "./routes/oauth";
app.use("/oauth", OAuthRouter);

import { appsRouter } from "./routes/api/apps";
import { membersRouter } from "./routes/api/members";
import { scopesRouter } from "./routes/api/scopes";
import { clientRouter } from "./routes/api/client";
import { userRouter } from "./routes/api/user";

// Routes for admin page
app.use("/api/apps", appsRouter);
app.use("/api/members", membersRouter);
app.use("/api/scopes", scopesRouter);

app.use("/api/client", clientRouter);
app.use("/api/user", userRouter);

app.use("/static", express.static(path.join(__dirname, "static")));

app.route("/version").get((request, response) => {
    response.json({
        "version": VERSION_NUMBER,
        "hash": VERSION_HASH,
        "node": process.version
    });
});

import { uiRoutes } from "./routes/ui";
app.use("/", uiRoutes);

// The sentry error handler must be before any other error middleware and after all controllers
if (config.secrets.sentryDSN) {
    app.use(Sentry.Handlers.errorHandler());
}

// Error handler middleware
app.use((error: any, request: express.Request, response: express.Response, next: express.NextFunction) => {
    // Error code by csurf when CSRF token validation fails
    if (error.code == "EBADCSRFTOKEN") {
        response.status(403).json({ error: "User is not authorized" });
        return;
    }

    console.error(error.stack);
    let templateData = {
        title: "Server Error",
        errorTitle: "An Error Occurred",
        errorSubtitle: "Sorry, something went wrong. Please try again later.",
        errorMessage: "Error Message: " + error.message,
        button: true
    };

    response.status(500).send(ErrorTemplate.render(templateData));
});

app.listen(PORT, () => {
    console.log(`Ground Truth system v${VERSION_NUMBER} @ ${VERSION_HASH} started on port ${PORT}`);
});

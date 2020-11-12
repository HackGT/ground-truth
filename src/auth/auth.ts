import session from "express-session";
import connectMongo from "connect-mongo";
import passport from "passport";
import { BasicStrategy } from "passport-http";
import { Strategy as BearerStrategy } from "passport-http-bearer";
import { Strategy as ClientPasswordStrategy } from "passport-oauth2-client-password";

import { config, mongoose, COOKIE_OPTIONS } from "../common";
import { IUser, User, AccessToken, IOAuthClient, OAuthClient } from "../schema";

const MongoStore = connectMongo(session);

// Passport authentication
import { app } from "../app";

if (!config.server.isProduction) {
    console.warn("OAuth callback(s) running in development mode");
} else {
    app.enable("trust proxy");
}

if (!config.sessionSecretSet) {
    console.warn("No session secret set; sessions won't carry over server restarts");
}

app.use(session({
    name: "groundtruthid",
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

app.use(passport.initialize());
app.use(passport.session());

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
        // Private apps must have a matching client secret
        // Public apps will verify their code challenge in the exchange step (where auth codes are exchanged for tokens)
        if (!client || (!client.public && client.clientSecret !== clientSecret)) {
            console.warn(`Unauthorized client: ${clientID} (secret: ${clientSecret}, public: ${client ? !!client.public : "Not found"})`);
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
            console.warn(`Invalid token: ${rawToken}`);
            done(null, false);
            return;
        }
        let user = await User.findOne({ uuid: token.uuid });
        if (!user) {
            console.warn(`Valid token mapped to non-existent user: ${token.uuid} (token: ${rawToken})`);
            done(null, false);
            return;
        }
        done(null, user, { scope: token.scopes, message: "" });
    }
    catch (err) {
        done(err);
    }
}));

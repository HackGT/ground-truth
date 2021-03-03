import * as vm from "vm";
import { URL } from "url";
import * as express from "express";
import passport from "passport";
import csrf from "csurf";

import { config } from "../common";
import { authenticateWithRedirect, rateLimit } from "../routes/middleware";
import { Model, IUser, AccessToken, IOAuthClient, OAuthClient, IScope, Scope } from "../schema";
import { AuthorizeTemplate } from "../templates";
import { server } from "../auth/server";
import { formatName } from "../email";

type IScopeWithValue = IScope & { value?: string };

export let OAuthRouter = express.Router();

OAuthRouter.get(
  "/authorize",
  rateLimit["oauth-authorize"],
  authenticateWithRedirect,
  server.authorization(
    async (clientID, redirectURI, done) => {
      try {
        let client = await OAuthClient.findOne({ clientID });
        // Redirect URIs are allowed on a same-origin basis
        // This is so that changing example.com/endpoint to example.com/other_endpoint doesn't result in failure
        let redirectOrigin = new URL(redirectURI).origin;
        if (
          !client ||
          (!client.redirectURIs.includes(redirectOrigin) &&
            !client.redirectURIs.includes(redirectURI))
        ) {
          console.warn(
            `Client doesn't exist or redirect URI is not allowed: ${clientID} (${
              client ? client.name : "Not found"
            }), ${redirectURI}`
          );
          done(null, false);
          return;
        }
        done(null, client, redirectURI);
      } catch (err) {
        done(err);
      }
    },
    async (client: IOAuthClient, user: IUser, scope, type, areq, done) => {
      try {
        let token = await AccessToken.findOne({ clientID: client.clientID, uuid: user.uuid });
        done(null, !!token, { scope }, null);
      } catch (err) {
        done(err, false, { scope }, null);
      }
    }
  ),
  csrf(),
  async (request, response) => {
    if (!request.session) {
      response.status(500).send("Session not enabled but is required");
      return;
    }
    // Save request url in session so that we can go back to it in /authorize/decision if there was a validation error
    request.session.authorizeURL = request.originalUrl;

    let oauth2 = (request as any).oauth2;
    let transactionID = oauth2.transactionID as string;
    let user = request.user as IUser;
    let client = oauth2.client as IOAuthClient;
    let requestScopes: string[] = oauth2.info.scope || [];

    let scopes: IScopeWithValue[] = [];
    for (let scopeName of requestScopes) {
      let scope = await Scope.findOne({ name: scopeName });
      if (scope) {
        let userScope: string | undefined = (user.scopes || {})[scopeName];
        scopes.push({
          ...scope.toObject(),
          value: userScope,
        });
      }
    }
    const scopeNames = scopes.map(scope => scope.name);
    request.session.scope = scopeNames;

    const redirectURI = new URL(oauth2.redirectURI);

    let templateData = {
      siteTitle: config.server.name,
      title: "Authorize",
      includeJS: null,

      error: request.flash("error"),

      name: formatName(user),
      email: user.email,
      redirect:
        redirectURI.origin === "null" // null as a string is intentional due to DOM spec
          ? `a native app`
          : redirectURI.origin,
      appName: client.name,
      transactionID,
      scopes,

      csrfToken: request.csrfToken(),
    };

    response.send(AuthorizeTemplate.render(templateData));
  }
);

interface IScopeValidatorContext {
  name: {
    first: string;
    preferred?: string;
    last: string;
  };
  email: string;
  scope: string;
  type: string;
  value: string;
}

OAuthRouter.post(
  "/authorize/decision",
  rateLimit["oauth-authorize"],
  authenticateWithRedirect,
  csrf(),
  async (request, response, next) => {
    if (!request.session) {
      response.status(500).send("Session not enabled but is required");
      return;
    }
    if (request.body.cancel) {
      next();
      return;
    }

    let user = request.user as Model<IUser>;
    let scopes: string[] = request.session ? request.session.scope || [] : [];

    for (let scope of scopes) {
      let scopeValue = request.body[`scope-${scope}`];
      if (scopeValue) {
        let scopeDetails = await Scope.findOne({ name: scope });
        if (!scopeDetails) {
          request.flash("error", `Scope "${scope}" is not specified in DB`);
          response.redirect(request.session.authorizeURL!);
          return;
        }
        if (scopeDetails.validator && scopeDetails.validator.code) {
          let context: IScopeValidatorContext = {
            name: user.name,
            email: user.email,
            scope,
            type: scopeDetails.type,
            value: scopeValue,
          };
          try {
            let success = vm.runInNewContext(scopeDetails.validator.code, context, {
              timeout: 500,
            });
            if (!success) {
              request.flash(
                "error",
                `Error validating "${scope}": ${scopeDetails.validator.errorMessage}`
              );
              response.redirect(request.session.authorizeURL!);
              return;
            }
          } catch {
            request.flash("error", `An error occurred while validating scope "${scope}"`);
            response.redirect(request.session.authorizeURL!);
            return;
          }
        }
        if (!user.scopes) {
          user.scopes = {};
        }
        user.scopes[scope] = scopeValue;
      } else {
        request.flash("error", "All data fields must be filled out");
        response.redirect(request.session.authorizeURL!);
        return;
      }
    }

    user.markModified("scopes");
    await user.save();
    request.session.authorizeURL = undefined;
    next();
  },
  server.decision((request, done) => {
    let session = (request as express.Request).session;
    let scope: string[] = session ? session.scope || [] : [];
    done(null, { scope });
  })
);

OAuthRouter.post(
  "/token",
  rateLimit["oauth-token"],
  passport.authenticate(["basic", "oauth2-client-password"], { session: false }),
  server.token(),
  server.errorHandler()
);

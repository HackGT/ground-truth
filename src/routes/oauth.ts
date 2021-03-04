import * as vm from "vm";
import { URL } from "url";
import * as express from "express";
import passport from "passport";
import csrf from "csurf";

import { config } from "../common";
import { authenticateWithRedirect, rateLimit } from "./middleware";
import { Model, IUser, AccessToken, IOAuthClient, OAuthClient, IScope, Scope } from "../schema";
import { AuthorizeTemplate } from "../views/templates";
import { server } from "../auth/server";
import { formatName } from "../email/email";

type IScopeWithValue = IScope & { value?: string };

export const OAuthRouter = express.Router();

OAuthRouter.get(
  "/authorize",
  rateLimit["oauth-authorize"],
  authenticateWithRedirect,
  server.authorization(
    async (clientID, redirectURI, done) => {
      try {
        const client = await OAuthClient.findOne({ clientID });
        // Redirect URIs are allowed on a same-origin basis
        // This is so that changing example.com/endpoint to example.com/other_endpoint doesn't result in failure
        const redirectOrigin = new URL(redirectURI).origin;
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
        const token = await AccessToken.findOne({ clientID: client.clientID, uuid: user.uuid });
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

    const { oauth2 } = request as any;
    const transactionID = oauth2.transactionID as string;
    const user = request.user as IUser;
    const client = oauth2.client as IOAuthClient;
    const requestScopes: string[] = oauth2.info.scope || [];

    const scopes: IScopeWithValue[] = [];
    for (const scopeName of requestScopes) {
      // eslint-disable-next-line no-await-in-loop
      const scope = await Scope.findOne({ name: scopeName });
      if (scope) {
        const userScope: string | undefined = (user.scopes || {})[scopeName];
        scopes.push({
          ...scope.toObject(),
          value: userScope,
        });
      }
    }
    const scopeNames = scopes.map(scope => scope.name);
    request.session.scope = scopeNames;

    const redirectURI = new URL(oauth2.redirectURI);

    const templateData = {
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

    const user = request.user as Model<IUser>;
    const scopes: string[] = request.session ? request.session.scope || [] : [];

    for (const scope of scopes) {
      const scopeValue = request.body[`scope-${scope}`];
      if (scopeValue) {
        // eslint-disable-next-line no-await-in-loop
        const scopeDetails = await Scope.findOne({ name: scope });
        if (!scopeDetails) {
          request.flash("error", `Scope "${scope}" is not specified in DB`);
          response.redirect(request.session.authorizeURL || "/login");
          return;
        }
        if (scopeDetails.validator && scopeDetails.validator.code) {
          const context: IScopeValidatorContext = {
            name: user.name,
            email: user.email,
            scope,
            type: scopeDetails.type,
            value: scopeValue,
          };
          try {
            const success = vm.runInNewContext(scopeDetails.validator.code, context, {
              timeout: 500,
            });
            if (!success) {
              request.flash(
                "error",
                `Error validating "${scope}": ${scopeDetails.validator.errorMessage}`
              );
              response.redirect(request.session.authorizeURL || "/login");
              return;
            }
          } catch {
            request.flash("error", `An error occurred while validating scope "${scope}"`);
            response.redirect(request.session.authorizeURL || "/login");
            return;
          }
        }
        if (!user.scopes) {
          user.scopes = {};
        }
        user.scopes[scope] = scopeValue;
      } else {
        request.flash("error", "All data fields must be filled out");
        response.redirect(request.session.authorizeURL || "/login");
        return;
      }
    }

    user.markModified("scopes");
    await user.save();
    request.session.authorizeURL = undefined;
    next();
  },
  server.decision((request, done) => {
    const { session } = request as express.Request;
    const scope: string[] = session ? session.scope || [] : [];
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

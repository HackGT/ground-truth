import * as crypto from "crypto";
import * as oauth2orize from "oauth2orize";
import moment from "moment";

import {
  createNew,
  IUser,
  IAuthorizationCode,
  AuthorizationCode,
  IAccessToken,
  AccessToken,
  IOAuthClient,
  OAuthClient,
} from "../schema";

// eslint-disable-next-line camelcase, @typescript-eslint/no-var-requires
const oauth2orize_pkce = require("oauth2orize-pkce");

export const server = oauth2orize.createServer();

server.serializeClient((client: IOAuthClient, done) => {
  done(null, client.uuid);
});

server.deserializeClient(async (uuid, done) => {
  try {
    const client = await OAuthClient.findOne({ uuid });
    done(null, client || false);
  } catch (err) {
    done(err);
  }
});

type GrantCodeDoneFunction = (err: Error | null, code?: string) => void;
type IssueGrantCodeFunction = (
  client: any,
  redirectUri: string,
  user: any,
  res: any,
  issued: GrantCodeDoneFunction
) => void;

server.grant(oauth2orize_pkce.extensions());

server.grant(
  oauth2orize.grant.code(((async (
    client: IOAuthClient,
    redirectURI: string,
    user: IUser,
    ares: any,
    areq: any,
    done: GrantCodeDoneFunction
  ) => {
    const code = crypto.randomBytes(16).toString("hex");
    try {
      await createNew<IAuthorizationCode>(AuthorizationCode, {
        clientID: client.clientID,
        code,
        redirectURI,
        uuid: user.uuid,
        scopes: ares.scope || [],
        expiresAt: moment().add(60, "seconds").toDate(),
        codeChallenge: areq.codeChallenge || undefined,
        codeChallengeMethod: areq.codeChallengeMethod || undefined,
      }).save();

      done(null, code);
    } catch (err) {
      done(err);
    }
  }) as unknown) as IssueGrantCodeFunction)
);

// As defined in types for oauth2orize
// The IssueExchangeCodeFunction is missing an undocumented optional extra parameter that allows access to the request body
type ExchangeDoneFunction = (
  err: Error | null,
  accessToken?: string | boolean,
  refreshToken?: string,
  params?: any
) => void;
type IssueExchangeCodeFunction = (
  client: any,
  code: string,
  redirectURI: string,
  issued: ExchangeDoneFunction
) => void;

server.exchange(
  oauth2orize.exchange.code(((async (
    client: IOAuthClient,
    code: string,
    redirectURI: string,
    body: any,
    done: ExchangeDoneFunction
  ) => {
    try {
      const authCode = await AuthorizationCode.findOne({ code });

      if (!authCode) {
        console.warn(`Could not find auth code to exchange for token: ${code}`);
        done(null, false);
        return;
      }

      if (client.clientID !== authCode.clientID) {
        console.warn(
          `Client ID mismatch when exchanging for token: via request: ${client.clientID}, on auth code: ${authCode.clientID}`
        );
        done(null, false);
        return;
      }

      if (redirectURI !== authCode.redirectURI) {
        console.warn(
          `Redirect URI mismatch when exchanging for token: via request: ${redirectURI}, on auth code: ${authCode.redirectURI}`
        );
        done(null, false);
        return;
      }

      if (moment().isAfter(moment(authCode.expiresAt))) {
        console.warn(
          `Auth code is expired when exchanging for token: expired at ${authCode.expiresAt.toISOString()} (now: ${new Date().toISOString()})`
        );
        done(null, false);
        return;
      }

      if (client.public) {
        // Verify PKCE code challenge
        // Private apps have already verified their client secret in verifyClient()
        let codeVerifier: string = body.code_verifier || "";
        if (!authCode.codeChallenge || !authCode.codeChallengeMethod || !codeVerifier) {
          console.warn(
            `Missing code challenge, challenge method, or code verifier in exchange for token: ${code} (challenge: ${authCode.codeChallenge}, method: ${authCode.codeChallengeMethod}, verifier: ${codeVerifier})`
          );
          done(null, false);
          return;
        }
        if (authCode.codeChallengeMethod === "S256") {
          codeVerifier = crypto
            .createHash("sha256")
            .update(codeVerifier)
            .digest()
            .toString("base64")
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
        }
        if (codeVerifier !== authCode.codeChallenge) {
          console.warn(
            `Code challenge mismatch: computed: ${codeVerifier}, expected: ${authCode.codeChallenge}`
          );
          done(null, false);
          return;
        }
      }

      await authCode.remove();
      const token = crypto.randomBytes(128).toString("hex");
      await createNew<IAccessToken>(AccessToken, {
        token,
        clientID: authCode.clientID,
        uuid: authCode.uuid,
        scopes: authCode.scopes,
      }).save();

      const params = {};
      done(null, token, undefined, params);
    } catch (err) {
      done(err);
    }
  }) as unknown) as IssueExchangeCodeFunction)
);

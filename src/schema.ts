// tslint:disable:interface-name variable-name
// The database schema used by Mongoose
// Exports TypeScript interfaces to be used for type checking and Mongoose models derived from these interfaces
import { IConfig, mongoose } from "./common";

// For stricter type checking of new object creation
type Omit<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>>;
interface RootDocument {
  _id: mongoose.Types.ObjectId;
}
export function createNew<T extends RootDocument>(
  Model: mongoose.Model<T & mongoose.Document>,
  doc: Omit<T, "_id">
) {
  return new Model(doc);
}
export type Model<T extends RootDocument> = T & mongoose.Document;

//
// DB types
//

export interface IUser extends RootDocument {
  uuid: string;
  email: string;
  name: {
    first: string;
    preferred?: string;
    last: string;
  };
  scopes?: {
    [name: string]: string;
  };

  verifiedEmail: boolean;
  emailVerificationCode?: string;
  admin: boolean;
  member: boolean;

  forceLogOut: boolean;

  local?: {
    hash: string;
    salt: string;
    rounds: number;
    resetCode?: string;
    resetRequestedTime?: Date;
  };
  services?: {
    [Service in Exclude<IConfig.Services, "local">]?: {
      id: string;
      // OAuth account email can be different than registration account email
      email?: string;
      username?: string;
    };
  };
}

// This is basically a type definition that exists at runtime and is derived manually from the IUser definition above
export const User = mongoose.model<Model<IUser>>(
  "User",
  new mongoose.Schema({
    uuid: {
      type: String,
      required: true,
      index: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      index: true,
      unique: true,
    },
    name: {
      first: String,
      preferred: String,
      last: String,
    },
    scopes: mongoose.Schema.Types.Mixed,

    verifiedEmail: Boolean,
    emailVerificationCode: String,
    admin: {
      type: Boolean,
      default: false,
    },
    member: {
      type: Boolean,
      default: false,
    },

    forceLogOut: Boolean,

    local: {
      hash: String,
      salt: String,
      rounds: Number,
      resetCode: String,
      resetRequestedTime: Date,
    },
    services: mongoose.Schema.Types.Mixed,
  }).index({
    email: "text",
    name: "text",
  })
);

export interface IOAuthClient extends RootDocument {
  uuid: string;
  name: string;
  clientID: string;
  clientSecret: string;
  redirectURIs: string[];
  public?: boolean;
}

export const OAuthClient = mongoose.model<Model<IOAuthClient>>(
  "OAuthClient",
  new mongoose.Schema({
    uuid: {
      type: String,
      required: true,
      index: true,
      unique: true,
    },
    name: String,
    clientID: String,
    clientSecret: String,
    redirectURIs: [String],
    public: Boolean,
  })
);

export interface IAuthorizationCode extends RootDocument {
  code: string;
  clientID: string;
  redirectURI: string;
  scopes: string[];
  uuid: string;
  expiresAt: Date;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
}

export const AuthorizationCode = mongoose.model<Model<IAuthorizationCode>>(
  "AuthorizationCode",
  new mongoose.Schema({
    code: {
      type: String,
      required: true,
      index: true,
      unique: true,
    },
    clientID: String,
    redirectURI: String,
    scopes: [String],
    uuid: String,
    expiresAt: Date,
    codeChallenge: String,
    codeChallengeMethod: String,
  })
);

export interface IAccessToken extends RootDocument {
  token: string;
  clientID: string;
  scopes: string[];
  uuid: string;
}

export const AccessToken = mongoose.model<Model<IAccessToken>>(
  "AccessToken",
  new mongoose.Schema({
    token: {
      type: String,
      required: true,
      index: true,
      unique: true,
    },
    clientID: String,
    scopes: [String],
    uuid: String,
  })
);

export interface IScope extends RootDocument {
  name: string;
  question: string;
  type: string;
  validator?: {
    code: string;
    errorMessage: string;
  };
  icon?: string;
}

export const Scope = mongoose.model<Model<IScope>>(
  "Scope",
  new mongoose.Schema({
    name: String,
    question: String,
    type: String,
    validator: {
      code: String,
      errorMessage: String,
    },
    icon: String,
  })
);

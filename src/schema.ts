// tslint:disable:interface-name variable-name
// The database schema used by Mongoose
// Exports TypeScript interfaces to be used for type checking and Mongoose models derived from these interfaces
import { mongoose } from "./common";

// Secrets JSON file schema
export namespace IConfig {
	export type OAuthServices = "github" | "google" | "facebook";
	export type CASServices = "gatech";
	export type Services = "local" | OAuthServices | CASServices;
	export interface Secrets {
		adminKey: string;
		session: string;
		oauth: {
			[Service in OAuthServices]: {
				id: string;
				secret: string;
			}
		};
	}
	export interface Email {
		from: string;
		key: string;
	}
	export interface Server {
		isProduction: boolean;
		port: number;
		versionHash: string;
		cookieMaxAge: number;
		cookieSecureOnly: boolean;
		mongoURL: string;
		passwordResetExpiration: number;
		defaultTimezone: string;
	}

	export interface Main {
		secrets: Secrets;
		email: Email;
		server: Server;
		loginMethods: Services[];
	}
}

export interface IUser {
	_id: mongoose.Types.ObjectId;
	uuid: string;
	email: string;
	name: string;
	verifiedEmail: boolean;
	accountConfirmed: boolean;

	local?: Partial<{
		hash: string;
		salt: string;
		verificationCode: string;
		resetRequested: boolean;
		resetCode: string;
		resetRequestedTime: Date;
	}>;
	services: {
		[Service in Exclude<IConfig.Services, "local">]?: {
			id: string;
			// OAuth account email can be different than registration account email
			email: string;
			username?: string;
			profileUrl?: string;
		};
	};
}
export type IUserMongoose = IUser & mongoose.Document;

// This is basically a type definition that exists at runtime and is derived manually from the IUser definition above
export const User = mongoose.model<IUserMongoose>("User", new mongoose.Schema({
	uuid: {
		type: String,
		required: true,
		index: true,
		unique: true
	},
	email: {
		type: String,
		required: true,
		index: true,
		unique: true
	},
	name: {
		type: String,
		index: true
	},
	verifiedEmail: Boolean,
	accountConfirmed: Boolean,

	local: {
		hash: String,
		salt: String,
		verificationCode: String,
		resetRequested: Boolean,
		resetCode: String,
		resetRequestedTime: Date
	},
	services: mongoose.Schema.Types.Mixed,
}).index({
	email: "text",
	name: "text"
}));

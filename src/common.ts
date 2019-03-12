// Needed so that common.ts <-> schema.ts cyclical dependencies don't cause problems
/* tslint:disable:no-duplicate-imports */
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import passport from "passport";

//
// Config
//
import { IConfig } from "./schema";
class Config implements IConfig.Main {
	public secrets: IConfig.Secrets = {
		adminKey: crypto.randomBytes(32).toString("hex"),
		session: crypto.randomBytes(32).toString("hex"),
		oauth: {
			github: {
				id: "",
				secret: ""
			},
			google: {
				id: "",
				secret: ""
			},
			facebook: {
				id: "",
				secret: ""
			}
		}
	};
	public email: IConfig.Email = {
		from: "HackGT Team <hello@hackgt.com>",
		key: ""
	};
	public server: IConfig.Server = {
		isProduction: false,
		port: 3000,
		versionHash: fs.existsSync(".git") ? require("git-rev-sync").short() : "",
		cookieMaxAge: 1000 * 60 * 60 * 24 * 30 * 6, // 6 months
		cookieSecureOnly: false,
		mongoURL: "mongodb://localhost/auth",
		passwordResetExpiration: 1000 * 60 * 60, // 1 hour
		defaultTimezone: "America/New_York",
		name: "HackGT",
	};
	public loginMethods = ["local", "github", "google", "facebook", "gatech"] as IConfig.Services[];
	public sessionSecretSet: boolean = false;

	constructor(fileName: string = "config.json") {
		this.loadFromJSON(fileName);
		this.loadFromEnv();
	}
	protected loadFromJSON(fileName: string): void {
		// tslint:disable-next-line:no-shadowed-variable
		let config: IConfig.Main | null = null;
		try {
			config = JSON.parse(fs.readFileSync(path.resolve(__dirname, "./config", fileName), "utf8"));
		}
		catch (err) {
			if (err.code !== "ENOENT") {
				throw err;
			}
		}
		if (!config) {
			return;
		}
		if (config.secrets) {
			for (let key of Object.keys(config.secrets) as (keyof IConfig.Secrets)[]) {
				this.secrets[key] = config.secrets[key];
			}
		}
		if (config.secrets && config.secrets.session) {
			this.sessionSecretSet = true;
		}
		if (config.email) {
			for (let key of Object.keys(config.email) as (keyof IConfig.Email)[]) {
				this.email[key] = config.email[key];
			}
		}
		if (config.server) {
			for (let key of Object.keys(config.server) as (keyof IConfig.Server)[]) {
				this.server[key] = config.server[key];
			}
		}
	}
	protected loadFromEnv(): void {
		// Secrets
		if (process.env.ADMIN_KEY_SECRET) {
			this.secrets.adminKey = process.env.ADMIN_KEY_SECRET;
		}
		else {
			console.warn("Setting random admin key! Cannot use the service-to-service APIs.");
		}
		if (process.env.SESSION_SECRET) {
			this.secrets.session = process.env.SESSION_SECRET;
			this.sessionSecretSet = true;
		}
		if (process.env.GITHUB_CLIENT_ID) {
			this.secrets.oauth.github.id = process.env.GITHUB_CLIENT_ID;
		}
		if (process.env.GITHUB_CLIENT_SECRET) {
			this.secrets.oauth.github.secret = process.env.GITHUB_CLIENT_SECRET;
		}
		if (process.env.GOOGLE_CLIENT_ID) {
			this.secrets.oauth.google.id = process.env.GOOGLE_CLIENT_ID;
		}
		if (process.env.GOOGLE_CLIENT_SECRET) {
			this.secrets.oauth.google.secret = process.env.GOOGLE_CLIENT_SECRET;
		}
		if (process.env.FACEBOOK_CLIENT_ID) {
			this.secrets.oauth.facebook.id = process.env.FACEBOOK_CLIENT_ID;
		}
		if (process.env.FACEBOOK_CLIENT_SECRET) {
			this.secrets.oauth.facebook.secret = process.env.FACEBOOK_CLIENT_SECRET;
		}
		// Email
		if (process.env.EMAIL_FROM) {
			this.email.from = process.env.EMAIL_FROM;
		}
		if (process.env.EMAIL_KEY) {
			this.email.key = process.env.EMAIL_KEY;
		}
		// Server
		if (process.env.PRODUCTION && process.env.PRODUCTION.toLowerCase() === "true") {
			this.server.isProduction = true;
		}
		if (process.env.PORT) {
			let port = parseInt(process.env.PORT, 10);
			if (!isNaN(port) && port > 0) {
				this.server.port = port;
			}
		}
		if (process.env.VERSION_HASH) {
			this.server.versionHash = process.env.VERSION_HASH;
		}
		if (process.env.SOURCE_REV) {
			this.server.versionHash = process.env.SOURCE_REV;
		}
		if (process.env.SOURCE_VERSION) {
			this.server.versionHash = process.env.SOURCE_VERSION;
		}
		if (process.env.COOKIE_MAX_AGE) {
			let maxAge = parseInt(process.env.COOKIE_MAX_AGE, 10);
			if (!isNaN(maxAge) && maxAge > 0) {
				this.server.cookieMaxAge = maxAge;
			}
		}
		if (process.env.COOKIE_SECURE_ONLY && process.env.COOKIE_SECURE_ONLY.toLowerCase() === "true") {
			this.server.cookieSecureOnly = true;
		}
		if (process.env.MONGO_URL) {
			this.server.mongoURL = process.env.MONGO_URL;
		}
		if (process.env.DEFAULT_TIMEZONE) {
			this.server.defaultTimezone = process.env.DEFAULT_TIMEZONE;
		}
		if (process.env.NAME) {
			this.server.name = process.env.NAME;
		}
		if (process.env.PASSWORD_RESET_EXPIRATION) {
			let expirationTime = parseInt(process.env.PASSWORD_RESET_EXPIRATION, 10);
			if (!isNaN(expirationTime) && expirationTime > 0) {
				this.server.passwordResetExpiration = expirationTime;
			}
		}
	}
}
export let config = new Config();

//
// Constants
//
export const PORT = config.server.port;
export const VERSION_NUMBER = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../package.json"), "utf8")).version;
export const VERSION_HASH = config.server.versionHash;
export const COOKIE_OPTIONS = {
	"path": "/",
	"maxAge": config.server.cookieMaxAge,
	"secure": config.server.cookieSecureOnly,
	"httpOnly": true
};

//
// Database connection
//
import mongoose from "mongoose";
mongoose.connect(config.server.mongoURL, { useNewUrlParser: true }).catch(err => {
	throw err;
});
export { mongoose };

import bodyParser from "body-parser";
export const postParser = bodyParser.urlencoded({
	extended: false
});

//
// Email
//
import sendgrid from "@sendgrid/mail";
sendgrid.setApiKey(config.email.key);
import marked from "marked";
// tslint:disable-next-line:no-var-requires
const striptags = require("striptags");
import { IUser } from "./schema";

export interface IMailObject {
	to: string;
	from: string;
	subject: string;
	html: string;
	text: string;
}
// Union types don't work well with overloaded method resolution in TypeScript so we split into two methods
export async function sendMailAsync(mail: IMailObject)  {
	return sendgrid.send(mail);
}
export function sanitize(input?: string): string {
	if (!input || typeof input !== "string") {
		return "";
	}
	return input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

let renderer = new marked.Renderer();
let singleLineRenderer = new marked.Renderer();
singleLineRenderer.link = (href, title, text) => `<a target=\"_blank\" href=\"${href}\" title=\"${title || ''}\">${text}</a>`;
singleLineRenderer.paragraph = (text) => text;
export async function renderMarkdown(markdown: string, options?: marked.MarkedOptions, singleLine: boolean = false): Promise<string> {
	let r = singleLine ? singleLineRenderer : renderer;
	return new Promise<string>((resolve, reject) => {
		marked(markdown, { sanitize: false, smartypants: true, renderer: r, ...options }, (err: Error | null, content: string) => {
			if (err) {
				reject(err);
				return;
			}
			resolve(content);
		});
	});
}
export async function renderEmailHTML(markdown: string, user: IUser): Promise<string> {
	markdown = markdown.replace(/{{email}}/g, sanitize(user.email));
	markdown = markdown.replace(/{{name}}/g, sanitize(user.name));
	return renderMarkdown(markdown);
}
export async function renderEmailText(markdown: string, user: IUser, markdownRendered: boolean = false): Promise<string> {
	let html: string;
	if (!markdownRendered) {
		html = await renderEmailHTML(markdown, user);
	}
	else {
		html = markdown;
	}
	// Remove <style> and <script> block's content
	html = html.replace(/<style>[\s\S]*?<\/style>/gi, "<style></style>").replace(/<script>[\s\S]*?<\/script>/gi, "<script></script>");

	// Append href of links to their text
	const cheerio = await import("cheerio");
	let $ = cheerio.load(html, { decodeEntities: false });
	$("a").each((i, el) => {
		let element = $(el);
		element.text(`${element.text()} (${element.attr("href")})`);
	});
	html = $.html();

	let text: string = striptags(html);
	// Reverse sanitization
	return text.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}

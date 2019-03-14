import * as fs from "fs";
import * as path from "path";
import * as express from "express";
import * as Handlebars from "handlebars";

import { config } from "./common";
import { authenticateWithRedirect } from "./auth/auth";
import { User } from "./schema";

// tslint:disable-next-line:no-any
// tslint:disable:no-invalid-this
Handlebars.registerHelper("ifCond", function (this: any, v1: any, v2: any, options: any) {
	if (v1 === v2) {
		return options.fn(this);
	}
	return options.inverse(this);
});
Handlebars.registerHelper("ifIn", function <T>(this: any, elem: T, list: T[], options: any) {
	if (list.includes(elem)) {
		return options.fn(this);
	}
	return options.inverse(this);
});

class Template<T> {
	private template: Handlebars.TemplateDelegate<T> | null = null;

	constructor(private file: string) {
		this.loadTemplate();
	}

	private loadTemplate(): void {
		let data = fs.readFileSync(path.resolve("src/ui", this.file), "utf8");
		this.template = Handlebars.compile(data);
	}

	public render(input: T): string {
		if (!config.server.isProduction) {
			this.loadTemplate();
		}
		return this.template!(input);
	}
}

const LoginTemplate = new Template("login.html");
const ForgotPasswordTemplate = new Template("forgotpassword.html");
const ResetPasswordTemplate = new Template("resetpassword.html");

export let uiRoutes = express.Router();

uiRoutes.route("/js/login.js").get((request, response) => {
	fs.createReadStream(path.resolve("src/ui", "login.js")).pipe(response);
});
uiRoutes.route("/css/wing.min.css").get((request, response) => {
	fs.createReadStream(path.resolve("src/ui", "wing-0.1.9.min.css")).pipe(response);
});
uiRoutes.route("/css/login.css").get((request, response) => {
	fs.createReadStream(path.resolve("src/ui", "login.css")).pipe(response);
});

uiRoutes.route("/").get(authenticateWithRedirect, (request, response) => {
	response.send("Hello, world");
});

uiRoutes.route("/login").get(async (request, response) => {
	let templateData = {
		error: request.flash("error"),
		success: request.flash("success"),
		loginMethods: config.loginMethods,
		localOnly: config.loginMethods && config.loginMethods.length === 1 && config.loginMethods[0] === "local"
	};
	response.send(LoginTemplate.render(templateData));
});

// uiRoutes.route("/login/confirm").get(async (request, response) => {
// 	let user = request.user as IUser;
// 	if (!user) {
// 		response.redirect("/login");
// 		return;
// 	}
// 	if (user.accountConfirmed) {
// 		response.redirect("/");
// 		return;
// 	}

// 	let usedLoginMethods: string[] = [];
// 	if (user.local && user.local!.hash) {
// 		usedLoginMethods.push("Local");
// 	}
// 	let services = Object.keys(user.services || {}) as (keyof typeof user.services)[];
// 	for (let service of services) {
// 		usedLoginMethods.push(prettyNames[service]);
// 	}
// 	let loginMethods = (await getSetting<IConfig.Services[]>("loginMethods")).filter(method => method !== "local" && !services.includes(method));

// 	response.send(postLoginTemplate({
// 		siteTitle: config.eventName,
// 		error: request.flash("error"),
// 		success: request.flash("success"),

// 		name: user.name || "",
// 		email: user.email || "",
// 		verifiedEmail: user.verifiedEmail || false,
// 		usedLoginMethods,
// 		loginMethods,
// 		canAddLogins: loginMethods.length !== 0
// 	}));
// });
uiRoutes.route("/login/forgot").get((request, response) => {
	let templateData = {
		error: request.flash("error"),
		success: request.flash("success")
	};
	response.send(ForgotPasswordTemplate.render(templateData));
});
uiRoutes.route("/login/forgot/:code").get(async (request, response) => {
	let user = await User.findOne({ "local.resetCode": request.params.code });
	if (!user) {
		request.flash("error", "Invalid password reset code");
		response.redirect("/login");
		return;
	}
	else if (!user.local || !user.local.resetCode || Date.now() - user.local.resetRequestedTime!.valueOf() > config.server.passwordResetExpiration) {
		request.flash("error", "Your password reset link has expired. Please request a new one.");
		if (user.local) {
			user.local.resetCode = undefined;
		}
		await user.save();
		response.redirect("/login");
		return;
	}
	let templateData = {
		error: request.flash("error"),
		success: request.flash("success"),
		resetCode: user.local!.resetCode!
	};
	response.send(ResetPasswordTemplate.render(templateData));
});

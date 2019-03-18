import * as fs from "fs";
import * as path from "path";
import * as express from "express";
import * as Handlebars from "handlebars";

import { config, authenticateWithRedirect } from "./common";
import { TemplateContent, User, IUser, OAuthClient } from "./schema";
import { bestLoginMethod } from "./auth/auth";

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
if (config.server.isProduction) {
	Handlebars.registerPartial("main", fs.readFileSync(path.resolve("src/ui", "partials", "main.hbs"), "utf8"));
}

export class Template<T extends TemplateContent> {
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
			Handlebars.registerPartial("main", fs.readFileSync(path.resolve("src/ui", "partials", "main.hbs"), "utf8"));
			this.loadTemplate();
		}
		return this.template!(input);
	}
}

const IndexTemplate = new Template("index.hbs");
const LoginTemplate = new Template("login.hbs");
const ForgotPasswordTemplate = new Template("forgotpassword.hbs");
const ResetPasswordTemplate = new Template("resetpassword.hbs");
const AdminTemplate = new Template("admin.hbs");

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

uiRoutes.route("/").get(authenticateWithRedirect, async (request, response) => {
	if (request.session) {
		let url = request.session.returnTo;
		if (url && url !== "/") {
			request.session.returnTo = undefined;
			response.redirect(url);
			return;
		}
	}
	let templateData = {
		siteTitle: config.server.name,
		title: "Home",
		includeJS: false,

		user: request.user,
		loginMethod: await bestLoginMethod(request.user.email),
	};
	response.send(IndexTemplate.render(templateData));
});

uiRoutes.route("/login").get(async (request, response) => {
	if (request.isAuthenticated() && request.user && (request.user as IUser).verifiedEmail) {
		response.redirect("/");
		return;
	}
	let templateData = {
		siteTitle: config.server.name,
		title: "Log in",
		includeJS: true,

		error: request.flash("error"),
		success: request.flash("success"),
		loginMethods: config.loginMethods,
		localOnly: config.loginMethods && config.loginMethods.length === 1 && config.loginMethods[0] === "local",
		email: request.session ? request.session.email : null,
	};
	response.send(LoginTemplate.render(templateData));
});

uiRoutes.route("/login/forgot").get((request, response) => {
	let templateData = {
		siteTitle: config.server.name,
		title: "Forgot Password",
		includeJS: false,

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
		siteTitle: config.server.name,
		title: "Reset Password",
		includeJS: false,

		error: request.flash("error"),
		success: request.flash("success"),
		resetCode: user.local!.resetCode!
	};
	response.send(ResetPasswordTemplate.render(templateData));
});

uiRoutes.route("/admin").get(authenticateWithRedirect, async (request, response) => {
	if (!request.user.admin) {
		response.redirect("/");
		return;
	}

	let templateData = {
		siteTitle: config.server.name,
		title: "Admin",
		includeJS: false,

		apps: await OAuthClient.find(),
		adminDomains: config.server.adminDomains,
		admins: config.server.admins,
		currentAdmins: await User.find({ admin: true })
	};
	response.send(AdminTemplate.render(templateData));
});

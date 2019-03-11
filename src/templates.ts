import * as fs from "fs";
import * as path from "path";
import * as express from "express";
import * as Handlebars from "handlebars";

import { config } from "./common";

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

uiRoutes.route("/").get(async (request, response) => {
	let templateData = {
		// error: request.flash("error"),
		// success: request.flash("success"),
		loginMethods: config.loginMethods,
		localOnly: config.loginMethods && config.loginMethods.length === 1 && config.loginMethods[0] === "local"
	};
	response.send(LoginTemplate.render(templateData));
});

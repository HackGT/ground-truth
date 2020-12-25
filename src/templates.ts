import * as fs from "fs";
import * as path from "path";
import * as Handlebars from "handlebars";

import { config } from "./common";
import { IUser } from "./schema";
import { formatName } from "./email";

//
// Template schema
//
export interface TemplateContent {
    siteTitle: string;
    contactEmail: string;
    title: string;
    includeJS: string | null;
}

// tslint:disable-next-line:no-any
// tslint:disable:no-invalid-this
Handlebars.registerHelper("ifCond", function (this: any, v1: any, v2: any, options: any) {
    if (v1 === v2) {
        return options.fn(this);
    }
    return options.inverse(this);
});

Handlebars.registerHelper("ifNotCond", function (this: any, v1: any, v2: any, options: any) {
    if (v1 === v2) {
        return options.inverse(this);
    }
    return options.fn(this);
});

Handlebars.registerHelper("ifIn", function <T>(this: any, elem: T, list: T[], options: any) {
    if (list.includes(elem)) {
        return options.fn(this);
    }
    return options.inverse(this);
});

Handlebars.registerHelper("attr", (name: string, value: string): string => {
    if (value) {
        value = value.replace(/"/g, "&quot;");
        return `${name}="${value}"`;
    }
    else {
        return "";
    }
});

Handlebars.registerHelper("join", <T>(arr: T[]): string => {
    return arr.join(", ");
});

Handlebars.registerHelper("formatName", (name: { first: string; preferred: string; last: string; }): string => {
    return formatName({ name } as IUser);
});

if (config.server.isProduction) {
    Handlebars.registerPartial("main", fs.readFileSync(path.resolve(__dirname, "templates", "partials", "main.hbs"), "utf8"));
}

export class Template<T extends TemplateContent> {
    private template: Handlebars.TemplateDelegate<T> | null = null;

    constructor(private file: string) {
        this.loadTemplate();
    }

    private loadTemplate(): void {
        let data = fs.readFileSync(path.resolve(__dirname, "templates", this.file), "utf8");
        this.template = Handlebars.compile(data);
    }

    public render(input: Partial<T>): string {
        if (!config.server.isProduction) {
            Handlebars.registerPartial("main", fs.readFileSync(path.resolve(__dirname, "templates", "partials", "main.hbs"), "utf8"));
            this.loadTemplate();
        }
        const renderData = {
            siteTitle: config.server.name,
            contactEmail: config.email.contactAddress,
            includeJS: null,
            ...input
        } as T;
        return this.template!(renderData);
    }
}

export const IndexTemplate = new Template("index.hbs");
export const LoginTemplate = new Template("login.hbs");
export const ForgotPasswordTemplate = new Template("forgotpassword.hbs");
export const ResetPasswordTemplate = new Template("resetpassword.hbs");
export const ChangePasswordTemplate = new Template("changepassword.hbs");
export const AdminTemplate = new Template("admin.hbs");
export const ErrorTemplate = new Template("error.hbs");

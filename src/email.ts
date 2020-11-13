import * as htmlToText from "html-to-text";
import * as path from "path";
import * as crypto from "crypto";
import marked from "marked";
import sendgrid from "@sendgrid/mail";
import { Request } from "express";

const Email = require("email-templates");

import { config } from "./common";
import { IUser, Model } from "./schema";
import { createLink } from "./auth/strategies/util";

sendgrid.setApiKey(config.email.key);

const email = new Email({
    views: {
        root: path.resolve("src/emails/")
    },
    juice: true,
    juiceResources: {
        preserveImportant: true,
        webResources: {
            relativeTo: path.join(__dirname, "emails", "email-template")
        }
    }
});

export interface IMailObject {
    to: string;
    from: string;
    subject: string;
    html: string;
    text: string;
}
// Union types don't work well with overloaded method resolution in TypeScript so we split into two methods
export async function sendMailAsync(mail: IMailObject) {
    return sendgrid.send(mail);
}
export function sanitize(input?: string): string {
    if (!input || typeof input !== "string") {
        return "";
    }
    return input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function formatName(user: IUser): string {
    return `${user.name.preferred || user.name.first} ${user.name.last}`;
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

async function templateMarkdown(markdown: string, user: IUser): Promise<string> {
    markdown = markdown.replace(/{{email}}/g, sanitize(user.email));
    markdown = markdown.replace(/{{name}}/g, sanitize(formatName(user)));
    markdown = markdown.replace(/{{firstName}}/g, sanitize(user.name.first));
    markdown = markdown.replace(/{{preferredName}}/g, sanitize(user.name.preferred));
    markdown = markdown.replace(/{{lastName}}/g, sanitize(user.name.last));
    return markdown;
}

export async function renderEmailHTML(markdown: string, user: IUser): Promise<string> {
    markdown = await templateMarkdown(markdown, user);

    let renderedMarkdown = await renderMarkdown(markdown);
    return email.render("email-template/html", {
        emailHeaderImage: config.email.headerImage,
        twitterHandle: config.email.twitterHandle,
        facebookHandle: config.email.facebookHandle,
        emailAddress: config.email.contactAddress,
        hackathonName: config.server.name,
        body: renderedMarkdown
    });
}

export async function renderEmailText(markdown: string, user: IUser): Promise<string> {
    let templatedMarkdown = await templateMarkdown(markdown, user);
    let renderedHtml = await renderMarkdown(templatedMarkdown);
    return htmlToText.fromString(renderedHtml);
}

export function resendVerificationEmailLink(request: Request, uuid: string): string {
    const link = createLink(request, `/auth/resend/${uuid}`);
    return `Haven't gotten it? <a href="${link}">Resend verification email</a>.`;
}

export async function sendVerificationEmail(request: Request, user: Model<IUser>) {
    if (user.verifiedEmail) return;
    // Send verification email (hostname validated by previous middleware)
    user.emailVerificationCode = crypto.randomBytes(32).toString("hex");
    await user.save();

    let link = createLink(request, `/auth/verify/${user.emailVerificationCode}`);
    let markdown =
        `Hi {{name}},

Thanks for creating an account with ${config.server.name}! To verify your email, please [click here](${link}).

If you are registering for a ${config.server.name} event, please note that this does **not** complete your registration. After verifying your email, you will be directed to the event registration portal to submit an application.

Sincerely,

The ${config.server.name} Team.`;

    await sendMailAsync({
        from: config.email.from,
        to: user.email,
        subject: `[${config.server.name}] - Verify your email`,
        html: await renderEmailHTML(markdown, user),
        text: await renderEmailText(markdown, user)
    });
}

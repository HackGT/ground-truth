import { htmlToText } from "html-to-text";
import * as path from "path";
import * as crypto from "crypto";
import marked from "marked";
import sendgrid from "@sendgrid/mail";
import { Request } from "express";

import { config } from "../common";
import { IUser, Model } from "../schema";
import { createLink } from "../auth/strategies/util";
import { verifyEmailMarkdown } from "./markdown";

// eslint-disable-next-line camelcase, @typescript-eslint/no-var-requires
const Email = require("email-templates");

sendgrid.setApiKey(config.email.key);

const email = new Email({
  views: {
    root: path.resolve("src/email/"),
  },
  juice: true,
  juiceResources: {
    preserveImportant: true,
    webResources: {
      relativeTo: path.join(__dirname, "template"),
    },
  },
});

function sanitize(input?: string): string {
  if (!input || typeof input !== "string") {
    return "";
  }
  return input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function formatName(user: IUser): string {
  return `${user.name.preferred || user.name.first} ${user.name.last}`;
}

const renderer = new marked.Renderer();
const singleLineRenderer = new marked.Renderer();
singleLineRenderer.link = (href, title, text) =>
  `<a target="_blank" href="${href}" title="${title || ""}">${text}</a>`;
singleLineRenderer.paragraph = text => text;

async function renderMarkdown(
  markdown: string,
  options?: marked.MarkedOptions,
  singleLine = false
): Promise<string> {
  const r = singleLine ? singleLineRenderer : renderer;
  return new Promise<string>((resolve, reject) => {
    marked(
      markdown,
      { sanitize: false, smartypants: true, renderer: r, ...options },
      (err: Error | null, content: string) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(content);
      }
    );
  });
}

async function templateMarkdown(markdown: string, user: IUser): Promise<string> {
  return markdown
    .replace(/{{email}}/g, sanitize(user.email))
    .replace(/{{name}}/g, sanitize(formatName(user)))
    .replace(/{{firstName}}/g, sanitize(user.name.first))
    .replace(/{{preferredName}}/g, sanitize(user.name.preferred))
    .replace(/{{lastName}}/g, sanitize(user.name.last));
}

async function renderEmailHTML(markdown: string, user: IUser): Promise<string> {
  const templatedMarkdown = await templateMarkdown(markdown, user);
  const renderedMarkdown = await renderMarkdown(templatedMarkdown);

  return email.render("template/html", {
    emailHeaderImage: config.email.headerImage,
    twitterHandle: config.email.twitterHandle,
    facebookHandle: config.email.facebookHandle,
    emailAddress: config.email.contactAddress,
    hackathonName: config.server.name,
    body: renderedMarkdown,
  });
}

async function renderEmailText(markdown: string, user: IUser): Promise<string> {
  const templatedMarkdown = await templateMarkdown(markdown, user);
  const renderedHtml = await renderMarkdown(templatedMarkdown);
  return htmlToText(renderedHtml);
}

export function resendVerificationEmailLink(request: Request, uuid: string): string {
  const link = createLink(request, `/auth/resend/${uuid}`);
  return `Haven't gotten it? <a href="${link}">Resend verification email</a>.`;
}

export async function sendMailAsync(user: IUser, subject: string, markdown: string) {
  return sendgrid.send({
    from: config.email.from,
    to: user.email,
    html: await renderEmailHTML(markdown, user),
    text: await renderEmailText(markdown, user),
    subject,
  });
}

export async function sendVerificationEmail(request: Request, user: Model<IUser>) {
  if (user.verifiedEmail) return;

  // eslint-disable-next-line no-param-reassign
  user.emailVerificationCode = crypto.randomBytes(32).toString("hex");
  await user.save();

  // Send verification email (hostname validated by previous middleware)
  const markdown = verifyEmailMarkdown(request, user.emailVerificationCode);
  await sendMailAsync(user, `[${config.server.name}] - Verify your email`, markdown);
}

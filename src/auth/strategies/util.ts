import * as crypto from "crypto";
import * as http from "http";
import * as https from "https";
import { Request, Response, NextFunction } from "express";

import { config } from "../../common";
import { IUser, Model } from "../../schema";

export async function checkAndSetAdmin(user: Model<IUser>) {
    if (!user.verifiedEmail) return;

    let domain = user.email.split("@").pop();
    if (!domain) return;

    if (config.server.adminDomains.includes(domain) || config.server.admins.includes(user.email)) {
        user.admin = true;
        await user.save();
    }
}

// Authentication helpers
export function getExternalPort(request: Request): number {
    function defaultPort(): number {
        // Default ports for HTTP and HTTPS
        return request.protocol === "http" ? 80 : 443;
    }

    let host = request.headers.host;
    if (!host || Array.isArray(host)) {
        return defaultPort();
    }

    // IPv6 literal support
    let offset = host[0] === "[" ? host.indexOf("]") + 1 : 0;
    let index = host.indexOf(":", offset);
    if (index !== -1) {
        return parseInt(host.substring(index + 1), 10);
    }
    else {
        return defaultPort();
    }
}

let validatedHostNames: string[] = [];
export function validateAndCacheHostName(request: Request, response: Response, next: NextFunction) {
    // Basically checks to see if the server behind the hostname has the same session key by HMACing a random nonce
    if (validatedHostNames.find(hostname => hostname === request.hostname)) {
        next();
        return;
    }

    let nonce = crypto.randomBytes(64).toString("hex");
    function callback(message: http.IncomingMessage) {
        if (message.statusCode !== 200) {
            console.error(`Got non-OK status code when validating hostname: ${request.hostname}`);
            message.resume();
            return;
        }
        message.setEncoding("utf8");
        let data = "";
        message.on("data", (chunk) => data += chunk);
        message.on("end", () => {
            let localHMAC = crypto.createHmac("sha256", config.secrets.session).update(nonce).digest().toString("hex");
            if (localHMAC === data) {
                validatedHostNames.push(request.hostname);
                next();
            }
            else {
                console.error(`Got invalid HMAC when validating hostname: ${request.hostname}`);
            }
        });
    }
    function onError(err: Error) {
        console.error(`Error when validating hostname: ${request.hostname}`, err);
    }
    if (request.protocol === "http") {
        http.get(`http://${request.hostname}:${getExternalPort(request)}/auth/validatehost/${nonce}`, callback).on("error", onError);
    }
    else {
        https.get(`https://${request.hostname}:${getExternalPort(request)}/auth/validatehost/${nonce}`, callback).on("error", onError);
    }
}

export function createLink(request: Request, link: string): string {
    if (link[0] === "/") {
        link = link.substring(1);
    }
    if ((request.secure && getExternalPort(request) === 443) || (!request.secure && getExternalPort(request) === 80)) {
        return `http${request.secure ? "s" : ""}://${request.hostname}/${link}`;
    }
    else {
        return `http${request.secure ? "s" : ""}://${request.hostname}:${getExternalPort(request)}/${link}`;
    }
}

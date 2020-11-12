import * as crypto from "crypto";
import * as express from "express";

import { config } from "../common";
import { User } from "../schema";
import { strategies } from "../auth/strategies/index";
import { RegistrationStrategy } from "../auth/strategies/types";
import { validateAndCacheHostName } from "../auth/strategies/util";
import { sendVerificationEmail, resendVerificationEmailLink } from "../email";

export let authRouter = express.Router();

let authenticationMethods: RegistrationStrategy[] = [];
console.info(`Using authentication methods: ${config.loginMethods.join(", ")}`);

for (let methodName of config.loginMethods) {
    if (!strategies[methodName]) {
        console.error(`Authentication method "${methodName}" is not available. Did you add it to the exported list of strategies?`);
        continue;
    }
    let method = new strategies[methodName]();
    authenticationMethods.push(method);
    method.use(authRouter);
}

authRouter.get("/validatehost/:nonce", (request, response) => {
    let nonce: string = request.params.nonce || "";
    response.send(crypto.createHmac("sha256", config.secrets.session).update(nonce).digest().toString("hex"));
});


authRouter.get("/resend/:uuid", validateAndCacheHostName, async (request, response) => {
    const user = await User.findOne({ uuid: request.params.uuid || "" });
    if (user) {
        await sendVerificationEmail(request, user);
        const email = user.email
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/&/g, "&amp;");
        request.flash("success", `Resent a verification email to ${email}. ${resendVerificationEmailLink(request, user.uuid)}`);
    }
    response.redirect("/login");
});

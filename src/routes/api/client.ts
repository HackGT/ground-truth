import express from "express";

import { UserSessionData } from "../../auth/strategies/types";
import { bestLoginMethod, postParser } from "../middleware";

export let clientRouter = express.Router();

clientRouter.get("/login-type", async (request, response) => {
    let email = request.query.email as string | undefined;
    response.json({
        type: await bestLoginMethod(email)
    });
});

clientRouter.post("/signup-data", postParser, (request, response) => {
    function attachToSession(bodyProperty: keyof UserSessionData) {
        if (!request.session) return;

        let value = request.body[bodyProperty] as string | undefined;
        if (value) {
            request.session[bodyProperty] = value;
        }
    }

    attachToSession("email");
    attachToSession("firstName");
    attachToSession("preferredName");
    attachToSession("lastName");

    response.send();
});

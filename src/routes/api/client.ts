import express from "express";

import { bestLoginMethod, postParser } from "../middleware";

export let clientRouter = express.Router();

clientRouter.get("/login-type", async (request, response) => {
    let email = request.query.email as string | undefined;
    response.json({
        type: await bestLoginMethod(email)
    });
});

clientRouter.post("/attach-session-data", postParser, (request, response) => {
    function attachToSession(bodyProperty: "email" | "firstName" | "preferredName" | "lastName") {
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

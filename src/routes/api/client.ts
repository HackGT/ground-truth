import express from "express";
import csrf from "csurf";

import { bestLoginMethod, rateLimit } from "../middleware";

export let clientRouter = express.Router();

clientRouter.use(rateLimit["api-client"]);
clientRouter.use(csrf());

clientRouter.get("/login-type", async (request, response) => {
    let email = request.query.email as string | undefined;
    response.json({
        type: await bestLoginMethod(email)
    });
});

clientRouter.post("/attach-session-data", (request, response) => {
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

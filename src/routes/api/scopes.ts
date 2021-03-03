import express from "express";
import csrf from "csurf";

import { createNew, Scope, IScope } from "../../schema";
import { isAdmin, rateLimit } from "../middleware";

export let scopesRouter = express.Router();

scopesRouter.use(rateLimit["api-admin"]);
scopesRouter.use(isAdmin);
scopesRouter.use(csrf());

scopesRouter.post("/", async (request, response) => {
  try {
    function getParam(name: string): string {
      return (request.body[name] || "").trim();
    }

    let name = getParam("name").toLowerCase().replace(/ /g, "-").replace(/,/, "");
    let question = getParam("question");
    let type = getParam("type");
    let validatorCode: string | undefined = request.body.validatorCode;
    let errorMessage: string | undefined = request.body.errorMessage;
    let icon: string | undefined = getParam("icon") || undefined;

    if (!name || !question || !type) {
      response.status(400).json({
        error: "Missing name, question, or type",
      });
      return;
    }

    if ((validatorCode && !errorMessage) || (!validatorCode && errorMessage)) {
      response.status(400).json({
        error: "Validator code and corresponding error message cannot appear individually",
      });
      return;
    }

    await createNew<IScope>(Scope, {
      name,
      question,
      type,
      validator: validatorCode
        ? {
            code: validatorCode,
            errorMessage: errorMessage!,
          }
        : undefined,
      icon,
    }).save();
    response.json({
      success: true,
    });
  } catch (err) {
    console.error(err);
    response.status(500).json({
      error: "An error occurred while creating scope",
    });
  }
});

scopesRouter.delete("/:id", async (request, response) => {
  try {
    let scope = await Scope.findById(request.params.id);
    if (!scope) {
      response.status(400).json({
        error: "Invalid scope ID",
      });
      return;
    }

    await scope.remove();
    response.json({
      success: true,
    });
  } catch (err) {
    console.error(err);
    response.status(500).json({
      error: "An error occurred while deleting this scope",
    });
  }
});

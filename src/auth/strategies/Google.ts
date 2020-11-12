import { Router } from "express";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

import { OAuthStrategy } from "./OAuthStrategy";

export class Google extends OAuthStrategy {
    constructor() {
        super("google", GoogleStrategy as any);
    }
    public use(authRoutes: Router) {
        super.use(authRoutes, ["email", "profile"]);
    }
}

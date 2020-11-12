import { Router } from "express";
import { Strategy as FacebookStrategy } from "passport-facebook";

import { OAuthStrategy } from "./OAuthStrategy";

export class Facebook extends OAuthStrategy {
    constructor() {
        super("facebook", FacebookStrategy as any, ["id", "displayName", "email"]);
    }
    public use(authRoutes: Router) {
        super.use(authRoutes, ["email"]);
    }
}

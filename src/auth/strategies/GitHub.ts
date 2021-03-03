import { Router } from "express";
import { Strategy as GitHubStrategy } from "passport-github2";

import { OAuthStrategy } from "./OAuthStrategy";

export class GitHub extends OAuthStrategy {
  constructor() {
    super("github", GitHubStrategy as any);
  }
  public use(authRoutes: Router) {
    super.use(authRoutes, ["user:email"]);
  }
}

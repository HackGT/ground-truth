import { Facebook } from "./Facebook";
import { GeorgiaTechCAS } from "./GeorgiaTechCAS";
import { GitHub } from "./GitHub";
import { Google } from "./Google";
import { Local } from "./Local";

export const strategies = {
  local: Local,
  gatech: GeorgiaTechCAS,
  github: GitHub,
  google: Google,
  facebook: Facebook,
};

export const prettyNames: Record<keyof typeof strategies, string> = {
  local: "Local",
  gatech: "Georgia Tech CAS",
  github: "GitHub",
  google: "Google",
  facebook: "Facebook",
};

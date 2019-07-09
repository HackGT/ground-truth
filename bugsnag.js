"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("./src/common");
const reportBuild = require("bugsnag-build-reporter");
(() => __awaiter(this, void 0, void 0, function* () {
    const bugsnagCommon = {
        apiKey: common_1.config.secrets.bugsnag,
        appVersion: common_1.VERSION_NUMBER
    };
    yield reportBuild(Object.assign({}, bugsnagCommon, { releaseStage: "production", autoAssignRelease: true }));
}))().catch(err => {
    throw err;
});
//# sourceMappingURL=bugsnag.js.map
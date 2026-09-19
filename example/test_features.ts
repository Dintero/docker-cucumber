import * as assert from "node:assert";
import { STATUS_CODES } from "node:http";
import {
    AfterAll,
    Given,
    setWorldConstructor,
    Then,
    When,
    World,
} from "@cucumber/cucumber";
import { harCapture, harFetch } from "@dintero/e2e-helpers";

export const StatusNameToCode: Record<string, number> = Object.fromEntries(
    Object.entries(STATUS_CODES).map(([code, message]) => [
        (message as string)
            .toUpperCase()
            .replace(/[^A-Z0-9]+/g, "_") // replace spaces and punctuation with _
            .replace(/^_+|_+$/g, ""),
        Number(code),
    ]),
);

class Context extends World {
    ctx: {
        response?: Response;
    } & Record<string, string> = {};
}

setWorldConstructor(Context);

Given<Context>("a {string}", function (url) {
    this.ctx.url = url;
});

When("I request {string}", async function (method: string) {
    this.ctx.response = await harFetch(this.ctx.url, { method });
});

Then("response status should be {string}", function (status: string) {
    assert.equal(this.ctx.response?.status, StatusNameToCode[status]);
});

// When HAR_OUT is set (make test), flush the captured requests so the
// downstream zap-scan service can feed them to ZAP.
AfterAll(async () => {
    if (harCapture.enabled()) await harCapture.dump();
});

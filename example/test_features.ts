import * as assert from "node:assert";
import { STATUS_CODES } from "node:http";
import {
    Given,
    setWorldConstructor,
    Then,
    When,
    World,
} from "@cucumber/cucumber";

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
    this.ctx.response = await fetch(this.ctx.url, { method });
});

Then("response status should be {string}", async function (status: string) {
    assert.equal(this.ctx.response?.status, StatusNameToCode[status]);
});

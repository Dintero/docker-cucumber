/**
 * Tests for the ZAP alerts → JUnit XML converter.
 *
 * Node's built-in test runner (`node --test`) with tsx as the loader so
 * we can import the .ts source directly — same pattern the rest of the
 * repo uses for running TypeScript.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";

import { alertsToJunit, writeJunit } from "./junit.ts";

const SPEC = `basePath: /
paths:
  /orders/{id}:
    get: {}
  /health:
    get: {}
`;

function alertsFixture() {
    return [
        {
            url: "https://api.example.com/orders/abc-123?q=1",
            param: "q",
            pluginId: "40018",
            method: "GET",
            risk: "Medium",
            confidence: "Medium",
            alert: "SQL Injection",
            description: "Boolean-based blind SQLi.",
            solution: "Use parameterised queries.",
            reference: "https://owasp.org/sqli",
            evidence: "1' OR '1'='1",
            cweid: "89",
        },
        {
            url: "https://api.example.com/orders/def-456?q=2",
            param: "q",
            pluginId: "40018",
            method: "GET",
            risk: "Medium",
            confidence: "Medium",
            alert: "SQL Injection",
        },
        {
            url: "https://api.example.com/health",
            pluginId: "10038",
            method: "GET",
            risk: "Low",
            confidence: "Medium",
            alert: "CSP not set",
        },
        {
            url: "https://api.example.com/admin",
            pluginId: "10202",
            method: "POST",
            risk: "High",
            confidence: "High",
            alert: "Missing Auth Header",
            description: "Endpoint reachable without auth",
        },
    ];
}

describe("alertsToJunit", () => {
    let tmpDir: string;
    let specPath: string;

    before(() => {
        tmpDir = mkdtempSync(join(tmpdir(), "junit-test-"));
        specPath = join(tmpDir, "spec.yaml");
        writeFileSync(specPath, SPEC);
    });

    after(() => {
        rmSync(tmpDir, { recursive: true, force: true });
    });

    test("filters below --min-risk", () => {
        const { xml, testcases } = alertsToJunit(alertsFixture(), {
            minRisk: "Medium",
        });
        assert.equal(testcases, 3);
        assert.ok(xml.includes(`tests="3"`));
        assert.ok(xml.includes(`failures="3"`));
        assert.ok(!xml.includes("CSP not set"), "Low findings must be dropped");
    });

    test("dedupes multiple URLs matching one template", () => {
        const { xml, testcases } = alertsToJunit(alertsFixture(), {
            minRisk: "Medium",
            specPath,
        });
        // 2 SQLi + 1 admin = 2 unique groups after templating.
        assert.equal(testcases, 2);
        assert.ok(xml.includes(`name="GET /orders/{id} [q]"`));
        assert.ok(xml.includes("Matched 2 URLs"));
    });

    test("sorts High before Medium", () => {
        const { xml } = alertsToJunit(alertsFixture(), { minRisk: "Medium" });
        const highIdx = xml.indexOf("zap.High.");
        const medIdx = xml.indexOf("zap.Medium.");
        assert.ok(highIdx > 0 && medIdx > 0);
        assert.ok(highIdx < medIdx, "High should come before Medium");
    });

    test("CDATA-wraps failure body without escaping apostrophes", () => {
        const { xml } = alertsToJunit(alertsFixture(), { minRisk: "Medium" });
        assert.ok(
            xml.includes("<![CDATA["),
            "failure body should be CDATA-wrapped",
        );
        assert.ok(
            xml.includes("1' OR '1'='1"),
            "apostrophes in evidence should be preserved literally",
        );
        assert.ok(
            !xml.includes("&apos;"),
            "no attribute-style entity escaping inside CDATA",
        );
    });

    test("attribute values are XML-escaped", () => {
        const alerts = [
            {
                url: "http://x/y",
                pluginId: "1",
                method: "GET",
                risk: "High",
                confidence: "High",
                // Ampersand + quote in the alert name become the classname
                // slug's *source*; they get stripped by the slug regex,
                // so instead test the message attribute directly.
                alert: 'A&B "quoted"',
            },
        ];
        const { xml } = alertsToJunit(alerts, { minRisk: "Medium" });
        assert.ok(xml.includes("&amp;"), "& must be escaped in attrs");
        assert.ok(xml.includes("&quot;"), '" must be escaped in attrs');
    });

    test("strips ASCII control chars from body", () => {
        const alerts = [
            {
                url: "http://x/y",
                pluginId: "1",
                method: "GET",
                risk: "High",
                confidence: "High",
                alert: "control-char test",
                description: "before\x00\x07\x1Fafter",
            },
        ];
        const { xml } = alertsToJunit(alerts, { minRisk: "Medium" });
        assert.ok(xml.includes("beforeafter"));
        assert.ok(!xml.includes("\x00"));
    });

    test("splits ]]> inside body so CDATA stays well-formed", () => {
        const alerts = [
            {
                url: "http://x/y",
                pluginId: "1",
                method: "GET",
                risk: "High",
                confidence: "High",
                alert: "cdata edge",
                description: "trailing bracket ]]> here",
            },
        ];
        const { xml } = alertsToJunit(alerts, { minRisk: "Medium" });
        // No raw ]]>_end-of-cdata_ marker inside a CDATA opening.
        // Naive check: the string "]]>" only appears at real CDATA
        // closes, never with body text preceding it on the same "run".
        const badPattern = /trailing bracket ]]>/;
        assert.ok(!badPattern.test(xml), "]]> in body must be split");
    });

    test("emits empty (but valid) suite when nothing survives filter", () => {
        const onlyLow = alertsFixture().filter((a) => a.risk === "Low");
        const { xml, testcases } = alertsToJunit(onlyLow, {
            minRisk: "Medium",
        });
        assert.equal(testcases, 0);
        assert.ok(xml.includes(`tests="0"`));
        assert.ok(xml.includes("</testsuite>"));
    });
});

describe("writeJunit", () => {
    let tmpDir: string;

    before(() => {
        tmpDir = mkdtempSync(join(tmpdir(), "junit-write-"));
    });

    after(() => {
        rmSync(tmpDir, { recursive: true, force: true });
    });

    test("writes to disk and returns the testcase count", () => {
        const alertsPath = join(tmpDir, "alerts.json");
        const outPath = join(tmpDir, "nested", "zap-junit.xml");
        writeFileSync(alertsPath, JSON.stringify({ alerts: alertsFixture() }));
        const count = writeJunit(alertsPath, outPath, { minRisk: "Medium" });
        assert.equal(count, 3);
        const written = readFileSync(outPath, "utf-8");
        assert.ok(written.startsWith("<?xml"));
        assert.ok(written.includes(`tests="3"`));
    });
});

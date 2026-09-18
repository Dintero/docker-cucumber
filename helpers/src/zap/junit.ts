/**
 * ZAP alerts JSON → JUnit XML.
 *
 * One <testcase> per unique (pluginId, templated_path, method, param)
 * tuple at risk ≥ threshold. Templated paths keep the report stable
 * across E2E runs — random per-run identifiers (order ids, catalog
 * ids) don't create a fresh finding each time. If the same finding
 * hits multiple raw URLs matching one template, they collapse into a
 * single <testcase> with a count in the failure body.
 *
 * Consumed by CodeBuild's JunitXml report format — findings show up
 * as failed test cases in the "reports" tab of every scheduled run.
 * Complementary to `dintero-zap import` (Security Hub): JUnit is the
 * per-build visibility, Security Hub is the tracked audit trail.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import {
    compileMatchers,
    loadSpecPaths,
    type Matcher,
    templatePath,
} from "./asff.ts";

export type MinRisk = "Low" | "Medium" | "High";

const RISK_ORDER: Record<string, number> = {
    Informational: 0,
    Low: 1,
    Medium: 2,
    High: 3,
};

interface ZapAlert {
    url?: string;
    param?: string;
    pluginId?: string;
    method?: string;
    risk?: string;
    confidence?: string;
    alert?: string;
    description?: string;
    solution?: string;
    reference?: string;
    evidence?: string;
    cweid?: string;
}

function xmlEscape(s: string): string {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function stripControlChars(s: string): string {
    // JUnit consumers reject ASCII control chars other than tab/LF/CR.
    // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
    return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "");
}

interface Grouped {
    key: string;
    alert: string;
    risk: string;
    confidence: string;
    method: string;
    host: string;
    path: string;
    param: string;
    pluginId: string;
    urls: Set<string>;
    description: string;
    solution: string;
    reference: string;
    evidence: string;
    cweid: string;
}

export interface AlertsToJunitOpts {
    minRisk?: MinRisk;
    specPath?: string | null;
    suiteName?: string;
}

export interface AlertsToJunitResult {
    xml: string;
    testcases: number;
}

// XML 1.0 forbids ]]> anywhere inside a CDATA section. Splitting the
// literal is the standard trick to keep the text intact when a body
// happens to contain it.
function cdata(text: string): string {
    return `<![CDATA[${text.replace(/]]>/g, "]]]]><![CDATA[>")}]]>`;
}

export function alertsToJunit(
    alerts: ZapAlert[],
    {
        minRisk = "Medium",
        specPath = null,
        suiteName = "zap-dast",
    }: AlertsToJunitOpts = {},
): AlertsToJunitResult {
    const threshold = RISK_ORDER[minRisk];
    let matchers: Matcher[] = [];
    if (specPath) {
        const [base, templates] = loadSpecPaths(specPath);
        matchers = compileMatchers(base, templates);
    }

    const groups = new Map<string, Grouped>();
    for (const a of alerts) {
        const risk = a.risk || "Informational";
        if ((RISK_ORDER[risk] ?? 0) < threshold) continue;
        const [host, path] = templatePath(a.url || "", matchers);
        const method = a.method || "";
        const param = a.param || "";
        const plugin = a.pluginId || "";
        const key = `${plugin}|${method}|${host}|${path}|${param}`;
        let g = groups.get(key);
        if (!g) {
            g = {
                key,
                alert: a.alert || "ZAP finding",
                risk,
                confidence: a.confidence || "",
                method,
                host,
                path,
                param,
                pluginId: plugin,
                urls: new Set(),
                description: (a.description || "").trim(),
                solution: (a.solution || "").trim(),
                reference: (a.reference || "").trim(),
                evidence: (a.evidence || "").trim(),
                cweid: a.cweid || "",
            };
            groups.set(key, g);
        }
        if (a.url) g.urls.add(a.url);
    }

    const sorted = [...groups.values()].sort((a, b) => {
        const dr = (RISK_ORDER[b.risk] ?? 0) - (RISK_ORDER[a.risk] ?? 0);
        if (dr) return dr;
        return a.key.localeCompare(b.key);
    });

    const failures = sorted.length;
    const lines: string[] = [];
    lines.push(`<?xml version="1.0" encoding="UTF-8"?>`);
    lines.push(
        `<testsuite name="${xmlEscape(suiteName)}" tests="${failures}" ` +
            `failures="${failures}" errors="0" skipped="0">`,
    );

    for (const g of sorted) {
        // classname groups by risk + alert-name in CodeBuild's UI so
        // "all Medium SQL Injection findings" appear together without
        // opening each testcase.
        const classSlug = g.alert.replace(/\s+/g, "-").replace(/[^\w.-]/g, "");
        const classname = xmlEscape(`zap.${g.risk}.${classSlug || "finding"}`);
        const testcaseName = xmlEscape(
            `${g.method || "GET"} ${g.path}${g.param ? ` [${g.param}]` : ""}`,
        );
        const message = xmlEscape(
            `${g.alert} (${g.risk}/${g.confidence || "?"})` +
                (g.pluginId ? ` plugin=${g.pluginId}` : ""),
        );

        const bodyParts: string[] = [];
        if (g.description) bodyParts.push(`Description:\n${g.description}`);
        if (g.evidence) bodyParts.push(`Evidence:\n${g.evidence}`);
        if (g.solution) bodyParts.push(`Solution:\n${g.solution}`);
        if (g.reference) bodyParts.push(`Reference:\n${g.reference}`);
        if (g.cweid) bodyParts.push(`CWE: CWE-${g.cweid}`);
        if (g.urls.size > 1) {
            const sample = [...g.urls].slice(0, 5).join("\n");
            bodyParts.push(
                `Matched ${g.urls.size} URLs (templated above); e.g.:\n${sample}`,
            );
        } else if (g.urls.size === 1) {
            bodyParts.push(`URL:\n${[...g.urls][0]}`);
        }
        // CDATA-wrap the failure body: multiline text needs no
        // per-character escaping and reads cleanly when someone opens
        // the file directly. Control chars are still stripped since XML
        // 1.0 forbids them even inside CDATA.
        const body = cdata(stripControlChars(bodyParts.join("\n\n")));

        lines.push(
            `  <testcase classname="${classname}" name="${testcaseName}">`,
        );
        lines.push(
            `    <failure message="${message}" type="${xmlEscape(g.risk)}">${body}</failure>`,
        );
        lines.push(`  </testcase>`);
    }
    lines.push(`</testsuite>`);
    return { xml: `${lines.join("\n")}\n`, testcases: failures };
}

export function writeJunit(
    alertsPath: string,
    outPath: string,
    opts: AlertsToJunitOpts = {},
): number {
    const payload = JSON.parse(readFileSync(alertsPath, "utf-8"));
    const alerts: ZapAlert[] = payload.alerts || [];
    const { xml, testcases } = alertsToJunit(alerts, opts);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, xml);
    return testcases;
}

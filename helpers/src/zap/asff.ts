/**
 * ZAP alerts JSON → ASFF findings.
 *
 * Deterministic finding Id = sha256(pluginId + host + templated_path + param),
 * where templated_path comes from matching the alert URL against the OpenAPI
 * spec so run-to-run random E2E identifiers (accounts, catalog ids, ...) do
 * not perturb the hash.
 *
 * Only depends on Node's stdlib (node:crypto, node:fs).
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

type SeverityLabel = "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

const SEVERITY: Record<string, [SeverityLabel, number]> = {
    High: ["HIGH", 75],
    Medium: ["MEDIUM", 50],
    Low: ["LOW", 25],
    Informational: ["INFORMATIONAL", 1],
};

// ZAP confidence -> ASFF Confidence (0-100). Kept distinct from Severity so a
// High-severity Medium-confidence finding still surfaces both facts.
const ASFF_CONFIDENCE: Record<string, number> = {
    Low: 25,
    Medium: 50,
    High: 75,
    Confirmed: 90,
    "User Confirmed": 90,
};

// ASFF fields accepted by BatchImportFindings. `additionalProperties: false`
// semantics — anything outside these lists gets rejected server-side. Kept as
// whitelists here so a typo like Vulnerabilities.Cwe (the actual bug that hit
// us in CodeBuild) fails locally in the parser rather than at import time.
// Extend when the parser starts emitting new fields.
const ASFF_TOP_LEVEL = new Set([
    "SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId",
    "CreatedAt", "UpdatedAt", "Severity", "Title", "Description",
    "Resources", "Types",
    "Confidence", "Criticality", "SourceUrl", "Remediation",
    "Vulnerabilities", "Compliance", "ProductFields", "UserDefinedFields",
    "Note", "Workflow", "RelatedFindings",
    "FirstObservedAt", "LastObservedAt", "VerificationState", "Sample",
    "GeneratorDetails", "FindingProviderFields",
    "Action", "Malware", "Network", "Process", "ThreatIntelIndicators",
]);
const ASFF_SEVERITY = new Set(["Label", "Normalized", "Original", "Product"]);
const ASFF_SEVERITY_LABELS = new Set<SeverityLabel>([
    "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL",
]);
const ASFF_REMEDIATION = new Set(["Recommendation"]);
const ASFF_RECOMMENDATION = new Set(["Text", "Url"]);
const ASFF_COMPLIANCE = new Set([
    "Status", "StatusReasons", "RelatedRequirements",
    "SecurityControlId", "AssociatedStandards",
]);
const ASFF_VULN = new Set([
    "Id", "VulnerablePackages", "Cvss", "RelatedVulnerabilities",
    "Vendor", "ReferenceUrls", "FixAvailable", "EpssScore",
    "ExploitAvailable", "LastKnownExploitAt", "CodeVulnerabilities",
]);
const ASFF_RESOURCE = new Set([
    "Type", "Id", "Partition", "Region", "ResourceRole", "Tags",
    "DataClassification", "Details", "ApplicationName", "ApplicationArn",
]);

const CONFIDENCE: Record<string, number> = {
    "False Positive": -1,
    Low: 0,
    Medium: 1,
    High: 2,
    Confirmed: 3,
    "User Confirmed": 3,
};

export type MinConfidence = "Low" | "Medium" | "High";

function checkKeys(actual: object, allowed: Set<string>, ctx: string): void {
    const unknown = Object.keys(actual)
        .filter((k) => !allowed.has(k))
        .sort();
    if (unknown.length) {
        throw new Error(
            `ASFF validation: ${ctx} has unknown fields ${JSON.stringify(unknown)}. ` +
                `Either drop the fields from the parser or add them to the ` +
                `allowlist at the top of asff.ts.`,
        );
    }
}

export function validateFinding(f: Record<string, unknown>): void {
    checkKeys(f, ASFF_TOP_LEVEL, "top-level");
    const sev = (f.Severity as Record<string, unknown>) || {};
    checkKeys(sev, ASFF_SEVERITY, "Severity");
    if ("Label" in sev && !ASFF_SEVERITY_LABELS.has(sev.Label as SeverityLabel)) {
        throw new Error(
            `ASFF validation: Severity.Label=${JSON.stringify(sev.Label)} must be one of` +
                ` ${JSON.stringify([...ASFF_SEVERITY_LABELS].sort())}`,
        );
    }
    if ("Remediation" in f) {
        const rem = f.Remediation as Record<string, unknown>;
        checkKeys(rem, ASFF_REMEDIATION, "Remediation");
        if ("Recommendation" in rem) {
            checkKeys(
                rem.Recommendation as object,
                ASFF_RECOMMENDATION,
                "Remediation.Recommendation",
            );
        }
    }
    if ("Compliance" in f) {
        checkKeys(f.Compliance as object, ASFF_COMPLIANCE, "Compliance");
    }
    const vulns = (f.Vulnerabilities as object[]) || [];
    vulns.forEach((v, i) => checkKeys(v, ASFF_VULN, `Vulnerabilities[${i}]`));
    const resources = (f.Resources as object[]) || [];
    resources.forEach((r, i) => checkKeys(r, ASFF_RESOURCE, `Resources[${i}]`));
}

export interface Matcher {
    regex: RegExp;
    template: string;
}

/**
 * Extract basePath and path templates from a Swagger/OpenAPI YAML file.
 *
 * Uses regex extraction so this module has no non-stdlib dependencies.
 * Only reads the two things we actually need: basePath and the top-level
 * keys under 'paths:'. If the spec ever grows a different indentation
 * or format, replace this with a real YAML parse.
 */
export function loadSpecPaths(specPath: string): [string, string[]] {
    const text = readFileSync(specPath, "utf-8");
    let base = "";
    const m = text.match(/^basePath:\s*(\S+)\s*$/m);
    if (m) {
        base = m[1].replace(/\/+$/, "");
    }

    const templates: string[] = [];
    let inPaths = false;
    for (const line of text.split("\n")) {
        if (/^paths:\s*$/.test(line)) {
            inPaths = true;
            continue;
        }
        if (!inPaths) continue;
        if (line && !/^\s/.test(line) && !line.startsWith("#")) {
            break;
        }
        const pm = line.match(/^ {2}(\/\S+):\s*$/);
        if (pm) {
            templates.push(pm[1]);
        }
    }
    return [base, templates];
}

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function compileMatchers(base: string, templates: string[]): Matcher[] {
    const compiled: Matcher[] = templates.map((t) => {
        const full = base + t;
        let pattern = escapeRegex(full);
        // {name} placeholders (already regex-escaped as \{name\}) → [^/]+
        pattern = pattern.replace(/\\\{[^}]+\\\}/g, "[^/]+");
        return { regex: new RegExp("^" + pattern + "$"), template: full };
    });
    compiled.sort((a, b) => b.template.length - a.template.length);
    return compiled;
}

export function templatePath(url: string, matchers: Matcher[]): [string, string] {
    let host = "";
    let path = "/";
    try {
        const u = new URL(url);
        host = u.host;
        path = u.pathname.replace(/\/+$/, "") || "/";
    } catch {
        return [host, path];
    }
    for (const { regex, template } of matchers) {
        if (regex.test(path)) return [host, template];
    }
    return [host, path];
}

export function findingId(
    pluginId: string,
    host: string,
    path: string,
    param: string,
): string {
    const payload = `${pluginId}|${host}|${path}|${param}`;
    return createHash("sha256").update(payload, "utf-8").digest("hex");
}

export interface FindingOpts {
    accountId: string;
    productArn: string;
    repo: string;
    branch: string;
}

interface ZapAlert {
    url?: string;
    param?: string;
    pluginId?: string;
    method?: string;
    risk?: string;
    confidence?: string;
    cweid?: string;
    description?: string;
    other?: string;
    alert?: string;
    inputVector?: string;
    attack?: string;
    evidence?: string;
    solution?: string;
    reference?: string;
    tags?: Record<string, string>;
    messageId?: number | string;
}

export function toFinding(
    alert: ZapAlert,
    matchers: Matcher[],
    opts: FindingOpts,
    now: string,
): Record<string, unknown> {
    const [host, path] = templatePath(alert.url || "", matchers);
    const param = alert.param || "";
    const plugin = alert.pluginId || "";
    const method = alert.method || "";
    const fid = findingId(plugin, host, path, param);

    const risk = alert.risk || "Informational";
    const [label, normalized] = SEVERITY[risk] || ["INFORMATIONAL", 1];

    const zapConf = alert.confidence || "";
    const cwe = alert.cweid || "";
    const srcUrl = alert.url || "";

    // Merge ZAP's terse description with the plugin's `other` field, which is
    // where the actual "how it was detected" methodology lives (boolean-based
    // SQLi test, evidence, etc.). Attack/Evidence/InputVector go into
    // Resources.Details.Other (structured, machine-readable) instead of being
    // inlined here — downstream renderers can lay them out as they see fit.
    // ASFF caps Description at 1024 chars.
    const descParts: string[] = [];
    for (const k of ["description", "other"] as const) {
        const v = ((alert[k] as string) || "").trim();
        if (v) descParts.push(v);
    }
    const description = (descParts.join("\n\n") || "ZAP finding").slice(0, 1024);

    // GeneratorId encodes the repo so SH's console (which doesn't expose
    // ProductFields as a searchable field) can filter on prefix "zap-<repo>-"
    // for a single service or "zap-" for every ZAP-generated finding.
    const generatorId = opts.repo
        ? `zap-${opts.repo}-plugin-${plugin}`
        : `zap-plugin-${plugin}`;

    const finding: Record<string, unknown> = {
        SchemaVersion: "2018-10-08",
        Id: fid,
        ProductArn: opts.productArn,
        GeneratorId: generatorId,
        AwsAccountId: opts.accountId,
        CreatedAt: now,
        UpdatedAt: now,
        Severity: { Label: label, Normalized: normalized },
        Title: `${alert.alert || "ZAP finding"} on ${path}`.slice(0, 256),
        Description: description,
        SourceUrl: srcUrl.slice(0, 512),
        Resources: [
            {
                Type: "Other",
                Id: `${host}${path}`,
                Details: {
                    Other: {
                        Method: method,
                        Parameter: param,
                        Confidence: zapConf,
                        PluginId: plugin,
                        CweId: cwe ? `CWE-${cwe}` : "",
                        InputVector: alert.inputVector || "",
                        Attack: (alert.attack || "").slice(0, 1024),
                        Evidence: (alert.evidence || "").slice(0, 1024),
                        SourceUrl: srcUrl.slice(0, 1024),
                    },
                },
            },
        ],
        Types: [
            "Software and Configuration Checks/Vulnerabilities",
            ...(cwe
                ? [`Software and Configuration Checks/Vulnerabilities/CWE-${cwe}`]
                : []),
        ],
    };

    if (zapConf in ASFF_CONFIDENCE) {
        finding.Confidence = ASFF_CONFIDENCE[zapConf];
    }

    // ProductFields is a flat key-value bag the security team can filter on in
    // the SH console — e.g. Dintero:Tool = ZAP-DAST + Dintero:Repo = products.
    const productFields: Record<string, string> = {
        "Dintero:Tool": "ZAP-DAST",
        "Dintero:PluginId": plugin,
    };
    if (opts.repo) productFields["Dintero:Repo"] = opts.repo;
    if (opts.branch) productFields["Dintero:Branch"] = opts.branch;
    finding.ProductFields = productFields;

    const solution = (alert.solution || "").trim();
    const reference = (alert.reference || "").trim();
    if (solution || reference) {
        const rec: Record<string, string> = {};
        if (solution) {
            // ASFF caps at 512, but a mid-word cut reads badly. Trim to the
            // last word boundary before the cap, add an ellipsis to signal
            // it was truncated. Full text is always visible via the SH
            // console (which renders the same field).
            if (solution.length > 512) {
                let trimmed = solution.slice(0, 511);
                const cut = trimmed.lastIndexOf(" ");
                if (cut > 400) trimmed = trimmed.slice(0, cut);
                rec.Text = trimmed.replace(/[,.;]+$/, "") + "…";
            } else {
                rec.Text = solution;
            }
        }
        if (reference) {
            rec.Url = reference.split("\n")[0].slice(0, 2048);
        }
        finding.Remediation = { Recommendation: rec };
    }

    // ASFF's Vulnerabilities[] block is for CVE/CPE-style dependency findings
    // (Cvss, VulnerablePackages, etc.). The CWE classification we care about
    // is already conveyed via Types = ".../CWE-89", which SH renders as a
    // clickable link — no Vulnerabilities entry needed.

    // ZAP tags carry OWASP / PCI / HIPAA framework references. Surface them as
    // ASFF Compliance.RelatedRequirements (max 32 items, 32 chars each).
    const tags = alert.tags || {};
    const reqs = Object.keys(tags).filter(
        (k) =>
            (k.startsWith("OWASP_") ||
                k.startsWith("API_") ||
                k === "PCI_DSS" ||
                k === "HIPAA") &&
            k.length <= 32,
    );
    if (reqs.length) {
        finding.Compliance = { RelatedRequirements: reqs.slice(0, 32) };
    }

    return finding;
}

export interface BuildFindingsResult {
    findings: Record<string, unknown>[];
    alertsCount: number;
    dropped: number;
}

/**
 * Convert a ZAP alerts JSON file into a list of ASFF findings.
 *
 * Shared entry point for both the standalone dintero-zap-to-asff CLI and
 * the `dintero-zap import` subcommand that additionally uploads to
 * Security Hub. Returns {findings, alertsCount, dropped} so callers can
 * log/skip empty imports.
 */
export function buildFindings(
    alertsPath: string,
    specPath: string,
    accountId: string,
    productArn: string,
    {
        minConfidence = "High",
        now,
        repo = "",
        branch = "",
    }: {
        minConfidence?: MinConfidence;
        now?: string;
        repo?: string;
        branch?: string;
    } = {},
): BuildFindingsResult {
    const ts =
        now ||
        new Date().toISOString().replace(/\.\d+Z$/, ".000Z");
    const threshold = CONFIDENCE[minConfidence];

    const [base, templates] = loadSpecPaths(specPath);
    const matchers = compileMatchers(base, templates);

    const payload = JSON.parse(readFileSync(alertsPath, "utf-8"));
    const alerts: ZapAlert[] = Array.isArray(payload)
        ? payload
        : payload.alerts || [];

    const opts: FindingOpts = { accountId, productArn, repo, branch };

    const findings = new Map<string, Record<string, unknown>>();
    let dropped = 0;
    for (const a of alerts) {
        const risk = a.risk || "Informational";
        const conf = a.confidence || "Low";
        if (risk !== "High" && (CONFIDENCE[conf] ?? 0) < threshold) {
            dropped++;
            continue;
        }
        const f = toFinding(a, matchers, opts, ts);
        validateFinding(f);
        const id = f.Id as string;
        if (!findings.has(id)) findings.set(id, f);
    }

    return { findings: [...findings.values()], alertsCount: alerts.length, dropped };
}

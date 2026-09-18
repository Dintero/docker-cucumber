/**
 * Command-line entry point for the ZAP client operations.
 *
 * Installed as `dintero-zap` via a shim on /usr/local/bin (see
 * Dockerfile). Every subcommand takes --zap <url> (default $ZAP_URL or
 * http://zap-proxy:8080, matching the compose-network service name most
 * of our stacks use).
 */

import type { MinConfidence } from "./asff.ts";
import * as client from "./client.ts";
import { importFindings } from "./importer.ts";
import { type MinRisk, writeJunit } from "./junit.ts";

interface Flag {
    name: string;
    hasValue: boolean;
    default?: string;
    required?: boolean;
    choices?: string[];
    help: string;
}

interface Subcommand {
    name: string;
    help: string;
    flags: Flag[];
    // biome-ignore lint/suspicious/noExplicitAny: values map is heterogeneous by design
    run: (values: Record<string, any>) => Promise<void> | void;
}

const ZAP_FLAG: Flag = {
    name: "--zap",
    hasValue: true,
    default: client.DEFAULT_ZAP_URL,
    help: `ZAP HTTP API base URL (default: $ZAP_URL or ${client.DEFAULT_ZAP_URL})`,
};

const SUBCOMMANDS: Subcommand[] = [
    {
        name: "wait",
        help: "Poll ZAP until it responds to /JSON/core/view/version/.",
        flags: [
            ZAP_FLAG,
            {
                name: "--timeout",
                hasValue: true,
                default: "120",
                help: "Seconds before giving up (default: 120).",
            },
        ],
        run: async (v) => {
            await client.wait(v["--zap"], Number(v["--timeout"]));
        },
    },
    {
        name: "import-har",
        help: "Import a HAR file into ZAP's site tree.",
        flags: [
            ZAP_FLAG,
            {
                name: "--file",
                hasValue: true,
                required: true,
                help: "HAR file path visible to the ZAP process.",
            },
        ],
        run: async (v) => {
            const r = await client.importHar(v["--zap"], v["--file"]);
            console.log(r);
        },
    },
    {
        name: "drain-passive",
        help: "Poll ZAP's passive-scan queue to zero.",
        flags: [
            ZAP_FLAG,
            {
                name: "--timeout",
                hasValue: true,
                default: "600",
                help: "Seconds before soft-timeout (default: 600).",
            },
            { name: "--poll-interval", hasValue: true, default: "5", help: "" },
        ],
        run: async (v) => {
            await client.drainPassive(
                v["--zap"],
                Number(v["--timeout"]),
                Number(v["--poll-interval"]),
            );
        },
    },
    {
        name: "active-scan",
        help: "Trigger + poll an active scan against a target URL.",
        flags: [
            ZAP_FLAG,
            {
                name: "--target",
                hasValue: true,
                required: true,
                help: "URL to attack (e.g., http://products:3000).",
            },
            {
                name: "--policy",
                hasValue: true,
                default: "API-Minimal",
                help: "Scan policy name (default: API-Minimal).",
            },
            {
                name: "--poll-interval",
                hasValue: true,
                default: "30",
                help: "Seconds between status polls (default: 30).",
            },
            {
                name: "--budget-iters",
                hasValue: true,
                default: "100",
                help: "Max poll iterations before soft-stop (default: 100).",
            },
        ],
        run: async (v) => {
            await client.activeScan(
                v["--zap"],
                v["--target"],
                v["--policy"],
                Number(v["--poll-interval"]),
                Number(v["--budget-iters"]),
            );
        },
    },
    {
        name: "dump",
        help: "Write zap-alerts.json + zap-alerts-summary.json to a directory.",
        flags: [
            ZAP_FLAG,
            {
                name: "--out",
                hasValue: true,
                required: true,
                help: "Output directory.",
            },
        ],
        run: async (v) => {
            await client.dumpAlerts(v["--zap"], v["--out"]);
        },
    },
    {
        name: "extract-messages",
        help:
            "Fetch raw request/response bytes for every alert at a given risk level." +
            " Useful for reproducing findings after ZAP is torn down.",
        flags: [
            ZAP_FLAG,
            {
                name: "--alerts",
                hasValue: true,
                required: true,
                help: "Path to a zap-alerts.json file.",
            },
            {
                name: "--out",
                hasValue: true,
                required: true,
                help: "Output directory.",
            },
            {
                name: "--risk",
                hasValue: true,
                default: "High",
                help: "Alert risk level to extract (default: High).",
            },
        ],
        run: async (v) => {
            await client.extractMessages(
                v["--zap"],
                v["--alerts"],
                v["--out"],
                v["--risk"],
            );
        },
    },
    {
        name: "import",
        help:
            "Convert zap-alerts.json to ASFF and upload to Security Hub." +
            " Auto-detects account via STS; branch from $CODEBUILD_SOURCE_VERSION.",
        flags: [
            {
                name: "--alerts",
                hasValue: true,
                required: true,
                help: "Path to a zap-alerts.json file.",
            },
            {
                name: "--spec",
                hasValue: true,
                required: true,
                help: "OpenAPI/Swagger spec used to template URL paths.",
            },
            {
                name: "--repo",
                hasValue: true,
                required: true,
                help: "Repo name, exposed as ProductFields[Dintero:Repo].",
            },
            {
                name: "--branch",
                hasValue: true,
                help: "Branch name; default: $CODEBUILD_SOURCE_VERSION.",
            },
            {
                name: "--region",
                hasValue: true,
                default: "eu-west-1",
                help: "Security Hub region (default: eu-west-1).",
            },
            {
                name: "--account-id",
                hasValue: true,
                help: "AWS account; default: STS get-caller-identity.",
            },
            {
                name: "--product-arn",
                hasValue: true,
                help: "ProductArn; default: default product in --region.",
            },
            {
                name: "--min-confidence",
                hasValue: true,
                default: "High",
                choices: ["Low", "Medium", "High"],
                help: "",
            },
            {
                name: "--out",
                hasValue: true,
                help: "If set, also write ASFF findings JSON to this path.",
            },
        ],
        run: async (v) => {
            await importFindings(v["--alerts"], v["--spec"], v["--repo"], {
                branch: v["--branch"] ?? null,
                region: v["--region"],
                accountId: v["--account-id"] ?? null,
                productArn: v["--product-arn"] ?? null,
                minConfidence: v["--min-confidence"] as MinConfidence,
                outPath: v["--out"] ?? null,
            });
        },
    },
    {
        name: "to-junit",
        help:
            "Convert zap-alerts.json to JUnit XML for CodeBuild's report view." +
            " One testcase per (plugin, templated_path, method, param) tuple" +
            " at risk ≥ --min-risk; complementary to `import` (which uploads to" +
            " Security Hub).",
        flags: [
            {
                name: "--alerts",
                hasValue: true,
                required: true,
                help: "Path to a zap-alerts.json file.",
            },
            {
                name: "--out",
                hasValue: true,
                required: true,
                help: "Output path for the JUnit XML file.",
            },
            {
                name: "--spec",
                hasValue: true,
                help: "OpenAPI/Swagger spec used to template URL paths.",
            },
            {
                name: "--min-risk",
                hasValue: true,
                default: "Medium",
                choices: ["Low", "Medium", "High"],
                help: "Minimum risk to include (default: Medium).",
            },
            {
                name: "--suite",
                hasValue: true,
                default: "zap-dast",
                help: "testsuite name (default: zap-dast).",
            },
        ],
        run: (v) => {
            const count = writeJunit(v["--alerts"], v["--out"], {
                minRisk: v["--min-risk"] as MinRisk,
                specPath: v["--spec"] ?? null,
                suiteName: v["--suite"],
            });
            console.log(
                `[zap-junit] wrote ${count} testcase(s) to ${v["--out"]}`,
            );
        },
    },
];

function printTopHelp(): void {
    console.log(
        "usage: dintero-zap <subcommand> [options]\n\n" +
            "ZAP HTTP API client for CI/CD scan orchestration. Each subcommand wraps\n" +
            "a small chunk of the ZAP REST API so buildspecs don't have to inline\n" +
            "curl + jq loops.\n\n" +
            "Subcommands:",
    );
    for (const s of SUBCOMMANDS) {
        console.log(`  ${s.name.padEnd(18)} ${s.help}`);
    }
}

function printSubHelp(sub: Subcommand): void {
    console.log(
        `usage: dintero-zap ${sub.name} [options]\n\n${sub.help}\n\nOptions:`,
    );
    for (const f of sub.flags) {
        const parts: string[] = [];
        if (f.required) parts.push("(required)");
        if (f.default !== undefined) parts.push(`(default: ${f.default})`);
        if (f.choices) parts.push(`(choices: ${f.choices.join(", ")})`);
        const suffix = parts.length ? ` ${parts.join(" ")}` : "";
        console.log(
            `  ${(f.name + (f.hasValue ? " <val>" : "")).padEnd(28)} ${f.help}${suffix}`,
        );
    }
}

function parseFlags(sub: Subcommand, argv: string[]): Record<string, string> {
    // biome-ignore lint/suspicious/noExplicitAny: values map is heterogeneous
    const values: Record<string, any> = {};
    for (const f of sub.flags) {
        if (f.default !== undefined) values[f.name] = f.default;
    }
    const flagByName = new Map(sub.flags.map((f) => [f.name, f]));

    let i = 0;
    while (i < argv.length) {
        const arg = argv[i];
        if (arg === "-h" || arg === "--help") {
            printSubHelp(sub);
            process.exit(0);
        }
        // Support --name=value
        const eq = arg.indexOf("=");
        const name = eq === -1 ? arg : arg.slice(0, eq);
        const inlineVal = eq === -1 ? null : arg.slice(eq + 1);
        const f = flagByName.get(name);
        if (!f) {
            console.error(`dintero-zap ${sub.name}: unknown option ${arg}`);
            process.exit(2);
        }
        if (f.hasValue) {
            let val: string;
            if (inlineVal !== null) {
                val = inlineVal;
                i++;
            } else {
                if (i + 1 >= argv.length) {
                    console.error(
                        `dintero-zap ${sub.name}: ${name} requires a value`,
                    );
                    process.exit(2);
                }
                val = argv[i + 1];
                i += 2;
            }
            if (f.choices && !f.choices.includes(val)) {
                console.error(
                    `dintero-zap ${sub.name}: ${name}=${val} not in [${f.choices.join(", ")}]`,
                );
                process.exit(2);
            }
            values[name] = val;
        } else {
            values[name] = true;
            i++;
        }
    }

    for (const f of sub.flags) {
        if (f.required && values[f.name] === undefined) {
            console.error(
                `dintero-zap ${sub.name}: missing required option ${f.name}`,
            );
            process.exit(2);
        }
    }
    return values;
}

export async function main(
    argv: string[] = process.argv.slice(2),
): Promise<void> {
    if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
        printTopHelp();
        process.exit(argv.length === 0 ? 2 : 0);
    }
    const name = argv[0];
    const sub = SUBCOMMANDS.find((s) => s.name === name);
    if (!sub) {
        console.error(`dintero-zap: unknown subcommand '${name}'`);
        printTopHelp();
        process.exit(2);
    }
    const values = parseFlags(sub, argv.slice(1));
    await sub.run(values);
}

// Direct-invoke guard: only run main when executed as the entry-point
// (not when imported for testing).
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch((e) => {
        console.error(e instanceof Error ? e.stack || e.message : e);
        process.exit(1);
    });
}

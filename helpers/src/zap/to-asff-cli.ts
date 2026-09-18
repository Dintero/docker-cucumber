/**
 * Standalone dintero-zap-to-asff CLI: convert a ZAP alerts JSON file to
 * ASFF findings on stdout. Kept separate from `dintero-zap import` so
 * local runs / inspection don't drag the AWS SDK in.
 */

import { buildFindings, type MinConfidence } from "./asff.ts";

interface Args {
    input: string;
    spec: string;
    accountId: string;
    productArn: string;
    minConfidence: MinConfidence;
    now?: string;
    repo: string;
    branch: string;
}

function printHelp(): void {
    console.log(
        `usage: dintero-zap-to-asff --input <path> [options]

ZAP alerts JSON → ASFF findings.

Options:
  --input <path>           ZAP alerts JSON (from /JSON/core/view/alerts/) (required)
  --spec <path>            OpenAPI/Swagger spec used to template URL paths.
                           (default: app/products/api-spec/spec-products.yaml)
  --account-id <id>        (default: 000000000000)
  --product-arn <arn>      (default: arn:aws:securityhub:local::product/dintero/zap)
  --min-confidence <lvl>   Drop Low/Medium-risk alerts below this ZAP confidence
                           level. High-risk findings are always emitted regardless
                           of confidence — a Medium-confidence SQL Injection is
                           still worth a human's eyes.
                           (choices: Low, Medium, High; default: High)
  --now <iso>              ISO 8601 timestamp; default: current UTC.
  --repo <name>            Repo name, exposed as ProductFields[Dintero:Repo] so
                           SH can slice findings by service.
  --branch <name>          Branch name, exposed as ProductFields[Dintero:Branch].
`,
    );
}

function parseArgs(argv: string[]): Args {
    const defaults: Args = {
        input: "",
        spec: "app/products/api-spec/spec-products.yaml",
        accountId: "000000000000",
        productArn: "arn:aws:securityhub:local::product/dintero/zap",
        minConfidence: "High",
        repo: "",
        branch: "",
    };
    const mapping: Record<string, keyof Args> = {
        "--input": "input",
        "--spec": "spec",
        "--account-id": "accountId",
        "--product-arn": "productArn",
        "--min-confidence": "minConfidence",
        "--now": "now",
        "--repo": "repo",
        "--branch": "branch",
    };
    const choices: Partial<Record<keyof Args, string[]>> = {
        minConfidence: ["Low", "Medium", "High"],
    };

    let i = 0;
    while (i < argv.length) {
        const arg = argv[i];
        if (arg === "-h" || arg === "--help") {
            printHelp();
            process.exit(0);
        }
        const eq = arg.indexOf("=");
        const name = eq === -1 ? arg : arg.slice(0, eq);
        const inlineVal = eq === -1 ? null : arg.slice(eq + 1);
        const key = mapping[name];
        if (!key) {
            console.error(`dintero-zap-to-asff: unknown option ${arg}`);
            process.exit(2);
        }
        let val: string;
        if (inlineVal !== null) {
            val = inlineVal;
            i++;
        } else {
            if (i + 1 >= argv.length) {
                console.error(`dintero-zap-to-asff: ${name} requires a value`);
                process.exit(2);
            }
            val = argv[i + 1];
            i += 2;
        }
        const allowed = choices[key];
        if (allowed && !allowed.includes(val)) {
            console.error(
                `dintero-zap-to-asff: ${name}=${val} not in [${allowed.join(", ")}]`,
            );
            process.exit(2);
        }
        (defaults[key] as string) = val;
    }
    if (!defaults.input) {
        console.error("dintero-zap-to-asff: missing required --input");
        process.exit(2);
    }
    return defaults;
}

export function main(argv: string[] = process.argv.slice(2)): void {
    const args = parseArgs(argv);
    const { findings, alertsCount, dropped } = buildFindings(
        args.input,
        args.spec,
        args.accountId,
        args.productArn,
        {
            minConfidence: args.minConfidence,
            now: args.now,
            repo: args.repo,
            branch: args.branch,
        },
    );
    console.error(
        `[zap-to-asff] ${alertsCount} alerts → ${findings.length} unique findings` +
            ` (dropped ${dropped} below min-confidence=${args.minConfidence})`,
    );
    process.stdout.write(
        `${JSON.stringify({ Findings: findings }, null, 2)}\n`,
    );
}

if (import.meta.url === `file://${process.argv[1]}`) {
    try {
        main();
    } catch (e) {
        console.error(e instanceof Error ? e.stack || e.message : e);
        process.exit(1);
    }
}

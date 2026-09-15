/**
 * Convert ZAP alerts to ASFF and upload to Security Hub in one step.
 *
 * Wraps buildFindings + @aws-sdk BatchImportFindings. Auto-detects the
 * AWS account via STS and builds the default product ARN from account
 * + region — the buildspec only has to supply repo + input paths.
 *
 * Skips the upload gracefully when the parser's confidence filter drops
 * every alert (avoids a spurious "no findings" API call).
 */

import { writeFileSync } from "node:fs";

import { buildFindings, type MinConfidence } from "./asff.ts";

export interface ImportFindingsOpts {
    branch?: string | null;
    region?: string;
    accountId?: string | null;
    productArn?: string | null;
    minConfidence?: MinConfidence;
    outPath?: string | null;
}

export async function importFindings(
    alertsPath: string,
    specPath: string,
    repo: string,
    {
        branch = null,
        region = "eu-west-1",
        accountId = null,
        productArn = null,
        minConfidence = "High",
        outPath = null,
    }: ImportFindingsOpts = {},
): Promise<void> {
    // Deferred AWS SDK imports so the parser stays stdlib-only — only pay
    // the SDK startup cost when we're actually uploading.
    const { STSClient, GetCallerIdentityCommand } = await import(
        "@aws-sdk/client-sts"
    );
    const { SecurityHubClient, BatchImportFindingsCommand } = await import(
        "@aws-sdk/client-securityhub"
    );

    let account = accountId;
    if (account === null) {
        const sts = new STSClient({ region });
        const id = await sts.send(new GetCallerIdentityCommand({}));
        account = id.Account!;
    }

    let arn = productArn;
    if (arn === null) {
        arn = `arn:aws:securityhub:${region}:${account}:product/${account}/default`;
    }

    let branchName = branch;
    if (branchName === null) {
        // CodeBuild sets CODEBUILD_SOURCE_VERSION to "refs/heads/<name>"
        // for branch builds and to the commit sha for tag/PR builds.
        // Strip the refs/heads/ prefix for the ProductFields payload.
        const raw = process.env.CODEBUILD_SOURCE_VERSION || "";
        branchName = raw.startsWith("refs/heads/")
            ? raw.slice("refs/heads/".length)
            : raw;
    }

    const { findings, alertsCount, dropped } = buildFindings(
        alertsPath,
        specPath,
        account,
        arn,
        { minConfidence, repo, branch: branchName },
    );
    console.log(
        `[zap-import] ${alertsCount} alerts → ${findings.length} unique findings` +
            ` (dropped ${dropped} below min-confidence=${minConfidence})`,
    );

    if (outPath) {
        writeFileSync(outPath, JSON.stringify({ Findings: findings }, null, 2));
        console.log(`[zap-import] wrote ${outPath}`);
    }

    if (!findings.length) {
        console.log(
            "[securityhub] no findings to import (all dropped by parser filter)",
        );
        return;
    }

    console.log(
        `[securityhub] importing ${findings.length} findings to region=${region}`,
    );
    const sh = new SecurityHubClient({ region });

    // BatchImportFindings caps at 100 findings per call. Chunk and
    // aggregate so a > 100-finding run doesn't fail the whole import.
    const BATCH = 100;
    let totalSuccess = 0;
    let totalFailed = 0;
    const failedFindings: Array<Record<string, unknown>> = [];
    for (let i = 0; i < findings.length; i += BATCH) {
        const chunk = findings.slice(i, i + BATCH);
        const resp = await sh.send(
            new BatchImportFindingsCommand({
                // biome-ignore lint/suspicious/noExplicitAny: SDK finding type is deeply structural
                Findings: chunk as any,
            }),
        );
        totalSuccess += resp.SuccessCount ?? 0;
        totalFailed += resp.FailedCount ?? 0;
        for (const f of resp.FailedFindings ?? []) {
            failedFindings.push(f as Record<string, unknown>);
        }
    }

    console.log(`[securityhub] success=${totalSuccess} failed=${totalFailed}`);
    for (const f of failedFindings) {
        console.log(
            `[securityhub] failed: Id=${f.Id} code=${f.ErrorCode} msg=${f.ErrorMessage}`,
        );
    }
    if (totalFailed) {
        process.exit(1);
    }
}

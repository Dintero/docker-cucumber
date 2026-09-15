/**
 * Thin ZAP HTTP API client for CI/CD scan orchestration.
 *
 * All operations take a zap_url base (default env ZAP_URL, else
 * http://zap-proxy:8080 — the docker-compose service name / port ZAP
 * typically listens on). Stdlib-only; safe to invoke from any container
 * that has network reach to ZAP.
 */

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const DEFAULT_ZAP_URL =
    process.env.ZAP_URL || "http://zap-proxy:8080";

async function getJson<T = unknown>(
    zapUrl: string,
    path: string,
    timeoutMs = 30_000,
): Promise<T> {
    const url = zapUrl.replace(/\/+$/, "") + path;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const r = await fetch(url, { signal: ctrl.signal });
        if (!r.ok) {
            throw new Error(`GET ${url} → ${r.status} ${r.statusText}`);
        }
        return (await r.json()) as T;
    } finally {
        clearTimeout(timer);
    }
}

async function getBytes(
    zapUrl: string,
    path: string,
    timeoutMs = 30_000,
): Promise<Uint8Array> {
    const url = zapUrl.replace(/\/+$/, "") + path;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const r = await fetch(url, { signal: ctrl.signal });
        if (!r.ok) {
            throw new Error(`GET ${url} → ${r.status} ${r.statusText}`);
        }
        return new Uint8Array(await r.arrayBuffer());
    } finally {
        clearTimeout(timer);
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

/** Poll ZAP's version endpoint until healthy, or raise on timeout. */
export async function wait(zapUrl: string, timeoutS = 120): Promise<void> {
    const deadline = Date.now() + timeoutS * 1000;
    while (Date.now() < deadline) {
        try {
            await getJson(zapUrl, "/JSON/core/view/version/");
            return;
        } catch {
            await sleep(2000);
        }
    }
    throw new Error(`ZAP not reachable at ${zapUrl} within ${timeoutS}s`);
}

/**
 * Import a HAR file into ZAP's site tree.
 *
 * `filePath` must be visible to the ZAP process — not the caller's
 * filesystem. Typically arranged via a docker volume mount that both
 * the E2E container (writes HAR) and the ZAP container (reads it) can
 * see.
 */
export async function importHar(
    zapUrl: string,
    filePath: string,
): Promise<unknown> {
    const q = new URLSearchParams({ filePath }).toString();
    return getJson(zapUrl, `/JSON/exim/action/importHar/?${q}`);
}

/** Poll ZAP's passive-scan queue until it reaches zero (or soft-timeout). */
export async function drainPassive(
    zapUrl: string,
    timeoutS = 600,
    pollIntervalS = 5,
): Promise<void> {
    const deadline = Date.now() + timeoutS * 1000;
    while (Date.now() < deadline) {
        const { recordsToScan } = await getJson<{ recordsToScan: string | number }>(
            zapUrl,
            "/JSON/pscan/view/recordsToScan/",
        );
        console.log(`[zap] passive queue: ${recordsToScan}`);
        if (String(recordsToScan) === "0") return;
        await sleep(pollIntervalS * 1000);
    }
    console.log(`[zap] passive drain hit ${timeoutS}s soft timeout`);
}

/**
 * Trigger an active scan against `target`, poll status, soft-stop if
 * budget exceeded. Returns the scan id.
 */
export async function activeScan(
    zapUrl: string,
    target: string,
    policy = "API-Minimal",
    pollIntervalS = 30,
    budgetIters = 100,
): Promise<string> {
    const q = new URLSearchParams({
        url: target,
        recurse: "true",
        inScopeOnly: "false",
        scanPolicyName: policy,
    }).toString();
    const { scan: scanId } = await getJson<{ scan: string }>(
        zapUrl,
        `/JSON/ascan/action/scan/?${q}`,
    );
    console.log(`[zap] active scan started (${policy}), id=${scanId}`);

    for (let i = 1; i <= budgetIters; i++) {
        const { status } = await getJson<{ status: string | number }>(
            zapUrl,
            `/JSON/ascan/view/status/?scanId=${scanId}`,
        );
        console.log(`[zap] active scan: ${status}% (${i}/${budgetIters})`);
        if (String(status) === "100") return scanId;
        await sleep(pollIntervalS * 1000);
    }

    console.log(`[zap] active scan hit soft-timeout; stopping`);
    await getJson(zapUrl, `/JSON/ascan/action/stop/?scanId=${scanId}`);
    return scanId;
}

/** Dump zap-alerts.json + zap-alerts-summary.json to `outDir`. */
export async function dumpAlerts(zapUrl: string, outDir: string): Promise<void> {
    mkdirSync(outDir, { recursive: true });
    for (const [name, path] of [
        ["zap-alerts.json", "/JSON/core/view/alerts/"],
        ["zap-alerts-summary.json", "/JSON/core/view/alertsSummary/"],
    ] as const) {
        const target = join(outDir, name);
        const bytes = await getBytes(zapUrl, path);
        writeFileSync(target, bytes);
        console.log(`[zap] wrote ${target}`);
    }
}

/**
 * For every alert at the given risk level, save its raw request +
 * response bytes via ZAP's message API.
 *
 * Each output file contains a Message object with requestHeader,
 * requestBody, responseHeader, responseBody — sufficient to curl-replay
 * the exact request ZAP sent when it triggered the finding. Necessary
 * because ZAP's container is normally torn down after the buildspec
 * completes, taking the in-memory messages with it.
 */
export async function extractMessages(
    zapUrl: string,
    alertsPath: string,
    outDir: string,
    risk = "High",
): Promise<void> {
    mkdirSync(outDir, { recursive: true });
    const payload = JSON.parse(readFileSync(alertsPath, "utf-8"));
    const alerts: Array<Record<string, unknown>> = payload.alerts || [];

    let n = 0;
    for (const a of alerts) {
        if (a.risk !== risk) continue;
        const mid = a.messageId;
        if (!mid) continue;
        let data: Uint8Array;
        try {
            data = await getBytes(zapUrl, `/JSON/core/view/message/?id=${mid}`);
        } catch (e) {
            console.log(`[zap] failed to fetch messageId=${mid}: ${e}`);
            continue;
        }
        const plugin = a.pluginId ?? "unknown";
        const alertName = a.alert ?? "unknown";
        const fname = `plugin-${plugin}-msg-${mid}.json`;
        writeFileSync(join(outDir, fname), data);
        console.log(`[zap] saved ${alertName} messageId=${mid} -> ${fname}`);
        n++;
    }

    console.log(`[zap] captured ${n} ${risk}-severity request/response pairs`);
}

/**
 * HAR export of E2E-driven HTTP requests for cucumber-js suites.
 *
 * Usage — replace the native `fetch(...)` in step definitions with
 * `harFetch(...)` (identical signature). When HAR_OUT is unset, harFetch
 * is a thin passthrough. When set, each call appends a HAR 1.2 entry to
 * an in-memory buffer; `dump()` from an AfterAll hook flushes to disk.
 *
 * Feed the resulting file to ZAP (`/JSON/exim/action/importHar/`), Burp,
 * or curl-replay tooling to run security scans post-hoc without needing
 * an inline proxy during the E2E run.
 *
 * ```typescript
 * // step definitions
 * import { harFetch } from "@dintero/e2e-helpers";
 * When("I request {string}", async function (method: string) {
 *   this.ctx.response = await harFetch(this.ctx.url, { method });
 * });
 *
 * // hooks.ts (register once, cucumber picks it up via --require)
 * import { AfterAll } from "@cucumber/cucumber";
 * import { harCapture } from "@dintero/e2e-helpers";
 * AfterAll(async () => {
 *   if (harCapture.enabled()) await harCapture.dump();
 * });
 * ```
 *
 * Enable at run time by setting HAR_OUT=/path/to/output.har.
 *
 * Design note: stdlib-only (no runtime deps), so it doesn't pull
 * anything into the image beyond what's already there. Uses Node's
 * native fetch (18+) and node:fs/promises.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const HAR_OUT = process.env.HAR_OUT || null;

interface HarHeader {
    name: string;
    value: string;
}

interface HarContent {
    size: number;
    mimeType: string;
    text: string;
    encoding?: string;
}

interface HarEntry {
    startedDateTime: string;
    time: number;
    request: {
        method: string;
        url: string;
        httpVersion: string;
        cookies: unknown[];
        headers: HarHeader[];
        queryString: HarHeader[];
        headersSize: number;
        bodySize: number;
        postData?: { mimeType: string; text: string };
    };
    response: {
        status: number;
        statusText: string;
        httpVersion: string;
        cookies: unknown[];
        headers: HarHeader[];
        content: HarContent;
        redirectURL: string;
        headersSize: number;
        bodySize: number;
    };
    cache: Record<string, never>;
    timings: { send: number; wait: number; receive: number };
}

const entries: HarEntry[] = [];

export function enabled(): boolean {
    return HAR_OUT !== null;
}

function headerPairs(headers: HeadersInit | undefined): HarHeader[] {
    if (!headers) return [];
    if (headers instanceof Headers) {
        return [...headers.entries()].map(([name, value]) => ({ name, value }));
    }
    if (Array.isArray(headers)) {
        return headers.map(([name, value]) => ({ name, value }));
    }
    return Object.entries(headers as Record<string, string>).map(
        ([name, value]) => ({ name, value: String(value) }),
    );
}

function responseHeaderPairs(headers: Headers): HarHeader[] {
    return [...headers.entries()].map(([name, value]) => ({ name, value }));
}

function queryPairs(url: string): HarHeader[] {
    try {
        const u = new URL(url);
        return [...u.searchParams.entries()].map(([name, value]) => ({
            name,
            value,
        }));
    } catch {
        return [];
    }
}

function mimeType(headers: Headers | HeadersInit | undefined): string {
    if (!headers) return "";
    if (headers instanceof Headers) {
        return headers.get("content-type") || "";
    }
    if (Array.isArray(headers)) {
        for (const [k, v] of headers) {
            if (k.toLowerCase() === "content-type") return v;
        }
        return "";
    }
    for (const [k, v] of Object.entries(headers as Record<string, string>)) {
        if (k.toLowerCase() === "content-type") return String(v);
    }
    return "";
}

function isTextish(mime: string): boolean {
    return (
        mime.startsWith("application/json") ||
        mime.startsWith("text/") ||
        mime.startsWith("application/xml")
    );
}

function urlOf(input: RequestInfo | URL): string {
    if (typeof input === "string") return input;
    if (input instanceof URL) return input.toString();
    return input.url;
}

async function captureEntry(
    startedAt: Date,
    input: RequestInfo | URL,
    init: RequestInit | undefined,
    response: Response,
): Promise<void> {
    const url = urlOf(input);
    const method = (init?.method || "GET").toUpperCase();
    const elapsedMs = Math.max(0, Date.now() - startedAt.getTime());

    // Clone so we don't consume the caller's response body.
    const bodyBuf = await response.clone().arrayBuffer();
    const bodyBytes = new Uint8Array(bodyBuf);
    const respMime = response.headers.get("content-type") || "";
    let bodyText: string;
    let encoding: string | undefined;
    if (isTextish(respMime)) {
        try {
            bodyText = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
        } catch {
            bodyText = Buffer.from(bodyBytes).toString("base64");
            encoding = "base64";
        }
    } else if (bodyBytes.byteLength === 0) {
        bodyText = "";
    } else {
        bodyText = Buffer.from(bodyBytes).toString("base64");
        encoding = "base64";
    }

    const reqBody = init?.body;
    const reqBodyText = typeof reqBody === "string" ? reqBody : null;
    const reqBodySize =
        typeof reqBody === "string"
            ? Buffer.byteLength(reqBody, "utf-8")
            : reqBody
              ? -1
              : -1;

    const entry: HarEntry = {
        startedDateTime: startedAt.toISOString(),
        time: elapsedMs,
        request: {
            method,
            url,
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: headerPairs(init?.headers),
            queryString: queryPairs(url),
            headersSize: -1,
            bodySize: reqBodySize,
        },
        response: {
            status: response.status,
            statusText: response.statusText,
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: responseHeaderPairs(response.headers),
            content: {
                size: bodyBytes.byteLength,
                mimeType: respMime,
                text: bodyText,
                ...(encoding && { encoding }),
            },
            redirectURL: response.headers.get("Location") || "",
            headersSize: -1,
            bodySize: bodyBytes.byteLength,
        },
        cache: {},
        timings: { send: 0, wait: elapsedMs, receive: 0 },
    };

    if (reqBodyText !== null) {
        entry.request.postData = {
            mimeType: mimeType(init?.headers),
            text: reqBodyText,
        };
    }

    entries.push(entry);
}

/**
 * Drop-in replacement for `fetch` that appends a HAR entry when HAR_OUT
 * is set. Signature and semantics identical to global `fetch`, including
 * the returned Response being unread (we clone before capturing so the
 * caller can still consume the body).
 */
export async function harFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
): Promise<Response> {
    if (!enabled()) {
        return fetch(input, init);
    }
    const startedAt = new Date();
    const response = await fetch(input, init);
    try {
        await captureEntry(startedAt, input, init, response);
    } catch (err) {
        console.error(`[har] capture failed for ${urlOf(input)}:`, err);
    }
    return response;
}

/**
 * Write accumulated entries to HAR_OUT. Call from an AfterAll hook.
 */
export async function dump(): Promise<void> {
    if (!enabled() || !HAR_OUT) return;
    const har = {
        log: {
            version: "1.2",
            creator: { name: "dintero-e2e-har", version: "0.1" },
            entries,
        },
    };
    const parent = dirname(HAR_OUT);
    if (parent) {
        await mkdir(parent, { recursive: true });
    }
    await writeFile(HAR_OUT, JSON.stringify(har), "utf-8");
    console.log(`\n[har] wrote ${entries.length} entries to ${HAR_OUT}`);
}

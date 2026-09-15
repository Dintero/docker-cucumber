# docker-cucumber

Testing applications using [cucumber][cucumber].

Simplify running cucumber in docker/docker-compose.

## Example

See the [example](example) directory for a complete example.

## Dintero E2E helpers

The image ships a small `@dintero/e2e-helpers` package (source: `helpers/`)
for cross-repo E2E utilities.

### `harFetch` — HAR export of E2E-driven HTTP requests

Drop-in replacement for the native `fetch` that captures every call into
a HAR 1.2 document. Feed the resulting file to ZAP (via
`/JSON/exim/action/importHar/`), Burp, or curl-replay tooling for
post-hoc security scans without needing an inline proxy during the E2E
run.

```typescript
// step definitions
import { harFetch } from "@dintero/e2e-helpers";
When("I request {string}", async function (method: string) {
    this.ctx.response = await harFetch(this.ctx.url, { method });
});
```

```typescript
// hooks.ts (register once, cucumber picks it up via --require)
import { AfterAll } from "@cucumber/cucumber";
import { harCapture } from "@dintero/e2e-helpers";
AfterAll(async () => {
    if (harCapture.enabled()) await harCapture.dump();
});
```

Enable at run time by setting `HAR_OUT=/path/to/output.har`. When
unset, `harFetch` is a thin passthrough over the native `fetch`.

### `dintero-zap` — ZAP scan orchestration CLI

Installed on `$PATH` inside the image. Each subcommand wraps a small
chunk of the ZAP REST API so buildspecs don't have to inline curl + jq
loops.

```
dintero-zap wait              --zap http://zap-proxy:8080
dintero-zap import-har        --file /tmp/reports/e2e.har
dintero-zap drain-passive
dintero-zap active-scan       --target http://fraud:3000 --policy API-Minimal
dintero-zap dump              --out /tmp/reports
dintero-zap extract-messages  --alerts /tmp/reports/zap-alerts.json --out /tmp/reports/messages
dintero-zap import            --alerts /tmp/reports/zap-alerts.json \
                              --spec /spec-fraud.yaml --repo fraud-service
```

Every subcommand defaults `--zap` to `$ZAP_URL` or
`http://zap-proxy:8080`. The `import` subcommand converts alerts to
[ASFF] and calls `BatchImportFindings` against AWS Security Hub;
account is auto-detected via STS, branch from
`$CODEBUILD_SOURCE_VERSION`.

For local inspection, `dintero-zap-to-asff --input alerts.json > findings.json`
runs the parser without pulling in the AWS SDK.

Typical consumer invocation from a compose stack:

```sh
docker compose run --rm --entrypoint dintero-zap end-to-end-tests wait
```

[cucumber]: https://cucumber.io
[ASFF]: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

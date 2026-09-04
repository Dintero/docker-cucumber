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

[cucumber]: https://cucumber.io

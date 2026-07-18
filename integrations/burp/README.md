# T3MP3ST Burp Bridge

The integration keeps Burp responsible for browser/session/TLS handling and sends captured request-response observations into the deterministic bug-bounty core.

## Data flow

```text
Burp Proxy or Repeater
  -> store User A / User B / Admin session headers
  -> replay selected request through Burp HTTP stack
  -> POST /api/burp/capture
  -> program scope gate
  -> asset/endpoint graph
  -> choose baseline / exploit / negative-control evidence
  -> POST /api/burp/analyze/authz
  -> BOLA/BFLA/cross-tenant candidate in the T3MP3ST tab
```

## Run the local bridge

```bash
npx tsx src/integrations/burp/server.ts
```

The bridge binds to `127.0.0.1:3000` by default. Override it with:

```bash
T3MP3ST_BURP_HOST=127.0.0.1 T3MP3ST_BURP_PORT=3000 \
  npx tsx src/integrations/burp/server.ts
```

## Build the extension

```bash
cd integrations/burp
./gradlew jar
```

Load the generated JAR through Burp Extensions. Set a different bridge URL with:

```bash
T3MP3ST_BURP_BRIDGE=http://127.0.0.1:3000/api/burp
```

## Workflow

1. Log in as User A and select any authenticated Proxy or Repeater request.
2. Right-click and choose `T3MP3ST -> Store session as User A`.
3. Repeat for User B or Admin. The extension stores only common session headers in memory.
4. Select an owner-object request and choose `Replay as User A`; this becomes the baseline observation.
5. Replay the same request as User B or Admin; this becomes the exploit observation.
6. Optionally replay an invalid object identifier and capture it as the negative control.
7. Open the `T3MP3ST` Suite tab, select owner, attacker, and evidence IDs, then click `Analyze AuthZ`.

## Session replacement

Before replay, the extension removes these headers from the selected request and applies the stored identity values:

```text
Authorization
Cookie
X-Api-Key
X-Auth-Token
X-CSRF-Token
X-XSRF-Token
```

Everything else remains on the original Burp request. Replay uses `api.http().sendRequest()`, so Burp remains responsible for HTTP transport, TLS, upstream proxying, and its normal request handling.

## Safety properties

- The bridge binds to loopback by default.
- Captures are rejected before storage when the URL or method fails the supplied program scope.
- Stored session material stays in the Burp extension process and is not included in bridge observations.
- AuthZ candidates require an owner baseline and attacker replay; a negative control strengthens confidence.
- Replay is operator-triggered. The extension does not automatically enumerate IDs or run intrusive scanners.

# T3MP3ST Burp Bridge

The integration keeps Burp responsible for browser/session/TLS handling and sends captured request-response observations into the deterministic bug-bounty core.

## Data flow

```text
Burp Proxy or Repeater
  -> T3MP3ST context menu
  -> POST /api/burp/capture
  -> program scope gate
  -> asset/endpoint graph
  -> POST /api/burp/analyze/authz
  -> BOLA/BFLA/cross-tenant candidate
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

## Current context-menu actions

- Capture as User A
- Capture as User B
- Capture as Admin
- Capture with a generic custom identity placeholder

Captures contain the request method and URL, response status/body/headers, a generated evidence ID, and an exact-host scope receipt. Authorization analysis is performed by calling:

```http
POST /api/burp/analyze/authz
Content-Type: application/json

{
  "ownerIdentityId": "user-a",
  "attackerIdentityId": "user-b",
  "baselineEvidenceId": "burp-baseline-id",
  "exploitEvidenceId": "burp-exploit-id",
  "negativeControlEvidenceId": "burp-control-id"
}
```

## Safety properties

- The bridge binds to loopback by default.
- Captures are rejected before storage when the URL or method fails the supplied program scope.
- AuthZ candidates require an owner baseline and attacker replay; a negative control strengthens confidence.
- The extension does not automatically run intrusive scanners or modify requests.

## Next increment

Add a Burp Suite tab for editable identities/program scope, replay requests through Burp's HTTP stack, select baseline/exploit/control evidence visually, and register validated candidates as Burp audit issues.

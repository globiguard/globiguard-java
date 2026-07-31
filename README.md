# globiguard-java

Official small-surface Java SDK for GlobiGuard.

The SDK uses the Java standard library for HTTP and cryptography plus Jackson 3
for strict JSON parsing. It mirrors the TypeScript, Python, Go, JavaScript, and
.NET SDK contracts for auth headers, safe request paths, governed actions,
install bootstrap, trust webhooks, and offline entitlement manifests.

## Requirements

- Java 17 or newer.
- One runtime dependency: `tools.jackson.core:jackson-databind` 3.x.

## Install

```xml
<dependency>
  <groupId>com.globiguard</groupId>
  <artifactId>globiguard</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Server client

```java
import com.globiguard.Globiguard;

var client = Globiguard.Client.server(new Globiguard.Client.Options(
    "sandbox",
    Map.of("controlPlane", "https://api.globiguard.com"),
    Globiguard.Credential.secret("proj_example", "ggsk_example_replace_me", "sandbox")
));

var decision = client.governedActions().authorizeActionOrThrow(
    """
    {
      "context": {
        "actionType": "refund.create",
        "destination": {
          "type": "custom",
          "name": "payments-production"
        },
        "dataClasses": ["CONFIDENTIAL"],
        "actor": {
          "id": "support-agent-123",
          "type": "agent"
        },
        "purpose": "Resolve an approved customer escalation",
        "correlationId": "case_456",
        "idempotencyKey": "case_456:refund:v1"
      }
    }
    """
);
```

The authorize-or-throw helper returns only a current, short-lived,
obligation-free `ALLOW` that explicitly authorizes the exact action once.
`MODIFY`, `QUEUE`, `BLOCK`, dry-run, expired, and incomplete responses stop
execution. The same governed client exposes approval status,
metadata-only evidence summaries, incident replay, evidence export, and every
queue review transition.

## Webhooks

Pass the exact raw request body bytes. Do not parse and re-serialize JSON before verification.

```java
var result = Globiguard.TrustWebhook.verify(headers, rawBody, "whsec_example_replace_me");
if (!result.ok()) throw new IllegalStateException(result.error());
```

## Development

```bash
mvn test
mvn package
```

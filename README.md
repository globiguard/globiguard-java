# globiguard-java

Official dependency-minimal Java SDK for GlobiGuard.

The SDK uses only the Java standard library at runtime. It mirrors the TypeScript, Python, Go, JavaScript, and .NET SDK contracts for auth headers, safe request paths, governed actions, install bootstrap, trust webhooks, and offline entitlement manifests.

## Requirements

- Java 17 or newer.
- No runtime package dependencies.

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
    "{\"actionType\":\"refund\",\"actor\":{\"id\":\"user_123\"}}"
);
```

## Webhooks

Pass the exact raw request body bytes. Do not parse and re-serialize JSON before verification.

```java
var result = Globiguard.TrustWebhook.verify(headers, rawBody, "whsec_example_replace_me");
if (!result.ok()) throw new IllegalStateException(result.error());
```

## Development

```bash
javac -d target/classes src/main/java/com/globiguard/Globiguard.java
javac -cp target/classes -d target/test-classes src/test/java/com/globiguard/GlobiguardTest.java
java -cp "target/classes;target/test-classes" com.globiguard.GlobiguardTest
```

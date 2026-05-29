package com.globiguard;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Globiguard {
  private Globiguard() {}

  public static final class Environments {
    public static final String LOCAL = "local";
    public static final String SANDBOX = "sandbox";
    public static final String LIVE = "live";
    public static boolean isValid(String value) {
      return LOCAL.equals(value) || SANDBOX.equals(value) || LIVE.equals(value);
    }
  }

  public record Credential(String kind, String projectId, String token, String environment) {
    public static Credential secret(String projectId, String token, String environment) {
      return new Credential("secret", projectId, token, environment);
    }
    public static Credential publishable(String projectId, String token, String environment) {
      return new Credential("publishable", projectId, token, environment);
    }
    public static Credential local(String token) {
      return new Credential("local", null, token, Environments.LOCAL);
    }
  }

  public static final class Client {
    private final Transport transport;
    private final GovernedActions governedActions;
    private Client(Transport transport) {
      this.transport = transport;
      this.governedActions = new GovernedActions(transport);
    }
    public record Options(String environment, Map<String, String> services, Credential credential) {}
    public static Client server(Options options) {
      if ("publishable".equals(options.credential().kind())) throw new IllegalArgumentException("Server clients require secret or local credentials.");
      return new Client(new Transport(options));
    }
    public static Client browser(Options options) {
      if ("secret".equals(options.credential().kind())) throw new IllegalArgumentException("Browser clients cannot use secret credentials.");
      return new Client(new Transport(options));
    }
    public ResourceClient actions() { return new ResourceClient(transport, "/v1/actions"); }
    public ResourceClient audit() { return new ResourceClient(transport, "/v1/audit"); }
    public ResourceClient installs() { return new ResourceClient(transport, "/v1/installs"); }
    public ResourceClient orgs() { return new ResourceClient(transport, "/v1/orgs"); }
    public ResourceClient policies() { return new ResourceClient(transport, "/v1/policies"); }
    public ResourceClient queue() { return new ResourceClient(transport, "/v1/queue"); }
    public ResourceClient workflows() { return new ResourceClient(transport, "/v1/workflows"); }
    public GovernedActions governedActions() { return governedActions; }
  }

  public static final class Transport {
    private static final Pattern BAD_PERCENT = Pattern.compile("%(?![0-9A-Fa-f]{2})");
    private static final List<String> RESERVED_HEADERS = List.of(
        "x-globiguard-project-id", "x-globiguard-secret-key", "x-globiguard-publishable-key",
        "x-globiguard-local-mode", "x-globiguard-local-token", "x-globiguard-client", "x-globiguard-environment");
    private final Client.Options options;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();

    Transport(Client.Options options) {
      if (!Environments.isValid(options.environment())) throw new IllegalArgumentException("Environment must be local, sandbox, or live.");
      if (!Objects.equals(options.environment(), options.credential().environment())) throw new IllegalArgumentException("Credential environment must match client environment.");
      var base = URI.create(options.services().getOrDefault("controlPlane", ""));
      if (!base.isAbsolute()) throw new IllegalArgumentException("services.controlPlane is required.");
      if (!Environments.LOCAL.equals(options.environment()) && !"https".equals(base.getScheme())) throw new IllegalArgumentException("HTTPS is required outside local.");
      if ("local".equals(options.credential().kind()) && !isLoopback(base)) throw new IllegalArgumentException("Local credentials require localhost or loopback URLs.");
      this.options = options;
    }

    public String request(String method, String path, String jsonBody, Map<String, String> headers) throws IOException, InterruptedException {
      validatePath(path);
      var uri = URI.create(options.services().get("controlPlane").replaceAll("/+$", "") + path);
      var builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30));
      authHeaders().forEach(builder::header);
      if (headers != null) {
        for (var entry : headers.entrySet()) {
          if (RESERVED_HEADERS.contains(entry.getKey().toLowerCase(Locale.ROOT))) throw new IllegalArgumentException("Reserved GlobiGuard header cannot be overridden: " + entry.getKey());
          builder.header(entry.getKey(), entry.getValue());
        }
      }
      if (jsonBody == null) builder.method(method, HttpRequest.BodyPublishers.noBody());
      else builder.method(method, HttpRequest.BodyPublishers.ofString(jsonBody)).header("content-type", "application/json");
      var response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IOException("GlobiGuard request failed with " + response.statusCode() + ": " + response.body());
      return response.body();
    }

    public Map<String, String> authHeaders() {
      var credential = options.credential();
      var headers = new HashMap<String, String>();
      headers.put("x-globiguard-client", "globiguard-java/0.1.0");
      headers.put("x-globiguard-environment", options.environment());
      if ("local".equals(credential.kind())) {
        headers.put("x-globiguard-local-mode", "true");
        if (credential.token() != null && !credential.token().isBlank()) headers.put("x-globiguard-local-token", credential.token());
      } else {
        headers.put("x-globiguard-project-id", require(credential.projectId(), "project id"));
        headers.put("secret".equals(credential.kind()) ? "x-globiguard-secret-key" : "x-globiguard-publishable-key", require(credential.token(), "credential token"));
      }
      return Map.copyOf(headers);
    }

    public static void validatePath(String path) {
      if (!path.startsWith("/")) throw new IllegalArgumentException("Request path must start with /.");
      if (path.startsWith("//") || path.contains("\\") || path.contains("?") || path.contains("#")) throw new IllegalArgumentException("Unsafe request path.");
      if (URI.create(path).isAbsolute()) throw new IllegalArgumentException("Absolute request paths are not allowed.");
      for (var segment : path.split("/")) if (".".equals(segment) || "..".equals(segment)) throw new IllegalArgumentException("Dot segments are not allowed.");
      if (BAD_PERCENT.matcher(path).find()) throw new IllegalArgumentException("Invalid percent encoding.");
    }

    private static boolean isLoopback(URI uri) {
      return "localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost());
    }
  }

  public record ResourceClient(Transport transport, String basePath) {
    public String list() throws IOException, InterruptedException { return transport.request("GET", basePath, null, null); }
    public String get(String id) throws IOException, InterruptedException { return transport.request("GET", basePath + "/" + id, null, null); }
    public String create(String jsonBody) throws IOException, InterruptedException { return transport.request("POST", basePath, jsonBody, null); }
    public String post(String suffix, String jsonBody) throws IOException, InterruptedException { 
      var encodedSuffix = URLEncoder.encode(suffix.replaceFirst("^/+", ""), StandardCharsets.UTF_8);
      return transport.request("POST", basePath + "/" + encodedSuffix, jsonBody, null); 
    }
  }

  public record GovernedActions(Transport transport) {
    public String authorizeActionOrThrow(String jsonBody) throws IOException, InterruptedException {
      return authorizeActionOrThrow(jsonBody, null, null);
    }
    
    public String authorizeActionOrThrow(String jsonBody, String idempotencyKey, String correlationId) throws IOException, InterruptedException {
      var headers = new HashMap<String, String>();
      if (idempotencyKey != null) headers.put("idempotency-key", idempotencyKey);
      if (correlationId != null) headers.put("correlation-id", correlationId);
      var response = transport.request("POST", "/v1/actions/authorize", jsonBody, headers.isEmpty() ? null : headers);
      if (response.contains("\"decision\":\"BLOCK\"")) throw new IllegalStateException("GlobiGuard blocked the governed action.");
      return response;
    }
  }

  public record WebhookResult(boolean ok, String error, String envelopeJson) {}

  public static final class TrustWebhook {
    public static WebhookResult verify(Map<String, String> headers, byte[] rawBody, String signingSecret) {
      try {
        var normalized = new HashMap<String, String>();
        headers.forEach((k, v) -> normalized.put(k.toLowerCase(Locale.ROOT), v));
        var delivery = normalized.get("x-globiguard-delivery-id");
        var timestamp = normalized.get("x-globiguard-timestamp");
        var eventType = normalized.get("x-globiguard-event-type");
        var signature = normalized.get("x-globiguard-signature");
        if (delivery == null || timestamp == null || eventType == null || signature == null) return new WebhookResult(false, "Missing required webhook headers.", null);
        var age = Duration.between(Instant.ofEpochSecond(Long.parseLong(timestamp)), Instant.now()).abs();
        if (age.compareTo(Duration.ofMinutes(5)) > 0) return new WebhookResult(false, "Webhook timestamp is outside the replay window.", null);
        var signed = "globiguard-hmac-sha256-v1." + delivery + "." + timestamp + "." + eventType + "." + new String(rawBody, StandardCharsets.UTF_8);
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(signingSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        var expected = "v1=" + hex(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
        if (!constantTimeEquals(expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8))) return new WebhookResult(false, "Invalid webhook signature.", null);
        return new WebhookResult(true, null, new String(rawBody, StandardCharsets.UTF_8));
      } catch (Exception ex) {
        return new WebhookResult(false, ex.getMessage(), null);
      }
    }
  }

  public record BootstrapProfile(String environment, String deploymentMode, String issuerMode, String installReporting, String installLabel) {}

  public static final class Bootstrap {
    public static Map<String, Object> installRegistration(BootstrapProfile profile, String packageName, String packageVersion, String integrationKind, String runtimeKind) {
      validate(profile);
      return Map.of(
          "environment", profile.environment(),
          "deploymentMode", profile.deploymentMode(),
          "issuerMode", profile.issuerMode(),
          "installReporting", profile.installReporting(),
          "package", Map.of("name", packageName, "version", packageVersion),
          "integration", Map.of("kind", integrationKind, "runtime", runtimeKind));
    }
    private static void validate(BootstrapProfile profile) {
      if (!Environments.isValid(profile.environment())) throw new IllegalArgumentException("Invalid environment.");
      if ("hosted".equals(profile.deploymentMode()) && !"globiguard_issued".equals(profile.issuerMode())) throw new IllegalArgumentException("Hosted deployments require globiguard_issued issuer mode.");
      if (List.of("self_hosted", "sovereign").contains(profile.deploymentMode())) {
        if (!"customer_issued".equals(profile.issuerMode())) throw new IllegalArgumentException("Self-hosted and sovereign deployments require customer_issued issuer mode.");
        if (!List.of("opt_in", "disabled").contains(profile.installReporting())) throw new IllegalArgumentException("Self-hosted and sovereign reporting must be opt_in or disabled.");
      }
    }
  }

  public static final class Entitlements {
    public static String verifySignedManifest(String compactJws, Map<String, byte[]> publicKeysById) throws GeneralSecurityException {
      var parts = compactJws.split("\\.");
      if (parts.length != 3) throw new IllegalArgumentException("Entitlement manifest must be compact JWS.");
      var header = new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8);
      if (!"EdDSA".equals(jsonString(header, "alg"))) throw new IllegalArgumentException("Entitlement manifest must use EdDSA.");
      var kid = jsonString(header, "kid");
      var publicKeyRaw = publicKeysById.get(kid);
      if (publicKeyRaw == null) throw new IllegalArgumentException("Unknown entitlement signing key.");
      var signature = Signature.getInstance("Ed25519");
      signature.initVerify(ed25519PublicKey(publicKeyRaw));
      signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
      if (!signature.verify(base64UrlDecode(parts[2]))) throw new GeneralSecurityException("Invalid entitlement manifest signature.");
      var payload = new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8);
      if (!"globiguard.entitlement_manifest.v1".equals(jsonString(payload, "schema"))) throw new IllegalArgumentException("Unsupported entitlement manifest schema.");
      var now = Instant.now().getEpochSecond();
      var nbf = jsonLong(payload, "nbf");
      var exp = jsonLong(payload, "exp");
      if (nbf != null && nbf > now) throw new IllegalArgumentException("Entitlement manifest is not active yet.");
      if (exp != null && exp <= now) throw new IllegalArgumentException("Entitlement manifest is expired.");
      return payload;
    }
  }

  private static PublicKey ed25519PublicKey(byte[] raw) throws GeneralSecurityException {
    var prefix = new byte[] {48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0};
    var x509 = new byte[prefix.length + raw.length];
    System.arraycopy(prefix, 0, x509, 0, prefix.length);
    System.arraycopy(raw, 0, x509, prefix.length, raw.length);
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(x509));
  }

  private static String require(String value, String label) {
    if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + label + ".");
    return value;
  }

  private static byte[] base64UrlDecode(String value) {
    return Base64.getUrlDecoder().decode(value);
  }

  private static String hex(byte[] bytes) {
    var builder = new StringBuilder(bytes.length * 2);
    for (var b : bytes) builder.append(String.format("%02x", b));
    return builder.toString();
  }

  private static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff == 0;
  }

  private static String jsonString(String json, String key) {
    var matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
    if (!matcher.find()) return null;
    return matcher.group(1);
  }

  private static Long jsonLong(String json, String key) {
    var matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)").matcher(json);
    if (!matcher.find()) return null;
    return Long.parseLong(matcher.group(1));
  }
}


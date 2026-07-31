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
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public final class Globiguard {
  private static final ObjectMapper JSON = new ObjectMapper();
  static final Duration MAX_EXECUTION_AUTHORIZATION_TTL = Duration.ofMinutes(5);

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
    private final boolean readOnly;
    private Client(Transport transport, boolean readOnly) {
      this.transport = transport;
      this.readOnly = readOnly;
      this.governedActions = new GovernedActions(transport, readOnly);
    }
    public record Options(String environment, Map<String, String> services, Credential credential) {}
    public static Client server(Options options) {
      if ("publishable".equals(options.credential().kind())) throw new IllegalArgumentException("Server clients require secret or local credentials.");
      return new Client(new Transport(options), false);
    }
    public static Client browser(Options options) {
      if ("secret".equals(options.credential().kind())) throw new IllegalArgumentException("Browser clients cannot use secret credentials.");
      return new Client(new Transport(options), true);
    }
    public ResourceClient actions() { return new ResourceClient(transport, "/v1/actions", readOnly); }
    public ResourceClient audit() { return new ResourceClient(transport, "/v1/audit", readOnly); }
    public ResourceClient installs() { return new ResourceClient(transport, "/v1/installs", readOnly); }
    public ResourceClient orgs() { return new ResourceClient(transport, "/v1/orgs", readOnly); }
    public ResourceClient policies() { return new ResourceClient(transport, "/v1/policies", readOnly); }
    public ResourceClient queue() { return new ResourceClient(transport, "/v1/queue", readOnly); }
    public ResourceClient workflows() { return new ResourceClient(transport, "/v1/workflows", readOnly); }
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
      return request(method, path, jsonBody, headers, null);
    }

    public String request(String method, String path, String jsonBody, Map<String, String> headers, Map<String, String> query) throws IOException, InterruptedException {
      validatePath(path);
      var queryString = query == null ? "" : query.entrySet().stream()
          .filter(entry -> entry.getValue() != null && !entry.getValue().isBlank())
          .map(entry -> encodeQuery(entry.getKey()) + "=" + encodeQuery(entry.getValue()))
          .reduce((left, right) -> left + "&" + right)
          .map(value -> "?" + value)
          .orElse("");
      var uri = URI.create(options.services().get("controlPlane").replaceAll("/+$", "") + path + queryString);
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

    private static String encodeQuery(String value) {
      return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
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
      if (path.startsWith("//") || path.contains("//") || path.contains("\\") || path.contains("?") || path.contains("#")) throw new IllegalArgumentException("Unsafe request path.");
      if (URI.create(path).isAbsolute()) throw new IllegalArgumentException("Absolute request paths are not allowed.");
      if (BAD_PERCENT.matcher(path).find()) throw new IllegalArgumentException("Invalid percent encoding.");
      for (var segment : path.split("/")) {
        var decoded = java.net.URLDecoder.decode(segment, StandardCharsets.UTF_8);
        if (".".equals(decoded) || "..".equals(decoded) || decoded.contains("/") || decoded.contains("\\")) {
          throw new IllegalArgumentException("Encoded separators and dot segments are not allowed.");
        }
      }
    }

    private static boolean isLoopback(URI uri) {
      return "localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost());
    }
  }

  public record ResourceClient(Transport transport, String basePath, boolean readOnly) {
    public String list() throws IOException, InterruptedException { return transport.request("GET", basePath, null, null); }
    public String get(String id) throws IOException, InterruptedException { return transport.request("GET", basePath + "/" + pathSegment(id), null, null); }
    public String create(String jsonBody) throws IOException, InterruptedException {
      requireWrite();
      return transport.request("POST", basePath, jsonBody, null);
    }
    public String post(String suffix, String jsonBody) throws IOException, InterruptedException {
      requireWrite();
      var encodedSuffix = pathSegment(suffix.replaceFirst("^/+", ""));
      return transport.request("POST", basePath + "/" + encodedSuffix, jsonBody, null);
    }
    private void requireWrite() {
      if (readOnly) throw new IllegalArgumentException("Resource writes require a server client.");
    }
  }

  public record GovernedActions(Transport transport, boolean readOnly) {
    public String authorizeAction(String jsonBody) throws IOException, InterruptedException {
      requireWrite("Action authorization");
      return transport.request("POST", "/v1/actions/authorize", jsonBody, null);
    }

    public String authorizeActionOrThrow(String jsonBody) throws IOException, InterruptedException {
      return requireExecutableDecision(authorizeAction(jsonBody), isDryRun(jsonBody), Instant.now());
    }

    public String requestApproval(String jsonBody) throws IOException, InterruptedException {
      requireWrite("Approval creation");
      return transport.request("POST", "/v1/actions/approvals", jsonBody, null);
    }

    public String getApprovalStatus(String approvalId) throws IOException, InterruptedException {
      return transport.request("GET", "/v1/actions/approvals/" + pathSegment(approvalId), null, null);
    }

    public String getEvidenceReferences(Map<String, String> query) throws IOException, InterruptedException {
      return transport.request("GET", "/v1/actions/evidence", null, null, query);
    }

    public String exportEvidencePackage(String jsonBody) throws IOException, InterruptedException {
      requireWrite("Evidence export");
      return transport.request("POST", "/v1/audit/export", jsonBody == null ? "{}" : jsonBody, null);
    }

    public String getEvidencePackageSummary(String evidencePackageId) throws IOException, InterruptedException {
      return transport.request("GET", "/v1/audit/evidence-packages/" + pathSegment(evidencePackageId) + "/summary", null, null);
    }

    public String getIncidentReplay(String lookupKind, String lookupId) throws IOException, InterruptedException {
      if (!List.of("workflowRunId", "correlationId", "queueEntryId", "auditEventId", "authorizationId").contains(lookupKind)) {
        throw new IllegalArgumentException("Unsupported incident replay lookup kind.");
      }
      return transport.request("GET", "/v1/audit/incident-replay", null, null, Map.of(lookupKind, lookupId));
    }

    public String reviewQueue(String queueEntryId, String action, String jsonBody) throws IOException, InterruptedException {
      requireWrite("Queue review");
      if (!List.of("approve", "reject", "modify", "escalate", "resume").contains(action)) {
        throw new IllegalArgumentException("Unsupported queue review action.");
      }
      return transport.request("POST", "/v1/queue/" + pathSegment(queueEntryId) + "/" + action, jsonBody == null ? "{}" : jsonBody, null);
    }

    private void requireWrite(String operation) {
      if (readOnly) throw new IllegalArgumentException(operation + " requires a server client.");
    }

    public String waitForApproval(String queueEntryId, int maxAttempts, Duration interval) throws IOException, InterruptedException {
      if (maxAttempts < 1) throw new IllegalArgumentException("maxAttempts must be at least 1.");
      var delay = interval == null ? Duration.ofSeconds(1) : interval;
      for (var attempt = 1; attempt <= maxAttempts; attempt++) {
        var entry = transport.request("GET", "/v1/queue/" + pathSegment(queueEntryId), null, null);
        var status = jsonString(entry, "status");
        if (List.of("APPROVED", "AUTO_APPROVED", "RESUMED").contains(status)) return entry;
        if (List.of("REJECTED", "EXPIRED", "FAILED").contains(status)) {
          throw new IllegalStateException("Queued action resolved as " + status + "; do not perform the downstream business action.");
        }
        if ("MODIFIED".equals(status)) {
          throw new IllegalStateException("The reviewer approved a modified action summary. Rebuild the real payload and request a new authorization before executing it.");
        }
        if (!List.of("PENDING", "ESCALATED").contains(status)) {
          throw new IllegalStateException("GlobiGuard returned an unsupported approval state; the downstream business action remains stopped.");
        }
        if (attempt < maxAttempts) Thread.sleep(delay.toMillis());
      }
      throw new IllegalStateException("Queued action is still pending; do not perform the downstream business action yet.");
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
          "packageName", packageName,
          "packageVersion", packageVersion,
          "integrationKind", integrationKind,
          "runtimeKind", runtimeKind,
          "environment", profile.environment(),
          "deploymentMode", profile.deploymentMode(),
          "issuerMode", profile.issuerMode(),
          "installReporting", profile.installReporting());
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
    private static final String MANIFEST_TYPE = "globiguard.entitlement.v1";

    public record VerificationOptions(
        String expectedIssuer,
        String expectedOrgId,
        String expectedProjectId,
        String expectedEnvironment,
        String expectedDeploymentMode,
        Instant now) {
      public static VerificationOptions defaults() {
        return new VerificationOptions(null, null, null, null, null, Instant.now());
      }
    }

    public static String verifySignedManifest(String compactJws, Map<String, byte[]> publicKeysById) throws GeneralSecurityException {
      return verifySignedManifest(compactJws, publicKeysById, VerificationOptions.defaults());
    }

    public static String verifySignedManifest(
        String compactJws,
        Map<String, byte[]> publicKeysById,
        VerificationOptions options) throws GeneralSecurityException {
      var parts = compactJws.split("\\.");
      if (parts.length != 3) throw new IllegalArgumentException("Entitlement manifest must be compact JWS.");
      var header = parseJson(base64UrlDecode(parts[0]), "protected header");
      if (!"EdDSA".equals(requiredText(header, "alg")) || !MANIFEST_TYPE.equals(requiredText(header, "typ"))) {
        throw new IllegalArgumentException("Unsupported entitlement manifest protected header.");
      }
      var kid = requiredText(header, "kid");
      var publicKeyRaw = publicKeysById.get(kid);
      if (publicKeyRaw == null) throw new IllegalArgumentException("Unknown entitlement signing key.");
      var signature = Signature.getInstance("Ed25519");
      signature.initVerify(ed25519PublicKey(publicKeyRaw));
      signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
      if (!signature.verify(base64UrlDecode(parts[2]))) throw new GeneralSecurityException("Invalid entitlement manifest signature.");
      var payload = new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8);
      var payloadNode = parseJson(payload.getBytes(StandardCharsets.UTF_8), "payload");
      validatePayload(payloadNode);

      var issuedAt = requiredInstant(payloadNode, "issuedAt");
      var notBefore = requiredInstant(payloadNode, "notBefore");
      var expiresAt = requiredInstant(payloadNode, "expiresAt");
      var now = options.now() == null ? Instant.now() : options.now();
      if (issuedAt.isAfter(expiresAt) || !notBefore.isBefore(expiresAt)) throw new IllegalArgumentException("Entitlement manifest timestamps are inconsistent.");
      if (notBefore.isAfter(now)) throw new IllegalArgumentException("Entitlement manifest is not active yet.");
      if (!expiresAt.isAfter(now)) throw new IllegalArgumentException("Entitlement manifest has expired.");

      var subject = requiredObject(payloadNode, "subject");
      expect(options.expectedIssuer(), requiredText(payloadNode, "issuer"), "issuer");
      expect(options.expectedOrgId(), requiredText(subject, "orgId"), "organization");
      expect(options.expectedProjectId(), requiredText(subject, "projectId"), "project");
      expect(options.expectedEnvironment(), requiredText(subject, "environment"), "environment");
      expect(options.expectedDeploymentMode(), requiredText(subject, "deploymentMode"), "deployment mode");
      return payload;
    }

    private static void validatePayload(JsonNode payload) {
      var manifestVersion = payload.get("manifestVersion");
      if (!MANIFEST_TYPE.equals(requiredText(payload, "manifestType"))
          || manifestVersion == null || !manifestVersion.isIntegralNumber() || manifestVersion.intValue() != 1) {
        throw new IllegalArgumentException("Unsupported entitlement manifest payload.");
      }
      for (var field : List.of("manifestId", "issuer", "issuedAt", "notBefore", "expiresAt")) requiredText(payload, field);

      var subject = requiredObject(payload, "subject");
      for (var field : List.of("orgId", "workspaceName", "orgSlug", "projectId", "projectSlug")) requiredText(subject, field);
      if (!List.of("sandbox", "live").contains(requiredText(subject, "environment"))) throw new IllegalArgumentException("Entitlement manifest subject environment is invalid.");
      if (!List.of("self_hosted", "sovereign").contains(requiredText(subject, "deploymentMode"))) throw new IllegalArgumentException("Entitlement manifest subject deployment mode is invalid.");

      var commercial = requiredObject(payload, "commercial");
      if (!List.of("FREE", "STARTER", "GROWTH", "SCALE", "ENTERPRISE").contains(requiredText(commercial, "commercialPlan"))) throw new IllegalArgumentException("Entitlement manifest commercial plan is invalid.");
      if (!List.of("FREE", "PILOT", "ACTIVE", "GRACE", "PAST_DUE", "SUSPENDED", "CANCELED").contains(requiredText(commercial, "billingStatus"))) throw new IllegalArgumentException("Entitlement manifest billing status is invalid.");
      var pilotActive = commercial.get("pilotActive");
      if (pilotActive == null || !pilotActive.isBoolean()) throw new IllegalArgumentException("Entitlement manifest pilotActive must be boolean.");

      var entitlements = requiredObject(payload, "entitlements");
      validateNullableCounter(entitlements, "includedQueriesPerMonth");
      validateNullableCounter(entitlements, "frameworkSlots");
      if (!List.of("NONE", "METERED", "CONTRACT").contains(requiredText(entitlements, "overageMode"))) throw new IllegalArgumentException("Entitlement manifest overage mode is invalid.");
    }

    private static JsonNode parseJson(byte[] bytes, String label) {
      JsonNode value;
      try {
        value = JSON.readTree(bytes);
      } catch (RuntimeException error) {
        throw new IllegalArgumentException("Invalid entitlement manifest " + label + ".", error);
      }
      if (value == null || !value.isObject()) throw new IllegalArgumentException("Entitlement manifest " + label + " must be a JSON object.");
      return value;
    }

    private static JsonNode requiredObject(JsonNode parent, String field) {
      var value = parent.get(field);
      if (value == null || !value.isObject()) throw new IllegalArgumentException("Entitlement manifest field " + field + " must be an object.");
      return value;
    }

    private static String requiredText(JsonNode parent, String field) {
      var value = parent.get(field);
      if (value == null || !value.isTextual() || value.textValue().isBlank()) throw new IllegalArgumentException("Entitlement manifest field " + field + " must be a non-empty string.");
      return value.textValue();
    }

    private static Instant requiredInstant(JsonNode parent, String field) {
      try {
        return Instant.parse(requiredText(parent, field));
      } catch (DateTimeParseException error) {
        throw new IllegalArgumentException("Entitlement manifest field " + field + " must be an ISO timestamp.", error);
      }
    }

    private static void validateNullableCounter(JsonNode parent, String field) {
      var value = parent.get(field);
      if (value == null) throw new IllegalArgumentException("Entitlement manifest field " + field + " is required.");
      if (value.isNull()) return;
      if (!value.isIntegralNumber() || value.longValue() < 0) throw new IllegalArgumentException("Entitlement manifest field " + field + " must be null or a non-negative integer.");
    }

    private static void expect(String expected, String actual, String label) {
      if (expected != null && !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8))) {
        throw new IllegalArgumentException("Entitlement manifest " + label + " does not match the expected value.");
      }
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

  private static String pathSegment(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8)
        .replace("+", "%20");
  }

  static String jsonString(String json, String field) {
    JsonNode document;
    try {
      document = JSON.readTree(json);
    } catch (RuntimeException error) {
      throw new IllegalStateException("GlobiGuard returned invalid JSON.", error);
    }
    var value = document == null ? null : document.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IllegalStateException("GlobiGuard response field " + field + " must be a non-empty string.");
    }
    return value.textValue();
  }

  static String requireExecutableDecision(String response) {
    return requireExecutableDecision(response, false, Instant.now());
  }

  static String requireExecutableDecision(String response, boolean simulation, Instant now) {
    JsonNode document;
    try {
      document = JSON.readTree(response);
    } catch (RuntimeException error) {
      throw new IllegalStateException("GlobiGuard returned invalid JSON; the governed action remains stopped.", error);
    }
    var decisionNode = document == null ? null : document.get("decision");
    var decision = decisionNode != null && decisionNode.isTextual() ? decisionNode.textValue() : null;
    if (decision == null) {
      throw new IllegalStateException("GlobiGuard returned an unsupported decision; the governed action remains stopped.");
    }
    switch (decision) {
      case "BLOCK" -> throw new IllegalStateException("GlobiGuard blocked the governed action.");
      case "QUEUE" -> throw new IllegalStateException("GlobiGuard queued the governed action for review; do not perform the downstream business action yet.");
      case "MODIFY" -> throw new IllegalStateException("Apply modifications through a typed handler and reauthorize the exact resulting action before execution.");
      case "ALLOW" -> { }
      default -> throw new IllegalStateException("GlobiGuard returned an unsupported decision; the governed action remains stopped.");
    }
    if (simulation) throw nonExecutable("A dry-run decision is not an execution permit. Reauthorize with dryRun disabled.");
    var executable = document.get("executable");
    var nextAction = document.get("nextAction");
    if (executable == null || !executable.isBoolean() || !executable.booleanValue()
        || nextAction == null || !nextAction.isTextual() || !"EXECUTE_EXACT_ACTION_ONCE".equals(nextAction.textValue())) {
      throw nonExecutable("The control plane marked this response as non-executable. Reauthorize before execution.");
    }
    var approvalState = document.get("approvalState");
    if (approvalState == null || !approvalState.isTextual()
        || !("NOT_REQUIRED".equals(approvalState.textValue()) || "APPROVED".equals(approvalState.textValue()))) {
      throw nonExecutable("Resolve review and reauthorize the exact current action before execution.");
    }
    Instant expiresAt;
    try {
      var expiry = document.get("expiresAt");
      expiresAt = expiry != null && expiry.isTextual() ? Instant.parse(expiry.textValue()) : null;
    } catch (DateTimeParseException error) {
      expiresAt = null;
    }
    if (expiresAt == null || !expiresAt.isAfter(now)
        || Duration.between(now, expiresAt).compareTo(MAX_EXECUTION_AUTHORIZATION_TTL) > 0) {
      throw nonExecutable("Execution authority must have a current, bounded expiry. Reauthorize immediately before execution.");
    }
    var obligations = document.get("obligations");
    if (obligations != null && obligations.isArray() && !obligations.isEmpty()) {
      throw nonExecutable("Enforce all obligations and reauthorize before execution.");
    }
    var modifications = document.get("modifications");
    if (modifications != null && modifications.isObject() && !modifications.isEmpty()) {
      throw nonExecutable("Apply all modifications and reauthorize the exact resulting action before execution.");
    }
    return response;
  }

  private static IllegalStateException nonExecutable(String message) {
    return new IllegalStateException(message);
  }

  private static boolean isDryRun(String request) {
    try {
      var document = JSON.readTree(request);
      var dryRun = document == null ? null : document.get("dryRun");
      return dryRun != null && dryRun.isBoolean() && dryRun.booleanValue();
    } catch (RuntimeException error) {
      return false;
    }
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

}


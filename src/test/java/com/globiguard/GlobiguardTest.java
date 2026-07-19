package com.globiguard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class GlobiguardTest {
  private static final String ENTITLEMENT_TOKEN =
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImtpZF90ZXN0IiwidHlwIjoiZ2xvYmlndWFyZC5lbnRpdGxlbWVudC52MSJ9."
          + "eyJtYW5pZmVzdFR5cGUiOiJnbG9iaWd1YXJkLmVudGl0bGVtZW50LnYxIiwibWFuaWZlc3RWZXJzaW9uIjoxLCJtYW5pZmVzdElkIjoibWFuaWZlc3RfMTIzIiwiaXNzdWVyIjoiaHR0cHM6Ly9hcGkuZ2xvYmlndWFyZC5jb20iLCJpc3N1ZWRBdCI6IjIwMjYtMDUtMjlUMTA6MDA6MDBaIiwibm90QmVmb3JlIjoiMjAyNi0wNS0yOVQxMDowMDowMFoiLCJleHBpcmVzQXQiOiIyMDI2LTA1LTMwVDEwOjAwOjAwWiIsInN1YmplY3QiOnsib3JnSWQiOiJvcmdfMTIzIiwid29ya3NwYWNlTmFtZSI6IkFjbWUiLCJvcmdTbHVnIjoiYWNtZSIsInByb2plY3RJZCI6InByb2pfMTIzIiwicHJvamVjdFNsdWciOiJtYWluIiwiZW52aXJvbm1lbnQiOiJzYW5kYm94IiwiZGVwbG95bWVudE1vZGUiOiJzZWxmX2hvc3RlZCJ9LCJjb21tZXJjaWFsIjp7ImNvbW1lcmNpYWxQbGFuIjoiR1JPV1RIIiwiYmlsbGluZ1N0YXR1cyI6IkFDVElWRSIsInBpbG90QWN0aXZlIjpmYWxzZX0sImVudGl0bGVtZW50cyI6eyJpbmNsdWRlZFF1ZXJpZXNQZXJNb250aCI6MTAwMDAsImZyYW1ld29ya1Nsb3RzIjozLCJvdmVyYWdlTW9kZSI6Ik1FVEVSRUQifX0."
          + "qJZVmhIyLBsSUmrFlpCzCytt6pUly5CZG7miWgxxZttuqXNnNWfleiSJ7ScK15AVhY0ZnLopSHZg4_uQbSi8CQ";

  @Test
  void validatesRequestPaths() {
    Globiguard.Transport.validatePath("/v1/actions");
    assertThrows(IllegalArgumentException.class, () -> Globiguard.Transport.validatePath("https://evil.example/v1"));
    assertThrows(IllegalArgumentException.class, () -> Globiguard.Transport.validatePath("/v1/../secret"));
    assertThrows(IllegalArgumentException.class, () -> Globiguard.Transport.validatePath("/v1%2f../secret"));
    assertThrows(IllegalArgumentException.class, () -> Globiguard.Transport.validatePath("/v1//double"));
  }

  @Test
  void buildsTheFlatInstallRegistrationContract() {
    var registration = Globiguard.Bootstrap.installRegistration(
        new Globiguard.BootstrapProfile("sandbox", "self_hosted", "customer_issued", "opt_in", "Java worker"),
        "globiguard", "0.1.0", "sdk", "java");
    assertEquals("sandbox", registration.get("environment"));
    assertEquals("globiguard", registration.get("packageName"));
    assertEquals("java", registration.get("runtimeKind"));
  }

  @Test
  void browserWritesFailBeforeTransport() {
    var browser = Globiguard.Client.browser(new Globiguard.Client.Options(
        "sandbox",
        Map.of("controlPlane", "https://api.globiguard.com"),
        Globiguard.Credential.publishable("proj_123", "ggpk_test", "sandbox")));
    assertThrows(IllegalArgumentException.class, () -> browser.policies().create("{}"));
    assertThrows(IllegalArgumentException.class, () -> browser.governedActions().authorizeAction("{}"));
    assertThrows(IllegalArgumentException.class, () -> browser.governedActions().reviewQueue("queue_1", "approve", "{}"));
    assertThrows(IllegalArgumentException.class, () -> browser.governedActions().exportEvidencePackage("{}"));
  }

  @Test
  void parsesApprovalStatusAndRejectsMalformedResponses() {
    assertEquals("PENDING", Globiguard.jsonString("{\"status\":\"PENDING\"}", "status"));
    assertThrows(IllegalStateException.class, () -> Globiguard.jsonString("{\"status\":7}", "status"));
    assertThrows(IllegalStateException.class, () -> Globiguard.jsonString("not-json", "status"));
  }

  @Test
  void onlyAllowsExplicitExecutableDecisions() {
    assertEquals("{\"decision\": \"ALLOW\"}", Globiguard.requireExecutableDecision("{\"decision\": \"ALLOW\"}"));
    assertEquals("{\"decision\":\"MODIFY\"}", Globiguard.requireExecutableDecision("{\"decision\":\"MODIFY\"}"));
    assertThrows(IllegalStateException.class, () -> Globiguard.requireExecutableDecision("{\"decision\":\"QUEUE\"}"));
    assertThrows(IllegalStateException.class, () -> Globiguard.requireExecutableDecision("{\"decision\":\"BLOCK\"}"));
    assertThrows(IllegalStateException.class, () -> Globiguard.requireExecutableDecision("{\"decision\":\"UNKNOWN\"}"));
    assertThrows(IllegalStateException.class, () -> Globiguard.requireExecutableDecision("{}"));
  }

  @Test
  void verifiesCurrentSignedEntitlementAndExpectedBindings() throws Exception {
    var publicKey = Base64.getUrlDecoder().decode("0EBi8A20QIJf5lwzzj98ZK1X8EzBJ2nli7rsMM8JXzc");
    var options = new Globiguard.Entitlements.VerificationOptions(
        "https://api.globiguard.com",
        "org_123",
        "proj_123",
        "sandbox",
        "self_hosted",
        Instant.parse("2026-05-29T10:30:00Z"));
    var payload = Globiguard.Entitlements.verifySignedManifest(
        ENTITLEMENT_TOKEN, Map.of("kid_test", publicKey), options);
    assertTrue(payload.contains("\"commercialPlan\":\"GROWTH\""));

    var wrongOrg = new Globiguard.Entitlements.VerificationOptions(
        null, "org_other", null, null, null, Instant.parse("2026-05-29T10:30:00Z"));
    assertThrows(
        IllegalArgumentException.class,
        () -> Globiguard.Entitlements.verifySignedManifest(
            ENTITLEMENT_TOKEN, Map.of("kid_test", publicKey), wrongOrg));
  }

  @Test
  void verifiesTrustWebhooksAndRejectsTampering() throws Exception {
    var rawBody = "{\"type\":\"globiguard.test\"}".getBytes(StandardCharsets.UTF_8);
    var timestamp = Long.toString(Instant.now().getEpochSecond());
    var delivery = "del_test";
    var secret = "whsec_test";
    var signed = "globiguard-hmac-sha256-v1." + delivery + "." + timestamp + ".globiguard.test." + new String(rawBody, StandardCharsets.UTF_8);
    var mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    var signature = "v1=" + hex(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
    var headers = Map.of(
        "x-globiguard-delivery-id", delivery,
        "x-globiguard-timestamp", timestamp,
        "x-globiguard-event-type", "globiguard.test",
        "x-globiguard-signature", signature);
    assertTrue(Globiguard.TrustWebhook.verify(headers, rawBody, secret).ok());
    assertTrue(!Globiguard.TrustWebhook.verify(headers, rawBody, "wrong-secret").ok());
  }

  private static String hex(byte[] bytes) {
    var builder = new StringBuilder(bytes.length * 2);
    for (var value : bytes) builder.append(String.format("%02x", value));
    return builder.toString();
  }
}

package com.globiguard;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class GlobiguardTest {
  public static void main(String[] args) throws Exception {
    Globiguard.Transport.validatePath("/v1/actions");
    expectThrows(() -> Globiguard.Transport.validatePath("https://evil.example/v1"));
    expectThrows(() -> Globiguard.Transport.validatePath("/v1/../secret"));

    var registration = Globiguard.Bootstrap.installRegistration(
        new Globiguard.BootstrapProfile("sandbox", "self_hosted", "customer_issued", "opt_in", "Java worker"),
        "globiguard", "0.1.0", "sdk", "java");
    assertTrue("sandbox".equals(registration.get("environment")), "bootstrap environment");

    var rawBody = "{\"type\":\"globiguard.test\"}".getBytes(StandardCharsets.UTF_8);
    var timestamp = Long.toString(Instant.now().getEpochSecond());
    var delivery = "del_test";
    var secret = "whsec_test";
    var signed = "globiguard-hmac-sha256-v1." + delivery + "." + timestamp + ".globiguard.test." + new String(rawBody, StandardCharsets.UTF_8);
    var mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    var signature = "v1=" + hex(mac.doFinal(signed.getBytes(StandardCharsets.UTF_8)));
    var result = Globiguard.TrustWebhook.verify(Map.of(
        "x-globiguard-delivery-id", delivery,
        "x-globiguard-timestamp", timestamp,
        "x-globiguard-event-type", "globiguard.test",
        "x-globiguard-signature", signature), rawBody, secret);
    assertTrue(result.ok(), "webhook verification");

    System.out.println("GlobiGuard Java SDK smoke tests passed.");
  }

  private static void assertTrue(boolean condition, String label) {
    if (!condition) throw new AssertionError(label);
  }

  private static void expectThrows(ThrowingRunnable runnable) {
    try {
      runnable.run();
    } catch (Exception expected) {
      return;
    }
    throw new AssertionError("Expected exception.");
  }

  private static String hex(byte[] bytes) {
    var builder = new StringBuilder(bytes.length * 2);
    for (var b : bytes) builder.append(String.format("%02x", b));
    return builder.toString();
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }
}


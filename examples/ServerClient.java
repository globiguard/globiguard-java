import com.globiguard.Globiguard;
import java.util.Map;

public final class ServerClient {
  public static void main(String[] args) throws Exception {
    var client = Globiguard.Client.server(new Globiguard.Client.Options(
        "sandbox",
        Map.of("controlPlane", "https://api.globiguard.com"),
        Globiguard.Credential.secret("proj_example", "ggsk_example_replace_me", "sandbox")));

    var decision = client.governedActions().authorizeActionOrThrow(
        "{\"actionType\":\"refund\",\"actor\":{\"id\":\"user_123\"},\"target\":{\"id\":\"order_456\"}}");
    System.out.println(decision);
  }
}


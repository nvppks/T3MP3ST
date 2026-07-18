package io.t3mp3st.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.Component;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public final class TempestBurpExtension implements BurpExtension, ContextMenuItemsProvider {
    private static final String BRIDGE_URL = System.getenv().getOrDefault(
        "T3MP3ST_BURP_BRIDGE", "http://127.0.0.1:3000/api/burp"
    );

    private final Gson gson = new Gson();
    private final HttpClient client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .build();

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("T3MP3ST Bug Bounty Bridge");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("T3MP3ST bridge ready: " + BRIDGE_URL);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selected = event.messageEditorRequestResponse();
        if (selected.isEmpty()) return List.of();

        JMenu root = new JMenu("T3MP3ST");
        root.add(captureItem("Capture as User A", "user-a", "user", null, selected.get()));
        root.add(captureItem("Capture as User B", "user-b", "user", null, selected.get()));
        root.add(captureItem("Capture as Admin", "admin", "admin", null, selected.get()));

        JMenuItem custom = new JMenuItem("Capture with custom identity");
        custom.addActionListener(ignored -> capture(selected.get(), "custom", "user", null));
        root.add(custom);
        return List.of(root);
    }

    private JMenuItem captureItem(
        String label,
        String identityId,
        String role,
        String tenant,
        HttpRequestResponse message
    ) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(ignored -> capture(message, identityId, role, tenant));
        return item;
    }

    private void capture(HttpRequestResponse message, String identityId, String role, String tenant) {
        try {
            JsonObject payload = buildCapture(message, identityId, role, tenant);
            HttpRequest request = HttpRequest.newBuilder(URI.create(BRIDGE_URL + "/capture"))
                .timeout(Duration.ofSeconds(10))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(payload), StandardCharsets.UTF_8))
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                api.logging().logToOutput("Captured " + identityId + ": " + response.body());
            } else {
                api.logging().logToError("T3MP3ST capture failed: HTTP " + response.statusCode() + " " + response.body());
            }
        } catch (Exception error) {
            api.logging().logToError("T3MP3ST capture failed: " + error.getMessage());
        }
    }

    private JsonObject buildCapture(HttpRequestResponse message, String identityId, String role, String tenant) {
        String url = message.request().url();
        JsonObject identity = new JsonObject();
        identity.addProperty("id", identityId);
        identity.addProperty("role", role);
        if (tenant != null && !tenant.isBlank()) identity.addProperty("tenant", tenant);

        JsonObject observation = new JsonObject();
        observation.addProperty("identityId", identityId);
        observation.addProperty("method", message.request().method());
        observation.addProperty("url", url);
        observation.addProperty("status", message.response() == null ? 0 : message.response().statusCode());
        observation.addProperty("requestBody", encode(message.request().body()));
        observation.addProperty("responseBody", message.response() == null ? "" : message.response().bodyToString());
        observation.addProperty("durationMs", 0);

        JsonObject headers = new JsonObject();
        if (message.response() != null) {
            message.response().headers().forEach(header -> headers.addProperty(header.name(), header.value()));
        }
        observation.add("responseHeaders", headers);

        JsonArray evidenceIds = new JsonArray();
        evidenceIds.add("burp-" + UUID.randomUUID());
        observation.add("evidenceIds", evidenceIds);

        URI uri = URI.create(url);
        JsonObject rule = new JsonObject();
        rule.addProperty("host", uri.getHost());
        rule.addProperty("includeSubdomains", false);
        JsonArray methods = new JsonArray();
        methods.add(message.request().method());
        rule.add("methods", methods);

        JsonArray included = new JsonArray();
        included.add(rule);
        JsonObject scope = new JsonObject();
        scope.addProperty("program", "burp-session");
        scope.add("included", included);

        JsonObject payload = new JsonObject();
        payload.add("identity", identity);
        payload.add("observation", observation);
        payload.add("scope", scope);
        return payload;
    }

    private static String encode(ByteArray body) {
        if (body == null || body.length() == 0) return "";
        return Base64.getEncoder().encodeToString(body.getBytes());
    }
}

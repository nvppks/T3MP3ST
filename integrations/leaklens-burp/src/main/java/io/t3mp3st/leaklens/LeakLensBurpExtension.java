package io.t3mp3st.leaklens;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public final class LeakLensBurpExtension implements BurpExtension, ContextMenuItemsProvider {
    private static final String BRIDGE_URL = System.getenv().getOrDefault(
        "T3MP3ST_LEAKLENS_BRIDGE", "http://127.0.0.1:3000/api/leaklens"
    );
    private static final int MAX_BODY_BYTES = 20 * 1024 * 1024;

    private final Gson gson = new Gson();
    private final HttpClient client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .build();
    private final JTextArea output = new JTextArea();

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("T3MP3ST LeakLens");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.userInterface().registerSuiteTab("T3MP3ST LeakLens", buildPanel());
        api.logging().logToOutput("T3MP3ST LeakLens ready: " + BRIDGE_URL);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> selected = event.messageEditorRequestResponse();
        if (selected.isEmpty()) return List.of();

        HttpRequestResponse message = selected.get().requestResponse();
        JMenu root = new JMenu("T3MP3ST LeakLens");

        if (message.response() != null) {
            JMenuItem responseItem = new JMenuItem("Scan response body");
            responseItem.addActionListener(ignored -> scanResponse(message));
            root.add(responseItem);
        }

        JMenuItem assetItem = new JMenuItem("Scan selected asset URL");
        assetItem.addActionListener(ignored -> scanAssetUrl(message.request().url()));
        root.add(assetItem);

        JMenuItem crawlItem = new JMenuItem("Crawl application JS assets");
        crawlItem.addActionListener(ignored -> crawlApplication(message.request().url()));
        root.add(crawlItem);

        return List.of(root);
    }

    private JPanel buildPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton health = new JButton("Check bridge");
        JButton clear = new JButton("Clear");

        health.addActionListener(ignored -> checkHealth());
        clear.addActionListener(ignored -> output.setText(""));
        controls.add(new JLabel("Deterministic LeakLens results; secret values stay masked."));
        controls.add(health);
        controls.add(clear);

        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        panel.add(controls, BorderLayout.NORTH);
        panel.add(new JScrollPane(output), BorderLayout.CENTER);
        return panel;
    }

    private void scanResponse(HttpRequestResponse message) {
        if (message.response() == null) {
            append("No response is available for the selected message.\n");
            return;
        }

        byte[] body = message.response().bodyToString().getBytes(StandardCharsets.UTF_8);
        if (body.length == 0) {
            append("Selected response body is empty.\n");
            return;
        }
        if (body.length > MAX_BODY_BYTES) {
            append("Refusing response larger than " + MAX_BODY_BYTES + " bytes.\n");
            return;
        }

        URI uri = URI.create(message.request().url());
        JsonObject payload = new JsonObject();
        payload.addProperty("kind", "content");
        payload.addProperty("contentBase64", Base64.getEncoder().encodeToString(body));
        payload.addProperty("sourceUrl", uri.toString());
        payload.addProperty("sourceMethod", message.request().method());
        payload.addProperty("fileName", fileName(uri));
        payload.addProperty("jsIntel", true);
        payload.add("scope", exactScope(uri, message.request().method()));
        postScan(payload, "response " + displayUri(uri));
    }

    private void scanAssetUrl(String url) {
        URI uri = URI.create(url);
        JsonObject payload = new JsonObject();
        payload.addProperty("kind", "url");
        payload.addProperty("targetUrl", uri.toString());
        payload.addProperty("crawl", false);
        payload.addProperty("jsIntel", true);
        payload.add("scope", exactScope(uri, "GET"));
        postScan(payload, "asset " + displayUri(uri));
    }

    private void crawlApplication(String url) {
        URI selected = URI.create(url);
        URI origin = URI.create(selected.getScheme() + "://" + selected.getRawAuthority() + "/");
        JsonObject payload = new JsonObject();
        payload.addProperty("kind", "url");
        payload.addProperty("targetUrl", origin.toString());
        payload.addProperty("crawl", true);
        payload.addProperty("jsIntel", true);
        payload.addProperty("rateLimit", 3);
        payload.addProperty("concurrency", 2);
        payload.add("scope", exactScope(origin, "GET"));
        postScan(payload, "crawl " + displayUri(origin));
    }

    private JsonObject exactScope(URI uri, String method) {
        JsonObject rule = new JsonObject();
        rule.addProperty("host", uri.getHost());
        rule.addProperty("includeSubdomains", false);
        JsonArray methods = new JsonArray();
        methods.add(method);
        rule.add("methods", methods);

        JsonArray included = new JsonArray();
        included.add(rule);
        JsonObject scope = new JsonObject();
        scope.addProperty("program", "burp-session");
        scope.add("included", included);
        return scope;
    }

    private String fileName(URI uri) {
        String path = uri.getPath();
        if (path == null || path.isBlank() || path.endsWith("/")) return "burp-response.js";
        int slash = path.lastIndexOf('/');
        String candidate = slash >= 0 ? path.substring(slash + 1) : path;
        return candidate.isBlank() ? "burp-response.js" : candidate;
    }

    private String displayUri(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isBlank()) path = "/";
        return uri.getScheme() + "://" + uri.getRawAuthority() + path;
    }

    private void checkHealth() {
        runAsync(() -> {
            HttpRequest request = HttpRequest.newBuilder(URI.create(BRIDGE_URL + "/health"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            append("Bridge health: HTTP " + response.statusCode() + " " + response.body() + "\n");
        }, "health check");
    }

    private void postScan(JsonObject payload, String label) {
        append("Starting LeakLens " + label + "\n");
        runAsync(() -> {
            HttpRequest request = HttpRequest.newBuilder(URI.create(BRIDGE_URL + "/scan"))
                .timeout(Duration.ofSeconds(190))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(payload), StandardCharsets.UTF_8))
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            renderScanResponse(response);
        }, label);
    }

    private void renderScanResponse(HttpResponse<String> response) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            append("LeakLens bridge failed: HTTP " + response.statusCode() + " " + response.body() + "\n");
            return;
        }

        JsonElement parsed = JsonParser.parseString(response.body());
        if (!parsed.isJsonObject()) {
            append("LeakLens bridge returned an unexpected response.\n");
            return;
        }

        JsonObject root = parsed.getAsJsonObject();
        if (!root.has("ok") || !root.get("ok").getAsBoolean()) {
            append("LeakLens bridge rejected the scan.\n");
            return;
        }

        int count = root.has("findingCount") ? root.get("findingCount").getAsInt() : 0;
        long duration = root.has("durationMs") ? root.get("durationMs").getAsLong() : 0;
        append("LeakLens completed: " + count + " finding(s), " + duration + " ms\n");

        JsonArray findings = root.has("findings") && root.get("findings").isJsonArray()
            ? root.getAsJsonArray("findings")
            : new JsonArray();
        for (JsonElement element : findings) {
            if (!element.isJsonObject()) continue;
            JsonObject finding = element.getAsJsonObject();
            String rule = safeString(finding, "ruleName", safeString(finding, "ruleId", "unknown rule"));
            String masked = safeString(finding, "maskedValue", "[MASKED]");
            String source = safeString(finding, "source", "unknown");
            String validation = safeString(finding, "validation", "not_run");
            String line = finding.has("line") ? ":" + finding.get("line").getAsInt() : "";
            String evidence = safeString(finding, "evidenceArtifact", "");
            append("- " + rule + " | " + masked + " | " + source + line
                + " | validation=" + validation + (evidence.isBlank() ? "" : " | " + evidence) + "\n");
        }
        append("\n");
    }

    private String safeString(JsonObject object, String key, String fallback) {
        if (!object.has(key) || object.get(key).isJsonNull()) return fallback;
        return object.get(key).getAsString();
    }

    private void runAsync(CheckedRunnable action, String label) {
        Thread worker = new Thread(() -> {
            try {
                action.run();
            } catch (Exception error) {
                api.logging().logToError("T3MP3ST LeakLens " + label + " failed: " + error.getMessage());
                append("Error during " + label + ": " + error.getMessage() + "\n");
            }
        }, "t3mp3st-leaklens");
        worker.setDaemon(true);
        worker.start();
    }

    private void append(String text) {
        SwingUtilities.invokeLater(() -> {
            output.append(text);
            output.setCaretPosition(output.getDocument().getLength());
        });
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}

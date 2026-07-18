package io.t3mp3st.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public final class TempestBurpExtension implements BurpExtension, ContextMenuItemsProvider {
    private static final String BRIDGE_URL = System.getenv().getOrDefault(
        "T3MP3ST_BURP_BRIDGE", "http://127.0.0.1:3000/api/burp"
    );

    private final Gson gson = new Gson();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final Map<String, IdentityProfile> identities = new LinkedHashMap<>();
    private final Map<String, HttpRequestResponse> evidence = new LinkedHashMap<>();

    private MontoyaApi api;
    private JTextArea eventLog;
    private JTextArea candidateView;
    private JComboBox<String> ownerIdentity;
    private JComboBox<String> attackerIdentity;
    private JComboBox<String> baselineEvidence;
    private JComboBox<String> exploitEvidence;
    private JComboBox<String> controlEvidence;
    private JTextField tenantField;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("T3MP3ST Bug Bounty Bridge");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.userInterface().registerSuiteTab("T3MP3ST", buildSuiteTab());
        log("Bridge ready: " + BRIDGE_URL);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selected = event.messageEditorRequestResponse();
        if (selected.isEmpty()) return List.of();

        HttpRequestResponse message = selected.get();
        JMenu root = new JMenu("T3MP3ST");
        root.add(storeIdentityItem("Store session as User A", "user-a", "user", message));
        root.add(storeIdentityItem("Store session as User B", "user-b", "user", message));
        root.add(storeIdentityItem("Store session as Admin", "admin", "admin", message));
        root.addSeparator();
        root.add(replayItem("Replay as User A", "user-a", message));
        root.add(replayItem("Replay as User B", "user-b", message));
        root.add(replayItem("Replay as Admin", "admin", message));
        root.addSeparator();
        root.add(captureItem("Capture current as baseline", "baseline", message));
        root.add(captureItem("Capture current as negative control", "negative-control", message));
        return List.of(root);
    }

    private Component buildSuiteTab() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel identityPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        identityPanel.setBorder(BorderFactory.createTitledBorder("Identity sessions"));
        tenantField = new JTextField(12);
        identityPanel.add(new JLabel("Tenant for next stored identity:"));
        identityPanel.add(tenantField);
        identityPanel.add(new JLabel("Store sessions from Proxy/Repeater context menu."));

        JPanel analysisPanel = new JPanel();
        analysisPanel.setLayout(new BoxLayout(analysisPanel, BoxLayout.Y_AXIS));
        analysisPanel.setBorder(BorderFactory.createTitledBorder("Authorization differential"));
        ownerIdentity = new JComboBox<>();
        attackerIdentity = new JComboBox<>();
        baselineEvidence = new JComboBox<>();
        exploitEvidence = new JComboBox<>();
        controlEvidence = new JComboBox<>();
        controlEvidence.addItem("");
        analysisPanel.add(row("Owner", ownerIdentity));
        analysisPanel.add(row("Attacker", attackerIdentity));
        analysisPanel.add(row("Baseline evidence", baselineEvidence));
        analysisPanel.add(row("Exploit evidence", exploitEvidence));
        analysisPanel.add(row("Negative control", controlEvidence));
        JButton analyze = new JButton("Analyze AuthZ");
        analyze.addActionListener(ignored -> analyzeSelection());
        JButton refresh = new JButton("Refresh bridge state");
        refresh.addActionListener(ignored -> refreshState());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(analyze);
        buttons.add(refresh);
        analysisPanel.add(buttons);

        eventLog = new JTextArea();
        eventLog.setEditable(false);
        candidateView = new JTextArea();
        candidateView.setEditable(false);
        candidateView.setLineWrap(true);
        candidateView.setWrapStyleWord(true);

        JSplitPane output = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            titledScroll("Workflow log", eventLog), titledScroll("Candidate", candidateView));
        output.setResizeWeight(0.5);

        JPanel left = new JPanel(new BorderLayout(8, 8));
        left.add(identityPanel, BorderLayout.NORTH);
        left.add(analysisPanel, BorderLayout.CENTER);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, output);
        split.setResizeWeight(0.35);
        root.add(split, BorderLayout.CENTER);
        return root;
    }

    private JPanel row(String label, JComboBox<String> combo) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row.add(new JLabel(label + ":"));
        combo.setPrototypeDisplayValue("burp-00000000-0000-0000-0000-000000000000");
        row.add(combo);
        return row;
    }

    private JScrollPane titledScroll(String title, JTextArea area) {
        JScrollPane scroll = new JScrollPane(area);
        scroll.setBorder(BorderFactory.createTitledBorder(title));
        return scroll;
    }

    private JMenuItem storeIdentityItem(String label, String id, String role, HttpRequestResponse message) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(ignored -> {
            String tenant = tenantField == null ? "" : tenantField.getText().trim();
            IdentityProfile profile = IdentityProfile.fromRequest(id, role, tenant, message.request());
            identities.put(id, profile);
            refreshIdentityCombos();
            log("Stored " + id + " with " + profile.headers.size() + " session header(s)" +
                (tenant.isBlank() ? "" : " tenant=" + tenant));
        });
        return item;
    }

    private JMenuItem replayItem(String label, String identityId, HttpRequestResponse source) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(ignored -> replay(source, identityId));
        return item;
    }

    private JMenuItem captureItem(String label, String identityId, HttpRequestResponse message) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(ignored -> capture(message, identityId, identityId, null));
        return item;
    }

    private void replay(HttpRequestResponse source, String identityId) {
        IdentityProfile profile = identities.get(identityId);
        if (profile == null) {
            logError("No stored session for " + identityId);
            return;
        }
        Thread.startVirtualThread(() -> {
            try {
                HttpRequest replayRequest = profile.applyTo(source.request());
                long started = System.currentTimeMillis();
                HttpRequestResponse result = api.http().sendRequest(replayRequest).copyToTempFile();
                long duration = System.currentTimeMillis() - started;
                String evidenceId = capture(result, profile.id, profile.role, profile.tenant, duration);
                evidence.put(evidenceId, result);
                refreshEvidenceCombos(evidenceId);
                log("Replay " + identityId + " -> " + statusOf(result) + " in " + duration + "ms, evidence=" + evidenceId);
            } catch (Exception error) {
                logError("Replay failed: " + error.getMessage());
            }
        });
    }

    private String capture(HttpRequestResponse message, String identityId, String role, String tenant) {
        return capture(message, identityId, role, tenant, 0);
    }

    private String capture(HttpRequestResponse message, String identityId, String role, String tenant, long durationMs) {
        try {
            JsonObject payload = buildCapture(message, identityId, role, tenant, durationMs);
            JsonObject response = postJson("/capture", payload);
            String evidenceId = response.get("evidenceId").getAsString();
            evidence.put(evidenceId, message.copyToTempFile());
            refreshEvidenceCombos(evidenceId);
            log("Captured " + identityId + " evidence=" + evidenceId);
            return evidenceId;
        } catch (Exception error) {
            logError("Capture failed: " + error.getMessage());
            return "";
        }
    }

    private void analyzeSelection() {
        String owner = selected(ownerIdentity);
        String attacker = selected(attackerIdentity);
        String baseline = selected(baselineEvidence);
        String exploit = selected(exploitEvidence);
        String control = selected(controlEvidence);
        if (owner.isBlank() || attacker.isBlank() || baseline.isBlank() || exploit.isBlank()) {
            logError("Select owner, attacker, baseline, and exploit evidence");
            return;
        }

        Thread.startVirtualThread(() -> {
            try {
                JsonObject request = new JsonObject();
                request.addProperty("ownerIdentityId", owner);
                request.addProperty("attackerIdentityId", attacker);
                request.addProperty("baselineEvidenceId", baseline);
                request.addProperty("exploitEvidenceId", exploit);
                if (!control.isBlank()) request.addProperty("negativeControlEvidenceId", control);
                JsonObject response = postJson("/analyze/authz", request);
                SwingUtilities.invokeLater(() -> candidateView.setText(gson.toJson(response.get("candidate"))));
                log("AuthZ analysis completed for " + owner + " -> " + attacker);
            } catch (Exception error) {
                logError("Analysis failed: " + error.getMessage());
            }
        });
    }

    private void refreshState() {
        Thread.startVirtualThread(() -> {
            try {
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(URI.create(BRIDGE_URL + "/state"))
                    .timeout(Duration.ofSeconds(10)).GET().build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IllegalStateException(response.body());
                JsonObject state = JsonParser.parseString(response.body()).getAsJsonObject();
                SwingUtilities.invokeLater(() -> {
                    state.getAsJsonArray("identities").forEach(item -> addIfMissing(ownerIdentity, item.getAsJsonObject().get("id").getAsString()));
                    state.getAsJsonArray("identities").forEach(item -> addIfMissing(attackerIdentity, item.getAsJsonObject().get("id").getAsString()));
                    state.getAsJsonArray("observations").forEach(item -> {
                        JsonArray ids = item.getAsJsonObject().getAsJsonArray("evidenceIds");
                        if (!ids.isEmpty()) refreshEvidenceCombos(ids.get(0).getAsString());
                    });
                });
                log("Bridge state refreshed");
            } catch (Exception error) {
                logError("State refresh failed: " + error.getMessage());
            }
        });
    }

    private JsonObject buildCapture(HttpRequestResponse message, String identityId, String role, String tenant, long durationMs) {
        String url = message.request().url();
        JsonObject identity = new JsonObject();
        identity.addProperty("id", identityId);
        identity.addProperty("role", role);
        if (tenant != null && !tenant.isBlank()) identity.addProperty("tenant", tenant);

        JsonObject observation = new JsonObject();
        observation.addProperty("identityId", identityId);
        observation.addProperty("method", message.request().method());
        observation.addProperty("url", url);
        observation.addProperty("status", statusOf(message));
        observation.addProperty("requestBody", encode(message.request().body()));
        observation.addProperty("responseBody", message.response() == null ? "" : message.response().bodyToString());
        observation.addProperty("durationMs", durationMs);

        JsonObject headers = new JsonObject();
        if (message.response() != null) message.response().headers().forEach(h -> headers.addProperty(h.name(), h.value()));
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

    private JsonObject postJson(String path, JsonObject body) throws Exception {
        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(URI.create(BRIDGE_URL + path))
            .timeout(Duration.ofSeconds(20))
            .header("content-type", "application/json")
            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(gson.toJson(body), StandardCharsets.UTF_8))
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " " + response.body());
        }
        return JsonParser.parseString(response.body()).getAsJsonObject();
    }

    private void refreshIdentityCombos() {
        SwingUtilities.invokeLater(() -> identities.keySet().forEach(id -> {
            addIfMissing(ownerIdentity, id);
            addIfMissing(attackerIdentity, id);
        }));
    }

    private void refreshEvidenceCombos(String id) {
        if (id == null || id.isBlank()) return;
        SwingUtilities.invokeLater(() -> {
            addIfMissing(baselineEvidence, id);
            addIfMissing(exploitEvidence, id);
            addIfMissing(controlEvidence, id);
        });
    }

    private void addIfMissing(JComboBox<String> combo, String value) {
        for (int i = 0; i < combo.getItemCount(); i++) if (value.equals(combo.getItemAt(i))) return;
        combo.addItem(value);
    }

    private static String selected(JComboBox<String> combo) {
        Object value = combo.getSelectedItem();
        return value == null ? "" : value.toString();
    }

    private static int statusOf(HttpRequestResponse message) {
        return message.response() == null ? 0 : message.response().statusCode();
    }

    private void log(String message) {
        api.logging().logToOutput(message);
        if (eventLog != null) SwingUtilities.invokeLater(() -> eventLog.append(message + "\n"));
    }

    private void logError(String message) {
        api.logging().logToError(message);
        if (eventLog != null) SwingUtilities.invokeLater(() -> eventLog.append("ERROR: " + message + "\n"));
    }

    private static String encode(ByteArray body) {
        if (body == null || body.length() == 0) return "";
        return Base64.getEncoder().encodeToString(body.getBytes());
    }
}

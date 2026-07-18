package io.t3mp3st.burp;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.Map;

final class IdentityProfile {
    private static final String[] SESSION_HEADERS = {
        "Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-CSRF-Token", "X-XSRF-Token"
    };

    final String id;
    final String role;
    final String tenant;
    final Map<String, String> headers;

    private IdentityProfile(String id, String role, String tenant, Map<String, String> headers) {
        this.id = id;
        this.role = role;
        this.tenant = tenant;
        this.headers = Map.copyOf(headers);
    }

    static IdentityProfile fromRequest(String id, String role, String tenant, HttpRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : SESSION_HEADERS) {
            String value = request.headerValue(name);
            if (value != null && !value.isBlank()) headers.put(name, value);
        }
        return new IdentityProfile(id, role, tenant, headers);
    }

    HttpRequest applyTo(HttpRequest request) {
        HttpRequest updated = request;
        for (String name : SESSION_HEADERS) updated = updated.withRemovedHeader(name);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            updated = updated.withHeader(header.getKey(), header.getValue());
        }
        return updated;
    }
}

package nexus;

import com.google.gson.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

final class Redactor {
    static final String MASK = "[REDACTED]";
    static final Pattern SECRET = Pattern.compile("password|passwd|token|secret|api[-_]?key|authorization|cookie|session|csrf|xsrf|private[-_]?key|credential|ssn|credit[-_]?card", Pattern.CASE_INSENSITIVE);
    private static final Pattern ASSIGN = Pattern.compile("(?i)((?:password|passwd|[\\w-]*token|[\\w-]*secret|api[_-]?key|session(?:_?id)?|csrf|xsrf|credential)\\s*[=:]\\s*)([^&\\s;<>]+)");
    private static final Pattern TOKEN = Pattern.compile("(?i)\\bBearer\\s+[^\\s\"'<>]+|\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*|\\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]+|sk-[A-Za-z0-9_-]{16,})");
    static String text(String value) {
        if (value == null || value.isEmpty()) return value;
        try {
            JsonElement json = JsonParser.parseString(value);
            if (json.isJsonObject() || json.isJsonArray()) return new Gson().toJson(json(json));
        } catch (JsonParseException ignored) {}
        return TOKEN.matcher(ASSIGN.matcher(value).replaceAll("$1" + java.util.regex.Matcher.quoteReplacement(MASK))).replaceAll(java.util.regex.Matcher.quoteReplacement(MASK));
    }
    static JsonElement json(JsonElement v) {
        if (v.isJsonObject()) {
            JsonObject out = new JsonObject();
            for (var e : v.getAsJsonObject().entrySet()) out.add(e.getKey(), SECRET.matcher(e.getKey()).find() ? new JsonPrimitive(MASK) : json(e.getValue()));
            return out;
        }
        if (v.isJsonArray()) { JsonArray a = new JsonArray(); for (var e : v.getAsJsonArray()) a.add(json(e)); return a; }
        if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) return new JsonPrimitive(text(v.getAsString()));
        return v;
    }
    static String url(String value) {
        if (value == null) return "";
        try {
            URI uri = URI.create(value);
            String raw = uri.getRawQuery();
            List<String> pairs = new ArrayList<>();
            if (raw != null) for (String pair : raw.split("&")) {
                String[] kv = pair.split("=", 2);
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String val = kv.length == 2 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
                val = SECRET.matcher(key).find() || key.equalsIgnoreCase("key") || key.equalsIgnoreCase("auth") ? MASK : text(val);
                pairs.add(kv[0] + "=" + URLEncoder.encode(val, StandardCharsets.UTF_8));
            }
            String authority = uri.getRawAuthority();
            if (authority != null) authority = authority.substring(authority.lastIndexOf('@') + 1);
            return (uri.getScheme() == null ? "" : uri.getScheme() + ":") + (authority == null ? "" : "//" + authority)
                + text(uri.getRawPath() == null ? "" : uri.getRawPath()) + (raw == null ? "" : "?" + String.join("&", pairs));
        } catch (IllegalArgumentException ex) { return text(value); }
    }
    static Map<String, String> headers(Map<String, String> headers) {
        Map<String, String> out = new LinkedHashMap<>();
        headers.forEach((k,v) -> out.put(k, SECRET.matcher(k).find() ? MASK : text(v)));
        return out;
    }
    static void item(NexusItem i) {
        i.url = url(i.url); i.path = url(i.path); i.comment = text(i.comment);
        String[] line = i.requestLine.split(" ", 3);
        if (line.length == 3) i.requestLine = line[0] + " " + url(line[1]) + " " + line[2];
        i.requestHeaders = headers(i.requestHeaders); i.responseHeaders = headers(i.responseHeaders);
        i.requestBody = text(i.requestBody); i.responseBody = text(i.responseBody);
        i.slug = NexusItem.makeSlug(i);
    }
}

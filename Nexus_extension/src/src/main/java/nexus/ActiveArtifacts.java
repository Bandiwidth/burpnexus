package nexus;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/** Offline, source-linked request mutations and review-only Nuclei templates. */
final class ActiveArtifacts {
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final Pattern IDS = Pattern.compile("(?i)^(id|uid|.*_id|userid|accountid|orderid|docid|fileid)$");
    record Point(String type, String name, String original, int index) {}
    static List<JsonObject> findings(Path dir) throws IOException {
        return JSON.fromJson(Files.readString(dir.resolve("security-findings.json")), new TypeToken<List<JsonObject>>() {}.getType());
    }
    static NexusItem source(JsonObject finding, NexusExport export) {
        JsonArray refs = finding.getAsJsonArray("items");
        if (refs != null && !refs.isEmpty()) for (NexusItem i : export.items) if (i.slug.equals(refs.get(0).getAsString())) return i;
        for (NexusItem i : export.items) if (i.host.equals(finding.get("host").getAsString()) && i.method.equals("GET")) return i;
        return null;
    }
    static List<String[]> query(String raw) {
        List<String[]> pairs = new ArrayList<>();
        if (raw != null && !raw.isEmpty()) for (String pair : raw.split("&")) {
            String[] kv = pair.split("=", 2);
            pairs.add(new String[]{URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : ""});
        }
        return pairs;
    }
    static String encode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
    static String join(List<String[]> pairs) { return String.join("&", pairs.stream().map(kv -> encode(kv[0]) + "=" + encode(kv[1])).toList()); }
    static List<Point> points(NexusItem item, JsonObject finding) {
        String category = finding.get("category").getAsString();
        URI uri = URI.create(item.url);
        List<Point> out = new ArrayList<>();
        String specific = "";
        Matcher named = Pattern.compile("(?i)param '([^']+)'").matcher(finding.get("title").getAsString() + " " + finding.get("detail").getAsString());
        if (named.find()) specific = named.group(1);
        for (String[] kv : query(uri.getRawQuery())) {
            if ((category.equals("IDOR") && IDS.matcher(kv[0]).matches()) || (!category.equals("IDOR") && (specific.isEmpty() || specific.equals(kv[0])))) out.add(new Point("query", kv[0], kv[1], 0));
        }
        if (category.equals("IDOR")) {
            String[] segments = uri.getRawPath().split("/", -1);
            for (int n = 0; n < segments.length; n++) if (segments[n].matches("[0-9]{1,10}")) out.add(new Point("path", "path[" + n + "]", segments[n], n));
            try {
                JsonObject body = JsonParser.parseString(item.requestBody).getAsJsonObject();
                for (var e : body.entrySet()) if (IDS.matcher(e.getKey()).matches() && e.getValue().isJsonPrimitive()) out.add(new Point("json", e.getKey(), e.getValue().getAsString(), 0));
            } catch (RuntimeException ignored) {
                if (item.requestHeaders.values().stream().anyMatch(v -> v.contains("application/x-www-form-urlencoded"))) {
                    for (String[] kv : query(item.requestBody)) if (IDS.matcher(kv[0]).matches()) out.add(new Point("form", kv[0], kv[1], 0));
                }
            }
        }
        return out;
    }
    static Map<String,Object> mutate(NexusItem item, Point point, String payload) {
        URI uri = URI.create(item.url);
        String path = uri.getRawPath(), rawQuery = uri.getRawQuery(), body = item.requestBody;
        if (point.type.equals("path")) {
            String[] parts = path.split("/", -1); parts[point.index] = encode(payload).replace("+", "%20"); path = String.join("/", parts);
        } else if (point.type.equals("query") || point.type.equals("form")) {
            List<String[]> pairs = query(point.type.equals("form") ? body : rawQuery);
            for (String[] kv : pairs) if (kv[0].equals(point.name)) { kv[1] = payload; break; }
            if (point.type.equals("form")) body = join(pairs); else rawQuery = join(pairs);
        } else if (point.type.equals("json")) {
            JsonObject data = JsonParser.parseString(body).getAsJsonObject();
            if (data.get(point.name).isJsonPrimitive() && data.get(point.name).getAsJsonPrimitive().isNumber() && payload.matches("-?\\d+")) data.addProperty(point.name, new java.math.BigInteger(payload));
            else data.addProperty(point.name, payload);
            body = JSON.toJson(data);
        }
        String url = uri.getScheme() + "://" + uri.getRawAuthority() + path + (rawQuery == null ? "" : "?" + rawQuery);
        Map<String,String> headers = new LinkedHashMap<>(item.requestHeaders);
        headers.keySet().removeIf(k -> k.equalsIgnoreCase("content-length") || k.equalsIgnoreCase("transfer-encoding") || k.startsWith(":"));
        return Map.of("method", item.method, "url", url, "headers", headers, "body", body);
    }
    static String quote(String s) { return "'" + s.replace("'", "'\"'\"'") + "'"; }
    @SuppressWarnings("unchecked")
    static String curl(Map<String,Object> req) {
        StringBuilder cmd = new StringBuilder("curl --silent --show-error --max-time 30 -X " + quote((String)req.get("method")));
        ((Map<String,String>)req.get("headers")).forEach((k,v) -> { if (!k.equalsIgnoreCase("host")) cmd.append(" -H ").append(quote(k + ": " + v)); });
        if (!((String)req.get("body")).isEmpty()) cmd.append(" --data-raw ").append(quote((String)req.get("body")));
        return cmd.append(" --url ").append(quote((String)req.get("url"))).toString();
    }
    static void fuzz(NexusExport export, Path dir) throws IOException {
        List<Map<String,Object>> cases = new ArrayList<>();
        StringBuilder commands = new StringBuilder("# Fuzz review commands\n\nOffline generated Bash commands. Review scope, identity and impact before execution.\n\n");
        int n = 0;
        for (JsonObject f : findings(dir)) {
            NexusItem item = source(f, export); if (item == null) continue;
            String category = f.get("category").getAsString();
            if (!Set.of("IDOR", "Reflected Input (XSS candidate)", "Open Redirect", "Information Disclosure").contains(category)) continue;
            for (Point point : points(item, f)) {
                Set<String> payloads = new LinkedHashSet<>(category.equals("IDOR") ? List.of("0", "1", "-1") : category.equals("Open Redirect") ? List.of("https://example.invalid/") : category.startsWith("Reflected") ? List.of("burpnexus-reflection-probe", "<script>alert(1)</script>") : List.of("'", "' OR 1=1--"));
                if (category.equals("IDOR") && point.original.matches("\\d{1,10}")) payloads.add(Long.toString(Long.parseLong(point.original) + 1));
                for (String payload : payloads) {
                    Map<String,Object> req = mutate(item, point, payload);
                    String id = "fuzz_" + n++;
                    cases.add(Map.of("id", id, "source_item", item.slug, "category", category, "injection_point", point.name, "payload", payload, "request", req));
                    commands.append("## ").append(id).append("\n\n```bash\n").append(curl(req)).append("\n```\n\n");
                }
            }
        }
        Files.writeString(dir.resolve("FUZZ_MANIFEST.json"), JSON.toJson(Map.of("summary", Map.of("total_cases", cases.size()), "fuzz_cases", cases)));
        Files.writeString(dir.resolve("FUZZ_COMMANDS.md"), commands);
    }
    static void nuclei(NexusExport export, Path dir) throws IOException {
        Path templates = dir.resolve("nuclei-templates"); Files.createDirectories(templates);
        List<String> names = new ArrayList<>(); int n = 0;
        for (JsonObject f : findings(dir)) {
            NexusItem item = source(f, export); if (item == null || !item.method.equals("GET")) continue;
            String category = f.get("category").getAsString();
            URI uri = URI.create(item.url);
            String target = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
            Map<String,Object> request = new LinkedHashMap<>(Map.of("method", "GET", "path", List.of("{{BaseURL}}" + target), "redirects", false));
            List<?> matchers;
            if (category.equals("IDOR")) {
                Point point = points(item, f).stream().filter(p -> !p.type.equals("json") && !p.type.equals("form") && p.original.matches("\\d{1,10}")).findFirst().orElse(null);
                if (point == null) continue;
                URI other = URI.create((String)mutate(item, point, Long.toString(Long.parseLong(point.original)+1)).get("url"));
                String changed = other.getRawPath() + (other.getRawQuery() == null ? "" : "?" + other.getRawQuery());
                request.clear(); request.put("raw", List.of("GET " + target + " HTTP/1.1\nHost: {{Hostname}}\n\n", "GET " + changed + " HTTP/1.1\nHost: {{Hostname}}\n\n"));
                request.put("req-condition", true); request.put("redirects", false);
                matchers = List.of(Map.of("type", "dsl", "dsl", List.of("status_code_1 == 200 && status_code_2 == 200 && body_1 != body_2")));
            } else if (category.startsWith("Reflected") || category.equals("Open Redirect")) {
                Point point = points(item, f).stream().filter(p -> p.type.equals("query")).findFirst().orElse(null); if (point == null) continue;
                boolean redirect = category.equals("Open Redirect"); String payload = redirect ? "https://example.invalid/" : "burpnexus-reflection-probe";
                URI changed = URI.create((String)mutate(item, point, payload).get("url"));
                request.put("path", List.of("{{BaseURL}}" + changed.getRawPath() + "?" + changed.getRawQuery()));
                matchers = redirect ? List.of(Map.of("type", "regex", "part", "header", "regex", List.of("(?im)^location:\\s*https://example\\.invalid/"))) : List.of(Map.of("type", "word", "part", "body", "words", List.of(payload)));
            } else if (category.equals("Security Headers")) {
                List<Map<String,Object>> checks = new ArrayList<>();
                for (String h : f.get("detail").getAsString().replace("Headers never observed: ", "").split(", ")) if (h.matches("[a-z-]+")) checks.add(Map.of("type", "word", "part", "header", "words", List.of(h + ":"), "negative", true, "case-insensitive", true));
                if (checks.isEmpty()) continue; matchers = checks; request.put("matchers-condition", "or");
            } else if (category.equals("Information Disclosure")) {
                matchers = List.of(Map.of("type", "regex", "part", "body", "regex", List.of("(?i)(SQL syntax|Traceback \\(most recent call last\\)|stack\\s*trace|Unhandled Exception)")));
            } else if (category.equals("Sensitive Data Exposure")) {
                matchers = List.of(Map.of("type", "regex", "part", "body", "regex", List.of("gh[pousr]_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")));
            } else if (category.equals("CORS Misconfiguration")) {
                request.put("headers", Map.of("Origin", "https://example.invalid")); request.put("matchers-condition", "and");
                matchers = List.of(Map.of("type", "regex", "part", "header", "regex", List.of("(?im)^access-control-allow-origin:\\s*https://example\\.invalid\\s*$")), Map.of("type", "regex", "part", "header", "regex", List.of("(?im)^access-control-allow-credentials:\\s*true\\s*$")));
            } else if (category.equals("Cookie Security")) {
                matchers = List.of(Map.of("type", "dsl", "dsl", List.of("contains(tolower(all_headers), 'set-cookie:') && (!contains(tolower(all_headers), 'httponly') || !contains(tolower(all_headers), 'secure'))")));
            } else continue;
            request.put("matchers", matchers);
            String id = String.format("burpnexus-review-%04d", n++);
            Map<String,Object> info = Map.of("name", f.get("title").getAsString() + " (review candidate)", "author", "BurpNexus", "severity", "info", "description", "Candidate only. Validate ownership, reflection context and impact manually.", "metadata", Map.of("source-item", item.slug, "source-host", item.host));
            Files.writeString(templates.resolve(id + ".yaml"), JSON.toJson(Map.of("id", id, "info", info, "http", List.of(request))));
            names.add(id + ".yaml");
        }
        Files.writeString(dir.resolve("NUCLEI_TEMPLATES.md"), "# Nuclei review templates\n\nGET probes only; no captured credentials copied. Candidates require manual validation, especially ownership and XSS execution. Unsupported methods/categories are omitted.\n\nValidate with `nuclei -validate -t nuclei-templates/`.\n\n" + String.join("\n", names));
    }
}

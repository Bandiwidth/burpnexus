package nexus;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Writes a {@link NexusExport} to disk as JSON + optional Markdown,
 * with README indexes and attack-surface-index.json.
 * <p>
 * Supports all 6 output modes: FLAT, SITEMAP, BY_HOST, HOST_FIRST,
 * SPLIT_BY_SESSION, BY_TIME.
 */
final class WriterEngine {

    private final Path outputDir;
    private final ExportConfig cfg;
    private final MdFormatter mdFormatter;

    private int writtenJson;
    private int writtenMd;
    private int skipped;

    interface ProgressCallback {
        void onProgress(int current, int total);
    }

    private ProgressCallback progressCallback;

    WriterEngine(Path outputDir, ExportConfig cfg) {
        this.outputDir   = outputDir;
        this.cfg         = cfg;
        this.mdFormatter = new MdFormatter();
    }

    void setProgressCallback(ProgressCallback cb) {
        this.progressCallback = cb;
    }

    int getWrittenJson() { return writtenJson; }
    int getWrittenMd()   { return writtenMd; }
    int getSkipped()     { return skipped; }

    // ---- main entry point ----------------------------------------------

    void write(NexusExport export) throws IOException {
        Files.createDirectories(outputDir);
        writtenJson = 0;
        writtenMd   = 0;
        skipped     = 0;

        int total = export.items.size();
        for (int i = 0; i < total; i++) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("Export cancelled");
            writeItem(export.items.get(i));
            if (progressCallback != null) progressCallback.onProgress(i + 1, total);
        }

        if (cfg.outputMode != ExportConfig.OutputMode.SITEMAP
                && cfg.outputMode != ExportConfig.OutputMode.BY_TIME) {
            for (String tool : export.tools()) {
                writeToolIndex(tool, export.itemsByTool(tool));
            }
        }

        writeRootReadme(export);
        writeAttackSurfaceIndex(export);
    }

    // ---- per-item writing ----------------------------------------------

    private void writeItem(NexusItem item) throws IOException {
        Path dir = itemDir(item);
        String slug = item.slug != null && !item.slug.isEmpty()
            ? item.slug : String.format("%04d_item", item.index);

        if (cfg.includeJson) {
            Path jsonPath = SafePaths.within(outputDir, dir.resolve(slug + ".json"));
            try {
                writeText(jsonPath, item.toJson());
                writtenJson++;
            } catch (Exception e) {
                skipped++;
                throw new IOException("Failed to write item " + item.index, e);
            }
        }

        if (cfg.includeMd) {
            Path mdPath = SafePaths.within(outputDir, dir.resolve(slug + ".md"));
            try {
                writeText(mdPath, mdFormatter.render(item));
                writtenMd++;
            } catch (Exception e) {
                skipped++;
                throw new IOException("Failed to write item " + item.index, e);
            }
        }
    }

    // ---- directory resolution for 6 modes ------------------------------

    private Path itemDir(NexusItem item) {
        switch (cfg.outputMode) {
            case BY_TIME: {
                if (item.timeParsed == null) return outputDir.resolve("unknown_datetime");
                String date = item.timeParsed.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                String hour = item.timeParsed.format(java.time.format.DateTimeFormatter.ofPattern("HH"));
                String min  = item.timeParsed.format(java.time.format.DateTimeFormatter.ofPattern("mm"));
                Path base = outputDir.resolve(date).resolve(hour).resolve(min);
                if (cfg.timeIncludeHost) {
                    return base.resolve(sanitise(item.host));
                }
                return base;
            }
            case SITEMAP: {
                Path hostDir = outputDir.resolve(sanitise(item.host));
                List<String> segments = urlToPathSegments(item.url, item.path);
                Path target = hostDir;
                for (String seg : segments) target = target.resolve(seg);
                return target;
            }
            case BY_HOST: {
                Path toolDir = outputDir.resolve(sanitise(item.tool));
                if (item.host != null && !item.host.isEmpty()) {
                    return toolDir.resolve(sanitise(item.host));
                }
                return toolDir;
            }
            case HOST_FIRST: {
                Path hostDir = outputDir.resolve(sanitise(item.host));
                return hostDir.resolve(sanitise(item.tool));
            }
            case SPLIT_BY_SESSION: {
                String tag = item.sessionTag != null && !item.sessionTag.isEmpty()
                    ? item.sessionTag : "session_anon";
                return outputDir.resolve(sanitise(tag)).resolve(sanitise(item.tool));
            }
            case FLAT:
            default:
                return outputDir.resolve(sanitise(item.tool));
        }
    }

    // ---- root README ---------------------------------------------------

    private void writeRootReadme(NexusExport export) throws IOException {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("# BurpNexus \u2014 Export Analysis\n\n");
        sb.append("> This repository was generated by **BurpNexus** from Burp Suite traffic.\n");
        sb.append("> Feed this data to **VS Code Copilot** or any AI assistant for security analysis.\n\n");
        sb.append("---\n\n");

        sb.append("## Export Information\n\n");
        sb.append("| Field | Value |\n");
        sb.append("| ----- | ----- |\n");
        sb.append("| Total Items    | `").append(export.items.size()).append("` |\n");
        sb.append("| Unique Hosts   | `").append(export.hosts().size()).append("` |\n");
        sb.append("| Tools Present  | `").append(String.join(", ", export.tools())).append("` |\n");
        sb.append("| Export Time    | `").append(export.exportTime).append("` |\n");
        sb.append("| JSON files     | `").append(writtenJson).append("` |\n");
        sb.append("| Markdown files | `").append(writtenMd).append("` |\n");
        sb.append('\n');

        String mode = cfg.outputMode.name();

        // mode-specific info
        if (cfg.outputMode == ExportConfig.OutputMode.SITEMAP) {
            sb.append("## Site Map Tree Structure\n\n");
            sb.append("The output mirrors Burp Suite's Site Map hierarchy:\n\n");
            sb.append("```\n");
            sb.append(outputDir.getFileName()).append("/\n");
            Map<String, Map<String, Object>> tree = new TreeMap<>();
            for (NexusItem item : export.items) {
                String host = sanitise(item.host);
                List<String> segs = urlToPathSegments(item.url, item.path);
                @SuppressWarnings("unchecked")
                Map<String, Object> node = tree.computeIfAbsent(host, k -> new TreeMap<>());
                for (String seg : segs) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> child = (Map<String, Object>) node.computeIfAbsent(seg, k -> new TreeMap<>());
                    node = child;
                }
            }
            for (Map.Entry<String, Map<String, Object>> e : tree.entrySet()) {
                sb.append("\u251c\u2500\u2500 ").append(e.getKey()).append("/\n");
                renderTree(e.getValue(), sb, "\u2502   ");
            }
            sb.append("```\n\n");
        } else if (cfg.outputMode == ExportConfig.OutputMode.BY_TIME) {
            sb.append("## Time-Based Output\n\n");
            sb.append("Output organized by request time: **date \u2192 hour \u2192 minute**.\n\n");
        } else {
            sb.append("## Tool Breakdown\n\n");
            sb.append("| Tool | Items | Unique Hosts | Methods |\n");
            sb.append("| ---- | ----- | ------------ | ------- |\n");
            Map<String, Set<String>> toolHosts = new LinkedHashMap<>();
            Map<String, Set<String>> toolMethods = new LinkedHashMap<>();
            Map<String, Integer> toolCounts = new LinkedHashMap<>();
            for (NexusItem item : export.items) {
                toolCounts.merge(item.tool, 1, Integer::sum);
                toolHosts.computeIfAbsent(item.tool, k -> new TreeSet<>()).add(item.host);
                toolMethods.computeIfAbsent(item.tool, k -> new TreeSet<>()).add(item.method);
            }
            for (String tool : new TreeSet<>(toolCounts.keySet())) {
                sb.append("| ").append(tool);
                sb.append(" | `").append(toolCounts.get(tool)).append('`');
                sb.append(" | `").append(toolHosts.getOrDefault(tool, Set.of()).size()).append('`');
                sb.append(" | `").append(String.join(", ", toolMethods.getOrDefault(tool, Set.of()))).append('`');
                sb.append(" |\n");
            }
            sb.append('\n');
        }

        sb.append("---\n\n");
        sb.append("## Host Summary\n\n");
        sb.append("| Host | Items | Tools |\n");
        sb.append("| ---- | ----- | ----- |\n");
        Map<String, Integer> hostCounts = new LinkedHashMap<>();
        Map<String, Set<String>> hostTools = new LinkedHashMap<>();
        for (NexusItem item : export.items) {
            String h = item.host != null && !item.host.isEmpty() ? item.host : "unknown";
            hostCounts.merge(h, 1, Integer::sum);
            hostTools.computeIfAbsent(h, k -> new TreeSet<>()).add(item.tool);
        }
        for (String host : new TreeSet<>(hostCounts.keySet())) {
            sb.append("| `").append(host).append("` | `").append(hostCounts.get(host));
            sb.append("` | `").append(String.join(", ", hostTools.getOrDefault(host, Set.of()))).append("` |\n");
        }
        sb.append("\n---\n\n");

        sb.append("## AI Analysis Tips\n\n");
        sb.append("Use the following VS Code Copilot prompts to analyse this export:\n\n");
        sb.append("```\n");
        sb.append("@workspace Analyse all HTTP requests for SQL injection vulnerabilities.\n");
        sb.append("@workspace Find all endpoints that accept user input and check for XSS vectors.\n");
        sb.append("@workspace Summarise all unique API endpoints discovered in this export.\n");
        sb.append("@workspace Identify authentication mechanisms used across all captured requests.\n");
        sb.append("@workspace List all cookies and security headers present in the responses.\n");
        sb.append("@workspace Find requests with sensitive data like passwords, tokens, or PII.\n");
        sb.append("```\n\n");
        sb.append("---\n");
        sb.append("*Generated by **BurpNexus** v1.0.0*\n");

        writeText(outputDir.resolve("README.md"), sb.toString());
    }

    // ---- attack-surface-index.json -------------------------------------

    private void writeAttackSurfaceIndex(NexusExport export) throws IOException {
        Map<String, Integer> endpoints = new LinkedHashMap<>();
        Map<String, Integer> methods   = new LinkedHashMap<>();
        Map<String, Integer> statuses  = new LinkedHashMap<>();
        Map<String, Integer> sessions  = new LinkedHashMap<>();
        Set<String> authHeaders    = new TreeSet<>();
        Set<String> secHeaders     = new TreeSet<>();
        Set<String> sensitiveParams = new TreeSet<>();

        for (NexusItem item : export.items) {
            String ep = (item.method != null ? item.method.toUpperCase() : "UNKNOWN") + " " + (item.path != null ? item.path : "/");
            endpoints.merge(ep, 1, Integer::sum);
            methods.merge(item.method != null ? item.method.toUpperCase() : "UNKNOWN", 1, Integer::sum);
            statuses.merge(item.status != null && !item.status.isEmpty() ? item.status : "unknown", 1, Integer::sum);
            sessions.merge(item.sessionTag != null && !item.sessionTag.isEmpty() ? item.sessionTag : "session_anon", 1, Integer::sum);

            for (String k : item.requestHeaders.keySet()) {
                String kl = k.toLowerCase(Locale.ROOT);
                if ("authorization".equals(kl) || "cookie".equals(kl)
                        || "x-api-key".equals(kl) || "x-auth-token".equals(kl)) {
                    authHeaders.add(k);
                }
            }
            for (String k : item.responseHeaders.keySet()) {
                String kl = k.toLowerCase(Locale.ROOT);
                if (kl.startsWith("x-") || "content-security-policy".equals(kl)
                        || "strict-transport-security".equals(kl)) {
                    secHeaders.add(k);
                }
            }

            try {
                String query = item.url != null && item.url.contains("?")
                    ? item.url.substring(item.url.indexOf('?') + 1) : "";
                for (String part : query.split("&")) {
                    int eq = part.indexOf('=');
                    if (eq > 0) {
                        String p = part.substring(0, eq).toLowerCase(Locale.ROOT);
                        if (Set.of("token","auth","session","password","api_key","apikey").contains(p)) {
                            sensitiveParams.add(part.substring(0, eq));
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        // Sort endpoints by count desc, take top 200
        List<Map.Entry<String, Integer>> sortedEndpoints = new ArrayList<>(endpoints.entrySet());
        sortedEndpoints.sort((a, b) -> b.getValue() - a.getValue());
        if (sortedEndpoints.size() > 200) sortedEndpoints = sortedEndpoints.subList(0, 200);

        JsonBuilder jb = new JsonBuilder(8192);
        jb.objectStart();

        jb.key("summary").objectStart();
        jb.field("total_items", export.items.size());
        jb.field("unique_hosts", export.hosts().size());
        jb.field("unique_tools", export.tools().size());
        jb.field("unique_endpoints", endpoints.size());
        jb.field("unique_sessions", sessions.size());
        jb.objectEnd();

        jb.key("top_endpoints").arrayStart();
        for (Map.Entry<String, Integer> e : sortedEndpoints) {
            jb.objectStart();
            jb.field("endpoint", e.getKey());
            jb.field("count", e.getValue());
            jb.objectEnd();
        }
        jb.arrayEnd();

        jb.key("methods").objectStart();
        for (Map.Entry<String, Integer> e : methods.entrySet()) jb.field(e.getKey(), e.getValue());
        jb.objectEnd();

        jb.key("statuses").objectStart();
        for (Map.Entry<String, Integer> e : statuses.entrySet()) jb.field(e.getKey(), e.getValue());
        jb.objectEnd();

        jb.key("auth_headers_observed").arrayStart();
        for (String h : authHeaders) jb.arrayValue(h);
        jb.arrayEnd();

        jb.key("security_headers_observed").arrayStart();
        for (String h : secHeaders) jb.arrayValue(h);
        jb.arrayEnd();

        jb.key("sensitive_query_params_observed").arrayStart();
        for (String p : sensitiveParams) jb.arrayValue(p);
        jb.arrayEnd();

        jb.key("session_buckets").objectStart();
        for (Map.Entry<String, Integer> e : sessions.entrySet()) jb.field(e.getKey(), e.getValue());
        jb.objectEnd();

        jb.objectEnd();

        writeText(outputDir.resolve("attack-surface-index.json"), jb.toPrettyString());
    }

    // ---- per-tool README -----------------------------------------------

    private void writeToolIndex(String tool, List<NexusItem> items) throws IOException {
        if (items.isEmpty()) return;
        Path toolDir = outputDir.resolve(sanitise(tool));
        StringBuilder sb = new StringBuilder(2048);
        sb.append("# ").append(tool.toUpperCase()).append(" \u2014 Request/Response Index\n\n");
        sb.append("> **").append(items.size()).append("** items captured from the **").append(tool).append("** tool.\n\n");
        sb.append("| # | Method | Path | Status | MIME | Host | File |\n");
        sb.append("| - | ------ | ---- | ------ | ---- | ---- | ---- |\n");
        for (NexusItem item : items) {
            String slug = item.slug != null ? item.slug : String.format("%04d_item", item.index);
            String path = item.path != null ? item.path : "/";
            if (path.length() > 60) path = path.substring(0, 60);
            sb.append("| ").append(item.index);
            sb.append(" | `").append(item.method != null ? item.method : "?").append('`');
            sb.append(" | `").append(path).append('`');
            sb.append(" | `").append(item.status != null ? item.status : "?").append('`');
            sb.append(" | `").append(item.mimeType != null ? item.mimeType : "?").append('`');
            sb.append(" | `").append(item.host != null ? item.host : "?").append('`');
            String ext = cfg.includeJson ? ".json" : ".md";
            String relative = toolDir.relativize(itemDir(item).resolve(slug + ext)).toString().replace('\\', '/');
            sb.append(" | [").append(slug).append(ext).append("](").append(relative).append(")");
            sb.append(" |\n");
        }
        sb.append("\n---\n*Generated by **BurpNexus***\n");
        try {
            writeText(toolDir.resolve("README.md"), sb.toString());
        } catch (Exception ex) { throw new IOException("Failed to write tool index", ex); }
    }

    // ---- helpers -------------------------------------------------------

    private static final Pattern UNSAFE_DIR = Pattern.compile("[^\\w\\-.]");
    private static final Pattern MULTI_UNDER = Pattern.compile("_+");

    private static String sanitise(String name) {
        if (name == null || name.isBlank()) return "unknown";
        String s = name.strip().toLowerCase(Locale.ROOT);
        s = UNSAFE_DIR.matcher(s).replaceAll("_");
        s = MULTI_UNDER.matcher(s).replaceAll("_");
        if (s.startsWith("_") || s.startsWith(".")) s = s.substring(1);
        if (s.endsWith("_") || s.endsWith(".")) s = s.substring(0, s.length() - 1);
        return SafePaths.segment(s);
    }

    static List<String> urlToPathSegments(String url, String pathField) {
        String rawPath = pathField != null && !pathField.isEmpty() ? pathField : "";
        if (rawPath.isEmpty() && url != null) {
            try {
                java.net.URI uri = new java.net.URI(url);
                rawPath = uri.getPath();
            } catch (Exception ignored) {}
        }
        if (rawPath == null || rawPath.isEmpty()) rawPath = "/";
        rawPath = rawPath.split("\\?")[0].split("#")[0];

        String[] parts = rawPath.split("/");
        List<String> segments = new ArrayList<>();
        for (String p : parts) {
            String t = p.trim();
            if (t.isEmpty()) continue;
            try { t = URLDecoder.decode(t, StandardCharsets.UTF_8); } catch (Exception ignored) {}
            t = UNSAFE_DIR.matcher(t).replaceAll("_");
            t = MULTI_UNDER.matcher(t).replaceAll("_");
            if (t.startsWith("_")) t = t.substring(1);
            if (t.endsWith("_")) t = t.substring(0, t.length() - 1);
            if (!t.isEmpty()) segments.add(SafePaths.segment(t));
        }
        if (segments.isEmpty()) segments.add("root");
        return segments;
    }

    @SuppressWarnings("unchecked")
    private void renderTree(Map<String, Object> node, StringBuilder sb, String prefix) {
        List<String> keys = new ArrayList<>(((Map<String, ?>) node).keySet());
        Collections.sort(keys);
        for (int i = 0; i < keys.size(); i++) {
            boolean last = (i == keys.size() - 1);
            String connector = last ? "\u2514\u2500\u2500 " : "\u251c\u2500\u2500 ";
            sb.append(prefix).append(connector).append(keys.get(i)).append("/\n");
            String childPrefix = prefix + (last ? "    " : "\u2502   ");
            Object child = ((Map<String, Object>) node).get(keys.get(i));
            if (child instanceof Map && !((Map<?, ?>) child).isEmpty()) {
                renderTree((Map<String, Object>) child, sb, childPrefix);
            }
        }
    }

    private static void writeText(Path path, String content) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }
}

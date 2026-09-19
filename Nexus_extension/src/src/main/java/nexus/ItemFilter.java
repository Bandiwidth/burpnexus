package nexus;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Filtering, deduplication, secret redaction, session tagging,
 * parameter search, and regex content search.
 * <p>
 * Ports every filtering feature from the Python CLI's {@code __main__.py}
 * plus two new features unique to BurpNexus: parameter search and regex search.
 */
final class ItemFilter {

    private ItemFilter() {}

    // ====================================================================
    // 1. Tool filter
    // ====================================================================

    static List<NexusItem> filterByTool(List<NexusItem> items, String onlyTools) {
        if (onlyTools == null || onlyTools.isBlank()) return items;
        Set<String> allowed = parseCsv(onlyTools);
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            if (allowed.contains((item.tool != null ? item.tool : "").toLowerCase(Locale.ROOT))) {
                result.add(item);
            }
        }
        return result;
    }

    // ====================================================================
    // 2. Status filter (supports exact codes and classes like 4xx, 5xx)
    // ====================================================================

    static List<NexusItem> filterByStatus(List<NexusItem> items, String onlyStatus) {
        if (onlyStatus == null || onlyStatus.isBlank()) return items;
        Set<String> filters = parseCsv(onlyStatus);
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            if (statusMatches(item.status, filters)) result.add(item);
        }
        return result;
    }

    private static boolean statusMatches(String status, Set<String> filters) {
        if (filters.isEmpty()) return true;
        String s = status != null ? status.strip() : "";
        if (s.isEmpty()) return false;
        if (filters.contains(s)) return true;
        if (!s.isEmpty() && Character.isDigit(s.charAt(0))) {
            String family = s.charAt(0) + "xx";
            return filters.contains(family);
        }
        return false;
    }

    // ====================================================================
    // 3. SHA-256 deduplication
    // ====================================================================

    static List<NexusItem> deduplicate(List<NexusItem> items) {
        Set<String> seen = new HashSet<>();
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            String key = item.url + "|" + item.sha256 + "|" + NexusItem.sha256Hex(item.reconstructResponseRaw());
            if (key.isEmpty() || !seen.contains(key)) {
                if (!key.isEmpty()) seen.add(key);
                result.add(item);
            }
        }
        return result;
    }

    // ====================================================================
    // 4. Re-index items after filtering (contiguous indices + new slugs)
    // ====================================================================

    static void reindex(List<NexusItem> items) {
        for (int i = 0; i < items.size(); i++) {
            NexusItem item = items.get(i);
            item.index = i + 1;
            item.slug  = NexusItem.makeSlug(item);
        }
    }

    // ====================================================================
    // 5. Session tag derivation
    // ====================================================================

    static void applySessionTags(List<NexusItem> items, boolean forSessionSplit) {
        for (NexusItem item : items) {
            item.sessionTag = deriveSessionTag(item);
        }
        if (forSessionSplit) {
            for (NexusItem item : items) {
                if (item.sessionTag == null || item.sessionTag.isEmpty()) {
                    item.sessionTag = "session_anon";
                }
            }
        }
    }

    private static String deriveSessionTag(NexusItem item) {
        List<String> sources = new ArrayList<>();
        for (Map.Entry<String, String> e : item.requestHeaders.entrySet()) {
            String kLow = e.getKey().toLowerCase(Locale.ROOT);
            if ("authorization".equals(kLow) || "cookie".equals(kLow)
                    || "x-api-key".equals(kLow) || "x-auth-token".equals(kLow)) {
                sources.add(kLow + ":" + (e.getValue() != null ? e.getValue() : ""));
            }
        }
        if (sources.isEmpty()) {
            try {
                String query = queryFromUrl(item.url);
                for (String[] kv : parseQueryString(query)) {
                    String kLow = kv[0].toLowerCase(Locale.ROOT);
                    if ("token".equals(kLow) || "auth".equals(kLow)
                            || "apikey".equals(kLow) || "api_key".equals(kLow)
                            || "session".equals(kLow)) {
                        sources.add(kv[0] + ":" + kv[1]);
                    }
                }
            } catch (Exception ignored) {}
        }
        if (sources.isEmpty()) return "session_anon";
        String joined = String.join("|", new java.util.TreeSet<>(sources));
        return "session_" + NexusItem.sha256Hex(joined).substring(0, 8);
    }

    // ====================================================================
    // 6. Secret redaction
    // ====================================================================

    static void redactSecrets(List<NexusItem> items) {
        for (NexusItem item : items) {
            Redactor.item(item);
            item.sha256 = NexusItem.sha256Hex(item.reconstructRequestRaw());
        }
    }

    // ====================================================================
    // 7. Parameter search (NEW — beyond CLI)
    // ====================================================================

    static List<NexusItem> filterByParameter(List<NexusItem> items,
                                              String name, String value,
                                              boolean exactMatch) {
        if ((name == null || name.isEmpty()) && (value == null || value.isEmpty())) {
            return items;
        }
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            if (itemMatchesParam(item, name, value, exactMatch)) {
                result.add(item);
            }
        }
        return result;
    }

    private static boolean itemMatchesParam(NexusItem item, String name,
                                             String value, boolean exact) {
        // 1. Query parameters
        try {
            String query = queryFromUrl(item.url);
            for (String[] kv : parseQueryString(query)) {
                if (paramMatch(kv[0], kv[1], name, value, exact)) return true;
            }
        } catch (Exception ignored) {}

        // 2. POST body (form-encoded)
        if (item.requestBody != null && !item.requestBody.isEmpty()) {
            String ct = headerValue(item.requestHeaders, "content-type");
            if (ct.contains("form") || (item.requestBody.contains("=")
                    && !item.requestBody.trim().startsWith("{"))) {
                for (String[] kv : parseQueryString(item.requestBody)) {
                    if (paramMatch(kv[0], kv[1], name, value, exact)) return true;
                }
            }
        }

        // 3. JSON body fields (recursive)
        if (item.requestBody != null && !item.requestBody.isEmpty()) {
            String trimmed = item.requestBody.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                if (jsonContainsParam(trimmed, name, value, exact)) return true;
            }
        }

        // 4. Cookies
        String cookieVal = headerValue(item.requestHeaders, "cookie");
        if (!cookieVal.isEmpty()) {
            for (String part : cookieVal.split(";")) {
                int eq = part.indexOf('=');
                if (eq > 0) {
                    String cn = part.substring(0, eq).trim();
                    String cv = part.substring(eq + 1).trim();
                    if (paramMatch(cn, cv, name, value, exact)) return true;
                }
            }
        }

        // 5. Custom headers
        Set<String> standard = Set.of("host", "user-agent", "accept",
            "accept-language", "accept-encoding", "connection", "content-type",
            "content-length", "cache-control", "pragma",
            "upgrade-insecure-requests", "referer", "origin");
        for (Map.Entry<String, String> e : item.requestHeaders.entrySet()) {
            if (!standard.contains(e.getKey().toLowerCase(Locale.ROOT))) {
                if (paramMatch(e.getKey(), e.getValue(), name, value, exact)) return true;
            }
        }

        // 6. URL path segments
        if ((name == null || name.isEmpty()) && item.path != null && !item.path.isEmpty()) {
            for (String seg : item.path.split("/")) {
                if (!seg.isEmpty() && valueMatch(seg, value, exact)) return true;
            }
        }

        return false;
    }

    private static boolean paramMatch(String paramName, String paramValue,
                                       String searchName, String searchValue,
                                       boolean exact) {
        boolean nameOk  = searchName == null || searchName.isEmpty()
            || matchString(paramName, searchName, exact);
        boolean valueOk = searchValue == null || searchValue.isEmpty()
            || matchString(paramValue, searchValue, exact);
        return nameOk && valueOk;
    }

    private static boolean valueMatch(String actual, String search, boolean exact) {
        if (search == null || search.isEmpty()) return false;
        return matchString(actual, search, exact);
    }

    private static boolean matchString(String hay, String needle, boolean exact) {
        if (hay == null || needle == null) return false;
        if (exact) return hay.equalsIgnoreCase(needle);
        return hay.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    private static boolean jsonContainsParam(String json, String name, String value, boolean exact) {
        try { return jsonParam(com.google.gson.JsonParser.parseString(json), name, value, exact); }
        catch (com.google.gson.JsonParseException | IllegalStateException ex) { return false; }
    }

    private static boolean jsonParam(com.google.gson.JsonElement element, String name, String value, boolean exact) {
        if (element.isJsonObject()) for (var entry : element.getAsJsonObject().entrySet()) {
            var child = entry.getValue();
            if (child.isJsonPrimitive() || child.isJsonNull()) {
                String text = child.isJsonNull() ? "null" : child.getAsString();
                if (paramMatch(entry.getKey(), text, name, value, exact)) return true;
            } else if (jsonParam(child, name, value, exact)) return true;
        }
        if (element.isJsonArray()) for (var child : element.getAsJsonArray()) if (jsonParam(child, name, value, exact)) return true;
        return false;
    }

    // ====================================================================
    // 8. Regex content search (NEW — beyond CLI)
    // ====================================================================

    static List<NexusItem> filterByRegex(List<NexusItem> items,
                                          String pattern,
                                          ExportConfig.RegexTarget target) {
        if (pattern == null || pattern.isEmpty()) return items;
        Pattern compiled;
        try {
            compiled = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid regex pattern", e);
        }

        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            boolean found = false;
            if (target == ExportConfig.RegexTarget.BOTH
                    || target == ExportConfig.RegexTarget.REQUEST) {
                if (searchableText(item.requestLine, compiled)) found = true;
                if (!found && searchHeaders(item.requestHeaders, compiled)) found = true;
                if (!found && searchableText(item.requestBody, compiled)) found = true;
            }
            if (!found && (target == ExportConfig.RegexTarget.BOTH
                    || target == ExportConfig.RegexTarget.RESPONSE)) {
                if (searchableText(item.responseStatusLine, compiled)) found = true;
                if (!found && searchHeaders(item.responseHeaders, compiled)) found = true;
                if (!found && searchableText(item.responseBody, compiled)) found = true;
            }
            if (found) result.add(item);
        }
        return result;
    }

    private static boolean searchableText(String text, Pattern compiled) {
        return text != null && !text.isEmpty() && compiled.matcher(text).find();
    }

    private static boolean searchHeaders(Map<String, String> headers, Pattern compiled) {
        if (headers == null) return false;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String line = e.getKey() + ": " + e.getValue();
            if (compiled.matcher(line).find()) return true;
        }
        return false;
    }

    // ====================================================================
    // 9. Time range filter
    // ====================================================================

    static List<NexusItem> filterByTimeRange(List<NexusItem> items,
                                              String fromTime, String toTime) {
        if ((fromTime == null || fromTime.isBlank())
                && (toTime == null || toTime.isBlank())) {
            return items;
        }
        java.time.ZonedDateTime from = parseFlexibleTime(fromTime);
        java.time.ZonedDateTime to   = parseFlexibleTime(toTime);
        if (to != null && toTime.strip().matches("\\d{4}-\\d{2}-\\d{2}")) to = to.plusDays(1).minusNanos(1);
        if (from != null && to != null && from.isAfter(to)) throw new IllegalArgumentException("From time must precede To time");
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            if (item.timeParsed == null) {
                result.add(item); // keep items without timestamp
                continue;
            }
            if (from != null && item.timeParsed.isBefore(from)) continue;
            if (to != null && item.timeParsed.isAfter(to)) continue;
            result.add(item);
        }
        return result;
    }

    private static java.time.ZonedDateTime parseFlexibleTime(String input) {
        if (input == null || input.isBlank()) return null;
        String s = input.strip();
        try {
            return java.time.ZonedDateTime.parse(s);
        } catch (Exception ignored) {}
        try {
            java.time.LocalDateTime ldt = java.time.LocalDateTime.parse(
                s, java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm[:ss]"));
            return ldt.atZone(java.time.ZoneId.systemDefault());
        } catch (Exception ignored) {}
        try {
            java.time.LocalDate ld = java.time.LocalDate.parse(s);
            return ld.atStartOfDay(java.time.ZoneId.systemDefault());
        } catch (Exception ignored) {}
        throw new IllegalArgumentException("Invalid time: " + input);
    }

    // ====================================================================
    // Composite: apply all configured filters
    // ====================================================================

    static List<NexusItem> applyAll(List<NexusItem> items, ExportConfig cfg) {
        List<NexusItem> result = new ArrayList<>(items);

        result = filterByTool(result, cfg.onlyTools);
        result = filterByStatus(result, cfg.onlyStatus);
        if (cfg.dedupe) result = deduplicate(result);
        result = filterByTimeRange(result, cfg.fromTime, cfg.toTime);

        if (cfg.hasParamSearch()) {
            result = filterByParameter(result,
                cfg.paramSearchName, cfg.paramSearchValue, cfg.paramSearchExact);
        }
        if (cfg.hasRegexSearch()) {
            result = filterByRegex(result, cfg.regexPattern, cfg.regexTarget);
        }

        reindex(result);
        applySessionTags(result,
            cfg.outputMode == ExportConfig.OutputMode.SPLIT_BY_SESSION);

        if (cfg.redactSecrets) {
            redactSecrets(result);
        }

        return result;
    }

    // ====================================================================
    // Shared helpers
    // ====================================================================

    private static Set<String> parseCsv(String csv) {
        Set<String> set = new HashSet<>();
        if (csv == null) return set;
        for (String s : csv.split(",")) {
            String v = s.strip().toLowerCase(Locale.ROOT);
            if (!v.isEmpty()) set.add(v);
        }
        return set;
    }

    private static String queryFromUrl(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        if (q < 0) return "";
        int f = url.indexOf('#', q);
        return f > q ? url.substring(q + 1, f) : url.substring(q + 1);
    }

    private static List<String[]> parseQueryString(String query) {
        List<String[]> pairs = new ArrayList<>();
        if (query == null || query.isEmpty()) return pairs;
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq > 0) {
                String k = urlDecode(part.substring(0, eq));
                String v = urlDecode(part.substring(eq + 1));
                pairs.add(new String[]{k, v});
            } else if (!part.isEmpty()) {
                pairs.add(new String[]{urlDecode(part), ""});
            }
        }
        return pairs;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    private static String headerValue(Map<String, String> headers, String name) {
        if (headers == null) return "";
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue() != null ? e.getValue() : "";
        }
        return "";
    }
}

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
            String key = item.sha256 != null ? item.sha256 : "";
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
        String joined = String.join("|", sources);
        return "session_" + NexusItem.sha256Hex(joined).substring(0, 8);
    }

    // ====================================================================
    // 6. Secret redaction
    // ====================================================================

    private static final Pattern SECRET_KEY_PAT = Pattern.compile(
        "(\"?(?:password|passwd|token|access_token|refresh_token|id_token"
        + "|secret|client_secret|api[_\\-]?key|authorization|jwt|session"
        + "|session_id|sessionid|csrf|xsrf|private_key|signing_key"
        + "|bearer|credential|ssn|credit_card)"
        + "\"?\\s*[:=]\\s*\")([^\"]*)(\")",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern AUTH_HEADER_PAT = Pattern.compile(
        "^(authorization|x-api-key|x-auth-token|x-csrf-token"
        + "|x-xsrf-token|proxy-authorization)\\s*:\\s*(.+)$",
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final Pattern COOKIE_HEADER_PAT = Pattern.compile(
        "^(cookie|set-cookie)\\s*:\\s*(.+)$",
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final Pattern QUERY_SECRET_PAT = Pattern.compile(
        "([?&](?:token|auth|apikey|api_key|session|password"
        + "|access_token|refresh_token|secret|key|csrf)=)([^&\\s]+)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern BEARER_INLINE_PAT = Pattern.compile(
        "(Bearer\\s+)([A-Za-z0-9\\-_.]{8,})", Pattern.CASE_INSENSITIVE);

    private static final Set<String> SENSITIVE_HEADER_NAMES = Set.of(
        "authorization", "x-api-key", "x-auth-token", "x-csrf-token",
        "x-xsrf-token", "proxy-authorization");

    private static final Set<String> SENSITIVE_HEADER_SUBSTRINGS = Set.of(
        "token", "secret", "api-key", "apikey", "auth");

    static void redactSecrets(List<NexusItem> items) {
        for (NexusItem item : items) {
            item.requestHeaders  = redactHeaders(item.requestHeaders);
            item.responseHeaders = redactHeaders(item.responseHeaders);
            item.requestBody     = redactText(item.requestBody);
            item.responseBody    = redactText(item.responseBody);
        }
    }

    private static Map<String, String> redactHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) return headers;
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String k = e.getKey();
            String v = e.getValue() != null ? e.getValue() : "";
            String kLow = k.toLowerCase(Locale.ROOT);

            if ("cookie".equals(kLow) || "set-cookie".equals(kLow)) {
                out.put(k, maskCookieLine(v));
            } else if (SENSITIVE_HEADER_NAMES.contains(kLow)
                    || SENSITIVE_HEADER_SUBSTRINGS.stream().anyMatch(kLow::contains)) {
                out.put(k, maskTokenish(v));
            } else {
                out.put(k, v);
            }
        }
        return out;
    }

    private static String redactText(String text) {
        if (text == null || text.isEmpty()) return text;
        String r = text;
        r = SECRET_KEY_PAT.matcher(r).replaceAll("$1***REDACTED***$3");
        r = AUTH_HEADER_PAT.matcher(r).replaceAll("$1: ***REDACTED***");
        r = replaceCookieHeaders(r);
        r = QUERY_SECRET_PAT.matcher(r).replaceAll("$1***REDACTED***");
        r = BEARER_INLINE_PAT.matcher(r).replaceAll("$1***REDACTED***");
        return r;
    }

    private static String replaceCookieHeaders(String text) {
        Matcher m = COOKIE_HEADER_PAT.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(
                m.group(1) + ": " + maskCookieLine(m.group(2))));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String maskCookieLine(String cookieLine) {
        if (cookieLine == null || cookieLine.isEmpty()) return cookieLine;
        String[] parts = cookieLine.split(";");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append("; ");
            String p = parts[i].trim();
            int eq = p.indexOf('=');
            if (eq > 0) {
                sb.append(p, 0, eq + 1).append("***REDACTED***");
            } else {
                sb.append(p);
            }
        }
        return sb.toString();
    }

    private static String maskTokenish(String value) {
        if (value == null || value.isEmpty()) return value;
        if (value.contains(" ")) {
            int sp = value.indexOf(' ');
            return value.substring(0, sp) + " ***REDACTED***";
        }
        return "***REDACTED***";
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
        if (item.path != null && !item.path.isEmpty()) {
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

    /**
     * Minimal JSON key/value scanner (no full parser needed — we just look
     * for quoted keys and their adjacent values).
     */
    private static boolean jsonContainsParam(String json, String name,
                                              String value, boolean exact) {
        if (json == null) return false;
        // Simple regex-based scan for "key": "value" or "key": number
        Pattern kvPat = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*(?:\"([^\"]*)\"|(-?\\d+(?:\\.\\d+)?)|true|false|null)");
        Matcher m = kvPat.matcher(json);
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2) != null ? m.group(2) : (m.group(3) != null ? m.group(3) : "");
            if (paramMatch(k, v, name, value, exact)) return true;
        }
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
            return List.of(); // invalid regex
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
        return null;
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

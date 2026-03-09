package nexus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Automated security analysis — 10 vulnerability checks,
 * parameter index extraction, and AI prompt generation.
 */
final class SecurityAnalyzer {

    private SecurityAnalyzer() {}

    // ====================================================================
    // Constants
    // ====================================================================

    private static final Set<String> SECURITY_HEADERS = Set.of(
        "content-security-policy", "strict-transport-security",
        "x-content-type-options", "x-frame-options", "x-xss-protection",
        "referrer-policy", "permissions-policy",
        "cross-origin-opener-policy", "cross-origin-resource-policy");

    private static final Set<String> IDOR_PARAMS = Set.of(
        "id", "uid", "user_id", "userid", "account_id", "accountid",
        "order_id", "orderid", "doc_id", "docid", "file_id", "fileid",
        "project_id", "projectid", "customer_id", "customerid",
        "invoice_id", "record_id", "item_id", "profile_id");

    private static final Pattern NUMERIC_ID_IN_PATH = Pattern.compile("/(\\d{1,10})(?:/|$|\\?)");

    private static final Object[][] SENSITIVE_PATTERNS = {
        {Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"), "email address"},
        {Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"), "SSN-like number"},
        {Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b"), "credit card number"},
        {Pattern.compile("(?i)(?:password|passwd|secret|private.?key)\\s*[:=]\\s*[\"']?[^\\s\"',}{]{4,}"), "hardcoded secret"},
        {Pattern.compile("(?i)(?:aws_?access_?key|AKIA)[A-Z0-9]{12,}"), "AWS key"},
        {Pattern.compile("(?i)(?:sk-|pk_live_|pk_test_|sk_live_|sk_test_)[A-Za-z0-9]{20,}"), "API secret key"},
    };

    private static final Object[][] ERROR_SIGNATURES = {
        {Pattern.compile("(?i)SQL\\s*syntax.*?(?:MySQL|MariaDB|PostgreSQL|ORA-|MSSQL)"), "SQL error disclosure"},
        {Pattern.compile("(?i)(?:Traceback \\(most recent call last\\)|stack ?trace|at [\\w$.]+\\([\\w.]+:\\d+\\))"), "Stack trace"},
        {Pattern.compile("(?i)(?:Internal Server Error|Unhandled Exception|System\\.Exception)"), "Unhandled exception"},
        {Pattern.compile("(?i)(?:phpinfo\\(\\)|<title>phpinfo\\(\\))"), "phpinfo() exposure"},
        {Pattern.compile("(?i)(?:root:|/etc/passwd|/etc/shadow|C:\\\\Windows\\\\system32)"), "Path/file disclosure"},
        {Pattern.compile("(?i)(?:debug\\s*=\\s*True|DEBUG_MODE|DJANGO_SETTINGS_MODULE)"), "Debug mode enabled"},
    };

    private static final Set<String> REDIRECT_PARAMS = Set.of(
        "url", "redirect", "redirect_uri", "redirect_url", "return",
        "returnto", "return_url", "next", "goto", "dest", "destination",
        "continue", "target", "rurl");

    private static final Set<String> AUTH_HEADER_NAMES = Set.of(
        "authorization", "cookie", "x-api-key", "x-auth-token");

    private static final Pattern JSON_KV_PAT = Pattern.compile(
        "\"([^\"]+)\"\\s*:\\s*(?:\"([^\"]*)\"|(-?\\d+(?:\\.\\d+)?))");

    // ====================================================================
    // 1. Security Findings
    // ====================================================================

    static void generateSecurityFindings(NexusExport export, Path outputDir) throws IOException {
        List<Map<String, Object>> findings = new ArrayList<>();
        checkMissingSecurityHeaders(export, findings);
        checkIdorCandidates(export, findings);
        checkReflectedInput(export, findings);
        checkErrorDisclosure(export, findings);
        checkSensitiveData(export, findings);
        checkUnauthEndpoints(export, findings);
        checkCorsMisconfig(export, findings);
        checkHttpMethods(export, findings);
        checkCookieSecurity(export, findings);
        checkOpenRedirects(export, findings);

        writeFindingsMd(export, findings, outputDir);
        writeFindingsJson(findings, outputDir);
    }

    // ---- checks --------------------------------------------------------

    private static void checkMissingSecurityHeaders(NexusExport export, List<Map<String, Object>> findings) {
        Map<String, Set<String>> hostMissing = new HashMap<>();
        Map<String, Set<String>> hostSeen    = new HashMap<>();
        for (NexusItem item : export.items) {
            if (item.responseHeaders.isEmpty()) continue;
            Set<String> respLower = new HashSet<>();
            for (String k : item.responseHeaders.keySet()) respLower.add(k.toLowerCase(Locale.ROOT));
            String host = item.host != null ? item.host : "unknown";
            for (String hdr : SECURITY_HEADERS) {
                if (respLower.contains(hdr)) {
                    hostSeen.computeIfAbsent(host, k -> new HashSet<>()).add(hdr);
                } else {
                    hostMissing.computeIfAbsent(host, k -> new HashSet<>()).add(hdr);
                }
            }
        }
        for (Map.Entry<String, Set<String>> e : hostMissing.entrySet()) {
            Set<String> actual = new HashSet<>(e.getValue());
            actual.removeAll(hostSeen.getOrDefault(e.getKey(), Set.of()));
            if (!actual.isEmpty()) {
                findings.add(finding("Security Headers", "Medium",
                    "Missing security headers on " + e.getKey(),
                    "Headers never observed: " + String.join(", ", new TreeSet<>(actual)),
                    e.getKey(), List.of()));
            }
        }
    }

    private static void checkIdorCandidates(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            List<String> suspects = new ArrayList<>();
            Matcher m = NUMERIC_ID_IN_PATH.matcher(item.path != null ? item.path : "");
            while (m.find()) suspects.add("path=" + m.group(1));
            String query = queryFromUrl(item.url);
            for (String[] kv : parseQs(query)) {
                if (IDOR_PARAMS.contains(kv[0].toLowerCase(Locale.ROOT)))
                    suspects.add("param:" + kv[0] + "=" + kv[1]);
            }
            if (item.requestBody != null && !item.requestBody.isEmpty()) {
                for (String[] kv : parseQs(item.requestBody)) {
                    if (IDOR_PARAMS.contains(kv[0].toLowerCase(Locale.ROOT)))
                        suspects.add("body:" + kv[0] + "=" + kv[1]);
                }
            }
            if (!suspects.isEmpty()) {
                findings.add(finding("IDOR", "High",
                    "Potential IDOR: " + item.method + " " + item.path,
                    "Numeric/predictable identifiers: " + String.join(", ", suspects),
                    item.host, List.of(item.slug)));
            }
        }
    }

    private static void checkReflectedInput(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            if (item.responseBody == null || item.responseBody.isEmpty()) continue;
            String respLower = item.responseBody.toLowerCase(Locale.ROOT);
            String query = queryFromUrl(item.url);
            for (String[] kv : parseQs(query)) {
                if (kv[1].length() >= 4 && respLower.contains(kv[1].toLowerCase(Locale.ROOT))) {
                    findings.add(finding("Reflected Input (XSS candidate)", "High",
                        "Reflected param '" + kv[0] + "' in response: " + item.method + " " + item.path,
                        "Value '" + kv[1].substring(0, Math.min(60, kv[1].length())) + "' from query param appears in response.",
                        item.host, List.of(item.slug)));
                    break;
                }
            }
        }
    }

    private static void checkErrorDisclosure(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            String body = item.responseBody != null ? item.responseBody : "";
            if (body.isEmpty()) continue;
            for (Object[] sig : ERROR_SIGNATURES) {
                if (((Pattern) sig[0]).matcher(body).find()) {
                    findings.add(finding("Information Disclosure", "Medium",
                        sig[1] + ": " + item.method + " " + item.path + " [" + item.status + "]",
                        "Response contains " + ((String)sig[1]).toLowerCase() + " pattern.",
                        item.host, List.of(item.slug)));
                    break;
                }
            }
        }
    }

    private static void checkSensitiveData(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            String body = item.responseBody != null ? item.responseBody : "";
            if (body.isEmpty()) continue;
            for (Object[] pat : SENSITIVE_PATTERNS) {
                Matcher m = ((Pattern) pat[0]).matcher(body);
                if (m.find()) {
                    findings.add(finding("Sensitive Data Exposure", "High",
                        pat[1] + " in response: " + item.method + " " + item.path,
                        "Matched pattern: '" + m.group(0).substring(0, Math.min(40, m.group(0).length())) + "...'",
                        item.host, List.of(item.slug)));
                    break;
                }
            }
        }
    }

    private static void checkUnauthEndpoints(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            if (item.requestHeaders.isEmpty()) continue;
            Set<String> reqLower = new HashSet<>();
            for (String k : item.requestHeaders.keySet()) reqLower.add(k.toLowerCase(Locale.ROOT));
            boolean hasAuth = false;
            for (String a : AUTH_HEADER_NAMES) { if (reqLower.contains(a)) { hasAuth = true; break; } }
            String status = item.status != null ? item.status : "";
            if (!hasAuth && status.startsWith("2")) {
                String path = item.path != null ? item.path : "/";
                if (!"/".equals(path) && !"/favicon.ico".equals(path) && !"/robots.txt".equals(path)) {
                    findings.add(finding("Authentication", "Medium",
                        "Unauthenticated 2xx: " + item.method + " " + path,
                        "Endpoint returned success without any auth headers in request.",
                        item.host, List.of(item.slug)));
                }
            }
        }
    }

    private static void checkCorsMisconfig(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            String acao = headerValue(item.responseHeaders, "access-control-allow-origin");
            if ("*".equals(acao)) {
                findings.add(finding("CORS Misconfiguration", "Medium",
                    "Wildcard CORS: " + item.method + " " + item.path,
                    "Access-Control-Allow-Origin: * allows any origin.",
                    item.host, List.of(item.slug)));
            } else if (!acao.isEmpty() && !acao.equals(item.host)) {
                String acac = headerValue(item.responseHeaders, "access-control-allow-credentials");
                if ("true".equalsIgnoreCase(acac)) {
                    findings.add(finding("CORS Misconfiguration", "High",
                        "CORS with credentials: " + item.method + " " + item.path,
                        "Origin '" + acao + "' with Allow-Credentials: true.",
                        item.host, List.of(item.slug)));
                }
            }
        }
    }

    private static void checkHttpMethods(NexusExport export, List<Map<String, Object>> findings) {
        Set<String> dangerous = Set.of("PUT", "DELETE", "PATCH", "TRACE", "OPTIONS");
        Map<String, Set<String>> endpointMethods = new HashMap<>();
        for (NexusItem item : export.items) {
            String key = item.host + ":" + item.path;
            endpointMethods.computeIfAbsent(key, k -> new HashSet<>())
                .add(item.method != null ? item.method.toUpperCase() : "");
        }
        for (Map.Entry<String, Set<String>> e : endpointMethods.entrySet()) {
            Set<String> risky = new HashSet<>(e.getValue());
            risky.retainAll(dangerous);
            if (!risky.isEmpty()) {
                String[] parts = e.getKey().split(":", 2);
                findings.add(finding("HTTP Methods", "Low",
                    "State-changing methods on " + (parts.length > 1 ? parts[1] : e.getKey()),
                    "Methods observed: " + String.join(", ", new TreeSet<>(risky)) + ". Verify authorization checks.",
                    parts[0], List.of()));
            }
        }
    }

    private static void checkCookieSecurity(NexusExport export, List<Map<String, Object>> findings) {
        Set<String> seen = new HashSet<>();
        for (NexusItem item : export.items) {
            String sc = headerValue(item.responseHeaders, "set-cookie");
            if (sc.isEmpty()) continue;
            String name = sc.contains("=") ? sc.split("=")[0].trim() : "unknown";
            if (seen.contains(name)) continue;
            String lower = sc.toLowerCase(Locale.ROOT);
            List<String> issues = new ArrayList<>();
            if (!lower.contains("httponly")) issues.add("missing HttpOnly");
            if (!lower.contains("secure"))   issues.add("missing Secure");
            if (!lower.contains("samesite")) issues.add("missing SameSite");
            if (!issues.isEmpty()) {
                seen.add(name);
                findings.add(finding("Cookie Security", "Medium",
                    "Insecure cookie '" + name + "' on " + item.host,
                    "Cookie flags: " + String.join(", ", issues) + ".",
                    item.host, List.of(item.slug)));
            }
        }
    }

    private static void checkOpenRedirects(NexusExport export, List<Map<String, Object>> findings) {
        for (NexusItem item : export.items) {
            String query = queryFromUrl(item.url);
            for (String[] kv : parseQs(query)) {
                if (REDIRECT_PARAMS.contains(kv[0].toLowerCase(Locale.ROOT))) {
                    if (kv[1].startsWith("http") || kv[1].startsWith("//")) {
                        findings.add(finding("Open Redirect", "Medium",
                            "Open redirect candidate: " + item.method + " " + item.path,
                            "Param '" + kv[0] + "' = '" + kv[1].substring(0, Math.min(80, kv[1].length())) + "' contains external URL.",
                            item.host, List.of(item.slug)));
                        break;
                    }
                }
            }
        }
    }

    // ---- findings output -----------------------------------------------

    private static void writeFindingsMd(NexusExport export, List<Map<String, Object>> findings, Path dir) throws IOException {
        Map<String, Integer> sevOrder = Map.of("Critical",0,"High",1,"Medium",2,"Low",3,"Info",4);
        findings.sort(Comparator.comparingInt(f -> sevOrder.getOrDefault(f.get("severity"), 4)));

        Map<String, List<Map<String, Object>>> byCat = new LinkedHashMap<>();
        for (Map<String, Object> f : findings) {
            byCat.computeIfAbsent((String)f.get("category"), k -> new ArrayList<>()).add(f);
        }

        Map<String, Integer> sevCounts = new LinkedHashMap<>();
        for (Map<String, Object> f : findings) sevCounts.merge((String)f.get("severity"), 1, Integer::sum);

        StringBuilder sb = new StringBuilder(8192);
        sb.append("# BurpNexus Security Findings Report\n\n");
        sb.append("> Auto-generated security analysis of captured HTTP traffic.\n");
        sb.append("> Feed this file alongside the JSON corpus to VS Code Copilot for deeper analysis.\n\n---\n\n");

        sb.append("## Summary\n\n");
        sb.append("| Metric | Value |\n| ------ | ----- |\n");
        sb.append("| Total items analyzed | `").append(export.items.size()).append("` |\n");
        sb.append("| Total findings | `").append(findings.size()).append("` |\n");
        sb.append("| Categories | `").append(byCat.size()).append("` |\n");
        for (String sev : List.of("Critical", "High", "Medium", "Low", "Info")) {
            if (sevCounts.containsKey(sev))
                sb.append("| ").append(sev).append(" severity | `").append(sevCounts.get(sev)).append("` |\n");
        }
        sb.append('\n');

        if (findings.isEmpty()) {
            sb.append("**No automated findings detected.** This does not mean the application is secure.\n\n");
            sb.append("Manual review with Copilot is still recommended.\n\n");
        } else {
            sb.append("---\n\n");
            for (Map.Entry<String, List<Map<String, Object>>> e : byCat.entrySet()) {
                sb.append("## ").append(e.getKey()).append("\n\n");
                int i = 1;
                for (Map<String, Object> f : e.getValue()) {
                    sb.append("### ").append(i++).append(". [").append(f.get("severity")).append("] ").append(f.get("title")).append("\n\n");
                    sb.append(f.get("detail")).append("\n\n");
                    @SuppressWarnings("unchecked")
                    List<String> items = (List<String>) f.get("items");
                    if (items != null && !items.isEmpty()) {
                        sb.append("**Related files:** ");
                        for (int j = 0; j < items.size(); j++) {
                            if (j > 0) sb.append(", ");
                            sb.append('`').append(items.get(j)).append(".json`");
                        }
                        sb.append("\n\n");
                    }
                }
            }
        }

        sb.append("---\n\n## Recommended Copilot Prompts for These Findings\n\n```\n");
        if (sevCounts.containsKey("High") || sevCounts.containsKey("Critical"))
            sb.append("@workspace Review all High/Critical findings in SECURITY_FINDINGS.md and cross-reference with the source code for exploitability.\n");
        if (byCat.containsKey("IDOR"))
            sb.append("@workspace Analyze all IDOR candidates and check if authorization is enforced server-side.\n");
        if (byCat.containsKey("Reflected Input (XSS candidate)"))
            sb.append("@workspace Check all reflected input findings for proper output encoding.\n");
        if (byCat.containsKey("Information Disclosure"))
            sb.append("@workspace Review error handling to ensure stack traces and SQL errors are not exposed in production.\n");
        if (byCat.containsKey("Authentication"))
            sb.append("@workspace Verify that all sensitive endpoints require authentication middleware.\n");
        sb.append("@workspace Based on SECURITY_FINDINGS.md and the JSON corpus, generate a prioritized vulnerability list with PoC scripts.\n");
        sb.append("```\n\n---\n*Generated by **BurpNexus** - Automated Security Analysis*\n");

        writeText(dir.resolve("SECURITY_FINDINGS.md"), sb.toString());
    }

    private static void writeFindingsJson(List<Map<String, Object>> findings, Path dir) throws IOException {
        JsonBuilder jb = new JsonBuilder(4096);
        jb.arrayStart();
        for (Map<String, Object> f : findings) {
            jb.objectStart();
            jb.field("category", (String) f.get("category"));
            jb.field("severity", (String) f.get("severity"));
            jb.field("title",    (String) f.get("title"));
            jb.field("detail",   (String) f.get("detail"));
            jb.field("host",     (String) f.get("host"));
            jb.key("items").arrayStart();
            @SuppressWarnings("unchecked")
            List<String> items = (List<String>) f.get("items");
            if (items != null) for (String s : items) jb.arrayValue(s);
            jb.arrayEnd();
            jb.objectEnd();
        }
        jb.arrayEnd();
        writeText(dir.resolve("security-findings.json"), jb.toPrettyString());
    }

    // ====================================================================
    // 2. Parameter Index
    // ====================================================================

    static void generateParamIndex(NexusExport export, Path outputDir) throws IOException {
        Map<String, ParamInfo> params = new LinkedHashMap<>();

        for (NexusItem item : export.items) {
            String endpoint = item.method + " " + item.path;
            String host = item.host != null ? item.host : "";

            // query params
            for (String[] kv : parseQs(queryFromUrl(item.url))) {
                register(params, kv[0], "query", kv[1], endpoint, host);
            }
            // body params
            String ct = headerValue(item.requestHeaders, "content-type");
            if (item.requestBody != null && !item.requestBody.isEmpty()) {
                if (ct.contains("form") || (item.requestBody.contains("=")
                        && !item.requestBody.trim().startsWith("{"))) {
                    for (String[] kv : parseQs(item.requestBody)) {
                        register(params, kv[0], "body_form", kv[1], endpoint, host);
                    }
                }
                // JSON fields
                String trimmed = item.requestBody.trim();
                if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                    Matcher m = JSON_KV_PAT.matcher(trimmed);
                    while (m.find()) {
                        String val = m.group(2) != null ? m.group(2) : (m.group(3) != null ? m.group(3) : "");
                        register(params, m.group(1), "json_body", val, endpoint, host);
                    }
                }
            }
            // cookies
            String cookieVal = headerValue(item.requestHeaders, "cookie");
            if (!cookieVal.isEmpty()) {
                for (String part : cookieVal.split(";")) {
                    int eq = part.indexOf('=');
                    if (eq > 0) register(params, part.substring(0, eq).trim(), "cookie", "(value)", endpoint, host);
                }
            }
            // custom headers
            Set<String> standard = Set.of("host","user-agent","accept","accept-language",
                "accept-encoding","connection","content-type","content-length",
                "cache-control","pragma","upgrade-insecure-requests","referer","origin",
                "sec-fetch-dest","sec-fetch-mode","sec-fetch-site","sec-fetch-user",
                "sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform","dnt","te",
                "if-none-match","if-modified-since");
            for (Map.Entry<String, String> e : item.requestHeaders.entrySet()) {
                if (!standard.contains(e.getKey().toLowerCase(Locale.ROOT))) {
                    register(params, e.getKey(), "header", e.getValue().substring(0, Math.min(60, e.getValue().length())), endpoint, host);
                }
            }
        }

        List<ParamInfo> sorted = new ArrayList<>(params.values());
        sorted.sort((a, b) -> b.occurrences != a.occurrences ? b.occurrences - a.occurrences : a.name.compareTo(b.name));

        JsonBuilder jb = new JsonBuilder(8192);
        jb.objectStart();
        jb.key("summary").objectStart();
        jb.field("total_unique_parameters", sorted.size());
        jb.field("total_items_analyzed", export.items.size());
        Set<String> sources = new TreeSet<>();
        for (ParamInfo p : sorted) sources.add(p.source);
        jb.key("parameter_sources").arrayStart();
        for (String s : sources) jb.arrayValue(s);
        jb.arrayEnd();
        jb.objectEnd();

        jb.key("parameters").arrayStart();
        for (ParamInfo p : sorted) {
            jb.objectStart();
            jb.field("name", p.name);
            jb.field("source", p.source);
            jb.field("occurrences", p.occurrences);
            jb.key("example_values").arrayStart();
            for (String v : p.exampleValues) jb.arrayValue(v);
            jb.arrayEnd();
            jb.key("endpoints").arrayStart();
            for (String e : new TreeSet<>(p.endpoints)) jb.arrayValue(e);
            jb.arrayEnd();
            jb.key("hosts").arrayStart();
            for (String h : new TreeSet<>(p.hosts)) jb.arrayValue(h);
            jb.arrayEnd();
            jb.field("is_sensitive", p.isSensitive);
            jb.objectEnd();
        }
        jb.arrayEnd();
        jb.objectEnd();

        writeText(outputDir.resolve("param-index.json"), jb.toPrettyString());
    }

    private static class ParamInfo {
        String name, source;
        int occurrences;
        List<String> exampleValues = new ArrayList<>();
        Set<String> endpoints = new HashSet<>();
        Set<String> hosts = new HashSet<>();
        boolean isSensitive;
    }

    private static void register(Map<String, ParamInfo> params, String name, String source,
                                  String value, String endpoint, String host) {
        String key = source + ":" + name.toLowerCase(Locale.ROOT);
        ParamInfo p = params.computeIfAbsent(key, k -> {
            ParamInfo pi = new ParamInfo();
            pi.name = name;
            pi.source = source;
            pi.isSensitive = isSensitiveParam(name);
            return pi;
        });
        p.occurrences++;
        p.endpoints.add(endpoint);
        p.hosts.add(host);
        if (value != null && p.exampleValues.size() < 3) {
            String trunc = value.length() > 100 ? value.substring(0, 100) : value;
            if (!p.exampleValues.contains(trunc)) p.exampleValues.add(trunc);
        }
    }

    private static boolean isSensitiveParam(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        Set<String> sensitive = Set.of("password","passwd","token","secret","api_key","apikey",
            "access_token","refresh_token","session","sessionid","csrf","xsrf",
            "ssn","credit_card","cc","cvv","authorization","auth","private_key");
        if (sensitive.contains(n)) return true;
        return n.contains("password") || n.contains("token") || n.contains("secret")
            || n.contains("key") || n.contains("auth");
    }

    // ====================================================================
    // 3. AI Prompts
    // ====================================================================

    static void generateAiPrompts(NexusExport export, Path outputDir) throws IOException {
        List<String> hosts = export.hosts();
        Set<String> endpoints = new LinkedHashSet<>();
        Set<String> statuses  = new TreeSet<>();
        List<String> authEps  = new ArrayList<>();
        List<String> noauthEps = new ArrayList<>();
        List<String> errorEps = new ArrayList<>();

        for (NexusItem item : export.items) {
            String ep = item.method + " " + item.path;
            endpoints.add(ep);
            statuses.add(item.status != null ? item.status : "?");
            Set<String> reqLower = new HashSet<>();
            for (String k : item.requestHeaders.keySet()) reqLower.add(k.toLowerCase(Locale.ROOT));
            boolean hasAuth = false;
            for (String a : AUTH_HEADER_NAMES) { if (reqLower.contains(a)) { hasAuth = true; break; } }
            if (hasAuth) authEps.add(ep); else noauthEps.add(ep);
            String s = item.status != null ? item.status : "";
            if (s.startsWith("4") || s.startsWith("5")) errorEps.add(ep + " [" + s + "]");
        }

        StringBuilder sb = new StringBuilder(8192);
        sb.append("# AI Analysis Prompts for This Export\n\n");
        sb.append("> Copy-paste these prompts into VS Code Copilot Chat to analyze this traffic\n");
        sb.append("> alongside the application source code.\n\n---\n\n");

        sb.append("## Export Context\n\n");
        sb.append("- **Hosts:** ").append(String.join(", ", hosts.subList(0, Math.min(5, hosts.size())))).append('\n');
        sb.append("- **Unique endpoints:** ").append(endpoints.size()).append('\n');
        sb.append("- **Items:** ").append(export.items.size()).append('\n');
        sb.append("- **Tools:** ").append(String.join(", ", export.tools())).append('\n');
        sb.append("- **Status codes:** ").append(String.join(", ", statuses)).append("\n\n---\n\n");

        sb.append("## Phase 1: Reconnaissance Prompts\n\n");
        sb.append("```\n@workspace Summarize all API endpoints discovered in this Burp export for hosts: ");
        sb.append(String.join(", ", hosts.subList(0, Math.min(5, hosts.size()))));
        sb.append(". Group by resource and list HTTP methods available for each.\n```\n\n");
        sb.append("```\n@workspace Map out the authentication flow: find login/logout/token-refresh endpoints, identify what auth mechanisms are used (JWT, session cookies, API keys), and note any weaknesses.\n```\n\n");
        sb.append("```\n@workspace List all user input vectors: query parameters, POST body fields, JSON fields, custom headers, and cookies. Flag any that look injectable or sensitive.\n```\n\n");

        sb.append("## Phase 2: Vulnerability Analysis Prompts\n\n");
        if (!authEps.isEmpty()) {
            sb.append("### Access Control / IDOR\n\n```\n@workspace Check these authenticated endpoints for IDOR vulnerabilities: ");
            List<String> sample = new ArrayList<>(new LinkedHashSet<>(authEps));
            sb.append(String.join("; ", sample.subList(0, Math.min(5, sample.size()))));
            sb.append(". For each endpoint, verify if the server validates resource ownership. Generate PoC scripts.\n```\n\n");
        }
        if (!noauthEps.isEmpty()) {
            sb.append("### Unauthenticated Access\n\n```\n@workspace These endpoints were accessed without authentication: ");
            List<String> sample = new ArrayList<>(new LinkedHashSet<>(noauthEps));
            sb.append(String.join("; ", sample.subList(0, Math.min(5, sample.size()))));
            sb.append(". Check the source code to determine if they should require auth.\n```\n\n");
        }
        sb.append("### Injection Flaws\n\n```\n@workspace Analyze all request parameters across the JSON corpus for SQL injection, command injection, and XSS. Focus on parameters reflected in responses or used in database queries. Generate PoC payloads.\n```\n\n");
        sb.append("### SSRF\n\n```\n@workspace Find any request parameters that accept URLs, hostnames, file paths, or IP addresses. Check if the application makes server-side requests based on this input.\n```\n\n");
        if (!errorEps.isEmpty()) {
            sb.append("### Error Analysis\n\n```\n@workspace Analyze these error responses: ");
            sb.append(String.join("; ", errorEps.subList(0, Math.min(5, errorEps.size()))));
            sb.append(". Check if they leak server internals.\n```\n\n");
        }

        sb.append("## Phase 3: Business Logic\n\n```\n@workspace Analyze request sequences for business logic flaws: race conditions, price manipulation, quantity bypasses, workflow skipping, state tampering.\n```\n\n");
        sb.append("## Phase 4: Comprehensive Report\n\n```\n@workspace Based on the complete analysis of the Burp export JSON corpus and SECURITY_FINDINGS.md, generate a penetration test report with: Executive Summary, Findings (severity, description, PoC, remediation), and Risk Matrix. Use the OWASP Top 10 framework.\n```\n\n");

        if (!hosts.isEmpty()) {
            sb.append("## Phase 5: Source Code Cross-Reference\n\n```\n@workspace Cross-reference the API endpoints from the Burp export with the application source code. For each endpoint, identify the handler function, trace user input through the code, and flag any missing input validation, authorization checks, or output encoding.\n```\n\n");
        }

        sb.append("---\n*Generated by **BurpNexus** - Tailored for this export*\n");
        writeText(outputDir.resolve("AI_ANALYSIS_PROMPTS.md"), sb.toString());
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    private static Map<String, Object> finding(String category, String severity,
                                                String title, String detail,
                                                String host, List<String> items) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("category", category);
        f.put("severity", severity);
        f.put("title", title);
        f.put("detail", detail);
        f.put("host", host);
        f.put("items", new ArrayList<>(items));
        return f;
    }

    private static String queryFromUrl(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        if (q < 0) return "";
        int f = url.indexOf('#', q);
        return f > q ? url.substring(q + 1, f) : url.substring(q + 1);
    }

    private static List<String[]> parseQs(String query) {
        List<String[]> pairs = new ArrayList<>();
        if (query == null || query.isEmpty()) return pairs;
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq > 0) pairs.add(new String[]{part.substring(0, eq), part.substring(eq + 1)});
        }
        return pairs;
    }

    private static String headerValue(Map<String, String> headers, String name) {
        if (headers == null) return "";
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue() != null ? e.getValue() : "";
        }
        return "";
    }

    private static void writeText(Path path, String content) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }
}

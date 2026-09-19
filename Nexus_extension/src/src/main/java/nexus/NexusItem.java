package nexus;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Represents a single HTTP request/response pair collected from Burp.
 * Populated directly from Montoya API objects — no XML round-trip.
 */
final class NexusItem {

    // ---- metadata ------------------------------------------------------
    int          index;
    String       tool       = "unknown";
    String       time       = "";
    ZonedDateTime timeParsed;
    String       url        = "";
    String       host       = "";
    String       hostIp     = "";
    String       port       = "";
    String       protocol   = "";
    String       method     = "";
    String       path       = "";
    String       extension  = "";
    String       status     = "";
    String       responseLength = "";
    String       mimeType   = "";
    String       comment    = "";

    // ---- parsed HTTP components ----------------------------------------
    String              requestLine     = "";   // e.g. "GET /path HTTP/1.1"
    Map<String, String> requestHeaders  = new LinkedHashMap<>();
    String              requestBody     = "";
    String              responseStatusLine = "";
    Map<String, String> responseHeaders = new LinkedHashMap<>();
    String              responseBody    = "";

    // ---- derived -------------------------------------------------------
    String slug       = "";
    String sha256     = "";
    String sessionTag = "";

    // ---- tool constants ------------------------------------------------

    static final String TOOL_PROXY    = "proxy";
    static final String TOOL_TARGET   = "target";
    static final String TOOL_REPEATER = "repeater";
    static final String TOOL_INTRUDER = "intruder";
    static final String TOOL_SCANNER  = "scanner";
    static final String TOOL_UNKNOWN  = "unknown";

    private static final Map<String, String> NUMERIC_TOOL_MAP = Map.ofEntries(
        Map.entry("1",   TOOL_TARGET),
        Map.entry("2",   TOOL_PROXY),
        Map.entry("4",   TOOL_SCANNER),
        Map.entry("8",   TOOL_INTRUDER),
        Map.entry("16",  TOOL_REPEATER),
        Map.entry("32",  "sequencer"),
        Map.entry("64",  "decoder"),
        Map.entry("128", "comparer"),
        Map.entry("256", "extender"),
        Map.entry("512", "logger")
    );

    private static final Pattern SLUG_UNSAFE = Pattern.compile("[^\\w\\-.]");
    private static final Pattern MULTI_UNDER = Pattern.compile("_+");

    // ---- construction from Montoya API ---------------------------------

    /**
     * Build a NexusItem from raw request/response bytes and metadata.
     * This is the primary factory — called by NexusCollector.
     */
    static NexusItem fromRaw(int index, byte[] rawReq, byte[] rawResp,
                             String host, int port, boolean secure,
                             String toolName, Instant requestTime) {
        NexusItem item = new NexusItem();
        item.index    = index;
        item.host     = host != null ? host : "";
        item.port     = String.valueOf(port);
        item.protocol = secure ? "https" : "http";
        item.tool     = toolName != null ? toolName : TOOL_UNKNOWN;

        if (requestTime != null) {
            item.timeParsed = requestTime.atZone(ZoneId.systemDefault());
            item.time = item.timeParsed.toString();
        }

        // decode + parse request, then discard raw to save memory
        {
            String rawReqStr = decodeBytes(rawReq);
            ParsedHttp reqParsed = parseHttpMessage(rawReqStr);
            item.requestLine    = reqParsed.firstLine;
            item.requestHeaders = reqParsed.headers;
            item.requestBody    = reqParsed.body;
            item.sha256         = sha256Hex(rawReqStr);
            // rawReqStr goes out of scope → GC-eligible
        }

        // extract method, path, and query from request line
        String requestTarget = "";
        if (!item.requestLine.isEmpty()) {
            String[] parts = item.requestLine.split("\\s+", 3);
            if (parts.length >= 1) item.method = parts[0];
            if (parts.length >= 2) {
                requestTarget = parts[1];
                try {
                    URI uri = new URI(parts[1]);
                    item.path = uri.getRawPath();
                    if (item.path == null || item.path.isEmpty()) item.path = "/";
                } catch (Exception ignored) {
                    item.path = parts[1];
                    if (item.path.contains("?"))
                        item.path = item.path.substring(0, item.path.indexOf('?'));
                }
            }
        }

        // extract file extension from path
        String pathForExt = item.path;
        int lastSlash = pathForExt.lastIndexOf('/');
        String lastSegment = lastSlash >= 0 ? pathForExt.substring(lastSlash + 1) : pathForExt;
        int dotIdx = lastSegment.lastIndexOf('.');
        if (dotIdx > 0 && dotIdx < lastSegment.length() - 1) {
            item.extension = lastSegment.substring(dotIdx + 1);
        }

        // build full URL (preserving query string from request target)
        if (item.host != null && !item.host.isEmpty()) {
            String portSuffix = "";
            if ((secure && port != 443) || (!secure && port != 80)) {
                portSuffix = ":" + port;
            }
            String pathAndQuery = requestTarget.isEmpty()
                ? (item.path.isEmpty() ? "/" : item.path)
                : requestTarget;
            if (pathAndQuery.startsWith("http://") || pathAndQuery.startsWith("https://")) {
                URI absolute = URI.create(pathAndQuery);
                pathAndQuery = absolute.getRawPath() + (absolute.getRawQuery() == null ? "" : "?" + absolute.getRawQuery());
            }
            String authorityHost = item.host.contains(":") && !item.host.startsWith("[") ? "[" + item.host + "]" : item.host;
            item.url = item.protocol + "://" + authorityHost + portSuffix + pathAndQuery;
        }

        // decode + parse response, then discard raw to save memory
        if (rawResp != null && rawResp.length > 0) {
            String rawRespStr = decodeBytes(rawResp);
            ParsedHttp respParsed = parseHttpMessage(rawRespStr);
            item.responseStatusLine = respParsed.firstLine;
            item.responseHeaders    = respParsed.headers;
            item.responseBody       = respParsed.body;
            // rawRespStr goes out of scope → GC-eligible

            String[] statusParts = item.responseStatusLine.split("\\s+", 3);
            if (statusParts.length >= 2) {
                item.status = statusParts[1];
            }

            item.responseLength = String.valueOf(rawResp.length);

            for (Map.Entry<String, String> e : item.responseHeaders.entrySet()) {
                if (e.getKey().equalsIgnoreCase("content-type")) {
                    item.mimeType = e.getValue().split(";")[0].trim();
                    break;
                }
            }
        }

        // derived fields
        item.slug = makeSlug(item);

        return item;
    }

    // ---- on-demand raw reconstruction (avoids storing 2x data) ---------

    String reconstructRequestRaw() {
        return reconstructRaw(requestLine, requestHeaders, requestBody);
    }

    String reconstructResponseRaw() {
        return reconstructRaw(responseStatusLine, responseHeaders, responseBody);
    }

    private static String reconstructRaw(String firstLine, Map<String, String> headers, String body) {
        StringBuilder sb = new StringBuilder(512);
        if (firstLine != null && !firstLine.isEmpty()) {
            sb.append(firstLine).append("\r\n");
        }
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                for (String value : e.getValue().split("\n", -1))
                    sb.append(e.getKey()).append(": ").append(value).append("\r\n");
            }
        }
        sb.append("\r\n");
        if (body != null && !body.isEmpty()) {
            sb.append(body);
        }
        return sb.toString();
    }

    // ---- JSON serialisation (zero-dep) ---------------------------------

    String toJson() {
        JsonBuilder jb = new JsonBuilder(4096);
        jb.objectStart();

        // metadata
        jb.key("metadata").objectStart();
        jb.field("index", index);
        jb.field("tool", tool);
        jb.field("time", time);
        jb.field("url", url);
        jb.field("host", host);
        jb.field("host_ip", hostIp);
        jb.field("port", port);
        jb.field("protocol", protocol);
        jb.field("method", method);
        jb.field("path", path);
        jb.field("extension", extension);
        jb.field("status", status);
        jb.field("response_length", responseLength);
        jb.field("mime_type", mimeType);
        jb.field("comment", comment);
        jb.field("sha256", sha256);
        jb.field("session_tag", sessionTag);
        jb.objectEnd();

        // request
        jb.key("request").objectStart();
        jb.field("raw", reconstructRequestRaw());
        jb.key("headers").rawValue(mapToJson(requestHeaders));
        jb.field("body", requestBody);
        jb.objectEnd();

        // response
        jb.key("response").objectStart();
        jb.field("status_line", responseStatusLine);
        jb.field("raw", reconstructResponseRaw());
        jb.key("headers").rawValue(mapToJson(responseHeaders));
        jb.field("body", responseBody);
        jb.objectEnd();

        jb.objectEnd();
        return jb.toPrettyString();
    }

    // ---- internal helpers ----------------------------------------------

    private static String decodeBytes(byte[] data) {
        if (data == null || data.length == 0) return "";
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(data)).toString();
        } catch (Exception e) {
            return new String(data, StandardCharsets.ISO_8859_1);
        }
    }

    static final class ParsedHttp {
        String firstLine = "";
        Map<String, String> headers = new LinkedHashMap<>();
        String body = "";
    }

    static ParsedHttp parseHttpMessage(String raw) {
        ParsedHttp result = new ParsedHttp();
        if (raw == null || raw.isEmpty()) return result;

        String headerBlock;
        String sep;
        int splitIdx = raw.indexOf("\r\n\r\n");
        if (splitIdx >= 0) {
            headerBlock = raw.substring(0, splitIdx);
            result.body = raw.substring(splitIdx + 4);
            sep = "\r\n";
        } else {
            splitIdx = raw.indexOf("\n\n");
            if (splitIdx >= 0) {
                headerBlock = raw.substring(0, splitIdx);
                result.body = raw.substring(splitIdx + 2);
                sep = "\n";
            } else {
                return result;
            }
        }

        String[] lines = headerBlock.split(sep);
        if (lines.length > 0) {
            result.firstLine = lines[0].trim();
        }
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String name  = lines[i].substring(0, colon).trim();
                String value = lines[i].substring(colon + 1).trim();
                String existing = result.headers.keySet().stream().filter(k -> k.equalsIgnoreCase(name)).findFirst().orElse(name);
                result.headers.merge(existing, value, (old, nw) -> old + "\n" + nw);
            }
        }
        return result;
    }

    static String makeSlug(NexusItem item) {
        String m = item.method != null && !item.method.isEmpty() ? item.method.toUpperCase() : "REQ";
        m = m.replaceAll("[^A-Z0-9_-]", "_");
        if (m.length() > 10) m = m.substring(0, 10);
        String p = item.path != null && !item.path.isEmpty() ? item.path : "root";
        p = SLUG_UNSAFE.matcher(p).replaceAll("_");
        p = MULTI_UNDER.matcher(p).replaceAll("_");
        if (p.startsWith("_")) p = p.substring(1);
        if (p.endsWith("_")) p = p.substring(0, p.length() - 1);
        if (p.length() > 60) p = p.substring(0, 60);
        if (p.isEmpty()) p = "root";
        return String.format("%04d_%s_%s", item.index, m, p);
    }

    static String sha256Hex(String data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    static String normaliseToolName(String raw) {
        if (raw == null || raw.isEmpty()) return TOOL_UNKNOWN;
        String s = raw.strip();
        String mapped = NUMERIC_TOOL_MAP.get(s);
        if (mapped != null) return mapped;
        String lower = s.toLowerCase(Locale.ROOT);
        if (lower.contains("proxy") || lower.contains("http history")) return TOOL_PROXY;
        if (lower.contains("target") || lower.contains("sitemap") || lower.contains("site map")) return TOOL_TARGET;
        if (lower.contains("repeater"))  return TOOL_REPEATER;
        if (lower.contains("intruder"))  return TOOL_INTRUDER;
        if (lower.contains("scanner"))   return TOOL_SCANNER;
        return lower.isEmpty() ? TOOL_UNKNOWN : lower;
    }

    private static String mapToJson(Map<String, String> map) {
        JsonBuilder jb = new JsonBuilder();
        jb.objectStart();
        for (Map.Entry<String, String> e : map.entrySet()) {
            jb.field(e.getKey(), e.getValue());
        }
        jb.objectEnd();
        return jb.toString();
    }
}

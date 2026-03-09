package nexus;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/**
 * Collects items from Burp's Proxy History and Site Map,
 * converting them into {@link NexusItem} objects with full
 * HTTP parsing — no XML round-trip needed.
 * <p>
 * Preserves the deep-crawl behavior: selecting a host grabs
 * ALL request/response pairs for that host, not just the root.
 */
final class NexusCollector {

    private final MontoyaApi api;

    NexusCollector(MontoyaApi api) {
        this.api = api;
    }

    // ---- extract unique hosts from a selection -------------------------

    List<String> extractHosts(List<HttpRequestResponse> items) {
        Set<String> hosts = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (HttpRequestResponse item : items) {
            try {
                if (item.request() != null && item.request().httpService() != null) {
                    hosts.add(item.request().httpService().host());
                }
            } catch (Exception ignored) {}
        }
        return new ArrayList<>(hosts);
    }

    // ---- deep-crawl: collect all items for given hosts -----------------

    List<NexusItem> collectForHosts(List<String> hosts) {
        if (hosts == null || hosts.isEmpty()) return List.of();
        Set<String> hostSet = new HashSet<>();
        for (String h : hosts) hostSet.add(h.toLowerCase(Locale.ROOT));

        Map<String, Boolean> seen = new HashMap<>();
        List<NexusItem> merged = new ArrayList<>();
        int counter = 1;

        // Proxy History
        try {
            for (ProxyHttpRequestResponse proxyItem : api.proxy().history()) {
                try {
                    HttpRequest req = proxyItem.request();
                    if (req == null || req.httpService() == null) continue;
                    if (!hostSet.contains(req.httpService().host().toLowerCase(Locale.ROOT))) continue;

                    String key = sha256(req.toByteArray().getBytes());
                    if (seen.containsKey(key)) continue;
                    seen.put(key, Boolean.TRUE);

                    Instant time = extractTime(proxyItem);
                    NexusItem item = buildItem(counter++, req, proxyItem.response(),
                        NexusItem.TOOL_PROXY, time);
                    merged.add(item);
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            api.logging().logToError("[!] Error reading proxy history: " + e.getMessage());
        }

        // Site Map
        try {
            for (HttpRequestResponse siteItem : api.siteMap().requestResponses()) {
                try {
                    HttpRequest req = siteItem.request();
                    if (req == null || req.httpService() == null) continue;
                    if (!hostSet.contains(req.httpService().host().toLowerCase(Locale.ROOT))) continue;

                    String key = sha256(req.toByteArray().getBytes());
                    if (seen.containsKey(key)) continue;
                    seen.put(key, Boolean.TRUE);

                    NexusItem item = buildItem(counter++, req, siteItem.response(),
                        NexusItem.TOOL_TARGET, null);
                    merged.add(item);
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            api.logging().logToError("[!] Error reading site map: " + e.getMessage());
        }

        api.logging().logToOutput(String.format(
            "[*] Deep-crawl: %d unique items for hosts: %s",
            merged.size(), String.join(", ", hosts)));

        return merged;
    }

    // ---- collect everything (full project export) ----------------------

    List<NexusItem> collectAll(boolean scopeOnly) {
        Map<String, Boolean> seen = new HashMap<>();
        List<NexusItem> merged = new ArrayList<>();
        int counter = 1;

        // Proxy History
        try {
            for (ProxyHttpRequestResponse proxyItem : api.proxy().history()) {
                try {
                    HttpRequest req = proxyItem.request();
                    if (req == null) continue;
                    if (scopeOnly && !isInScope(req)) continue;

                    String key = sha256(req.toByteArray().getBytes());
                    if (seen.containsKey(key)) continue;
                    seen.put(key, Boolean.TRUE);

                    Instant time = extractTime(proxyItem);
                    NexusItem item = buildItem(counter++, req, proxyItem.response(),
                        NexusItem.TOOL_PROXY, time);
                    merged.add(item);
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}

        // Site Map
        try {
            for (HttpRequestResponse siteItem : api.siteMap().requestResponses()) {
                try {
                    HttpRequest req = siteItem.request();
                    if (req == null) continue;
                    if (scopeOnly && !isInScope(req)) continue;

                    String key = sha256(req.toByteArray().getBytes());
                    if (seen.containsKey(key)) continue;
                    seen.put(key, Boolean.TRUE);

                    NexusItem item = buildItem(counter++, req, siteItem.response(),
                        NexusItem.TOOL_TARGET, null);
                    merged.add(item);
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}

        return merged;
    }

    // ---- build NexusItem from Montoya API objects ----------------------

    private NexusItem buildItem(int index, HttpRequest req, HttpResponse resp,
                                 String toolName, Instant time) {
        byte[] rawReq  = req.toByteArray().getBytes();
        byte[] rawResp = resp != null ? resp.toByteArray().getBytes() : new byte[0];
        String host    = req.httpService().host();
        int port       = req.httpService().port();
        boolean secure = req.httpService().secure();

        return NexusItem.fromRaw(index, rawReq, rawResp, host, port, secure, toolName, time);
    }

    /**
     * Extract the request timestamp from a ProxyHttpRequestResponse.
     * The Montoya API exposes {@code time()} on proxy items.
     */
    private Instant extractTime(ProxyHttpRequestResponse proxyItem) {
        try {
            // Montoya API: ProxyHttpRequestResponse.time() returns java.time.ZonedDateTime (2024+)
            // or String in older versions. We handle both gracefully.
            Object timeObj = proxyItem.getClass().getMethod("time").invoke(proxyItem);
            if (timeObj instanceof java.time.ZonedDateTime) {
                return ((java.time.ZonedDateTime) timeObj).toInstant();
            } else if (timeObj instanceof String) {
                return java.time.ZonedDateTime.parse((String) timeObj).toInstant();
            }
        } catch (Exception ignored) {
            // Fallback if the time() method is not available in this API version
        }
        return Instant.now();
    }

    // ---- helpers -------------------------------------------------------

    private boolean isInScope(HttpRequest request) {
        try {
            return api.scope().isInScope(request.url());
        } catch (Exception e) {
            return true; // fail-open, same as old extension
        }
    }

    private static String sha256(byte[] data) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return Arrays.toString(data);
        }
    }
}

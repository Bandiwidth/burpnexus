package nexus;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;

class RegressionTest {
    @TempDir Path dir;
    NexusItem item(String method, String path, String body, String response) {
        String req = method + " " + path + " HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer headersecret\r\nCookie: sid=cookiesecret\r\nContent-Type: application/json\r\n\r\n" + body;
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1; Secure\r\nSet-Cookie: b=2\r\n\r\n" + response;
        return NexusItem.fromRaw(1, req.getBytes(StandardCharsets.UTF_8), resp.getBytes(StandardCharsets.UTF_8), "example.test", 8443, true, "proxy", Instant.parse("2026-09-15T14:00:00Z"));
    }
    NexusExport corpus() {
        NexusExport export = new NexusExport();
        export.items = new ArrayList<>(List.of(item("GET", "/api/users/12?id=12", "", "{\"id\":12}"),
            item("GET", "/search?q=hello", "", "hello"), item("POST", "/api/orders", "{\"id\":12}", "Traceback (most recent call last)")));
        ItemFilter.reindex(export.items); return export;
    }
    @Test void structuredJsonArrays() {
        String json = new JsonBuilder().objectStart().key("a").arrayStart().objectStart().field("x", "}\\\"\n日本語").objectEnd().objectStart().field("y", 2).objectEnd().arrayEnd().field("b", true).objectEnd().toPrettyString();
        JsonObject parsed = JsonParser.parseString(json).getAsJsonObject();
        assertEquals(2, parsed.getAsJsonArray("a").size()); assertTrue(parsed.get("b").getAsBoolean());
    }
    @Test void traversalSegmentsContained() throws Exception {
        List<String> segments = WriterEngine.urlToPathSegments("", "/%2e%2e/%2e%2e/CON/a");
        assertFalse(segments.contains("..")); assertFalse(segments.contains("CON"));
        Path target = dir; for (String s : segments) target = target.resolve(s);
        assertTrue(SafePaths.within(dir, target).startsWith(dir));
        assertThrows(java.io.IOException.class, () -> SafePaths.within(dir, dir.resolve("../outside")));
    }
    @Test void portableNames() { assertTrue(SafePaths.segment("NUL").startsWith("_")); assertTrue(SafePaths.segment("x".repeat(300)).length() <= 64); }
    @Test void unsafeMethodCannotEscape() {
        NexusItem i = item("../../GET", "/", "", ""); assertFalse(i.slug.contains("/"));
    }
    @Test void duplicateCookiesPreserved() { assertTrue(item("GET", "/", "", "").responseHeaders.get("Set-Cookie").contains("\n")); }
    @Test void absoluteTargetAndIpv6() {
        NexusItem i = item("GET", "https://example.test/a?q=1", "", ""); assertEquals("https://example.test:8443/a?q=1", i.url);
    }
    @Test void redactsUrlBodyHeadersAndRaw() {
        NexusItem i = item("POST", "/login?access%5Ftoken=urlsecret", "{\"password\":123,\"nested\":{\"token\":\"bodysecret\"}}", "{\"secret\":\"responsesecret\"}");
        ItemFilter.redactSecrets(List.of(i)); String out = i.toJson();
        for (String secret : List.of("headersecret", "cookiesecret", "urlsecret", "123", "bodysecret", "responsesecret")) assertFalse(out.contains(secret), secret);
    }
    @Test void redactsFormFirstField() { assertFalse(Redactor.text("password=formsecret&ok=1").contains("formsecret")); }
    @Test void malformedRegexErrors() { assertThrows(IllegalArgumentException.class, () -> ItemFilter.filterByRegex(List.of(), "[", ExportConfig.RegexTarget.BOTH)); }
    @Test void invalidTimeErrors() { assertThrows(IllegalArgumentException.class, () -> ItemFilter.filterByTimeRange(List.of(), "nonsense", "")); }
    @Test void dateUpperBoundIncludesWholeDay() {
        NexusItem i = item("GET", "/", "", ""); i.timeParsed = LocalDateTime.of(2026,9,15,18,0).atZone(ZoneId.systemDefault());
        assertEquals(1, ItemFilter.filterByTimeRange(List.of(i), "2026-09-15", "2026-09-15").size());
    }
    @Test void dedupKeepsDifferentResponses() {
        NexusItem a=item("GET","/","","a"), b=item("GET","/","","b");
        assertEquals(2,ItemFilter.deduplicate(List.of(a,b)).size());
        assertEquals(1,ItemFilter.deduplicate(List.of(a,a)).size());
    }
    @Test void allLayoutsProduceValidJson() throws Exception {
        for (ExportConfig.OutputMode mode : ExportConfig.OutputMode.values()) {
            Path out=dir.resolve(mode.name()); new WriterEngine(out, ExportConfig.builder().outputMode(mode).includeMd(true).build()).write(corpus());
            try (var files=Files.walk(out)) { for(Path f:files.filter(p->p.toString().endsWith(".json")).toList()) assertNotNull(JsonParser.parseString(Files.readString(f))); }
        }
    }
    @Test void writerPropagatesFailure() throws Exception {
        Files.writeString(dir.resolve("blocked"),"file");
        assertThrows(java.io.IOException.class, () -> new WriterEngine(dir.resolve("blocked"),ExportConfig.builder().build()).write(corpus()));
    }
    @Test void fuzzTemplatesAndWorkspace() throws Exception {
        NexusExport export=corpus(); SecurityAnalyzer.generateSecurityFindings(export,dir);
        SecurityAnalyzer.generateParamIndex(export,dir); SecurityAnalyzer.generateAiPrompts(export,dir);
        SecurityAnalyzer.generateFuzzManifest(export,dir); SecurityAnalyzer.generateNucleiTemplates(export,dir); WorkspaceExport.write(dir);
        JsonObject manifest=JsonParser.parseString(Files.readString(dir.resolve("FUZZ_MANIFEST.json"))).getAsJsonObject();
        assertTrue(manifest.getAsJsonArray("fuzz_cases").size()>0);
        try(var files=Files.list(dir.resolve("nuclei-templates"))) {
            List<Path> templates=files.toList();assertFalse(templates.isEmpty());
            for(Path t:templates) { JsonObject obj=JsonParser.parseString(Files.readString(t)).getAsJsonObject();assertEquals("info",obj.getAsJsonObject("info").get("severity").getAsString()); }
        }
        assertTrue(Files.exists(dir.resolve("BurpNexus.code-workspace")));
    }
    @Test void mutationUsesSourcePortMethodBodyAndParameter() {
        NexusItem i=item("POST","/orders?keep=1","{\"id\":12}","");
        Map<String,Object> req=ActiveArtifacts.mutate(i,new ActiveArtifacts.Point("json","id","12",0),"13");
        assertEquals("https://example.test:8443/orders?keep=1",req.get("url"));assertEquals("POST",req.get("method"));
        assertEquals(13,JsonParser.parseString((String)req.get("body")).getAsJsonObject().get("id").getAsInt());
    }
    @Test void shellQuotesUntrustedStrings() { assertEquals("'a'\"'\"'b'",ActiveArtifacts.quote("a'b")); }
    @Test void burpHasNoProviderClientOrKeyControls() throws Exception {
        assertThrows(ClassNotFoundException.class, () -> Class.forName("nexus.LLMClient"));
        final javax.swing.JPanel[] panel = new javax.swing.JPanel[1];
        javax.swing.SwingUtilities.invokeAndWait(() -> panel[0] = new NexusTab(null).getPanel());
        assertNoAiControls(panel[0]);
    }
    void assertNoAiControls(java.awt.Container parent) {
        for (java.awt.Component c : parent.getComponents()) {
            assertFalse(c instanceof javax.swing.JPasswordField);
            if (c instanceof javax.swing.AbstractButton b) assertFalse(b.getText().matches(".*(Ask AI|OpenAI|Anthropic|Gemini).*"));
            if (c instanceof java.awt.Container child) assertNoAiControls(child);
        }
    }
    @Test void fullPresetIncludesPendingFeatures() { assertTrue(NexusProfiles.TAB_PRESETS[0].config.generateFuzz); assertTrue(NexusProfiles.TAB_PRESETS[0].config.generateNuclei); }
    @Test void writesVsCodeContractFixture() throws Exception {
        Path target = Path.of(System.getProperty("nexus.contractDir", dir.resolve("contract").toString()));
        NexusExport export = corpus();
        ItemFilter.redactSecrets(export.items);
        new WriterEngine(target, ExportConfig.builder().outputMode(ExportConfig.OutputMode.SITEMAP).fullAnalysis(true).build()).write(export);
        SecurityAnalyzer.generateSecurityFindings(export, target);
        WorkspaceExport.write(target);
        assertTrue(Files.exists(target.resolve("attack-surface-index.json")));
        assertTrue(Files.readString(target.resolve("VSCODE_ANALYSIS.md")).contains("Connect Export to Source Repository"));
    }
    @Test void scopeFailsClosed() throws Exception {
        burp.api.montoya.MontoyaApi api=(burp.api.montoya.MontoyaApi)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class[]{burp.api.montoya.MontoyaApi.class},(p,m,a)->{throw new IllegalStateException("scope unavailable");});
        var method=NexusCollector.class.getDeclaredMethod("isInScope",burp.api.montoya.http.message.requests.HttpRequest.class); method.setAccessible(true);
        assertEquals(false,method.invoke(new NexusCollector(api),new Object[]{null}));
    }
    @Test void mixedCaseHeadersReconstructValidLines() {
        var parsed=NexusItem.parseHttpMessage("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\n\r\n");
        assertEquals(1,parsed.headers.size());
        NexusItem i=item("GET","/","","");i.responseHeaders=parsed.headers;
        assertTrue(i.reconstructResponseRaw().contains("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n"));
    }
    @Test void parameterNameCannotMatchUnrelatedPath() {
        assertTrue(ItemFilter.filterByParameter(List.of(item("GET","/13","","")),"missing","13",true).isEmpty());
    }
    @Test void jwtAndCookieChecksUseEvidence() throws Exception {
        NexusExport e=new NexusExport();NexusItem i=item("GET","/","","");
        String header=Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload=Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"1\"}".getBytes(StandardCharsets.UTF_8));
        i.requestHeaders.put("Authorization","Bearer "+header+"."+payload+".");
        i.responseHeaders.put("Set-Cookie","good=1; Secure; HttpOnly; SameSite=Lax\nbad=secure; SameSite=Lax");
        i.responseHeaders.put("Access-Control-Allow-Origin","https://example.test");i.responseHeaders.put("Access-Control-Allow-Credentials","true");
        e.items=new ArrayList<>(List.of(i));SecurityAnalyzer.generateSecurityFindings(e,dir);
        var findings=JsonParser.parseString(Files.readString(dir.resolve("security-findings.json"))).getAsJsonArray();
        boolean jwt=false,cookie=false,cors=false;
        for(var f:findings) {
            var obj=f.getAsJsonObject();String category=obj.get("category").getAsString();
            if(category.equals("JWT Security")) jwt=true;
            if(category.equals("Cookie Security")) {cookie=true;assertTrue(obj.get("title").getAsString().contains("bad"));assertTrue(obj.get("detail").getAsString().contains("missing Secure"));}
            if(category.equals("CORS Misconfiguration")) {cors=true;assertEquals("Info",obj.get("severity").getAsString());}
        }
        assertTrue(jwt);assertTrue(cookie);assertTrue(cors);
    }

    @Test void parameterSearchParsesNestedBooleanAndEscapes() {
        NexusItem i=item("POST","/","{\"outer\":{\"active\":true,\"name\":\"a\\\"b\"}}","");
        assertEquals(1,ItemFilter.filterByParameter(List.of(i),"active","true",true).size());
        assertEquals(1,ItemFilter.filterByParameter(List.of(i),"name","a\"b",true).size());
    }

}

package nexus;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

/**
 * BurpNexus — Self-contained Burp Suite extension.
 * <p>
 * All parsing, writing, analysis, filtering, and redaction run
 * natively in Java. No Python CLI dependency. No XML round-trip.
 * <p>
 * Discovered via {@code META-INF/services/burp.api.montoya.BurpExtension}.
 */
public class BurpNexusExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BurpNexus");

        Logging log = api.logging();
        NexusCollector collector = new NexusCollector(api);
        NexusEngine engine      = new NexusEngine(api, collector);

        // Register right-click context menu
        api.userInterface().registerContextMenuItemsProvider(
            new NexusContextMenu(api, collector, engine));

        // Register suite tab
        api.userInterface().registerSuiteTab(
            "BurpNexus", new NexusTab(engine, collector).getPanel());

        log.logToOutput("[+] BurpNexus v1.0.0 loaded.");
        log.logToOutput("[*] Self-contained export engine — no Python/CLI required.");
        log.logToOutput("[*] Right-click in Proxy/Site Map for export options.");
        log.logToOutput("[*] Use the BurpNexus tab for full project exports, parameter search, and regex search.");
        log.logToOutput("[*] Output: ~/burpnexus_exports/");
    }
}

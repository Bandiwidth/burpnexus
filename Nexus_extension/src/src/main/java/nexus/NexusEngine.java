package nexus;

import burp.api.montoya.MontoyaApi;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Orchestrates the full export pipeline on a background thread:
 * collect → convert → filter → write → analyze.
 */
final class NexusEngine {

    private final MontoyaApi api;
    private final NexusCollector collector;

    private static final String HOME = System.getProperty("user.home");

    /** Callback for status updates — invoked on the export thread. */
    interface StatusCallback {
        void onStatus(String message);
    }

    NexusEngine(MontoyaApi api, NexusCollector collector) {
        this.api       = api;
        this.collector = collector;
    }

    // ---- public entry points -------------------------------------------

    /**
     * Export the given pre-collected items with the specified configuration.
     * Runs on a daemon background thread.
     */
    void exportAsync(List<NexusItem> items, ExportConfig cfg, StatusCallback statusCb) {
        if (items == null || items.isEmpty()) {
            api.logging().logToError("[-] No items to export.");
            if (statusCb != null) statusCb.onStatus("No items to export.");
            return;
        }

        Thread t = new Thread(() -> runExport(items, cfg, statusCb), "BurpNexus-Export");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Collect all items (full project or scope-only) and export.
     */
    void exportAllAsync(ExportConfig cfg, StatusCallback statusCb) {
        Thread t = new Thread(() -> {
            try {
                if (statusCb != null) statusCb.onStatus("Collecting items...");
                List<NexusItem> items = collector.collectAll(cfg.scopeOnly);
                api.logging().logToOutput("[*] Collected " + items.size() + " items.");
                runExport(items, cfg, statusCb);
            } catch (OutOfMemoryError oom) {
                api.logging().logToError("[-] OUT OF MEMORY during collection: " + oom.getMessage());
                if (statusCb != null) statusCb.onStatus("Error: Out of memory during collection.");
            } catch (Throwable t1) {
                api.logging().logToError("[-] Collection error: " + t1.getMessage());
                if (statusCb != null) statusCb.onStatus("Error: " + t1.getMessage());
            }
        }, "BurpNexus-Export");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Collect for specific hosts and export.
     */
    void exportForHostsAsync(List<String> hosts, ExportConfig cfg, StatusCallback statusCb) {
        Thread t = new Thread(() -> {
            try {
                if (statusCb != null) statusCb.onStatus("Deep-crawling hosts...");
                List<NexusItem> items = collector.collectForHosts(hosts);
                runExport(items, cfg, statusCb);
            } catch (OutOfMemoryError oom) {
                api.logging().logToError("[-] OUT OF MEMORY during host crawl: " + oom.getMessage());
                if (statusCb != null) statusCb.onStatus("Error: Out of memory during collection.");
            } catch (Throwable t1) {
                api.logging().logToError("[-] Collection error: " + t1.getMessage());
                if (statusCb != null) statusCb.onStatus("Error: " + t1.getMessage());
            }
        }, "BurpNexus-Export");
        t.setDaemon(true);
        t.start();
    }

    // ---- core pipeline -------------------------------------------------

    private void runExport(List<NexusItem> items, ExportConfig cfg, StatusCallback statusCb) {
        try {
            String ts = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String subdir = "export_" + ts;

            // Determine output subfolder for special search modes
            if (cfg.hasParamSearch()) {
                String label = sanitiseLabel(cfg.paramSearchName) + "_" + sanitiseLabel(cfg.paramSearchValue);
                subdir = "param_search_" + label + "_" + ts;
            } else if (cfg.hasRegexSearch()) {
                String label = sanitiseLabel(cfg.regexPattern);
                subdir = "regex_search_" + label + "_" + ts;
            }

            Path outputDir = Paths.get(HOME, "burpnexus_exports", subdir);

            // Step 1: Filter
            if (statusCb != null) statusCb.onStatus("Filtering " + items.size() + " items...");
            api.logging().logToOutput("[*] Applying filters to " + items.size() + " items...");

            List<NexusItem> filtered = ItemFilter.applyAll(items, cfg);

            if (filtered.isEmpty()) {
                api.logging().logToOutput("[!] No items remain after filtering.");
                if (statusCb != null) statusCb.onStatus("No items match the current filters.");
                return;
            }

            api.logging().logToOutput("[*] " + filtered.size() + " items after filtering.");

            // Step 2: Build export container
            NexusExport export = new NexusExport();
            export.items = filtered;
            export.exportTime = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", java.util.Locale.US).format(new Date());

            // Step 3: Write files
            if (statusCb != null) statusCb.onStatus("Writing " + filtered.size() + " items to disk...");

            WriterEngine writer = new WriterEngine(outputDir, cfg);
            writer.setProgressCallback((current, total) -> {
                if (statusCb != null && current % 50 == 0) {
                    statusCb.onStatus(String.format("Writing... %,d / %,d items", current, total));
                }
            });
            writer.write(export);

            api.logging().logToOutput(String.format(
                "[+] Written: %d JSON, %d MD files to %s",
                writer.getWrittenJson(), writer.getWrittenMd(), outputDir));

            // Step 4: Analysis
            if (cfg.autoFindings) {
                if (statusCb != null) statusCb.onStatus("Running security analysis...");
                SecurityAnalyzer.generateSecurityFindings(export, outputDir);
                api.logging().logToOutput("[+] Security findings generated.");
            }
            if (cfg.paramIndex) {
                if (statusCb != null) statusCb.onStatus("Generating parameter index...");
                SecurityAnalyzer.generateParamIndex(export, outputDir);
                api.logging().logToOutput("[+] Parameter index generated.");
            }
            if (cfg.aiPrompts) {
                if (statusCb != null) statusCb.onStatus("Generating AI prompts...");
                SecurityAnalyzer.generateAiPrompts(export, outputDir);
                api.logging().logToOutput("[+] AI prompts generated.");
            }

            // Done
            String doneMsg = String.format("Done! %,d items exported to %s",
                filtered.size(), outputDir);
            api.logging().logToOutput("[+] " + doneMsg);
            if (statusCb != null) statusCb.onStatus(doneMsg);

        } catch (OutOfMemoryError oom) {
            api.logging().logToError("[-] OUT OF MEMORY: " + oom.getMessage());
            if (statusCb != null) statusCb.onStatus("Error: Out of memory — too many/large items. Try filtering by tool or status first.");
        } catch (Throwable t) {
            api.logging().logToError("[-] Export error: " + t.getClass().getName() + ": " + t.getMessage());
            if (statusCb != null) statusCb.onStatus("Error: " + t.getMessage());
        }
    }

    private static String sanitiseLabel(String input) {
        if (input == null || input.isEmpty()) return "any";
        String s = input.replaceAll("[^a-zA-Z0-9_-]", "_");
        if (s.length() > 30) s = s.substring(0, 30);
        return s;
    }
}

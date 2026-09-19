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

    private final java.util.concurrent.atomic.AtomicBoolean busy = new java.util.concurrent.atomic.AtomicBoolean();
    private volatile Thread worker;
    private volatile boolean closed;

    private void submit(Runnable task, StatusCallback callback) {
        if (closed || !busy.compareAndSet(false, true)) {
            if (callback != null) callback.onStatus("Error: Export engine is busy or unloaded.");
            return;
        }
        worker = new Thread(() -> {
            try { task.run(); }
            catch (Exception ex) {
                api.logging().logToError("[-] Export failed: " + ex.getMessage());
                if (callback != null) callback.onStatus("Error: " + ex.getMessage());
            } finally { busy.set(false); }
        }, "BurpNexus-Export");
        worker.setDaemon(true);
        worker.start();
    }
    void close() { closed = true; Thread t = worker; if (t != null) t.interrupt(); }
    void exportAsync(List<NexusItem> items, ExportConfig cfg, StatusCallback cb) {
        submit(() -> runExport(items, cfg, cb), cb);
    }
    void exportAllAsync(ExportConfig cfg, StatusCallback cb) {
        submit(() -> { if (cb != null) cb.onStatus("Collecting items..."); runExport(collector.collectAll(cfg.scopeOnly), cfg, cb); }, cb);
    }
    void exportForHostsAsync(List<String> hosts, ExportConfig cfg, StatusCallback cb) {
        submit(() -> { if (cb != null) cb.onStatus("Collecting selected hosts..."); runExport(collector.collectForHosts(hosts, cfg.scopeOnly), cfg, cb); }, cb);
    }

    // ---- core pipeline -------------------------------------------------

    private void runExport(List<NexusItem> items, ExportConfig cfg, StatusCallback statusCb) {
        try {
            String ts = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS").format(new Date());
            String subdir = "export_" + ts;

            // Determine output subfolder for special search modes
            if (cfg.hasParamSearch()) {
                String label = sanitiseLabel(cfg.paramSearchName) + "_" + sanitiseLabel(cfg.paramSearchValue);
                subdir = "param_search_" + label + "_" + ts;
            } else if (cfg.hasRegexSearch()) {
                String label = sanitiseLabel(cfg.regexPattern);
                subdir = "regex_search_" + label + "_" + ts;
            }

            Path parent = Paths.get(HOME, "burpnexus_exports");
            java.nio.file.Files.createDirectories(parent);
            Path outputDir = java.nio.file.Files.createTempDirectory(parent, subdir + "_");

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
                WorkspaceExport.write(outputDir);
                api.logging().logToOutput("[+] AI prompts generated.");
            }
            if (cfg.generateFuzz) {
                // Auto-enable findings if not already generated (fuzz depends on findings)
                if (!cfg.autoFindings) {
                    SecurityAnalyzer.generateSecurityFindings(export, outputDir);
                }
                if (statusCb != null) statusCb.onStatus("Generating fuzz manifest...");
                SecurityAnalyzer.generateFuzzManifest(export, outputDir);
                api.logging().logToOutput("[+] Fuzz manifest generated.");
            }
            if (cfg.generateNuclei) {
                // Auto-enable findings if not already generated (nuclei depends on findings)
                if (!cfg.autoFindings && !cfg.generateFuzz) {
                    SecurityAnalyzer.generateSecurityFindings(export, outputDir);
                }
                if (statusCb != null) statusCb.onStatus("Generating Nuclei templates...");
                SecurityAnalyzer.generateNucleiTemplates(export, outputDir);
                api.logging().logToOutput("[+] Nuclei templates generated.");
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

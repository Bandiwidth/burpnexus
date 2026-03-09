package nexus;

import nexus.ExportConfig.OutputMode;

/**
 * Preset export profiles — mirrors every combination from the CLI
 * and the old extension, expressed as {@link ExportConfig} instances.
 * <p>
 * Used by both the context menu (right-click) and the quick-preset
 * buttons in the suite tab.
 */
final class NexusProfiles {

    private NexusProfiles() {}

    // ---- profile definition --------------------------------------------

    static final class Profile {
        final String label;
        final String category;
        final ExportConfig config;

        Profile(String category, String label, ExportConfig config) {
            this.category = category;
            this.label    = label;
            this.config   = config;
        }
    }

    // ---- context menu profiles (right-click) ---------------------------

    static final Profile[] CONTEXT_PROFILES = {
        // AI Analysis
        new Profile("AI Analysis", "Full AI Analysis (JSON + findings + prompts)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).dedupe(true)
                .fullAnalysis(true).build()),
        new Profile("AI Analysis", "Full AI Analysis (JSON + MD + findings + prompts)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).includeMd(true).dedupe(true)
                .fullAnalysis(true).build()),

        // Output Format
        new Profile("Output Format", "JSON only (sitemap)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).dedupe(true).build()),
        new Profile("Output Format", "Markdown only (sitemap)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).includeJson(false).includeMd(true)
                .dedupe(true).build()),
        new Profile("Output Format", "JSON + Markdown (sitemap)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).includeMd(true).dedupe(true).build()),

        // Layout Mode
        new Profile("Layout Mode", "Flat (by tool)",
            ExportConfig.builder()
                .outputMode(OutputMode.FLAT).dedupe(true).build()),
        new Profile("Layout Mode", "By Host",
            ExportConfig.builder()
                .outputMode(OutputMode.BY_HOST).dedupe(true).build()),
        new Profile("Layout Mode", "Host First",
            ExportConfig.builder()
                .outputMode(OutputMode.HOST_FIRST).dedupe(true).build()),
        new Profile("Layout Mode", "Split by Session",
            ExportConfig.builder()
                .outputMode(OutputMode.SPLIT_BY_SESSION).dedupe(true).build()),
        new Profile("Layout Mode", "By Time",
            ExportConfig.builder()
                .outputMode(OutputMode.BY_TIME).dedupe(true).build()),

        // Triage
        new Profile("Triage", "Errors + Auth only (401,403,5xx)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).onlyStatus("401,403,5xx")
                .dedupe(true).build()),
        new Profile("Triage", "Errors + Auth (JSON + MD)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).includeMd(true)
                .onlyStatus("401,403,5xx").dedupe(true).build()),

        // Redacted
        new Profile("Redacted", "Redacted JSON (secrets masked)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).redactSecrets(true)
                .dedupe(true).build()),
        new Profile("Redacted", "Redacted JSON + MD",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).includeMd(true)
                .redactSecrets(true).dedupe(true).build()),
        new Profile("Redacted", "Redacted + Session Split",
            ExportConfig.builder()
                .outputMode(OutputMode.SPLIT_BY_SESSION).redactSecrets(true)
                .dedupe(true).build()),

        // Scope
        new Profile("Scope", "In-Scope only (JSON + full analysis)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).dedupe(true)
                .fullAnalysis(true).scopeOnly(true).build()),
    };

    // ---- tab quick-export presets --------------------------------------

    static final Profile[] TAB_PRESETS = {
        new Profile("Quick", "\u25b6 Export: Full AI Analysis",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).dedupe(true)
                .fullAnalysis(true).build()),
        new Profile("Quick", "\u25b6 Export: JSON Only",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).dedupe(true).build()),
        new Profile("Quick", "\u25b6 Export: JSON + MD + Findings",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).includeMd(true).dedupe(true)
                .autoFindings(true).build()),
        new Profile("Quick", "\u25b6 Export: Triage (401,403,5xx)",
            ExportConfig.builder()
                .outputMode(OutputMode.SITEMAP).onlyStatus("401,403,5xx")
                .dedupe(true).build()),
        new Profile("Quick", "\u25b6 Export: Redacted + Session Split",
            ExportConfig.builder()
                .outputMode(OutputMode.SPLIT_BY_SESSION).redactSecrets(true)
                .dedupe(true).build()),
    };
}

package nexus;

/**
 * Structured export configuration — replaces CLI string flags with
 * typed fields.  Use the {@link Builder} for fluent construction.
 */
final class ExportConfig {

    // ---- output mode (mutually exclusive) ------------------------------
    enum OutputMode { FLAT, SITEMAP, BY_HOST, HOST_FIRST, SPLIT_BY_SESSION, BY_TIME }

    final OutputMode outputMode;

    // ---- format --------------------------------------------------------
    final boolean includeJson;
    final boolean includeMd;

    // ---- filtering -----------------------------------------------------
    final String  onlyTools;       // comma-separated, empty = all
    final String  onlyStatus;      // comma-separated with class support (4xx, 5xx)
    final boolean dedupe;

    // ---- redaction -----------------------------------------------------
    final boolean redactSecrets;

    // ---- time range ----------------------------------------------------
    final String  fromTime;        // ISO-ish string, empty = no lower bound
    final String  toTime;          // ISO-ish string, empty = no upper bound
    final boolean timeIncludeHost;

    // ---- analysis ------------------------------------------------------
    final boolean autoFindings;
    final boolean paramIndex;
    final boolean aiPrompts;
    final boolean generateFuzz;
    final boolean generateNuclei;

    // ---- scope ---------------------------------------------------------
    final boolean scopeOnly;

    // ---- parameter search (UI-only feature) ----------------------------
    final String  paramSearchName;
    final String  paramSearchValue;
    final boolean paramSearchExact; // false = contains

    // ---- regex search (UI-only feature) --------------------------------
    final String  regexPattern;
    final RegexTarget regexTarget;

    enum RegexTarget { BOTH, REQUEST, RESPONSE }

    // ---- verbose / progress --------------------------------------------
    final boolean verbose;

    private ExportConfig(Builder b) {
        this.outputMode       = b.outputMode;
        this.includeJson      = b.includeJson;
        this.includeMd        = b.includeMd;
        this.onlyTools        = b.onlyTools;
        this.onlyStatus       = b.onlyStatus;
        this.dedupe           = b.dedupe;
        this.redactSecrets    = b.redactSecrets;
        this.fromTime         = b.fromTime;
        this.toTime           = b.toTime;
        this.timeIncludeHost  = b.timeIncludeHost;
        this.autoFindings     = b.autoFindings;
        this.paramIndex       = b.paramIndex;
        this.aiPrompts        = b.aiPrompts;
        this.generateFuzz     = b.generateFuzz;
        this.generateNuclei   = b.generateNuclei;
        this.scopeOnly        = b.scopeOnly;
        this.paramSearchName  = b.paramSearchName;
        this.paramSearchValue = b.paramSearchValue;
        this.paramSearchExact = b.paramSearchExact;
        this.regexPattern     = b.regexPattern;
        this.regexTarget      = b.regexTarget;
        this.verbose          = b.verbose;
    }

    boolean hasFullAnalysis() {
        return autoFindings && paramIndex && aiPrompts && generateFuzz && generateNuclei;
    }

    boolean hasAnyAnalysis() {
        return autoFindings || paramIndex || aiPrompts || generateFuzz || generateNuclei;
    }

    boolean hasParamSearch() {
        return (paramSearchName != null && !paramSearchName.isEmpty())
            || (paramSearchValue != null && !paramSearchValue.isEmpty());
    }

    boolean hasRegexSearch() {
        return regexPattern != null && !regexPattern.isEmpty();
    }

    // ---- builder -------------------------------------------------------

    static Builder builder() {
        return new Builder();
    }

    static final class Builder {
        OutputMode  outputMode       = OutputMode.SITEMAP;
        boolean     includeJson      = true;
        boolean     includeMd        = false;
        String      onlyTools        = "";
        String      onlyStatus       = "";
        boolean     dedupe           = true;
        boolean     redactSecrets    = false;
        String      fromTime         = "";
        String      toTime           = "";
        boolean     timeIncludeHost  = false;
        boolean     autoFindings     = false;
        boolean     paramIndex       = false;
        boolean     aiPrompts        = false;
        boolean     generateFuzz     = false;
        boolean     generateNuclei   = false;
        boolean     scopeOnly        = false;
        String      paramSearchName  = "";
        String      paramSearchValue = "";
        boolean     paramSearchExact = false;
        String      regexPattern     = "";
        RegexTarget regexTarget      = RegexTarget.BOTH;
        boolean     verbose          = true;

        Builder outputMode(OutputMode m)       { this.outputMode = m; return this; }
        Builder includeJson(boolean v)         { this.includeJson = v; return this; }
        Builder includeMd(boolean v)           { this.includeMd = v; return this; }
        Builder onlyTools(String v)            { this.onlyTools = v == null ? "" : v; return this; }
        Builder onlyStatus(String v)           { this.onlyStatus = v == null ? "" : v; return this; }
        Builder dedupe(boolean v)              { this.dedupe = v; return this; }
        Builder redactSecrets(boolean v)       { this.redactSecrets = v; return this; }
        Builder fromTime(String v)             { this.fromTime = v == null ? "" : v; return this; }
        Builder toTime(String v)               { this.toTime = v == null ? "" : v; return this; }
        Builder timeIncludeHost(boolean v)     { this.timeIncludeHost = v; return this; }
        Builder autoFindings(boolean v)        { this.autoFindings = v; return this; }
        Builder paramIndex(boolean v)          { this.paramIndex = v; return this; }
        Builder aiPrompts(boolean v)           { this.aiPrompts = v; return this; }
        Builder generateFuzz(boolean v)        { this.generateFuzz = v; return this; }
        Builder generateNuclei(boolean v)      { this.generateNuclei = v; return this; }
        Builder fullAnalysis(boolean v)        { this.autoFindings = v; this.paramIndex = v; this.aiPrompts = v; this.generateFuzz = v; this.generateNuclei = v; return this; }
        Builder scopeOnly(boolean v)           { this.scopeOnly = v; return this; }
        Builder paramSearchName(String v)      { this.paramSearchName = v == null ? "" : v; return this; }
        Builder paramSearchValue(String v)     { this.paramSearchValue = v == null ? "" : v; return this; }
        Builder paramSearchExact(boolean v)    { this.paramSearchExact = v; return this; }
        Builder regexPattern(String v)         { this.regexPattern = v == null ? "" : v; return this; }
        Builder regexTarget(RegexTarget v)     { this.regexTarget = v; return this; }
        Builder verbose(boolean v)             { this.verbose = v; return this; }

        ExportConfig build() { return new ExportConfig(this); }
    }
}

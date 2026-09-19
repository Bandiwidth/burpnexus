package nexus;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Polished suite tab with titled sections, radio groups, checkboxes,
 * text fields, quick-preset buttons, parameter search, regex search,
 * and a live status bar.
 */
final class NexusTab {

    private final NexusEngine engine;
    private final JPanel panel;

    // ---- output mode radios --------------------------------------------
    private final JRadioButton rbSitemap      = new JRadioButton("Sitemap (recommended)", true);
    private final JRadioButton rbFlat         = new JRadioButton("Flat (by tool)");
    private final JRadioButton rbByHost       = new JRadioButton("By Host");
    private final JRadioButton rbHostFirst    = new JRadioButton("Host First");
    private final JRadioButton rbSplitSession = new JRadioButton("Split by Session");
    private final JRadioButton rbByTime       = new JRadioButton("By Time");

    // ---- scope radios --------------------------------------------------
    private final JRadioButton rbAllTraffic  = new JRadioButton("All traffic", true);
    private final JRadioButton rbScopeOnly   = new JRadioButton("In-scope only");

    // ---- option checkboxes ---------------------------------------------
    private final JCheckBox cbDedupe       = new JCheckBox("Deduplicate", true);
    private final JCheckBox cbIncludeMd    = new JCheckBox("Include Markdown");
    private final JCheckBox cbMdOnly       = new JCheckBox("Markdown only");
    private final JCheckBox cbRedact       = new JCheckBox("Redact secrets");
    private final JCheckBox cbFullAnalysis = new JCheckBox("Full analysis");
    private final JCheckBox cbFindings     = new JCheckBox("Auto findings");
    private final JCheckBox cbParamIndex   = new JCheckBox("Param index");
    private final JCheckBox cbAiPrompts    = new JCheckBox("VS Code review guide");
    private final JCheckBox cbFuzzManifest = new JCheckBox("Fuzz manifest");
    private final JCheckBox cbNucleiTpls   = new JCheckBox("Nuclei templates");

    // ---- filter text fields --------------------------------------------
    private final JTextField tfTools  = new JTextField(14);
    private final JTextField tfStatus = new JTextField(14);

    // ---- time range fields ---------------------------------------------
    private final JTextField tfFromTime = new JTextField(16);
    private final JTextField tfToTime   = new JTextField(16);
    private final JCheckBox cbTimeHost  = new JCheckBox("Include host in time dir");

    // ---- parameter search fields ---------------------------------------
    private final JTextField tfParamName   = new JTextField(14);
    private final JTextField tfParamValue  = new JTextField(14);
    private final JRadioButton rbContains  = new JRadioButton("Contains", true);
    private final JRadioButton rbExact     = new JRadioButton("Exact");
    private final JRadioButton rbParamJson = new JRadioButton("JSON", true);
    private final JRadioButton rbParamMd   = new JRadioButton("MD");

    // ---- regex search fields -------------------------------------------
    private final JTextField tfRegex         = new JTextField(28);
    private final JRadioButton rbRegexBoth   = new JRadioButton("Both", true);
    private final JRadioButton rbRegexReq    = new JRadioButton("Request only");
    private final JRadioButton rbRegexResp   = new JRadioButton("Response only");
    private final JRadioButton rbRegexJson   = new JRadioButton("JSON", true);
    private final JRadioButton rbRegexMd     = new JRadioButton("MD");

    // ---- main export button --------------------------------------------
    private final JButton btnExport = new JButton("EXPORT");

    // ---- status bar ----------------------------------------------------
    private final JLabel lblStatus = new JLabel("Ready");

    // ---- concurrency guard ---------------------------------------------
    private volatile boolean exporting = false;

    NexusTab(NexusEngine engine) {
        this.engine    = engine;
        this.panel     = buildUi();
    }

    JPanel getPanel() { return panel; }

    // ====================================================================
    // UI construction
    // ====================================================================

    private JPanel buildUi() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        // ---- header ----------------------------------------------------
        JPanel header = new JPanel(new BorderLayout());
        JLabel title = new JLabel("BURPNEXUS");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        JLabel subtitle = new JLabel("Local traffic export — connect to source code in VS Code");
        subtitle.setFont(subtitle.getFont().deriveFont(Font.PLAIN, 12f));
        header.add(title, BorderLayout.NORTH);
        header.add(subtitle, BorderLayout.SOUTH);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        // ---- main body (two columns) -----------------------------------
        JPanel body = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(4, 4, 4, 4);

        // Left column
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.45;
        body.add(buildOutputModePanel(), gbc);

        gbc.gridy = 1;
        body.add(buildScopePanel(), gbc);

        gbc.gridy = 2;
        body.add(buildTimeRangePanel(), gbc);

        // Right column
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 0.55;
        body.add(buildOptionsPanel(), gbc);

        gbc.gridy = 1;
        body.add(buildFilterPanel(), gbc);

        gbc.gridy = 2;
        body.add(buildParamSearchPanel(), gbc);

        // Regex search (full width)
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2; gbc.weightx = 1.0;
        body.add(buildRegexSearchPanel(), gbc);

        // Quick export (full width)
        gbc.gridy = 4;
        body.add(buildQuickExportPanel(), gbc);

        // Main export button (full width, prominent)
        gbc.gridy = 5;
        body.add(buildMainExportPanel(), gbc);

        // ---- status bar ------------------------------------------------
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY),
            BorderFactory.createEmptyBorder(6, 4, 4, 4)));
        lblStatus.setFont(lblStatus.getFont().deriveFont(Font.PLAIN, 11f));
        statusBar.add(new JLabel("STATUS: "), BorderLayout.WEST);
        statusBar.add(lblStatus, BorderLayout.CENTER);

        // ---- scrollable body -------------------------------------------
        JScrollPane scrollPane = new JScrollPane(body);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        root.add(header, BorderLayout.NORTH);
        root.add(scrollPane, BorderLayout.CENTER);
        root.add(statusBar, BorderLayout.SOUTH);

        // wire up full analysis checkbox
        cbFullAnalysis.addActionListener(e -> {
            boolean sel = cbFullAnalysis.isSelected();
            cbFindings.setSelected(sel);
            cbParamIndex.setSelected(sel);
            cbAiPrompts.setSelected(sel);
            cbFuzzManifest.setSelected(sel);
            cbNucleiTpls.setSelected(sel);
        });

        // wire up md-only exclusivity
        cbMdOnly.addActionListener(e -> {
            if (cbMdOnly.isSelected()) cbIncludeMd.setSelected(false);
        });
        cbIncludeMd.addActionListener(e -> {
            if (cbIncludeMd.isSelected()) cbMdOnly.setSelected(false);
        });

        return root;
    }

    // ---- sub-panels ----------------------------------------------------

    private JPanel buildOutputModePanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(titledBorder("OUTPUT MODE"));
        ButtonGroup bg = new ButtonGroup();
        for (JRadioButton rb : new JRadioButton[]{rbSitemap, rbFlat, rbByHost, rbHostFirst, rbSplitSession, rbByTime}) {
            bg.add(rb);
            p.add(rb);
        }
        return p;
    }

    private JPanel buildScopePanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(titledBorder("SCOPE"));
        ButtonGroup bg = new ButtonGroup();
        bg.add(rbAllTraffic); bg.add(rbScopeOnly);
        p.add(rbAllTraffic); p.add(rbScopeOnly);
        return p;
    }

    private JPanel buildTimeRangePanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(titledBorder("TIME RANGE (optional)"));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; p.add(new JLabel("From:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        tfFromTime.setToolTipText("e.g. 2026-03-02 10:00 or ISO datetime");
        p.add(tfFromTime, g);

        g.gridx = 0; g.gridy = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;
        p.add(new JLabel("To:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        tfToTime.setToolTipText("e.g. 2026-03-02 11:00 or ISO datetime");
        p.add(tfToTime, g);

        g.gridx = 0; g.gridy = 2; g.gridwidth = 2;
        p.add(cbTimeHost, g);

        JLabel hint = new JLabel("Format: yyyy-MM-dd HH:mm  or  yyyy-MM-dd  or  ISO-8601 (e.g. 2026-03-02 10:00)");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 10f));
        hint.setForeground(Color.GRAY);
        g.gridy = 3;
        p.add(hint, g);
        return p;
    }

    private JPanel buildOptionsPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(titledBorder("OPTIONS"));
        for (JCheckBox cb : new JCheckBox[]{cbDedupe, cbIncludeMd, cbMdOnly, cbRedact, cbFullAnalysis, cbFindings, cbParamIndex, cbAiPrompts, cbFuzzManifest, cbNucleiTpls}) {
            p.add(cb);
        }
        return p;
    }

    private JPanel buildFilterPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(titledBorder("FILTER (optional)"));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; p.add(new JLabel("Tools:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        tfTools.setToolTipText("e.g. proxy,repeater,scanner");
        p.add(tfTools, g);

        g.gridx = 0; g.gridy = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;
        p.add(new JLabel("Status:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        tfStatus.setToolTipText("e.g. 401,403,5xx");
        p.add(tfStatus, g);
        return p;
    }

    private JPanel buildParamSearchPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(titledBorder("PARAMETER SEARCH"));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; p.add(new JLabel("Name:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        p.add(tfParamName, g);

        g.gridx = 0; g.gridy = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;
        p.add(new JLabel("Value:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        p.add(tfParamValue, g);

        g.gridx = 0; g.gridy = 2; g.gridwidth = 2; g.fill = GridBagConstraints.NONE;
        JPanel matchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        ButtonGroup matchBg = new ButtonGroup();
        matchBg.add(rbContains); matchBg.add(rbExact);
        matchPanel.add(rbContains); matchPanel.add(rbExact);
        ButtonGroup fmtBg = new ButtonGroup();
        fmtBg.add(rbParamJson); fmtBg.add(rbParamMd);
        matchPanel.add(Box.createHorizontalStrut(8));
        matchPanel.add(new JLabel("Format:"));
        matchPanel.add(rbParamJson); matchPanel.add(rbParamMd);
        p.add(matchPanel, g);

        g.gridy = 3;
        JButton btnParamSearch = new JButton("Search & Export");
        btnParamSearch.addActionListener(e -> doParamSearch());
        p.add(btnParamSearch, g);
        return p;
    }

    private JPanel buildRegexSearchPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(titledBorder("REGEX EXPORT"));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0; p.add(new JLabel("Pattern:"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1; g.gridwidth = 3;
        tfRegex.setToolTipText("Java regex, e.g. eyJ[A-Za-z0-9_-]+\\.eyJ or (?i)password\\s*[:=]");
        p.add(tfRegex, g);

        g.gridx = 0; g.gridy = 1; g.gridwidth = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;
        p.add(new JLabel("Search in:"), g);
        g.gridx = 1; g.gridwidth = 3;
        JPanel targetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        ButtonGroup tBg = new ButtonGroup();
        tBg.add(rbRegexBoth); tBg.add(rbRegexReq); tBg.add(rbRegexResp);
        targetPanel.add(rbRegexBoth); targetPanel.add(rbRegexReq); targetPanel.add(rbRegexResp);
        targetPanel.add(Box.createHorizontalStrut(8));
        targetPanel.add(new JLabel("Format:"));
        ButtonGroup rfBg = new ButtonGroup();
        rfBg.add(rbRegexJson); rfBg.add(rbRegexMd);
        targetPanel.add(rbRegexJson); targetPanel.add(rbRegexMd);
        p.add(targetPanel, g);

        g.gridx = 0; g.gridy = 2; g.gridwidth = 4;
        JButton btnRegex = new JButton("Search & Export");
        btnRegex.addActionListener(e -> doRegexSearch());
        p.add(btnRegex, g);
        return p;
    }

    private JPanel buildQuickExportPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        p.setBorder(titledBorder("QUICK EXPORT (presets)"));

        for (NexusProfiles.Profile profile : NexusProfiles.TAB_PRESETS) {
            JButton btn = new JButton(profile.label);
            btn.addActionListener(e -> runPreset(profile.config));
            p.add(btn);
        }

        return p;
    }

    private JPanel buildMainExportPanel() {
        JPanel p = new JPanel(new BorderLayout(8, 4));
        p.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 4));

        btnExport.setFont(btnExport.getFont().deriveFont(Font.BOLD, 16f));
        btnExport.setBackground(new Color(0x28, 0x8C, 0x28));
        btnExport.setForeground(Color.WHITE);
        btnExport.setFocusPainted(false);
        btnExport.setOpaque(true);
        btnExport.setPreferredSize(new Dimension(0, 44));
        btnExport.addActionListener(e -> runCustom());
        p.add(btnExport, BorderLayout.CENTER);

        JLabel hint = new JLabel("Uses all settings configured above (output mode, options, filters, scope)");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 10f));
        hint.setForeground(Color.GRAY);
        hint.setHorizontalAlignment(SwingConstants.CENTER);
        p.add(hint, BorderLayout.SOUTH);

        return p;
    }

    // ====================================================================
    // Actions
    // ====================================================================

    private void guardedRun(Runnable task) {
        if (exporting) {
            updateStatus("Export already in progress, please wait...");
            return;
        }
        exporting = true;
        btnExport.setEnabled(false);
        updateStatus("Starting export...");
        try { task.run(); } catch (RuntimeException ex) { exportDone("Error: " + ex.getMessage()); }
    }

    private void exportDone(String msg) {
        exporting = false;
        SwingUtilities.invokeLater(() -> btnExport.setEnabled(true));
        updateStatus(msg);
    }

    private NexusEngine.StatusCallback guardedCallback() {
        return msg -> {
            if (msg.startsWith("Done!") || msg.startsWith("Error") || msg.startsWith("No items")) {
                exportDone(msg);
            } else {
                updateStatus(msg);
            }
        };
    }

    private void runPreset(ExportConfig presetCfg) {
        guardedRun(() -> {
            boolean scopeOnly = rbScopeOnly.isSelected();
            ExportConfig cfg = ExportConfig.builder()
                .outputMode(presetCfg.outputMode)
                .includeJson(presetCfg.includeJson)
                .includeMd(presetCfg.includeMd)
                .onlyTools(presetCfg.onlyTools)
                .onlyStatus(presetCfg.onlyStatus)
                .dedupe(presetCfg.dedupe)
                .redactSecrets(presetCfg.redactSecrets)
                .autoFindings(presetCfg.autoFindings)
                .paramIndex(presetCfg.paramIndex)
                .generateFuzz(presetCfg.generateFuzz)
                .generateNuclei(presetCfg.generateNuclei)
                .aiPrompts(presetCfg.aiPrompts)
                .scopeOnly(scopeOnly)
                .build();
            engine.exportAllAsync(cfg, guardedCallback());
        });
    }

    private void runCustom() {
        guardedRun(() -> {
            ExportConfig cfg = buildConfigFromUi();
            engine.exportAllAsync(cfg, guardedCallback());
        });
    }

    private void doParamSearch() {
        String name  = tfParamName.getText().trim();
        String value = tfParamValue.getText().trim();
        if (name.isEmpty() && value.isEmpty()) {
            updateStatus("Enter a parameter name and/or value to search.");
            return;
        }
        guardedRun(() -> {
            ExportConfig cfg = ExportConfig.builder()
                .outputMode(ExportConfig.OutputMode.SITEMAP)
                .includeJson(rbParamJson.isSelected())
                .includeMd(rbParamMd.isSelected())
                .dedupe(true)
                .scopeOnly(rbScopeOnly.isSelected())
                .paramSearchName(name)
                .paramSearchValue(value)
                .paramSearchExact(rbExact.isSelected())
                .build();
            engine.exportAllAsync(cfg, guardedCallback());
        });
    }

    private void doRegexSearch() {
        String pattern = tfRegex.getText().trim();
        if (pattern.isEmpty()) {
            updateStatus("Enter a regex pattern to search.");
            return;
        }
        guardedRun(() -> {
            ExportConfig.RegexTarget target = ExportConfig.RegexTarget.BOTH;
            if (rbRegexReq.isSelected())  target = ExportConfig.RegexTarget.REQUEST;
            if (rbRegexResp.isSelected()) target = ExportConfig.RegexTarget.RESPONSE;

            ExportConfig cfg = ExportConfig.builder()
                .outputMode(ExportConfig.OutputMode.SITEMAP)
                .includeJson(rbRegexJson.isSelected())
                .includeMd(rbRegexMd.isSelected())
                .dedupe(true)
                .scopeOnly(rbScopeOnly.isSelected())
                .regexPattern(pattern)
                .regexTarget(target)
                .build();
            engine.exportAllAsync(cfg, guardedCallback());
        });
    }

    // ---- build config from current UI state ----------------------------

    private ExportConfig buildConfigFromUi() {
        ExportConfig.OutputMode mode = ExportConfig.OutputMode.SITEMAP;
        if (rbFlat.isSelected())         mode = ExportConfig.OutputMode.FLAT;
        if (rbByHost.isSelected())       mode = ExportConfig.OutputMode.BY_HOST;
        if (rbHostFirst.isSelected())    mode = ExportConfig.OutputMode.HOST_FIRST;
        if (rbSplitSession.isSelected()) mode = ExportConfig.OutputMode.SPLIT_BY_SESSION;
        if (rbByTime.isSelected())       mode = ExportConfig.OutputMode.BY_TIME;

        boolean mdOnly = cbMdOnly.isSelected();

        return ExportConfig.builder()
            .outputMode(mode)
            .includeJson(!mdOnly)
            .includeMd(cbIncludeMd.isSelected() || mdOnly)
            .onlyTools(tfTools.getText().trim())
            .onlyStatus(tfStatus.getText().trim())
            .dedupe(cbDedupe.isSelected())
            .redactSecrets(cbRedact.isSelected())
            .fromTime(tfFromTime.getText().trim())
            .toTime(tfToTime.getText().trim())
            .timeIncludeHost(cbTimeHost.isSelected())
            .autoFindings(cbFindings.isSelected() || cbFullAnalysis.isSelected())
            .paramIndex(cbParamIndex.isSelected() || cbFullAnalysis.isSelected())
            .aiPrompts(cbAiPrompts.isSelected() || cbFullAnalysis.isSelected())
            .generateFuzz(cbFuzzManifest.isSelected() || cbFullAnalysis.isSelected())
            .generateNuclei(cbNucleiTpls.isSelected() || cbFullAnalysis.isSelected())
            .scopeOnly(rbScopeOnly.isSelected())
            .build();
    }

    // ---- status updates (thread-safe) ----------------------------------

    private void updateStatus(String msg) {
        SwingUtilities.invokeLater(() -> lblStatus.setText(msg));
    }

    // ---- helpers -------------------------------------------------------

    private static TitledBorder titledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), title);
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD, 11f));
        return border;
    }
}

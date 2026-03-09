package nexus;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.Component;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Context-menu provider — organized submenu structure with
 * nested categories: AI Analysis, Output Format, Layout Mode,
 * Triage, Redacted, Scope.
 * <p>
 * Preserves the deep-crawl behavior: selecting items extracts
 * hosts and grabs ALL matching traffic from Proxy + Site Map.
 */
final class NexusContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final NexusCollector collector;
    private final NexusEngine engine;

    NexusContextMenu(MontoyaApi api, NexusCollector collector, NexusEngine engine) {
        this.api       = api;
        this.collector = collector;
        this.engine    = engine;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> result = new ArrayList<>();

        try {
            List<HttpRequestResponse> selected = event.selectedRequestResponses();

            if ((selected == null || selected.isEmpty())
                    && event.messageEditorRequestResponse().isPresent()) {
                selected = List.of(
                    event.messageEditorRequestResponse().get().requestResponse());
            }

            if (selected != null && !selected.isEmpty()) {
                List<String> hosts = collector.extractHosts(selected);
                String hostLabel = hosts.stream().limit(3)
                    .collect(Collectors.joining(", "));
                if (hosts.size() > 3) hostLabel += " +" + (hosts.size() - 3);

                JMenu root = new JMenu(String.format(
                    "BurpNexus: Export (%s)", hostLabel));
                buildCategoryMenus(root, hosts);
                result.add(root);
            } else {
                JMenu root = new JMenu("BurpNexus: Export Entire Project");
                buildProjectMenus(root);
                result.add(root);
            }

        } catch (Exception ex) {
            api.logging().logToError("[!] Context menu error: " + ex.getMessage());
            JMenuItem fallback = new JMenuItem("BurpNexus: Export Entire Project (fallback)");
            fallback.addActionListener(e -> engine.exportAllAsync(
                ExportConfig.builder()
                    .outputMode(ExportConfig.OutputMode.SITEMAP)
                    .includeMd(true).dedupe(true).build(),
                null));
            result.add(fallback);
        }

        return result;
    }

    // ---- build categorised submenus (lazy collection on click) ----------

    private void buildCategoryMenus(JMenu root, List<String> hosts) {
        Map<String, List<NexusProfiles.Profile>> byCategory = new LinkedHashMap<>();
        for (NexusProfiles.Profile p : NexusProfiles.CONTEXT_PROFILES) {
            byCategory.computeIfAbsent(p.category, k -> new ArrayList<>()).add(p);
        }

        boolean first = true;
        for (Map.Entry<String, List<NexusProfiles.Profile>> entry : byCategory.entrySet()) {
            if (!first) root.addSeparator();
            first = false;

            JMenu catMenu = new JMenu(entry.getKey());
            for (NexusProfiles.Profile profile : entry.getValue()) {
                final ExportConfig cfg = profile.config;
                JMenuItem mi = new JMenuItem(profile.label);
                mi.addActionListener(e -> engine.exportForHostsAsync(hosts, cfg, null));
                catMenu.add(mi);
            }
            root.add(catMenu);
        }
    }

    // ---- build categorised submenus for full project export -------------

    private void buildProjectMenus(JMenu root) {
        Map<String, List<NexusProfiles.Profile>> byCategory = new LinkedHashMap<>();
        for (NexusProfiles.Profile p : NexusProfiles.CONTEXT_PROFILES) {
            byCategory.computeIfAbsent(p.category, k -> new ArrayList<>()).add(p);
        }

        boolean first = true;
        for (Map.Entry<String, List<NexusProfiles.Profile>> entry : byCategory.entrySet()) {
            if (!first) root.addSeparator();
            first = false;

            JMenu catMenu = new JMenu(entry.getKey());
            for (NexusProfiles.Profile profile : entry.getValue()) {
                final ExportConfig cfg = profile.config;
                JMenuItem mi = new JMenuItem(profile.label);
                mi.addActionListener(e -> engine.exportAllAsync(cfg, null));
                catMenu.add(mi);
            }
            root.add(catMenu);
        }
    }
}

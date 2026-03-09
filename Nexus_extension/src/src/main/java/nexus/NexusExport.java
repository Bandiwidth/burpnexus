package nexus;

import java.util.*;

/**
 * Container for a set of collected {@link NexusItem}s.
 * Analogous to the Python BurpExport dataclass.
 */
final class NexusExport {

    String sourceLabel = "BurpNexus";
    String exportTime  = "";
    List<NexusItem> items = new ArrayList<>();

    List<String> tools() {
        Set<String> set = new TreeSet<>();
        for (NexusItem item : items) set.add(item.tool);
        return new ArrayList<>(set);
    }

    List<String> hosts() {
        Set<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (NexusItem item : items) {
            if (item.host != null && !item.host.isEmpty()) set.add(item.host);
        }
        return new ArrayList<>(set);
    }

    List<NexusItem> itemsByTool(String tool) {
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            if (tool.equals(item.tool)) result.add(item);
        }
        return result;
    }

    List<NexusItem> itemsByHost(String host) {
        List<NexusItem> result = new ArrayList<>();
        for (NexusItem item : items) {
            if (host.equalsIgnoreCase(item.host)) result.add(item);
        }
        return result;
    }
}

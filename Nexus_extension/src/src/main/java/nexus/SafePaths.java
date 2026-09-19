package nexus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

final class SafePaths {
    private SafePaths() {}
    static String segment(String input) {
        String s = (input == null ? "" : input).replaceAll("[^a-zA-Z0-9_.-]", "_")
            .replaceAll("^[._]+|[._]+$", "");
        if (s.isEmpty()) s = "unknown";
        if (s.split("\\.")[0].toUpperCase(Locale.ROOT).matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]")) s = "_" + s;
        if (s.length() > 64) s = s.substring(0, 48) + "_" + NexusItem.sha256Hex(s).substring(0, 12);
        return s;
    }
    static Path within(Path root, Path target) throws IOException {
        Path base = root.toAbsolutePath().normalize();
        Path result = target.toAbsolutePath().normalize();
        if (!result.startsWith(base)) throw new IOException("Output path escapes export directory");
        // Reject links in the output tree, including a pre-existing root link.
        for (Path p = result; p != null && p.startsWith(base); p = p.getParent()) {
            if (Files.isSymbolicLink(p)) throw new IOException("Output path contains a symbolic link");
        }
        return result;
    }
}

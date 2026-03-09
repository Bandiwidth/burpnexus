package nexus;

/**
 * Zero-dependency JSON serialisation helper.
 * Builds JSON strings via {@link StringBuilder} so the extension
 * ships as a single JAR with no third-party libraries.
 */
final class JsonBuilder {

    private final StringBuilder sb;
    private boolean firstField = true;

    JsonBuilder() {
        this.sb = new StringBuilder(4096);
    }

    JsonBuilder(int capacity) {
        this.sb = new StringBuilder(capacity);
    }

    // ---- objects --------------------------------------------------------

    JsonBuilder objectStart() {
        sb.append('{');
        firstField = true;
        return this;
    }

    JsonBuilder objectEnd() {
        sb.append('}');
        firstField = false;
        return this;
    }

    // ---- arrays --------------------------------------------------------

    JsonBuilder arrayStart() {
        sb.append('[');
        firstField = true;
        return this;
    }

    JsonBuilder arrayEnd() {
        sb.append(']');
        firstField = false;
        return this;
    }

    // ---- fields --------------------------------------------------------

    JsonBuilder key(String name) {
        comma();
        sb.append('"').append(escapeJson(name)).append("\":");
        return this;
    }

    JsonBuilder value(String val) {
        if (val == null) {
            sb.append("null");
        } else {
            sb.append('"').append(escapeJson(val)).append('"');
        }
        return this;
    }

    JsonBuilder value(int val) {
        sb.append(val);
        return this;
    }

    JsonBuilder value(long val) {
        sb.append(val);
        return this;
    }

    JsonBuilder value(boolean val) {
        sb.append(val);
        return this;
    }

    JsonBuilder rawValue(String raw) {
        sb.append(raw);
        return this;
    }

    /** Shorthand: key + string value. */
    JsonBuilder field(String name, String val) {
        key(name);
        value(val);
        return this;
    }

    /** Shorthand: key + int value. */
    JsonBuilder field(String name, int val) {
        key(name);
        value(val);
        return this;
    }

    /** Shorthand: key + long value. */
    JsonBuilder field(String name, long val) {
        key(name);
        value(val);
        return this;
    }

    /** Shorthand: key + boolean value. */
    JsonBuilder field(String name, boolean val) {
        key(name);
        value(val);
        return this;
    }

    /** Key + raw JSON fragment (already serialised object/array). */
    JsonBuilder fieldRaw(String name, String rawJson) {
        key(name);
        sb.append(rawJson);
        return this;
    }

    /** Append a bare string value inside an array. */
    JsonBuilder arrayValue(String val) {
        comma();
        value(val);
        return this;
    }

    /** Append a bare int value inside an array. */
    JsonBuilder arrayValue(int val) {
        comma();
        value(val);
        return this;
    }

    /** Append a raw JSON fragment as an array element. */
    JsonBuilder arrayRaw(String rawJson) {
        comma();
        sb.append(rawJson);
        return this;
    }

    // ---- output --------------------------------------------------------

    @Override
    public String toString() {
        return sb.toString();
    }

    String toPrettyString() {
        return prettyPrint(sb.toString());
    }

    // ---- internal ------------------------------------------------------

    private void comma() {
        if (!firstField) {
            sb.append(',');
        }
        firstField = false;
    }

    static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b");  break;
                case '\f': out.append("\\f");  break;
                case '\n': out.append("\\n");  break;
                case '\r': out.append("\\r");  break;
                case '\t': out.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    /** Minimal pretty-printer: adds newlines and 2-space indentation. */
    static String prettyPrint(String json) {
        StringBuilder out = new StringBuilder(json.length() * 2);
        int indent = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (escaped) {
                out.append(c);
                escaped = false;
                continue;
            }
            if (c == '\\' && inString) {
                out.append(c);
                escaped = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                out.append(c);
                continue;
            }
            if (inString) {
                out.append(c);
                continue;
            }

            switch (c) {
                case '{': case '[':
                    out.append(c);
                    indent++;
                    out.append('\n');
                    appendIndent(out, indent);
                    break;
                case '}': case ']':
                    indent--;
                    out.append('\n');
                    appendIndent(out, indent);
                    out.append(c);
                    break;
                case ',':
                    out.append(c);
                    out.append('\n');
                    appendIndent(out, indent);
                    break;
                case ':':
                    out.append(": ");
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    private static void appendIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
    }
}

package nexus;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;
import java.io.*;

/** Structured JSON writer; handles nested arrays/objects and all string escapes. */
final class JsonBuilder {
    private final StringWriter buffer = new StringWriter();
    private final JsonWriter writer = new JsonWriter(buffer);
    JsonBuilder() {}
    JsonBuilder(int ignoredCapacity) {}
    private interface Write { void run() throws IOException; }
    private JsonBuilder put(Write op) { try { op.run(); return this; } catch (IOException ex) { throw new UncheckedIOException(ex); } }
    JsonBuilder objectStart() { return put(() -> writer.beginObject()); }
    JsonBuilder objectEnd() { return put(() -> writer.endObject()); }
    JsonBuilder arrayStart() { return put(() -> writer.beginArray()); }
    JsonBuilder arrayEnd() { return put(() -> writer.endArray()); }
    JsonBuilder key(String name) { return put(() -> writer.name(name)); }
    JsonBuilder value(String v) { return put(() -> writer.value(v)); }
    JsonBuilder value(int v) { return put(() -> writer.value(v)); }
    JsonBuilder value(long v) { return put(() -> writer.value(v)); }
    JsonBuilder value(boolean v) { return put(() -> writer.value(v)); }
    JsonBuilder rawValue(String v) { JsonParser.parseString(v); return put(() -> writer.jsonValue(v)); }
    JsonBuilder field(String k, String v) { return key(k).value(v); }
    JsonBuilder field(String k, int v) { return key(k).value(v); }
    JsonBuilder field(String k, long v) { return key(k).value(v); }
    JsonBuilder field(String k, boolean v) { return key(k).value(v); }
    JsonBuilder fieldRaw(String k, String v) { return key(k).rawValue(v); }
    JsonBuilder arrayValue(String v) { return value(v); }
    JsonBuilder arrayValue(int v) { return value(v); }
    JsonBuilder arrayRaw(String v) { return rawValue(v); }
    public String toString() { return buffer.toString(); }
    String build() { return toString(); }
    String toPrettyString() { return prettyPrint(toString()); }
    static String prettyPrint(String json) { return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(JsonParser.parseString(json)); }
    static String escapeJson(String s) { String j = new Gson().toJson(s == null ? "" : s); return j.substring(1, j.length()-1); }
}

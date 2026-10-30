package Main;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.*;

/** Only an unframed, uncompressed entity can be edited as plain text bytes. */
public final class RequestBodyPolicy {
    private RequestBodyPolicy() {}

    public static String headers(byte[] request) {
        String text = new String(request, StandardCharsets.ISO_8859_1);
        int end = text.indexOf("\r\n\r\n");
        if (end < 0) end = text.indexOf("\n\n");
        return end < 0 ? text : text.substring(0, end);
    }

    public static String header(String headers, String name) {
        StringBuilder value = new StringBuilder();
        for (String line : headers.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                if (value.length() > 0) value.append(',');
                value.append(line.substring(colon + 1).trim());
            }
        }
        return value.toString();
    }

    public static boolean hasTransferEncoding(String headers) {
        return hasHeader(headers, "Transfer-Encoding");
    }

    public static boolean hasHeader(String headers, String name) {
        for (String line : headers.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    public static boolean isEditable(byte[] request) { return isEditable(headers(request)); }

    public static boolean isEditable(String headers) {
        String encoding = header(headers, "Content-Encoding");
        return !hasTransferEncoding(headers) && (encoding.isEmpty() || "identity".equalsIgnoreCase(encoding));
    }

    public static Charset charset(String headers) {
        Matcher matcher = Pattern.compile("(?i)(?:^|;)\\s*charset\\s*=\\s*(?:\"([^\"]+)\"|([^;\\s]+))")
                .matcher(header(headers, "Content-Type"));
        return matcher.find() ? Charset.forName(matcher.group(1) == null ? matcher.group(2) : matcher.group(1))
                : StandardCharsets.UTF_8;
    }
}

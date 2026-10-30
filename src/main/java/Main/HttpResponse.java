package Main;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/** HTTP/1 response framing and bounded entity decoding, independent of Burp. */
public final class HttpResponse {
    public static final int MAX_BYTES = 16 * 1024 * 1024;
    private HttpResponse() {}

    public static final class Analysis {
        public final byte[] rawBytes;
        public final int statusCode;
        public final boolean complete;
        public final String issue;
        public final int finalOffset, bodyOffset;
        private final String headers;
        private final byte[] entity;
        private final boolean noBody;

        private Analysis(Reader reader, boolean complete, String issue) {
            rawBytes = reader.raw.toByteArray();
            entity = reader.entity.toByteArray();
            statusCode = reader.status;
            finalOffset = reader.finalOffset;
            bodyOffset = reader.bodyOffset;
            headers = reader.headers;
            noBody = reader.noBody;
            this.complete = complete;
            this.issue = issue;
        }

        public byte[] finalResponseBytes() {
            return Arrays.copyOfRange(rawBytes, Math.min(finalOffset, rawBytes.length), rawBytes.length);
        }

        public String header(String name) { return RequestBodyPolicy.header(headers, name); }

        public Text decodeText() {
            if (!complete) return new Text(null, issue);
            if (noBody) return new Text("", "");
            try {
                String transfer = header("Transfer-Encoding");
                for (String token : tokens(transfer))
                    if (!token.equals("chunked") && !token.equals("identity"))
                        return new Text(null, "unsupported transfer encoding: " + token);
                byte[] decoded = entity;
                List<String> encodings = tokens(header("Content-Encoding"));
                for (int i = encodings.size() - 1; i >= 0; i--) {
                    String encoding = encodings.get(i);
                    if (encoding.equals("identity")) continue;
                    InputStream stream;
                    if (encoding.equals("gzip") || encoding.equals("x-gzip"))
                        stream = new GZIPInputStream(new ByteArrayInputStream(decoded));
                    else if (encoding.equals("deflate"))
                        stream = new InflaterInputStream(new ByteArrayInputStream(decoded));
                    else return new Text(null, "unsupported content encoding: " + encoding);
                    try (InputStream in = stream) { decoded = boundedBytes(in); }
                }
                String type = header("Content-Type").toLowerCase(Locale.ROOT);
                if (!type.isEmpty() && !(type.startsWith("text/") || type.contains("json")
                        || type.contains("xml") || type.contains("javascript") || type.contains("x-www-form-urlencoded")))
                    return new Text(null, "binary response; text comparison skipped");
                return new Text(TextCodec.decode(decoded, RequestBodyPolicy.charset(headers)), "");
            } catch (Exception invalid) {
                return new Text(null, "response decoding failed: " + invalid.getClass().getSimpleName());
            }
        }
    }

    public static final class Text {
        public final String value, issue;
        Text(String value, String issue) { this.value = value; this.issue = issue; }
    }

    public static Analysis analyze(byte[] response, String requestMethod) {
        return read(new ByteArrayInputStream(response == null ? new byte[0] : response), requestMethod);
    }

    public static Analysis read(InputStream input, String requestMethod) {
        Reader reader = new Reader(input);
        try {
            for (;;) {
                reader.finalOffset = reader.raw.size();
                StringBuilder headers = new StringBuilder();
                String first = reader.line();
                String[] parts = first.split(" +", 3);
                if (parts.length < 2 || !parts[0].startsWith("HTTP/")) throw new IOException("invalid response status line");
                reader.status = Integer.parseInt(parts[1]);
                if (reader.status < 100 || reader.status > 599) throw new IOException("invalid response status code");
                headers.append(first).append("\r\n");
                for (;;) {
                    String line = reader.line();
                    if (line.isEmpty()) break;
                    headers.append(line).append("\r\n");
                }
                reader.headers = headers.toString();
                reader.bodyOffset = reader.raw.size();
                if (reader.status < 200 && reader.status != 101) continue;
                break;
            }
            if ("HEAD".equalsIgnoreCase(requestMethod) || reader.status == 204 || reader.status == 304
                    || reader.status == 101 || ("CONNECT".equalsIgnoreCase(requestMethod) && reader.status / 100 == 2))
            {
                reader.noBody = true;
                return new Analysis(reader, true, "");
            }
            List<String> transfer = tokens(RequestBodyPolicy.header(reader.headers, "Transfer-Encoding"));
            if (RequestBodyPolicy.hasTransferEncoding(reader.headers) && transfer.isEmpty())
                throw new IOException("invalid transfer encoding");
            if (!transfer.isEmpty() && transfer.get(transfer.size() - 1).equals("chunked")) {
                for (;;) {
                    String sizeLine = reader.line();
                    int extension = sizeLine.indexOf(';');
                    String sizeText = (extension < 0 ? sizeLine : sizeLine.substring(0, extension)).trim();
                    if (!sizeText.matches("[0-9A-Fa-f]+")) throw new IOException("invalid chunk size");
                    long size = Long.parseLong(sizeText, 16);
                    if (size == 0) {
                        while (!reader.line().isEmpty()) { }
                        break;
                    }
                    reader.body(size);
                    if (!reader.line().isEmpty()) throw new IOException("invalid chunk terminator");
                }
            } else if (transfer.isEmpty()) {
                String length = RequestBodyPolicy.header(reader.headers, "Content-Length");
                if (length.isEmpty()) {
                    if (RequestBodyPolicy.hasHeader(reader.headers, "Content-Length")) throw new IOException("invalid content length");
                    reader.untilClose();
                }
                else {
                    long expected = -1;
                    for (String value : length.split(",", -1)) {
                        if (!value.trim().matches("[0-9]+")) throw new IOException("invalid content length");
                        long parsed = Long.parseLong(value.trim());
                        if (expected >= 0 && expected != parsed) throw new IOException("conflicting content lengths");
                        expected = parsed;
                    }
                    if (expected > MAX_BYTES) throw new IOException("response size limit reached");
                    reader.body(expected);
                }
            } else reader.untilClose();
            return new Analysis(reader, true, "");
        } catch (Exception incomplete) {
            String message = incomplete.getMessage();
            return new Analysis(reader, false, message == null ? incomplete.getClass().getSimpleName() : message);
        }
    }

    private static List<String> tokens(String value) {
        List<String> result = new ArrayList<>();
        if (value == null || value.trim().isEmpty()) return result;
        for (String token : value.split(",")) result.add(token.trim().toLowerCase(Locale.ROOT));
        return result;
    }

    private static byte[] boundedBytes(InputStream input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            if (out.size() + count > MAX_BYTES) throw new IOException("decoded response size limit reached");
            out.write(buffer, 0, count);
        }
        return out.toByteArray();
    }

    private static final class Reader {
        final InputStream input;
        final ByteArrayOutputStream raw = new ByteArrayOutputStream(), entity = new ByteArrayOutputStream();
        int status, finalOffset, bodyOffset;
        String headers = "";
        boolean noBody;
        Reader(InputStream input) { this.input = input; }
        int readByte() throws IOException {
            if (raw.size() >= MAX_BYTES) throw new IOException("response size limit reached");
            int value = input.read();
            if (value < 0) throw new EOFException("incomplete response");
            raw.write(value);
            return value;
        }
        String line() throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            for (;;) {
                int value = readByte();
                if (value == '\n') {
                    byte[] bytes = line.toByteArray();
                    int length = bytes.length > 0 && bytes[bytes.length - 1] == '\r' ? bytes.length - 1 : bytes.length;
                    return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
                }
                line.write(value);
            }
        }
        void body(long remaining) throws IOException {
            byte[] buffer = new byte[8192];
            while (remaining > 0) {
                int wanted = (int)Math.min(Math.min(remaining, buffer.length), MAX_BYTES - raw.size());
                if (wanted <= 0) throw new IOException("response size limit reached");
                int count = input.read(buffer, 0, wanted);
                if (count < 0) throw new EOFException("incomplete response body");
                raw.write(buffer, 0, count);
                entity.write(buffer, 0, count);
                remaining -= count;
            }
        }
        void untilClose() throws IOException {
            byte[] buffer = new byte[8192];
            for (;;) {
                int wanted = Math.min(buffer.length, MAX_BYTES - raw.size());
                if (wanted <= 0) throw new IOException("response size limit reached");
                int count = input.read(buffer, 0, wanted);
                if (count < 0) return;
                raw.write(buffer, 0, count);
                entity.write(buffer, 0, count);
            }
        }
    }
}

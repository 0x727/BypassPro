package Main;

import org.junit.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;
import static org.junit.Assert.*;

public class HttpResponseTest {
    static byte[] bytes(String value) { return value.getBytes(StandardCharsets.ISO_8859_1); }
    static byte[] response(String headers, byte[] body) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(bytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n" + headers + "\r\n"));
        out.write(body); return out.toByteArray();
    }

    @Test public void interimResponsesDoNotReplaceFinalStatusOrBody() {
        byte[] wire = bytes("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        HttpResponse.Analysis result = HttpResponse.read(fragmented(wire), "GET");
        assertTrue(result.complete); assertEquals(200, result.statusCode);
        assertArrayEquals(wire, result.rawBytes);
        assertEquals("OK", result.decodeText().value);
        assertTrue(new String(result.finalResponseBytes(), StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 200"));
        assertEquals("OK", new String(wire, result.bodyOffset, wire.length - result.bodyOffset, StandardCharsets.ISO_8859_1));
    }

    @Test public void headAndBodylessStatusesFinishAtHeaders() {
        for (String status : new String[]{"200 OK", "204 No Content", "304 Not Modified"}) {
            final ByteArrayInputStream initial = new ByteArrayInputStream(bytes("HTTP/1.1 " + status + "\r\nContent-Length: 999\r\nContent-Encoding: gzip\r\n\r\n"));
            InputStream neverReadBody = new InputStream() {
                public int read() {
                    int value = initial.read();
                    if (value < 0) throw new AssertionError("attempted to read a nonexistent body");
                    return value;
                }
            };
            HttpResponse.Analysis result = HttpResponse.read(neverReadBody, status.startsWith("200") ? "HEAD" : "GET");
            assertTrue(result.issue, result.complete); assertEquals("", result.decodeText().value);
        }
    }

    @Test public void fragmentedChunksAndTrailersDecodeWithoutChangingWire() throws Exception {
        byte[] wire = response("Transfer-Encoding: chunked\r\n", bytes("4;ext=yes\r\nroot\r\n3\r\n:x:\r\n0\r\nX-Trailer: value\r\n\r\n"));
        HttpResponse.Analysis result = HttpResponse.read(fragmented(wire), "GET");
        assertTrue(result.issue, result.complete);
        assertEquals("root:x:", result.decodeText().value); assertArrayEquals(wire, result.rawBytes);
    }

    @Test public void shortFixedAndChunkedBodiesAreExplicitlyIncomplete() throws Exception {
        for (byte[] wire : new byte[][]{
                response("Content-Length: 10\r\n", bytes("OK")),
                response("Transfer-Encoding: chunked\r\n", bytes("5\r\nOK")),
                response("Transfer-Encoding: chunked\r\n", bytes("2\r\nOKX\r\n0\r\n\r\n"))}) {
            HttpResponse.Analysis result = HttpResponse.analyze(wire, "GET");
            assertFalse(result.complete); assertEquals(200, result.statusCode);
            assertNull(result.decodeText().value); assertFalse(result.issue.isEmpty());
        }
    }

    @Test public void gzipAndPlainEntitiesCompareEqually() throws Exception {
        byte[] page = "Hello é 文".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(compressed)) { gzip.write(page); }
        byte[] wire = response("Content-Encoding: gzip\r\nContent-Length: " + compressed.size() + "\r\n", compressed.toByteArray());
        String plain = HttpResponse.analyze(response("Content-Length: " + page.length + "\r\n", page), "GET").decodeText().value;
        HttpResponse.Analysis result = HttpResponse.analyze(wire, "GET");
        assertEquals(plain, result.decodeText().value); assertArrayEquals(wire, result.rawBytes);
        assertEquals(1, DiffPage.getRatio(plain, result.decodeText().value), 0);
    }

    static InputStream fragmented(final byte[] bytes) {
        return new ByteArrayInputStream(bytes) {
            public synchronized int read(byte[] buffer, int offset, int length) {
                return super.read(buffer, offset, Math.min(length, 1));
            }
        };
    }
}

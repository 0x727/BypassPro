package Main;

import burp.IHttpService;
import org.junit.Test;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

public class RedirectPolicyTest {
    static IHttpService service(String host, int port, String protocol) {
        return new IHttpService() {
            public String getHost() { return host; }
            public int getPort() { return port; }
            public String getProtocol() { return protocol; }
        };
    }
    static byte[] bytes(String text) { return text.getBytes(StandardCharsets.ISO_8859_1); }
    private final IHttpService origin = service("origin.test", 8080, "http");
    private final byte[] get = bytes("GET /dir/page?old=1 HTTP/1.1\r\nHost: intentionally-different.test\r\n\r\n");

    @Test public void relativeLocationResolvesAgainstCurrentResourceAndActualNetworkTarget() throws Exception {
        assertEquals("http://origin.test:8080/dir/next", RedirectPolicy.resolve(origin, get, "next").toString());
        assertEquals("/parent", RedirectPolicy.resolve(origin, get, "../parent").getFile());
        assertEquals("/dir/page?new=2", RedirectPolicy.resolve(origin, get, "?new=2").getFile());
        assertEquals("/dir/page?old=1", RedirectPolicy.resolve(origin, get, "#fragment").getFile());
    }
    @Test public void crossHostPortSchemeAndUserInfoNeverReceiveCredentials() throws Exception {
        for (String location : new String[]{"http://other.test:8080/path", "http://origin.test/path",
                "https://origin.test:8080/path", "//other.test/path", "http://user@origin.test:8080/path"}) {
            try { RedirectPolicy.resolve(origin, get, location); fail(location); }
            catch (IllegalArgumentException expected) { }
        }
    }
    @Test public void explicitDefaultPortIsSameOrigin() throws Exception {
        assertEquals("/next", RedirectPolicy.resolve(service("ORIGIN.test", 80, "http"), get,
                "http://origin.test/next").getFile());
    }
    @Test public void postRedirectRetrievalDropsEntityAndEntityHeadersButKeepsSameOriginAuth() throws Exception {
        byte[] post = bytes("POST / HTTP/1.1\r\nHost: origin.test\r\nAuthorization: token\r\nCookie: a=b\r\n"
                + "Content-Type: application/json\r\nContent-Length: 4\r\nContent-Encoding: gzip\r\n\r\nBODY");
        for (int code : new int[]{301, 302, 303}) {
            String next = new String(RedirectPolicy.followRequest(post, new URL("http://origin.test/next"), code), StandardCharsets.ISO_8859_1);
            assertTrue(next.startsWith("GET /next HTTP/1.1\r\n"));
            assertFalse(next.contains("Content-"));
            assertFalse(next.contains("BODY"));
            assertTrue(next.contains("Authorization: token\r\nCookie: a=b\r\n"));
        }
    }
    @Test public void preservingRedirectsKeepAllMethodsAndBodyBytes() throws Exception {
        for (String method : new String[]{"GET", "DELETE", "PUT", "POST", "CUSTOM"}) {
            byte[] original = bytes(method + " / HTTP/1.0\r\nHost: other-host-header\r\nContent-Length: 3\r\n\r\n\u0000\u00ffA");
            for (int code : new int[]{307, 308}) {
                byte[] follow = RedirectPolicy.followRequest(original, new URL("http://origin.test/next"), code);
                assertArrayEquals(bytes(new String(original, StandardCharsets.ISO_8859_1).replace(" / HTTP", " /next HTTP")), follow);
            }
        }
    }
    @Test public void headNeverBecomesGetAnd301PutKeepsBody() throws Exception {
        assertTrue(new String(RedirectPolicy.followRequest(bytes("HEAD / HTTP/1.1\r\nHost: origin.test\r\n\r\n"),
                new URL("http://origin.test"), 303), StandardCharsets.ISO_8859_1).startsWith("HEAD / HTTP"));
        assertTrue(new String(RedirectPolicy.followRequest(bytes("PUT / HTTP/1.1\r\nHost: origin.test\r\n\r\nDATA"),
                new URL("http://origin.test/next"), 301), StandardCharsets.ISO_8859_1).endsWith("\r\n\r\nDATA"));
    }
}

package Main.ghostbits;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Raw Socket 字节完整性测试。
 *
 * 验收标准：客户端发送 "阮严灵丰丰甲来" 后, server 收到的字节流必须是 UTF-8 原始字节
 *   E9 98 AE E4 B8 A5 E7 81 B5 E4 B8 B0 E4 B8 B0 E7 94 B2 E6 9D A5
 * 不能是已经折叠后的 .%u002e (2E 25 75 30 30 32 65)，也不能是 percent-encoding。
 */
public class RawSocketSenderTest {
    @Test public void tlsHandshakeUsesReadTimeoutAndClosesFailedSocket() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            java.util.concurrent.CountDownLatch closed = new java.util.concurrent.CountDownLatch(1);
            Thread peer = new Thread(() -> {
                try (Socket connection = listener.accept()) {
                    connection.setSoTimeout(2000);
                    byte[] data = new byte[8192];
                    while (connection.getInputStream().read(data) >= 0) { }
                    closed.countDown();
                } catch (IOException ignored) { }
            });
            peer.setDaemon(true); peer.start();
            long start = System.currentTimeMillis();
            try {
                new RawSocketSender().send("127.0.0.1", listener.getLocalPort(), true,
                        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), 1000, 150);
                fail("TLS peer that never replies must time out");
            } catch (IOException expected) {
                assertTrue(System.currentTimeMillis() - start < 2000);
                assertTrue("failed TLS connection leaked", closed.await(2, java.util.concurrent.TimeUnit.SECONDS));
            } finally { peer.join(2500); }
        }
    }

    private static EchoServer server;

    @BeforeClass
    public static void start() throws IOException {
        server = new EchoServer();
        server.start();
    }

    @AfterClass
    public static void stop() {
        if (server != null) server.stop();
    }

    @Test
    public void unicodePathBytesArePreservedOnTheWire() throws Exception {
        String segment = "阮严灵丰丰甲来";
        String requestLine = "GET /" + segment + "/etc/passwd HTTP/1.1\r\n"
                + "Host: 127.0.0.1:" + server.port + "\r\n"
                + "Connection: close\r\n\r\n";
        byte[] requestBytes = requestLine.getBytes(StandardCharsets.UTF_8);

        RawSocketSender sender = new RawSocketSender();
        RawSocketSender.RawResponse resp = sender.send(
                "127.0.0.1", server.port, false, requestBytes, 2000, 1000);

        assertNotNull(resp);
        // 服务器应该看到我们发的原始字节
        byte[] seen = server.lastReceivedBytes();
        assertNotNull("server must have received bytes", seen);

        String hex = bytesToHex(seen);
        // UTF-8 编码后的字节序列
        String expectedUtf8Hex = "e9 98 ae e4 b8 a5 e7 81 b5 e4 b8 b0 e4 b8 b0 e7 94 b2 e6 9d a5";
        assertTrue("server must see raw UTF-8 bytes, got: " + hex,
                hex.contains(expectedUtf8Hex));

        // 反向断言：不能看到客户端提前折叠的痕迹
        assertTrue("must NOT see client-side folded ASCII '.%u002e'",
                !hex.contains("2e 25 75 30 30 32 65"));
        // 不能看到 percent-encoding
        String requestText = new String(seen, StandardCharsets.ISO_8859_1);
        assertTrue("must NOT see percent-encoded form '%E9%98%AE'",
                !requestText.contains("%E9%98%AE"));

        // 响应也应能拿到 200
        assertEquals(200, resp.getStatusCode());
    }

    /**
     * keep-alive + Content-Length 场景：服务器响应里有 CL 但不主动 close。
     * 旧实现会等到 readTimeout 才返回（5 秒），新实现读够 CL 字节立刻返回。
     */
    @Test
    public void contentLengthResponseDoesNotWaitForTimeout() throws Exception {
        try (KeepAliveServer ka = new KeepAliveServer(req -> {
            String body = "hello world";
            return ("HTTP/1.1 200 OK\r\n"
                    + "Content-Type: text/plain\r\n"
                    + "Content-Length: " + body.length() + "\r\n"
                    + "Connection: keep-alive\r\n\r\n" + body)
                    .getBytes(StandardCharsets.ISO_8859_1);
        })) {
            ka.start();
            String request = "GET / HTTP/1.1\r\nHost: 127.0.0.1:" + ka.port + "\r\n\r\n";

            long start = System.currentTimeMillis();
            // 关键：故意把 readTimeout 设很大，验证不靠超时也能立刻返回
            RawSocketSender.RawResponse resp = new RawSocketSender().send(
                    "127.0.0.1", ka.port, false,
                    request.getBytes(StandardCharsets.UTF_8),
                    2000, 30000);
            long elapsed = System.currentTimeMillis() - start;

            assertEquals(200, resp.getStatusCode());
            byte[] body = java.util.Arrays.copyOfRange(resp.getResponseBytes(),
                    resp.getBodyOffset(), resp.getResponseBytes().length);
            assertEquals("hello world", new String(body, StandardCharsets.UTF_8));
            assertTrue("Content-Length 路径不应等满超时, 实际 " + elapsed + "ms",
                    elapsed < 2000);
        }
    }

    /**
     * keep-alive + chunked 场景：服务器响应用 chunked 编码且不主动 close。
     * 验证按 chunked 终结符 "0\r\n\r\n" 立刻返回，不卡读超时。
     */
    @Test
    public void chunkedResponseDoesNotWaitForTimeout() throws Exception {
        try (KeepAliveServer ka = new KeepAliveServer(req -> {
            // 两个 chunk: "Hello " 和 "world!"，然后终止
            StringBuilder sb = new StringBuilder();
            sb.append("HTTP/1.1 200 OK\r\n");
            sb.append("Content-Type: text/plain\r\n");
            sb.append("Transfer-Encoding: chunked\r\n");
            sb.append("Connection: keep-alive\r\n\r\n");
            sb.append("6\r\nHello \r\n");
            sb.append("6\r\nworld!\r\n");
            sb.append("0\r\n\r\n");
            return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        })) {
            ka.start();
            String request = "GET / HTTP/1.1\r\nHost: 127.0.0.1:" + ka.port + "\r\n\r\n";

            long start = System.currentTimeMillis();
            RawSocketSender.RawResponse resp = new RawSocketSender().send(
                    "127.0.0.1", ka.port, false,
                    request.getBytes(StandardCharsets.UTF_8),
                    2000, 30000);
            long elapsed = System.currentTimeMillis() - start;

            assertEquals(200, resp.getStatusCode());
            String full = new String(resp.getResponseBytes(), StandardCharsets.ISO_8859_1);
            assertTrue("响应必须包含 chunked 终结符", full.endsWith("0\r\n\r\n"));
            assertTrue("chunked 路径不应等满超时, 实际 " + elapsed + "ms",
                    elapsed < 2000);
        }
    }

    @Test
    public void chunkedResponseWithExtensionDoesNotWaitForTimeout() throws Exception {
        try (KeepAliveServer ka = new KeepAliveServer(req -> {
            StringBuilder sb = new StringBuilder();
            sb.append("HTTP/1.1 200 OK\r\n");
            sb.append("Content-Type: text/plain\r\n");
            sb.append("Transfer-Encoding: chunked\r\n");
            sb.append("Connection: keep-alive\r\n\r\n");
            sb.append("5\r\nhello\r\n");
            sb.append("0;name=value\r\n");
            sb.append("X-Trailer: done\r\n\r\n");
            return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        })) {
            ka.start();
            String request = "GET / HTTP/1.1\r\nHost: 127.0.0.1:" + ka.port + "\r\n\r\n";

            long start = System.currentTimeMillis();
            RawSocketSender.RawResponse resp = new RawSocketSender().send(
                    "127.0.0.1", ka.port, false,
                    request.getBytes(StandardCharsets.UTF_8),
                    2000, 30000);
            long elapsed = System.currentTimeMillis() - start;

            assertEquals(200, resp.getStatusCode());
            String full = new String(resp.getResponseBytes(), StandardCharsets.ISO_8859_1);
            assertTrue("响应必须包含 chunk extension 终结符", full.contains("0;name=value\r\n"));
            assertTrue("chunked extension 路径不应等满超时, 实际 " + elapsed + "ms",
                    elapsed < 2000);
        }
    }

    @Test
    public void crlfGhostSequenceIsPreservedInHeaderValue() throws Exception {
        String crlf = "瘍瘊"; // 折叠后是真实 \r\n
        String body = "<a@b.com>" + crlf + "X-Injected: yes" + crlf;
        String request = "POST / HTTP/1.1\r\n"
                + "Host: 127.0.0.1:" + server.port + "\r\n"
                + "X-Custom: " + body + "\r\n"
                + "Content-Length: 0\r\n"
                + "Connection: close\r\n\r\n";

        RawSocketSender sender = new RawSocketSender();
        sender.send("127.0.0.1", server.port, false,
                request.getBytes(StandardCharsets.UTF_8), 2000, 1000);

        byte[] seen = server.lastReceivedBytes();
        String hex = bytesToHex(seen);
        // 瘍瘊 UTF-8 = E7 98 8D E7 98 8A
        // 服务器收到的必须是这个，而不是 0d 0a (那意味着客户端先折叠了)
        assertTrue("expected raw 瘍瘊 UTF-8 bytes on wire",
                hex.contains("e7 98 8d e7 98 8a"));
    }

    // ------------------------------------------------------------------
    // 一个最简的 echo server，不依赖 Python 进程，避免测试环境装依赖
    // ------------------------------------------------------------------

    private static class EchoServer {
        ServerSocket socket;
        int port;
        Thread acceptThread;
        final AtomicBoolean running = new AtomicBoolean(false);
        volatile byte[] lastReceived;

        void start() throws IOException {
            socket = new ServerSocket(0, 8, java.net.InetAddress.getByName("127.0.0.1"));
            port = socket.getLocalPort();
            running.set(true);
            acceptThread = new Thread(this::acceptLoop, "ghostbits-echo-server");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        void stop() {
            running.set(false);
            try { socket.close(); } catch (Exception ignored) {}
            try { acceptThread.interrupt(); } catch (Exception ignored) {}
        }

        byte[] lastReceivedBytes() {
            return lastReceived;
        }

        void acceptLoop() {
            while (running.get()) {
                try {
                    Socket conn = socket.accept();
                    handleClient(conn);
                } catch (IOException e) {
                    if (running.get()) {
                        // 测试期间偶发，忽略
                    }
                    return;
                }
            }
        }

        void handleClient(Socket conn) {
            try {
                conn.setSoTimeout(300);
                InputStream in = conn.getInputStream();
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] chunk = new byte[4096];
                while (true) {
                    int n;
                    try {
                        n = in.read(chunk);
                    } catch (java.net.SocketTimeoutException e) {
                        break;
                    }
                    if (n < 0) break;
                    buf.write(chunk, 0, n);
                }
                lastReceived = buf.toByteArray();

                String hex = bytesToHex(lastReceived);
                String decoded = new String(lastReceived, StandardCharsets.UTF_8);
                String body = "=== HEX VIEW ===\n" + hex + "\n\n=== UTF-8 DECODED ===\n" + decoded + "\n";
                byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

                OutputStream out = conn.getOutputStream();
                String head = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/plain; charset=utf-8\r\n"
                        + "Content-Length: " + bodyBytes.length + "\r\n"
                        + "Connection: close\r\n\r\n";
                out.write(head.getBytes(StandardCharsets.ISO_8859_1));
                out.write(bodyBytes);
                out.flush();
            } catch (Exception ignored) {
                fail("echo server crashed: " + ignored.getMessage());
            } finally {
                try { conn.close(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * keep-alive 行为模拟：响应一次后保持连接半秒不主动 close，让客户端必须靠 CL/chunked
     * 自己判断何时返回。
     */
    private static class KeepAliveServer implements AutoCloseable {
        final ServerSocket socket;
        int port;
        final Function<byte[], byte[]> handler;
        Thread acceptThread;
        final AtomicBoolean running = new AtomicBoolean(false);

        KeepAliveServer(Function<byte[], byte[]> handler) throws IOException {
            this.handler = handler;
            this.socket = new ServerSocket(0, 8, java.net.InetAddress.getByName("127.0.0.1"));
            this.port = socket.getLocalPort();
        }

        void start() {
            running.set(true);
            acceptThread = new Thread(this::acceptLoop, "ka-server");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        @Override
        public void close() {
            running.set(false);
            try { socket.close(); } catch (Exception ignored) {}
            try { acceptThread.interrupt(); } catch (Exception ignored) {}
        }

        void acceptLoop() {
            while (running.get()) {
                try {
                    Socket conn = socket.accept();
                    new Thread(() -> handle(conn), "ka-handler").start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        void handle(Socket conn) {
            try {
                conn.setSoTimeout(300);
                InputStream in = conn.getInputStream();
                ByteArrayOutputStream req = new ByteArrayOutputStream();
                byte[] chunk = new byte[4096];
                while (true) {
                    int n;
                    try { n = in.read(chunk); }
                    catch (java.net.SocketTimeoutException e) { break; }
                    if (n < 0) break;
                    req.write(chunk, 0, n);
                    String s = req.toString("ISO-8859-1");
                    if (s.contains("\r\n\r\n")) break;
                }
                byte[] resp = handler.apply(req.toByteArray());
                OutputStream out = conn.getOutputStream();
                out.write(resp);
                out.flush();
                // 关键：故意保持连接 1 秒不主动 close，模拟 keep-alive
                // 如果客户端按 CL/chunked 解析正确，应该立刻返回，远早于这 1 秒
                Thread.sleep(1000);
            } catch (Exception ignored) {
            } finally {
                try { conn.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }
}

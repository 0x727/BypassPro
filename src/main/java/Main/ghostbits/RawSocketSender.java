package Main.ghostbits;

import Main.HttpResponse;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * 原始字节级别的 HTTP/HTTPS 发送器。
 *
 * 设计目标：让用户编辑器里的 byte[] 不经任何字符串中转直接进 socket，专门用于
 * 复现 Ghost Bits 这类对 wire 字节流敏感的漏洞。
 *
 * 关键约束：
 *  1. 入口 send(...) 接收 byte[]，内部 OutputStream.write(bytes)。
 *  2. 不依赖 Burp callbacks，不依赖 IExtensionHelpers。
 *  3. HTTPS 默认 TrustAll，方便本地 CTF/测试环境（UI 上要明确标识）。
 */
public class RawSocketSender {

    /**
     * 发送原始字节，按 HTTP/1 响应边界结束读取；保留临时响应及原始 framing。
     * 超时、截断和 16MB 上限会标记为不完整响应。
     *
     * @param host        目标主机
     * @param port        目标端口
     * @param https       是否启用 TLS
     * @param requestBytes 请求字节流（必须包含完整 HTTP 头 + 空行 + body）
     * @param connectTimeoutMs 连接超时（毫秒）
     * @param readTimeoutMs    TLS 握手及读超时（毫秒）
     * @return 原始字节响应封装
     */
    public RawResponse send(String host, int port, boolean https,
                            byte[] requestBytes,
                            int connectTimeoutMs, int readTimeoutMs) throws IOException {
        if (host == null || host.isEmpty()) {
            throw new IOException("host is empty");
        }
        if (requestBytes == null || requestBytes.length == 0) {
            throw new IOException("request bytes is empty");
        }

        long startNs = System.nanoTime();
        Socket socket = null;
        try {
            socket = createSocket(host, port, https, connectTimeoutMs, readTimeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write(requestBytes);
            out.flush();

            String method = new String(requestBytes, 0, Math.min(requestBytes.length, 32), java.nio.charset.StandardCharsets.ISO_8859_1).split(" ", 2)[0];
            HttpResponse.Analysis response = HttpResponse.read(socket.getInputStream(), method);
            long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
            return new RawResponse(response, requestBytes, durationMs, host, port, https);
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception ignored) {}
            }
        }
    }

    private Socket createSocket(String host, int port, boolean https, int connectTimeoutMs, int readTimeoutMs) throws IOException {
        Socket plain = new Socket();
        Socket connected = plain;
        try {
            plain.connect(new InetSocketAddress(host, port), connectTimeoutMs <= 0 ? 5000 : connectTimeoutMs);
            plain.setSoTimeout(readTimeoutMs <= 0 ? 5000 : readTimeoutMs);
            if (!https) return plain;
            SSLSocket ssl = (SSLSocket) trustAllSocketFactory().createSocket(plain, host, port, true);
            connected = ssl;
            ssl.setSoTimeout(readTimeoutMs <= 0 ? 5000 : readTimeoutMs);
            SSLParameters params = ssl.getSSLParameters();
            params.setEndpointIdentificationAlgorithm(null);
            ssl.setSSLParameters(params);
            ssl.startHandshake();
            return ssl;
        } catch (IOException | NoSuchAlgorithmException | KeyManagementException | RuntimeException e) {
            try { connected.close(); } catch (Exception ignored) {}
            try { plain.close(); } catch (Exception ignored) {}
            if (e instanceof IOException) throw (IOException)e;
            throw new IOException("TLS/connect failed: " + e.getMessage(), e);
        }
    }

    private SSLSocketFactory trustAllSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] tms = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {}
                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {}
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tms, new SecureRandom());
        return ctx.getSocketFactory();
    }

    /**
     * 静态获取一个 always-true HostnameVerifier，便于 UI 层共用。
     */
    public static HostnameVerifier trustAllHostnameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    public static class RawResponse {
        private final HttpResponse.Analysis analysis;
        private final byte[] requestBytesActuallySent;
        private final long durationMs;
        private final String host;
        private final int port;
        private final boolean https;

        public RawResponse(byte[] responseBytes, byte[] requestBytesActuallySent,
                           long durationMs, String host, int port, boolean https) {
            this(HttpResponse.analyze(responseBytes, requestMethod(requestBytesActuallySent)),
                    requestBytesActuallySent, durationMs, host, port, https);
        }

        public RawResponse(HttpResponse.Analysis analysis, byte[] requestBytesActuallySent,
                           long durationMs, String host, int port, boolean https) {
            this.analysis = analysis;
            this.requestBytesActuallySent = requestBytesActuallySent == null ? new byte[0] : requestBytesActuallySent;
            this.durationMs = durationMs;
            this.host = host;
            this.port = port;
            this.https = https;
        }

        private static String requestMethod(byte[] request) {
            return request == null ? "" : new String(request, 0, Math.min(request.length, 32),
                    java.nio.charset.StandardCharsets.ISO_8859_1).split(" ", 2)[0];
        }

        public HttpResponse.Analysis getAnalysis() { return analysis; }
        public byte[] getResponseBytes() { return analysis.rawBytes; }
        public byte[] getRequestBytesActuallySent() { return requestBytesActuallySent; }
        public long getDurationMs() { return durationMs; }
        public String getHost() { return host; }
        public int getPort() { return port; }
        public boolean isHttps() { return https; }
        public int getStatusCode() { return analysis.statusCode; }
        public int getBodyOffset() { return analysis.bodyOffset; }
    }
}

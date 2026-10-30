package Main;

import burp.IHttpService;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Shared, same-origin redirect policy. Only the next request line changes when preserving a method. */
final class RedirectPolicy {
    private RedirectPolicy() { }

    static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    static URL requestUrl(IHttpService service, byte[] request) throws Exception {
        String line = new String(request, StandardCharsets.ISO_8859_1).split("\\r?\\n", 2)[0];
        String[] parts = line.split(" ", 3);
        if (parts.length < 3) throw new IllegalArgumentException("Invalid request line");
        String path = parts[1];
        if (path.startsWith("http://") || path.startsWith("https://")) path = new URL(path).getFile();
        return new URL(service.getProtocol(), service.getHost(), effectivePort(service), path);
    }

    static URL resolve(IHttpService service, byte[] request, String location) throws Exception {
        URL base = requestUrl(service, request);
        // java.net.URL treats a query-only reference as a directory reference; retain the resource path.
        URL next = new URL(base, location.startsWith("?") ? base.getPath() + location : location);
        int port = next.getPort() < 0 ? next.getDefaultPort() : next.getPort();
        if (!service.getHost().equalsIgnoreCase(next.getHost())
                || !service.getProtocol().equalsIgnoreCase(next.getProtocol())
                || effectivePort(service) != port || next.getUserInfo() != null) {
            throw new IllegalArgumentException(I18n.t("redirect.cross_origin"));
        }
        return new URL(next.getProtocol(), next.getHost(), port, next.getFile());
    }

    private static int effectivePort(IHttpService service) {
        return service.getPort() > 0 ? service.getPort() : "https".equalsIgnoreCase(service.getProtocol()) ? 443 : 80;
    }

    static byte[] followRequest(byte[] request, URL next, int code) {
        int lineEnd = 0;
        while (lineEnd < request.length && request[lineEnd] != '\n') lineEnd++;
        if (lineEnd == request.length) throw new IllegalArgumentException("Invalid request line");
        String[] line = new String(request, 0, lineEnd, StandardCharsets.ISO_8859_1).trim().split(" ", 3);
        if (line.length != 3) throw new IllegalArgumentException("Invalid request line");
        String method = line[0];
        // RFC 9110 15.4: POST can become GET on 301/302; 303 retrieves via GET/HEAD; 307/308 preserve.
        boolean dropBody = code == 303 || ((code == 301 || code == 302) && "POST".equalsIgnoreCase(method));
        if (dropBody && !"HEAD".equalsIgnoreCase(method)) method = "GET";
        String path = next.getFile();
        if (path.isEmpty() || path.charAt(0) == '?') path = "/" + path;
        byte[] first = (method + " " + path + " " + line[2] + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        if (!dropBody) {
            byte[] result = Arrays.copyOf(first, first.length + request.length - lineEnd - 1);
            System.arraycopy(request, lineEnd + 1, result, first.length, request.length - lineEnd - 1);
            return result;
        }
        StringBuilder headers = new StringBuilder(new String(first, StandardCharsets.ISO_8859_1));
        String rest = new String(request, lineEnd + 1, request.length - lineEnd - 1, StandardCharsets.ISO_8859_1);
        for (String header : rest.split("\\r?\\n")) {
            if (header.isEmpty()) break;
            String name = header.split(":", 2)[0].trim().toLowerCase(java.util.Locale.ROOT);
            if (name.equals("content-length") || name.equals("transfer-encoding") || name.equals("content-type")
                    || name.equals("content-encoding") || name.equals("expect") || name.equals("trailer")) continue;
            headers.append(header).append("\r\n");
        }
        return headers.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
    }
}

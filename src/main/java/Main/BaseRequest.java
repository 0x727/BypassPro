package Main;

import java.util.Map;

public class BaseRequest {
    public String method;
    public String path;
    public Map<String, String> headers;

    public BaseRequest(String method, String path, Map<String, String> headers) {
        this.method = method;
        this.headers = headers;
        this.path = path;
    }

    public String toString() {
        return method + " : " + path;
    }
}
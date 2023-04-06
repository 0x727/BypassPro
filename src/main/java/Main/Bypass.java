package Main;

import burp.IHttpRequestResponsePersisted;

import java.net.URL;

public class Bypass {

    final String timestamp;
    final String length;
    final IHttpRequestResponsePersisted requestResponse;
    final URL url;
    final short status;
    final String mimeType;
    final String method;
    final String title;
    final long id;
    final String tool;

    public Bypass(String timestamp, String method, String length, IHttpRequestResponsePersisted requestResponse, URL url, short status, String mimeType, String title, long id, String tool) {

        this.timestamp = timestamp;
        this.method = method;
        this.length = length;
        this.requestResponse = requestResponse;
        this.url = url;
        this.status = status;
        this.mimeType = mimeType;
        this.title = title;
        this.id = id;
        this.tool = tool;
    }
}


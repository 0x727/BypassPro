package Main;

import burp.IHttpRequestResponsePersisted;

import java.net.URL;

public class Bypass {
    enum Outcome { SIGNAL, FILTERED, ERROR, BASELINE }
    final Outcome outcome;

    final String timestamp;
    final String length;
    final IHttpRequestResponsePersisted requestResponse;
    final URL url;
    final String redirect;
    final String redirectTooltip;
    final short status;
    final String mimeType;
    final String method;
    final String title;
    final long id;
    /**
     * Short source label shown in Dashboard.
     * Expected values: auto / send access / send waf / manual waf.
     */
    final String tool;
    final String reason;

    public Bypass(String timestamp, String method, String length, IHttpRequestResponsePersisted requestResponse, URL url, short status, String mimeType, String title, long id, String tool, String reason) {
        this(timestamp, method, length, requestResponse, url, "", "", status, mimeType, title, id, tool, reason);
    }

    public Bypass(String timestamp, String method, String length, IHttpRequestResponsePersisted requestResponse,
                  URL url, String redirect, String redirectTooltip, short status, String mimeType,
                  String title, long id, String tool, String reason) {

        this(timestamp, method, length, requestResponse, url, redirect, redirectTooltip, status, mimeType,
                title, id, tool, reason, Outcome.SIGNAL);
    }

    Bypass(String timestamp, String method, String length, IHttpRequestResponsePersisted requestResponse,
           URL url, String redirect, String redirectTooltip, short status, String mimeType,
           String title, long id, String tool, String reason, Outcome outcome) {
        this.outcome = outcome;
        this.timestamp = timestamp;
        this.method = method;
        this.length = length;
        this.requestResponse = requestResponse;
        this.url = url;
        this.redirect = redirect == null ? "" : redirect;
        this.redirectTooltip = redirectTooltip == null ? "" : redirectTooltip;
        this.status = status;
        this.mimeType = mimeType;
        this.title = title;
        this.id = id;
        this.tool = tool;
        this.reason = reason;
    }
}

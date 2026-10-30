package Main;

import Main.ghostbits.AutoGhostBitsGenerator;
import Main.ghostbits.GhostBitsAutoVariant;
import Main.ghostbits.RawSocketSender;
import burp.*;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.zip.GZIPOutputStream;

public class BypassMain implements IContextMenuFactory, IProxyListener {

    private static final int DEFAULT_MAX_REDIRECT_HOPS = 3;

    static synchronized long nextId() {
        return Utils.count++;
    }

    /**
     * 生成 payload 变体
     * 
     * @param path    原始路径
     * @param profile 配置 profile 名称
     * @param method  原始请求方法（GET/POST/PUT 等）
     */
    public List<BaseRequest> make_payload_v2(String path, String profile, String method) {
        if (path == null || path.isEmpty()) {
            path = "";
        }
        // 兼容非标准请求：仅在以 "/" 开头时才去掉首字符
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        String headerPath = path;

        Boolean isEnd = false;

        if (!path.isEmpty() && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
            isEnd = true;
        }
        String[] paths = path.isEmpty() ? new String[0] : path.split("/");

        Map<String, Object> profileConfig = Utils.getProfileConfig(profile);
        List<BaseRequest> allRequests = new ArrayList<>();
        List<String> suffixList = safeStringList(profileConfig.get("suffix"));
        if (isEnd) {
            allRequests.addAll(makeRequestSuffix(suffixList, path, method));
            allRequests.addAll(makeRequestSuffix(suffixList, path + "/", method));
        } else {
            allRequests.addAll(makeRequestSuffix(suffixList, path, method));
        }

        // prefix 规则：对每层目录前置变形
        List<String> prefixList = safeStringList(profileConfig.get("prefix"));
        if (paths.length > 0) {
            int paths_len = paths.length;
            if (isEnd) {
                allRequests.addAll(makeRequestPrefix(prefixList, paths, paths_len, "/", method));
            } else {
                allRequests.addAll(makeRequestPrefix(prefixList, paths, paths_len, "", method));
            }
        }

        // 对每一级目录边界进行插入FUZZ（一次只插入一个边界，避免组合爆炸）
        List<String> insertList = safeStringList(profileConfig.get("boundary_insert"));
        if (!insertList.isEmpty() && paths.length > 1) {
            allRequests.addAll(makeRequestBoundaryInsert(insertList, paths, isEnd ? "/" : "", method));
        }

        // headers 规则：Header 伪造变体
        List<?> headersList = safeList(profileConfig.get("headers"));
        allRequests.addAll(makeRequestHeader(headersList, headerPath, method));

        return deduplicateRequests(allRequests);

    }

    private static List<?> safeList(Object o) {
        if (o instanceof List) {
            return (List<?>) o;
        }
        return Collections.emptyList();
    }

    private static List<String> safeStringList(Object o) {
        if (!(o instanceof List)) {
            return Collections.emptyList();
        }
        List<?> in = (List<?>) o;
        List<String> out = new ArrayList<>(in.size());
        for (Object x : in) {
            if (x == null)
                continue;
            out.add(String.valueOf(x));
        }
        return out;
    }

    private static List<BaseRequest> deduplicateRequests(List<BaseRequest> requests) {
        if (requests == null || requests.isEmpty()) {
            return requests;
        }

        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<BaseRequest> out = new ArrayList<>(requests.size());
        for (BaseRequest r : requests) {
            if (r == null) {
                continue;
            }
            String key = buildDedupKey(r);
            if (seen.add(key)) {
                out.add(r);
            }
        }
        return out;
    }

    private static String buildDedupKey(BaseRequest r) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.valueOf(r.method)).append(' ').append(String.valueOf(r.path));
        Map<String, String> h = r.headers;
        if (h == null || h.isEmpty()) {
            sb.append(" H:{}");
            return sb.toString();
        }
        ArrayList<String> pairs = new ArrayList<>(h.size());
        for (Map.Entry<String, String> e : h.entrySet()) {
            String k = e.getKey();
            String v = e.getValue();
            if (k == null)
                continue;
            pairs.add(k.trim().toLowerCase() + "=" + String.valueOf(v));
        }
        Collections.sort(pairs);
        sb.append(" H:{").append(StringUtils.join(pairs, ";")).append('}');
        return sb.toString();
    }

    public static List<BaseRequest> makeRequestSuffix(List<String> suffixList, String path, String method) {
        List<BaseRequest> baseRequestList = new ArrayList<>();

        for (String item : suffixList) {
            baseRequestList.add(new BaseRequest(method, "/" + path + item, null));
        }

        return baseRequestList;
    }

    public static List<BaseRequest> makeRequestPrefix(List<String> prefixList, String[] paths, int paths_len,
            String end, String method) {
        List<BaseRequest> baseRequestList = new ArrayList<>();
        for (String item : prefixList) {
            for (int i = 0; i < paths_len; i++) {
                String _target = paths[i];
                String new_path = "";

                paths[i] = item + _target;
                new_path = StringUtils.join(paths, "/") + end;
                baseRequestList.add(new BaseRequest(method, "/" + new_path, null));
                paths[i] = _target;
            }
        }

        return baseRequestList;
    }

    public static List<BaseRequest> makeRequestHeader(List<?> headerList, String path, String method) {
        List<BaseRequest> baseRequestList = new ArrayList<>();
        for (Object item : headerList) {
            if (item instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, String> headers = (Map<String, String>) ((HashMap<String, String>) item).clone();
                baseRequestList.add(new BaseRequest(method, "/" + path, headers));
            }
        }
        return baseRequestList;
    }

    /**
     * 在目录边界插入标记（一次只改一个边界）：
     * a/b/c + ";" => a;/b/c、a/b;/c
     */
    public static List<BaseRequest> makeRequestBoundaryInsert(List<String> insertList, String[] paths, String end,
            String method) {
        List<BaseRequest> baseRequestList = new ArrayList<>();
        if (insertList == null || insertList.isEmpty() || paths == null || paths.length < 2) {
            return baseRequestList;
        }

        int pathsLen = paths.length;
        for (String insert : insertList) {
            if (insert == null || insert.isEmpty()) {
                continue;
            }
            for (int i = 0; i < pathsLen - 1; i++) {
                String original = paths[i];
                paths[i] = original + insert;
                String newPath = StringUtils.join(paths, "/") + end;
                baseRequestList.add(new BaseRequest(method, "/" + newPath, null));
                paths[i] = original;
            }
        }

        return baseRequestList;
    }

    class Run_request implements Runnable {
        private BaseRequest baseRequest;
        private IHttpRequestResponse iHttpRequestResponse;
        private String tool;
        private final boolean followRedirect;
        private final int maxRedirects;
        private final ScanSession session;

        public Run_request(BaseRequest baseRequest, IHttpRequestResponse iHttpRequestResponse, String tool,
                           boolean followRedirect, int maxRedirects, ScanSession session) {
            this.session = session;
            this.baseRequest = baseRequest;
            this.iHttpRequestResponse = iHttpRequestResponse;
            this.tool = tool;
            this.followRedirect = followRedirect;
            this.maxRedirects = maxRedirects;
        }

        @Override
        public void run() {
            if (session.cancelled) return;
            byte[] attempted = iHttpRequestResponse.getRequest();
            String method = baseRequest.method;
            String path = baseRequest.path;
            Map<String, String> headers = baseRequest.headers;

            try {
                byte[] oldRequestBytes = iHttpRequestResponse.getRequest();
                if (oldRequestBytes == null) {
                    throw new IllegalArgumentException("Invalid source request");
                }

                IRequestInfo requestInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse.getHttpService(),
                        oldRequestBytes);
                List<String> newHeaders = new ArrayList<>(requestInfo.getHeaders());
                if (newHeaders.isEmpty()) {
                    throw new IllegalArgumentException("Invalid source request");
                }

                // 请求行：METHOD path HTTP/x.x
                String requestLine = newHeaders.get(0);
                String[] parts = requestLine.split(" ", 3);
                if (parts.length < 3) {
                    throw new IllegalArgumentException("Invalid source request");
                }

                String httpVersion = parts[2];
                if (headers != null && headers.containsKey("HTTP-Version")) {
                    httpVersion = headers.get("HTTP-Version");
                }

                String newRequestLine = method + " " + path + " " + httpVersion;

                // 只改请求行，不清空原始请求头
                newHeaders.set(0, newRequestLine);
                if (headers != null) {
                    for (Map.Entry<String, String> e : headers.entrySet()) {
                        String key = e.getKey();
                        String value = e.getValue();
                        if (key == null || value == null || "HTTP-Version".equals(key)) {
                            continue;
                        }

                        int idx = findHeaderIndex(newHeaders, key);
                        if (idx >= 0) {
                            newHeaders.set(idx, key + ": " + value);
                        } else {
                            newHeaders.add(key + ": " + value);
                        }
                    }
                }

                int bodyOffset = requestInfo.getBodyOffset();
                byte[] body = null;
                if (bodyOffset >= 0 && bodyOffset < oldRequestBytes.length) {
                    body = Arrays.copyOfRange(oldRequestBytes, bodyOffset, oldRequestBytes.length);
                }
                byte[] newRequestBytes = Utils.helpers.buildHttpMessage(newHeaders, body);

                attempted = newRequestBytes;
                SendResult sendResult = sendWithRedirectPolicy(iHttpRequestResponse.getHttpService(),
                        newRequestBytes, followRedirect, maxRedirects, session);

                byte[] finalResponseBytes = sendResult.getJudgedResponseBytes();
                if (session.cancelled) return;
                if (finalResponseBytes == null || finalResponseBytes.length == 0)
                    throw new IllegalStateException(I18n.t("manual.no_response"));

                double threshold = Utils.panel.getSimilarityThreshold();
                ResponseComparison comparison = new ResponseComparison(iHttpRequestResponse, sendResult.analysis());
                short oldStatus = comparison.oldStatus;
                short newStatus = comparison.newStatus;
                String newBody = comparison.body;
                double ratio = comparison.ratio;
                boolean statusClassChanged = (oldStatus > 0 && newStatus > 0) && (oldStatus / 100 != newStatus / 100);

                boolean shouldLog = comparison.complete && isCandidateStatus(newStatus) && (ratio < threshold || statusClassChanged);

                if (sendResult.judgedMessage != null && finalResponseBytes != null) {
                    String title = Utils.getBodyTitle(newBody == null ? "" : newBody);
                    String reason = comparison.reason(buildAutoReason(oldStatus, newStatus, ratio, threshold, statusClassChanged));
                    reason = candidateReason(iHttpRequestResponse, newRequestBytes, sendResult.analysis(), ratio, reason, false);
                    addLog(session, sendResult, title, tool, reason, shouldLog);
                }
                Utils.panel.addFinishRequestNum(session, 1);

            } catch (Exception ee) {
                recordFailure(session, iHttpRequestResponse.getHttpService(), attempted, tool, ee);
            }
        }
    }

    static boolean isCandidateStatus(short statusCode) {
        return statusCode == 200 || statusCode == 206 || statusCode == 304
                || statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308
                || statusCode == 405 || statusCode == 415;
    }

    /**
     * Dashboard only persists addLog's 200/405/415 subset; this reason explains
     * the already-accepted candidate without changing that existing filter.
     */
    static String buildAutoReason(short oldStatus, short newStatus,
                                  double ratio, double threshold,
                                  boolean statusClassChanged) {
        StringBuilder sb = new StringBuilder();
        boolean hasStatus = oldStatus > 0 || newStatus > 0;
        if (hasStatus) {
            sb.append("status:")
                    .append(formatStatus(oldStatus))
                    .append(" -> ")
                    .append(formatStatus(newStatus));
        }

        boolean ratioUsable = Double.isFinite(ratio) && Double.isFinite(threshold);
        if (ratioUsable && ratio < threshold) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append("sim:")
                    .append(String.format(Locale.ROOT, "%.2f", ratio))
                    .append(" < ")
                    .append(String.format(Locale.ROOT, "%.2f", threshold));
        } else if (statusClassChanged) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append("class changed");
        }

        return sb.toString();
    }

    private static String formatStatus(short status) {
        return status <= 0 ? "?" : Short.toString(status);
    }

    private static boolean isRedirectStatus(short statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    }

    private static short getStatusSafe(byte[] responseBytes) {
        int code = HttpResponse.analyze(responseBytes, "").statusCode;
        return (short)(code == 0 ? -1 : code);
    }

    private static HttpResponse.Analysis analyzeMessage(IHttpRequestResponse message) {
        if (message instanceof SimpleHttpRequestResponse) {
            HttpResponse.Analysis saved = ((SimpleHttpRequestResponse)message).responseAnalysis;
            if (saved != null) return saved;
        }
        if (message == null) return HttpResponse.analyze(null, "");
        byte[] request = message.getRequest();
        String method = request == null ? "" : new String(request, 0, Math.min(request.length, 32),
                StandardCharsets.ISO_8859_1).split(" ", 2)[0];
        return HttpResponse.analyze(message.getResponse(), method);
    }

    private static final class ResponseComparison {
        final short oldStatus, newStatus;
        final String body, baselineBody, issue;
        final double ratio;
        final boolean complete;
        ResponseComparison(IHttpRequestResponse original, HttpResponse.Analysis current) {
            HttpResponse.Analysis baseline = analyzeMessage(original);
            oldStatus = (short)baseline.statusCode;
            newStatus = (short)current.statusCode;
            complete = current.complete;
            HttpResponse.Text oldText = original instanceof SimpleHttpRequestResponse
                    ? ((SimpleHttpRequestResponse)original).responseText : null;
            if (oldText == null) oldText = baseline.decodeText();
            HttpResponse.Text newText = current.decodeText();
            baselineBody = oldText.value;
            body = newText.value;
            ratio = oldText.value == null || newText.value == null ? Double.NaN
                    : DiffPage.getRatio(oldText.value, newText.value, current.header("Content-Type"));
            issue = !newText.issue.isEmpty() ? newText.issue
                    : !oldText.issue.isEmpty() ? "baseline: " + oldText.issue : "";
        }
        String reason(String reason) { return issue.isEmpty() ? reason : reason + "; " + issue; }
    }

    static String baselineSummary(IHttpRequestResponse reference, HttpResponse.Analysis replay) {
        if (reference == null || reference.getResponse() == null || reference.getResponse().length == 0)
            return I18n.t("baseline.no_reference") + " | " + replay.statusCode + " / " + replay.rawBytes.length + "B";
        HttpResponse.Analysis previous = analyzeMessage(reference);
        ResponseComparison comparison = new ResponseComparison(reference, replay);
        boolean locationChanged = !previous.header("Location").equals(replay.header("Location"));
        boolean typeChanged = !previous.header("Content-Type").equalsIgnoreCase(replay.header("Content-Type"));
        boolean changed = previous.statusCode != replay.statusCode || locationChanged || typeChanged
                || (comparison.baselineBody != null && comparison.body != null && !comparison.baselineBody.equals(comparison.body));
        String label = changed ? "baseline.changed"
                : !previous.complete || !replay.complete || comparison.baselineBody == null || comparison.body == null
                ? "baseline.unknown" : "baseline.same";
        return I18n.t(label) + " | " + responseMetrics(reference, replay, comparison.ratio)
                + (locationChanged ? " | " + I18n.t("baseline.location_changed") : "")
                + (typeChanged ? " | " + I18n.t("baseline.type_changed") : "")
                + (comparison.issue.isEmpty() ? "" : " | " + comparison.issue);
    }

    static String responseMetrics(IHttpRequestResponse reference, HttpResponse.Analysis current) {
        return responseMetrics(reference, current, new ResponseComparison(reference, current).ratio);
    }

    private static String responseMetrics(IHttpRequestResponse reference, HttpResponse.Analysis current, double ratio) {
        return I18n.t("baseline.metrics", formatStatus((short)analyzeMessage(reference).statusCode),
                formatStatus((short)current.statusCode), reference.getResponse().length, current.rawBytes.length,
                Double.isFinite(ratio) ? String.format(Locale.ROOT, "%.2f", ratio) : "N/A");
    }

    private static String candidateReason(IHttpRequestResponse original, byte[] variant,
                                          HttpResponse.Analysis response, double ratio, String reason, boolean raw) {
        if (!(original instanceof SimpleHttpRequestResponse)) return reason;
        String baseline = ((SimpleHttpRequestResponse)original).baselineReason;
        if (baseline.isEmpty()) return reason;
        return baseline + "; " + I18n.t("auto.changes", ManualWafPanel.requestDiffSummary(original.getRequest(), variant))
                + "; " + I18n.t("baseline.compare", responseMetrics(original, response, ratio))
                + (raw ? "; " + I18n.t("baseline.raw_comparison") : "") + "; " + reason;
    }

    private SimpleHttpRequestResponse replayBaseline(SimpleHttpRequestResponse captured, boolean followRedirect,
                                                    int maxRedirects, ScanSession session, ExecutorService executor) throws Exception {
        Utils.panel.addAllRequestNum(session, 1);
        Utils.panel.checkingBaseline(session, RedirectPolicy.requestUrl(captured.getHttpService(), captured.getRequest()).toString());
        FutureTask<SimpleHttpRequestResponse> replay = new FutureTask<>(() -> {
            SendResult sent = sendWithRedirectPolicy(captured.getHttpService(), captured.getRequest(),
                    followRedirect, maxRedirects, session);
            if (session.cancelled) return null;
            HttpResponse.Analysis analysis = sent.analysis();
            if (!analysis.complete) throw new IllegalStateException("Baseline: " + analysis.issue);
            SimpleHttpRequestResponse snapshot = new SimpleHttpRequestResponse(captured.getHttpService(),
                    captured.getRequest(), sent.getJudgedResponseBytes().clone());
            snapshot.responseAnalysis = analysis;
            snapshot.responseText = analysis.decodeText();
            snapshot.baselineReason = baselineSummary(captured, analyzeMessage(sent.testedMessage));
            if (sent.redirectCount > 0) snapshot.baselineReason += " | " + I18n.t("baseline.final", analysis.statusCode, analysis.rawBytes.length);
            addLog(session, sent, Utils.getBodyTitle(snapshot.responseText.value == null ? "" : snapshot.responseText.value),
                    "baseline", snapshot.baselineReason, Bypass.Outcome.BASELINE);
            Utils.panel.addFinishRequestNum(session, 1);
            Utils.panel.baselineChecked(session, snapshot.baselineReason);
            return snapshot;
        });
        Utils.submitScan(executor, session, replay);
        while (!session.cancelled && !executor.isShutdown()) {
            try { return replay.get(250, TimeUnit.MILLISECONDS); }
            catch (TimeoutException waiting) { /* Keep cancellation responsive while the transport finishes. */ }
        }
        return null;
    }

    private SendResult sendWithRedirectPolicy(IHttpService service, byte[] requestBytes,
                                              boolean followRedirect, int maxRedirects, ScanSession session) {
        int maxHops = normalizeMaxRedirects(maxRedirects);
        if (session.cancelled) return new SendResult(service, requestBytes, null, followRedirect, maxHops);
        IHttpRequestResponse firstResponse = Utils.callbacks.makeHttpRequest(service, requestBytes);
        SendResult result = new SendResult(service, requestBytes, firstResponse, followRedirect, maxHops);
        if (!followRedirect || firstResponse == null || firstResponse.getResponse() == null || service == null) {
            return result;
        }

        IHttpRequestResponse current = firstResponse;
        byte[] currentRequestBytes = requestBytes;
        java.util.HashSet<String> visited = new java.util.HashSet<>();
        try { visited.add(RedirectPolicy.requestUrl(service, requestBytes).toString()); }
        catch (Exception ignored) { }

        for (int i = 0; i < maxHops && !session.cancelled; i++) {
            byte[] resp = current.getResponse();
            if (resp == null) {
                return result;
            }
            HttpResponse.Analysis analysis = result.analysis();
            short code = (short)analysis.statusCode;
            if (!isRedirectStatus(code)) {
                return result;
            }

            String location = analysis.header("Location");
            if (location == null || location.isEmpty()) {
                return result;
            }

            try {
                URL next = RedirectPolicy.resolve(service, currentRequestBytes, location);
                if (!visited.add(next.toString())) {
                    result.stopReason = I18n.t("redirect.loop");
                    return result;
                }
                byte[] nextReq = RedirectPolicy.followRequest(currentRequestBytes, next, code);
                if (session.cancelled) return result;
                current = Utils.callbacks.makeHttpRequest(service, nextReq);
                if (current == null || current.getResponse() == null || current.getResponse().length == 0) {
                    throw new IllegalStateException(I18n.t("manual.no_response"));
                }
                currentRequestBytes = nextReq;
                result.recordRedirect(next, current);
            } catch (Exception e) {
                result.stopReason = I18n.t("redirect.stopped", e.getMessage());
                return result;
            }
        }

        if (!session.cancelled && isRedirectStatus(getStatusSafe(result.getJudgedResponseBytes())))
            result.stopReason = I18n.t("redirect.limit");
        return result;
    }

    private static int normalizeMaxRedirects(int maxRedirects) {
        if (maxRedirects < 1) {
            return DEFAULT_MAX_REDIRECT_HOPS;
        }
        return Math.min(maxRedirects, 10);
    }

    private static class SendResult {
        final IHttpRequestResponse testedMessage;
        IHttpRequestResponse judgedMessage;
        final URL testedUrl;
        URL finalUrl;
        final boolean followRedirect;
        final int maxRedirects;
        int redirectCount;
        String stopReason = "";
        final List<String> redirectChain = new ArrayList<>();
        HttpResponse.Analysis judgedAnalysis;

        SendResult(IHttpService service, byte[] testedRequestBytes, IHttpRequestResponse testedMessage,
                   boolean followRedirect, int maxRedirects) {
            this.testedMessage = testedMessage;
            this.judgedMessage = testedMessage;
            this.followRedirect = followRedirect;
            this.maxRedirects = maxRedirects;
            this.testedUrl = analyzeUrl(service, testedRequestBytes);
            this.finalUrl = this.testedUrl;
            if (this.testedUrl != null) {
                this.redirectChain.add(displayUrl(this.testedUrl));
            }
        }

        void recordRedirect(URL nextUrl, IHttpRequestResponse nextMessage) {
            redirectCount++;
            finalUrl = nextUrl;
            judgedMessage = nextMessage;
            judgedAnalysis = null;
            redirectChain.add(displayUrl(nextUrl));
        }

        HttpResponse.Analysis analysis() {
            if (judgedAnalysis == null) judgedAnalysis = analyzeMessage(judgedMessage);
            return judgedAnalysis;
        }

        byte[] getJudgedResponseBytes() {
            return judgedMessage == null ? null : judgedMessage.getResponse();
        }

        String redirectDisplay() {
            if (!followRedirect) {
                return stopReason.isEmpty() ? "false" : "false (Raw)";
            }
            return "true " + redirectCount + "/" + maxRedirects + (stopReason.isEmpty() ? "" : " (stopped)");
        }

        String redirectTooltip() {
            return StringUtils.join(redirectChain, " -> ") + (stopReason.isEmpty() ? "" : " | " + stopReason);
        }

        private static URL analyzeUrl(IHttpService service, byte[] requestBytes) {
            try {
                return Utils.helpers.analyzeRequest(service, requestBytes).getUrl();
            } catch (Exception e) {
                return null;
            }
        }

        private static String displayUrl(URL url) {
            if (url == null) {
                return "";
            }
            String file = url.getFile();
            return (file == null || file.isEmpty()) ? url.toString() : file;
        }
    }

    private void removeHeadersIgnoreCase(List<String> headers, String... names) {
        if (headers == null || headers.size() <= 1 || names == null || names.length == 0) {
            return;
        }
        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i);
            if (h == null)
                continue;
            int colon = h.indexOf(':');
            if (colon <= 0)
                continue;
            String n = h.substring(0, colon).trim();
            for (String name : names) {
                if (name == null)
                    continue;
                if (n.equalsIgnoreCase(name)) {
                    headers.remove(i);
                    break;
                }
            }
        }
    }

    /**
     * 右键菜单：Send to BypassPro (Access Control / WAF)
     */
    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> list;
        list = new ArrayList<JMenuItem>();

        if (invocation != null && invocation.getSelectedMessages() != null
                && invocation.getSelectedMessages().length > 0
                && invocation.getSelectedMessages()[0] != null
                && invocation.getSelectedMessages()[0].getHttpService() != null) {
            JMenuItem acMenuItem = new JMenuItem("Send to BypassPro (Access Control)");
            JMenuItem wafMenuItem = new JMenuItem("Send to BypassPro (WAF)");
            JMenuItem manualWafMenuItem = new JMenuItem("Send to BypassPro (Manual WAF)");

            acMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {

                    Utils.panel.showDashboard();
                    enqueueHttp(invocation.getSelectedMessages(), "send access", Utils.PROFILE_AUTO_ACCESS_BYPASS);

                }
            });

            wafMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    Utils.panel.showDashboard();
                    enqueueHttp(invocation.getSelectedMessages(), "send waf", Utils.PROFILE_AUTO_WAF_BYPASS);
                }
            });

            manualWafMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    SwingUtilities.invokeLater(() -> {
                        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                        if (messages != null && messages.length > 0) {
                            // 加载到 Manual WAF 面板
                            if (Utils.panel.getManualWafPanel().acceptRequest(messages[0])) Utils.panel.showManualWaf();
                        }
                    });
                }
            });

            list.add(acMenuItem);
            list.add(wafMenuItem);
            list.add(manualWafMenuItem);
        }
        return list;
    }

    private void addLog(ScanSession session, SendResult sendResult, String title, String tool, String reason, boolean signal) {
        addLog(session, sendResult, title, tool, reason, signal ? Bypass.Outcome.SIGNAL : Bypass.Outcome.FILTERED);
    }

    private void addLog(ScanSession session, SendResult sendResult, String title, String tool, String reason, Bypass.Outcome outcome) {
        // 入表写 UI：放到 EDT 串行执行，避免并发写 ArrayList 造成数据竞争
        {
            IHttpRequestResponse messageInfo = sendResult.judgedMessage;
            if (messageInfo == null || messageInfo.getResponse() == null) {
                return;
            }
            short statusCode = (short)sendResult.analysis().statusCode;
            if (!session.cancelled) {
                if (outcome != Bypass.Outcome.BASELINE) {
                    reason = (outcome == Bypass.Outcome.SIGNAL ? "Signal; " : "Filtered: no candidate signal; ") + reason;
                    if (statusCode == 405 || statusCode == 415) reason += "; parser/method clue, not confirmed bypass";
                }
                String displayMethod = Utils.helpers.analyzeRequest(
                        sendResult.testedMessage == null ? messageInfo : sendResult.testedMessage).getMethod();
                Utils.panel.addResult(session, new Bypass(
                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                        displayMethod,
                        String.valueOf(messageInfo.getResponse().length),
                        Utils.callbacks.saveBuffersToTempFiles(messageInfo),
                        sendResult.testedUrl == null ? Utils.helpers.analyzeRequest(messageInfo).getUrl() : sendResult.testedUrl,
                        sendResult.redirectDisplay(),
                        sendResult.redirectTooltip(),
                        statusCode,
                        sendResult.analysis().header("Content-Type"),
                        title,
                        nextId(), tool, reason, outcome));
            }
        }
    }

    private static int findHeaderIndex(List<String> headers, String headerName) {
        if (headers == null || headerName == null)
            return -1;
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null)
                continue;
            int colon = h.indexOf(':');
            if (colon <= 0)
                continue;
            String name = h.substring(0, colon).trim();
            if (name.equalsIgnoreCase(headerName)) {
                return i;
            }
        }
        return -1;
    }

    private void recordFailure(ScanSession session, IHttpService service, byte[] request, String tool, Exception failure) {
        if (session.cancelled) return;
        Utils.panel.addErrorRequestNum(session, 1);
        try {
            IHttpRequestResponse message = new SimpleHttpRequestResponse(service, request, new byte[0]);
            URL url = RedirectPolicy.requestUrl(service, request);
            Utils.panel.addResult(session, new Bypass(
                    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                    Utils.helpers.analyzeRequest(service, request).getMethod(), "0",
                    Utils.callbacks.saveBuffersToTempFiles(message), url, "", "", (short) 0, "", "",
                    nextId(), tool, "Error: " + failure.getMessage(), Bypass.Outcome.ERROR));
        } catch (Exception persistence) {
            Utils.panel.preparationFailed(session, "Could not record failed request: " + persistence.getMessage());
            Utils.out("Request failed: " + failure.getMessage());
        }
    }

    private void enqueueHttp(IHttpRequestResponse[] messages, String tool, String profile) {
        ScanSession session = Utils.panel == null ? new ScanSession() : Utils.panel.sessionForInput("auto".equals(tool));
        if (session == null) return;
        if (!Utils.dispatchScan(() -> {
            if (session.cancelled) return;
            try { processHttp(messages, tool, profile, session); }
            catch (Exception e) { if (Utils.panel != null) Utils.panel.preparationFailed(session, e.getMessage()); }
        })
                && Utils.panel != null) Utils.panel.queueFull();
    }

    public void processHttp(IHttpRequestResponse[] messages, String tool, String profile) {
        enqueueHttp(messages, tool, profile);
    }

    protected void processHttp(IHttpRequestResponse[] iHttpRequestResponses, String tool, String profile, ScanSession session) {
        if (iHttpRequestResponses == null) return;
        for (IHttpRequestResponse iHttpRequestResponse : iHttpRequestResponses) {
            if (session.cancelled) return;
            if (iHttpRequestResponse == null || iHttpRequestResponse.getHttpService() == null || iHttpRequestResponse.getRequest() == null) continue;
            byte[] sourceResponse = iHttpRequestResponse.getResponse();
            SimpleHttpRequestResponse snapshot = new SimpleHttpRequestResponse(iHttpRequestResponse.getHttpService(),
                    iHttpRequestResponse.getRequest().clone(), sourceResponse == null ? null : sourceResponse.clone());
            snapshot.responseAnalysis = analyzeMessage(snapshot);
            snapshot.responseText = snapshot.responseAnalysis.decodeText();
            int thread_num = Utils.panel.getThreadNum();
            boolean followRedirect = Utils.panel.isFollowRedirectEnabled();
            int maxRedirects = Utils.getConfigMaxRedirects(DEFAULT_MAX_REDIRECT_HOPS);
            ExecutorService es = Utils.getSharedExecutor(thread_num);
            try {
                snapshot = replayBaseline(snapshot, followRedirect, maxRedirects, session, es);
            } catch (Exception e) {
                recordFailure(session, iHttpRequestResponse.getHttpService(), iHttpRequestResponse.getRequest(), "baseline",
                        e.getCause() instanceof Exception ? (Exception)e.getCause() : e);
                Utils.panel.baselineChecked(session, I18n.t("baseline.failed"));
                continue;
            }
            if (snapshot == null || session.cancelled) return;
            iHttpRequestResponse = snapshot;
            IRequestInfo reqInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse);
            String old_path = reqInfo.getUrl().getPath();
            String query = reqInfo.getUrl().getQuery();
            String originalMethod = reqInfo.getMethod(); // 获取原始请求方法
            // response 可能为空（例如主动扫描选中未返回的请求），避免这里直接 NPE

            List<BaseRequest> allRequests;
            allRequests = make_payload_v2(old_path, profile, originalMethod);

            if (query != null && !query.isEmpty()) {
                for (BaseRequest r : allRequests) {
                    if (r.path.contains("?")) {
                        r.path = r.path + "&" + query;
                    } else {
                        r.path = r.path + "?" + query;
                    }
                }
            }

            Utils.out("start thread, number: " + String.valueOf(thread_num) + " path: " + old_path);

            List<Runnable> jobs = new ArrayList<>();
            for (BaseRequest baseRequest : allRequests) {
                jobs.add(new Run_request(baseRequest, iHttpRequestResponse, tool, followRedirect, maxRedirects, session));
            }
            if (Utils.PROFILE_AUTO_WAF_BYPASS.equals(profile)) {
                byte[] requestBytes = iHttpRequestResponse.getRequest();
                IRequestInfo wafReqInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), requestBytes);
                if (hasBody(originalMethod, requestBytes, wafReqInfo)) {
                    for (byte[] encoded : generateBodyEncodedRequests(requestBytes, wafReqInfo, iHttpRequestResponse.getHttpService()))
                        jobs.add(new Run_body_encoded_request(encoded, iHttpRequestResponse, tool, followRedirect, maxRedirects, session));
                }
                for (GhostBitsAutoVariant variant : generateGhostBitsAutoVariants(requestBytes))
                    jobs.add(new Run_ghost_bits_request(variant, iHttpRequestResponse, tool, followRedirect, maxRedirects, session));
            }
            Utils.panel.addAllRequestNum(session, jobs.size());
            for (Runnable job : jobs) Utils.submitScan(es, session, job);

            // 使用全局共享线程池：不在此处 shutdown
        }

    }

    private List<GhostBitsAutoVariant> generateGhostBitsAutoVariants(byte[] requestBytes) {
        AutoGhostBitsGenerator generator = new AutoGhostBitsGenerator(
                Utils.getGhostBitsRule(),
                Utils.getWafGhostBitsOptions());
        return generator.generate(requestBytes);
    }

    /**
     * 判断请求是否有 Body
     */
    private boolean hasBody(String method, byte[] requestBytes, IRequestInfo reqInfo) {
        // 不依赖 HTTP Method：只要存在 bodyOffset 就认为“有 Body”
        int bodyOffset = reqInfo.getBodyOffset();
        return bodyOffset > 0 && bodyOffset < requestBytes.length;
    }

    /**
     * 生成 Body 编码变体请求
     */
    private List<byte[]> generateBodyEncodedRequests(byte[] originalRequest, IRequestInfo reqInfo,
            IHttpService service) {
        List<byte[]> result = new ArrayList<>();

        int bodyOffset = reqInfo.getBodyOffset();
        byte[] originalBody = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);
        List<String> originalHeaders = new ArrayList<>(reqInfo.getHeaders());

        // 如果原始请求是 chunked 传输，则 body 区域很可能包含 chunk framing，直接做编码/压缩/类型欺骗会破坏语义
        // 这里保守处理：跳过所有 body 变体（避免发送格式错误的请求）
        if (RequestBodyPolicy.hasTransferEncoding(RequestBodyPolicy.headers(originalRequest))) {
            return result;
        }

        String originalContentType = getOriginalContentType(originalHeaders);
        if (originalContentType == null || originalContentType.isEmpty()) {
            originalContentType = "application/x-www-form-urlencoded";
        }

        Map<String, Object> charsetOptions = Utils.getWafBodyCharsetOptions();
        Map<String, Object> transformOptions = Utils.getWafBodyTransformOptions();
        Map<String, Object> ctOptions = Utils.getWafContentTypeSpoofOptions();

        // Body Charset 变体（仅对文本类 body 生效；二进制/已 gzip 会跳过）
        if (Boolean.TRUE.equals(charsetOptions.get("utf_16"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-16", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-16"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_16be"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-16BE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-16be"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_16le"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-16LE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-16le"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_32"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-32", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-32"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_32be"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-32BE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-32be"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("utf_32le"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "UTF-32LE", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "utf-32le"));
            }
        }
        if (Boolean.TRUE.equals(charsetOptions.get("ibm037"))) {
            byte[] encoded = encodeBodyWithCharset(originalBody, "IBM037", originalContentType, originalHeaders);
            if (encoded != null) {
                result.add(buildRequestWithCharset(originalHeaders, encoded, originalContentType, "ibm037"));
            }
        }

        // Gzip 变体（避免重复 gzip：原始已 gzip 则跳过）
        if (Boolean.TRUE.equals(transformOptions.get("gzip"))
                && RequestBodyPolicy.isEditable(originalRequest)) {
            byte[] gzipped = gzipBody(originalBody);
            if (gzipped != null) {
                result.add(buildRequestWithGzipBody(originalHeaders, gzipped));
            }
        }

        // Content-Type Spoof 变体
        if (Boolean.TRUE.equals(ctOptions.get("form_urlencoded"))) {
            if (!originalContentType.toLowerCase().contains("x-www-form-urlencoded")) {
                result.add(buildRequestWithContentType(originalHeaders, originalBody,
                        "application/x-www-form-urlencoded"));
            }
        }
        if (Boolean.TRUE.equals(ctOptions.get("multipart"))) {
            if (!originalContentType.toLowerCase().contains("multipart")) {
                String boundary = generateRandomBoundary();
                // A) 完美转换：仅对 x-www-form-urlencoded 生效
                byte[] cleanMultipartBody = smartWrapBodyAsMultipart(originalBody, boundary, originalHeaders);
                if (cleanMultipartBody != null) {
                    result.add(buildRequestWithMultipart(originalHeaders, cleanMultipartBody, boundary));
                } else {
                    // B) Header 欺骗：对 JSON/XML 等保持原 Body，只改 Content-Type
                    List<String> spoofHeaders = new ArrayList<>(originalHeaders);
                    removeHeadersIgnoreCase(spoofHeaders, "Content-Type");
                    spoofHeaders.add("Content-Type: multipart/form-data; boundary=" + boundary);
                    // buildHttpMessage 构造实体 body：强制移除 TE 并同步 CL
                    removeHeadersIgnoreCase(spoofHeaders, "Transfer-Encoding");
                    updateOrAddHeader(spoofHeaders, "Content-Length", String.valueOf(originalBody.length));
                    result.add(Utils.helpers.buildHttpMessage(spoofHeaders, originalBody));
                }
            }
        }
        if (Boolean.TRUE.equals(ctOptions.get("text_plain"))) {
            if (!originalContentType.toLowerCase().contains("text/plain")) {
                result.add(buildRequestWithContentType(originalHeaders, originalBody, "text/plain"));
            }
        }

        return result;
    }

    /**
     * 获取原始 Content-Type（去除 charset 参数）
     */
    private String getOriginalContentType(List<String> headers) {
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h != null && h.toLowerCase().startsWith("content-type:")) {
                String value = h.substring("content-type:".length()).trim();
                int semicolon = value.indexOf(';');
                if (semicolon > 0) {
                    return value.substring(0, semicolon).trim();
                }
                return value;
            }
        }
        return "application/octet-stream"; // 默认
    }

    /**
     * 构建带 charset 的请求（保留原始 Content-Type）
     */
    private byte[] buildRequestWithCharset(List<String> originalHeaders, byte[] encodedBody, String contentType,
            String charset) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeaderWithCharset(newHeaders, contentType, charset);
        // 修改 body 后必须移除 Transfer-Encoding，避免 CL-TE 冲突
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(encodedBody.length));
        return Utils.helpers.buildHttpMessage(newHeaders, encodedBody);
    }

    /**
     * 用指定字符集编码 Body
     */
    private byte[] encodeBodyWithCharset(byte[] body, String charsetName, String contentType,
            List<String> originalHeaders) {
        try {
            // 非文本类 content-type 或已 gzip 的 body，不做字符集转码（避免破坏二进制）
            if (!isTextualContentType(contentType)) {
                return null;
            }
            if (!RequestBodyPolicy.isEditable(StringUtils.join(originalHeaders, "\r\n"))) {
                return null;
            }

            // 按声明字符集严格解码和编码，避免替换字符损坏 payload
            String bodyStr = TextCodec.decode(body, RequestBodyPolicy.charset(StringUtils.join(originalHeaders, "\r\n")));
            Charset charset = Charset.forName(charsetName);
            return TextCodec.encode(bodyStr, charset);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isTextualContentType(String contentType) {
        if (contentType == null)
            return false;
        String ct = contentType.toLowerCase();
        return ct.contains("json")
                || ct.contains("xml")
                || ct.contains("text")
                || ct.contains("x-www-form-urlencoded")
                || ct.contains("javascript")
                || ct.contains("html");
    }

    /**
     * Gzip 压缩 Body
     */
    private byte[] gzipBody(byte[] body) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            GZIPOutputStream gzos = new GZIPOutputStream(baos);
            gzos.write(body);
            gzos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 构建带 Gzip Body 的请求
     */
    private byte[] buildRequestWithGzipBody(List<String> originalHeaders, byte[] gzippedBody) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeader(newHeaders, "Content-Encoding", "gzip");
        // 修改 body 后必须移除 Transfer-Encoding，避免 CL-TE 冲突
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(gzippedBody.length));
        return Utils.helpers.buildHttpMessage(newHeaders, gzippedBody);
    }

    /**
     * 构建带指定 Content-Type 的请求
     */
    private byte[] buildRequestWithContentType(List<String> originalHeaders, byte[] body, String contentType) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeader(newHeaders, "Content-Type", contentType);
        // buildHttpMessage 构造的是非 chunked 的实体 body：移除 Transfer-Encoding，并同步
        // Content-Length
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(body == null ? 0 : body.length));
        return Utils.helpers.buildHttpMessage(newHeaders, body);
    }

    /**
     * 生成随机 boundary
     */
    private String generateRandomBoundary() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder("----WebKitFormBoundary");
        Random random = new Random();
        for (int i = 0; i < 16; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * 将 Body 包装成 multipart 格式
     */
    private byte[] wrapBodyAsMultipart(byte[] originalBody, String boundary) {
        try {
            // 直接操作 byte[]，避免把二进制 body 误当 UTF-8 文本导致损坏
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("Content-Disposition: form-data; name=\"data\"\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(originalBody);
            out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * form-urlencoded -> multipart/form-data
     * 非表单类型返回 null
     */
    private byte[] smartWrapBodyAsMultipart(byte[] originalBody, String boundary, List<String> headers) {
        try {
            if (!RequestBodyPolicy.isEditable(StringUtils.join(headers, "\r\n"))) return null;
            String originalContentType = getOriginalContentType(headers).toLowerCase();
            if (!originalContentType.contains("application/x-www-form-urlencoded")) {
                return null;
            }
            if (originalBody == null || originalBody.length == 0) {
                return null;
            }
            Charset cs = RequestBodyPolicy.charset(StringUtils.join(headers, "\r\n"));
            String bodyStr = TextCodec.decode(originalBody, cs);
            if (bodyStr.trim().isEmpty()) {
                return null;
            }

            String[] pairs = bodyStr.split("&");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (String pair : pairs) {
                if (pair == null || pair.isEmpty())
                    continue;
                String[] kv = pair.split("=", 2);
                String key = URLDecoder.decode(kv[0], cs.name());
                String value = kv.length > 1 ? URLDecoder.decode(kv[1], cs.name()) : "";

                out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(
                        ("Content-Disposition: form-data; name=\"" + key + "\"\r\n").getBytes(StandardCharsets.UTF_8));
                // 显式声明字段字符集，提升后端兼容性
                out.write(("Content-Type: text/plain; charset=" + cs.name() + "\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(TextCodec.encode(value, cs));
                out.write(("\r\n").getBytes(StandardCharsets.ISO_8859_1));
            }
            out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 构建 multipart 请求
     */
    private byte[] buildRequestWithMultipart(List<String> originalHeaders, byte[] multipartBody, String boundary) {
        List<String> newHeaders = new ArrayList<>(originalHeaders);
        updateOrAddHeader(newHeaders, "Content-Type", "multipart/form-data; boundary=" + boundary);
        // 修改 body 后必须移除 Transfer-Encoding，避免 CL-TE 冲突
        removeHeadersIgnoreCase(newHeaders, "Transfer-Encoding");
        updateOrAddHeader(newHeaders, "Content-Length", String.valueOf(multipartBody.length));
        return Utils.helpers.buildHttpMessage(newHeaders, multipartBody);
    }

    private void updateOrAddHeaderWithCharset(List<String> headers, String fallbackContentType, String charset) {
        // 优先修改已有 Content-Type：仅替换/追加 charset，保留其它参数
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null)
                continue;
            int colon = h.indexOf(':');
            if (colon <= 0)
                continue;
            String n = h.substring(0, colon).trim();
            if (!n.equalsIgnoreCase("Content-Type"))
                continue;

            String v = h.substring(colon + 1).trim();
            // 去掉已有 charset=...
            v = v.replaceAll("(?i);\\s*charset\\s*=\\s*[^;\\r\\n]+", "");
            v = v.trim();
            // 追加 charset
            if (!v.isEmpty()) {
                v = v + "; charset=" + charset;
            } else if (fallbackContentType != null && !fallbackContentType.isEmpty()) {
                v = fallbackContentType + "; charset=" + charset;
            } else {
                v = "application/octet-stream; charset=" + charset;
            }
            headers.set(i, "Content-Type: " + v);
            return;
        }
        // 没有 Content-Type 时补一个
        String ct = (fallbackContentType == null || fallbackContentType.isEmpty()) ? "application/octet-stream"
                : fallbackContentType;
        headers.add("Content-Type: " + ct + "; charset=" + charset);
    }

    /**
     * 更新或添加 Header
     */
    private void updateOrAddHeader(List<String> headers, String name, String value) {
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h != null) {
                int colon = h.indexOf(':');
                if (colon > 0) {
                    String n = h.substring(0, colon).trim();
                    if (n.equalsIgnoreCase(name)) {
                        headers.set(i, name + ": " + value);
                        return;
                    }
                }
            }
        }
        headers.add(name + ": " + value);
    }

    /**
     * 处理 Body 编码变体请求的 Runnable
     */
    class Run_body_encoded_request implements Runnable {
        private final byte[] requestBytes;
        private final IHttpRequestResponse originalReqResp;
        private final String tool;
        private final boolean followRedirect;
        private final int maxRedirects;
        private final ScanSession session;

        public Run_body_encoded_request(byte[] requestBytes, IHttpRequestResponse originalReqResp, String tool,
                                        boolean followRedirect, int maxRedirects, ScanSession session) {
            this.session = session;
            this.requestBytes = requestBytes;
            this.originalReqResp = originalReqResp;
            this.tool = tool;
            this.followRedirect = followRedirect;
            this.maxRedirects = maxRedirects;
        }

        @Override
        public void run() {
            if (session.cancelled) return;
            try {
                SendResult sendResult = sendWithRedirectPolicy(originalReqResp.getHttpService(), requestBytes,
                        followRedirect, maxRedirects, session);

                byte[] finalResponseBytes = sendResult.getJudgedResponseBytes();
                if (session.cancelled) return;
                if (finalResponseBytes == null || finalResponseBytes.length == 0)
                    throw new IllegalStateException(I18n.t("manual.no_response"));

                double threshold = Utils.panel.getSimilarityThreshold();
                ResponseComparison comparison = new ResponseComparison(originalReqResp, sendResult.analysis());
                short oldStatus = comparison.oldStatus;
                short newStatus = comparison.newStatus;
                String newBody = comparison.body;
                double ratio = comparison.ratio;
                boolean statusClassChanged = (oldStatus > 0 && newStatus > 0) && (oldStatus / 100 != newStatus / 100);

                boolean shouldLog = comparison.complete && isCandidateStatus(newStatus) && (ratio < threshold || statusClassChanged);

                if (sendResult.judgedMessage != null && finalResponseBytes != null) {
                    String title = Utils.getBodyTitle(newBody == null ? "" : newBody);
                    String reason = comparison.reason(buildAutoReason(oldStatus, newStatus, ratio, threshold, statusClassChanged));
                    reason = candidateReason(originalReqResp, requestBytes, sendResult.analysis(), ratio, reason, false);
                    addLog(session, sendResult, title, tool, reason, shouldLog);
                }
                Utils.panel.addFinishRequestNum(session, 1);
            } catch (Exception e) {
                recordFailure(session, originalReqResp.getHttpService(), requestBytes, tool, e);
            }
        }
    }

    private String ghostToolLabel(String tool) {
        if (tool == null || tool.trim().isEmpty()) {
            return "ghost";
        }
        String normalized = tool.trim().toLowerCase();
        if ("auto".equals(normalized)) {
            return "auto-waf/ghost";
        }
        if ("send waf".equals(normalized)) {
            return "send-waf/ghost";
        }
        return tool + "/ghost";
    }

    /**
     * Auto WAF 的 Ghost Bits 模板探测请求。
     * 关键区别：path/header 含非 ASCII 或模板 sender=raw 时走 RawSocketSender。
     */
    class Run_ghost_bits_request implements Runnable {
        private final GhostBitsAutoVariant variant;
        private final IHttpRequestResponse originalReqResp;
        private final String tool;
        private final boolean followRedirect;
        private final int maxRedirects;
        private final ScanSession session;

        public Run_ghost_bits_request(GhostBitsAutoVariant variant, IHttpRequestResponse originalReqResp, String tool,
                                      boolean followRedirect, int maxRedirects, ScanSession session) {
            this.session = session;
            this.variant = variant;
            this.originalReqResp = originalReqResp;
            this.tool = tool;
            this.followRedirect = followRedirect;
            this.maxRedirects = maxRedirects;
        }

        @Override
        public void run() {
            if (session.cancelled) return;
            try {
                IHttpService service = originalReqResp.getHttpService();
                SendResult sendResult;
                if (variant.isRawRequired()) {
                    IHttpRequestResponse rawResponse = sendGhostVariantRaw(variant, service);
                    sendResult = new SendResult(service, variant.getRequestBytes(),
                            rawResponse, false, normalizeMaxRedirects(maxRedirects));
                    if (followRedirect) sendResult.stopReason = I18n.t("manual.redirect.raw");
                } else {
                    sendResult = sendWithRedirectPolicy(service, variant.getRequestBytes(),
                            followRedirect, maxRedirects, session);
                }

                byte[] finalResponseBytes = sendResult.getJudgedResponseBytes();
                if (session.cancelled) return;
                if (finalResponseBytes == null || finalResponseBytes.length == 0)
                    throw new IllegalStateException(I18n.t("manual.no_response"));
                double threshold = Utils.panel.getSimilarityThreshold();
                ResponseComparison comparison = new ResponseComparison(originalReqResp, sendResult.analysis());
                short oldStatus = comparison.oldStatus;
                short newStatus = comparison.newStatus;
                String newBody = comparison.body;
                double ratio = comparison.ratio;
                boolean statusClassChanged = (oldStatus > 0 && newStatus > 0) && (oldStatus / 100 != newStatus / 100);

                String baseReason = comparison.reason(buildAutoReason(oldStatus, newStatus, ratio, threshold, statusClassChanged));
                String signatureReason = buildGhostSignatureReason(newBody);
                boolean signatureMatched = !signatureReason.isEmpty();
                boolean shouldLog = comparison.complete && isCandidateStatus(newStatus)
                        && (signatureMatched || ratio < threshold || statusClassChanged);
                String reason = variant.getReason();
                if (!baseReason.isEmpty()) {
                    reason += "; " + baseReason;
                }
                if (signatureMatched) {
                    reason += "; " + signatureReason;
                }

                reason = candidateReason(originalReqResp, variant.getRequestBytes(), sendResult.analysis(), ratio, reason, variant.isRawRequired());
                if (sendResult.judgedMessage != null && finalResponseBytes != null) {
                    String title = Utils.getBodyTitle(newBody == null ? "" : newBody);
                    addLog(session, sendResult, title, ghostToolLabel(tool), reason, shouldLog);
                }
                Utils.panel.addFinishRequestNum(session, 1);
            } catch (Exception e) {
                recordFailure(session, originalReqResp.getHttpService(), variant.getRequestBytes(), tool, e);
            }
        }
    }

    private IHttpRequestResponse sendGhostVariantRaw(GhostBitsAutoVariant variant, IHttpService service) throws Exception {
        String host = service.getHost();
        int port = service.getPort();
        boolean https = "https".equalsIgnoreCase(service.getProtocol());
        if (port <= 0) {
            port = https ? 443 : 80;
        }
        RawSocketSender.RawResponse raw = new RawSocketSender().send(host, port, https,
                variant.getRequestBytes(), 5000, 5000);
        SimpleHttpRequestResponse result = new SimpleHttpRequestResponse(service,
                raw.getRequestBytesActuallySent(), raw.getResponseBytes());
        result.responseAnalysis = raw.getAnalysis();
        return result;
    }

    private String buildGhostSignatureReason(String body) {
        if (body == null || body.isEmpty()) {
            return "";
        }
        String lower = body.toLowerCase(Locale.ROOT);
        if (lower.contains("root:x:") || lower.contains("/bin/bash")
                || lower.contains("nologin") || lower.contains("daemon:x:")) {
            return "ghost file signature matched";
        }
        if (lower.contains("[fonts]") || lower.contains("[extensions]") || lower.contains("[mci extensions]")) {
            return "ghost file signature matched";
        }
        return "";
    }

    static class SimpleHttpRequestResponse implements IHttpRequestResponse {
        private byte[] request;
        private byte[] response;
        private HttpResponse.Analysis responseAnalysis;
        private HttpResponse.Text responseText;
        private String baselineReason = "";
        private String comment;
        private String highlight;
        private IHttpService service;

        SimpleHttpRequestResponse(IHttpService service, byte[] request, byte[] response) {
            this.service = service;
            this.request = request == null ? new byte[0] : request;
            this.response = response == null ? new byte[0] : response;
        }

        @Override
        public byte[] getRequest() { return request; }

        @Override
        public void setRequest(byte[] message) {
            request = message == null ? new byte[0] : message;
            responseAnalysis = null;
            responseText = null;
        }

        @Override
        public byte[] getResponse() { return response; }

        @Override
        public void setResponse(byte[] message) {
            response = message == null ? new byte[0] : message;
            responseAnalysis = null;
            responseText = null;
        }

        @Override
        public String getComment() { return comment; }

        @Override
        public void setComment(String comment) { this.comment = comment; }

        @Override
        public String getHighlight() { return highlight; }

        @Override
        public void setHighlight(String color) { this.highlight = color; }

        @Override
        public IHttpService getHttpService() { return service; }

        @Override
        public void setHttpService(IHttpService httpService) { this.service = httpService; }
    }

    public void processHttp(IHttpRequestResponse[] iHttpRequestResponses, String tool) {
        processHttp(iHttpRequestResponses, tool, Utils.PROFILE_AUTO_ACCESS_BYPASS);
    }

    /**
     * Auto Scan：Proxy 响应监听，命中条件自动触发扫描
     */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

        if (Utils.isProxySelected && !messageIsRequest && message != null) {
            IHttpRequestResponse httpRequestResponse = message.getMessageInfo();
            if (httpRequestResponse == null) return;
            byte[] old_response = httpRequestResponse.getResponse();
            if (old_response != null) {
                short old_status = Utils.helpers.analyzeResponse(old_response).getStatusCode();
                String path = Utils.helpers.analyzeRequest(httpRequestResponse).getUrl().getPath();
                IHttpRequestResponse[] iHttpRequestResponses = new IHttpRequestResponse[] { httpRequestResponse };

                if (old_status == 401 || old_status == 403) {
                    int lastSlash = path.lastIndexOf('/');
                    String fileName = (lastSlash >= 0) ? path.substring(lastSlash + 1) : path;
                    int lastDot = fileName.lastIndexOf('.');
                    if (lastDot >= 0 && lastDot < fileName.length() - 1) {
                        String extension = fileName.substring(lastDot + 1).toLowerCase();
                        if (!extension.isEmpty() && Utils.getIgnoreExtensions().contains(extension)) {
                            return;
                        }
                    }
                    enqueueHttp(iHttpRequestResponses, "auto", Utils.PROFILE_AUTO_ACCESS_BYPASS);

                }

            }
        }

    }

}

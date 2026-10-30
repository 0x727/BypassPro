package Main;

import burp.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import javax.swing.*;
import java.awt.Component;
import java.lang.reflect.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;

/** User operations with real Swing panels and a controlled Burp transport; no external traffic. */
@SuppressWarnings("unchecked")
public class UiWorkflowTest {
    @Test public void manualSendPreservesUtf8AndBinaryBodiesExactly() throws Exception {
        for (byte[] body : new byte[][]{"é 文".getBytes(StandardCharsets.UTF_8), new byte[]{(byte)255, 0, (byte)128, 65}}) {
            byte[] original = requestBody(body, "text/plain; charset=utf-8");
            byte[] wire = bytes("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>final</title>");
            transport = (target, actual) -> { assertArrayEquals(original, actual); return exchange(target, actual, wire); };
            Thread[] sending = new Thread[1];
            edt(() -> { manual.loadRequest(exchange(service("a.test", 80, "http"), original, null)); sending[0] = send(); });
            join(sending[0]); flush();
            edt(() -> {
                assertArrayEquals(original, histories().get(0).requestBytes);
                assertEquals(200, histories().get(0).status);
                Bypass row = panel.getBypassTableModel().getBypassAt(panel.getBypassTableModel().getRowCount() - 1);
                assertEquals(200, row.status); assertEquals("final", row.title);
                assertArrayEquals(wire, row.requestResponse.getResponse());
            });
        }
    }

    @Test public void textAndByteToolsUseTheirOwnEncodingAndRemainUndoable() throws Exception {
        edt(() -> {
            Editor editor = (Editor)field(manual, "requestViewer");
            byte[] original = requestBody(bytes("A"), "text/plain; charset=utf-8");
            manual.loadRequest(exchange(service("a.test", 80, "http"), original, null));
            editor.selection = bytes("A"); invoke(manual, "refreshRequestInspector");
            button(manual, "Fullwidth").doClick();
            assertArrayEquals("Ａ".getBytes(StandardCharsets.UTF_8), body(manual.getRequest()));
            invoke(manual, "undo"); assertArrayEquals(original, manual.getRequest());
            byte[] binary = new byte[]{(byte)255, 0, 65};
            editor.setMessage(requestBody(binary, "application/octet-stream"), true); editor.selection = binary;
            invoke(manual, "base64Encode"); assertEquals("/wBB", text(body(manual.getRequest())));
            byte[] utf8 = "é".getBytes(StandardCharsets.UTF_8);
            editor.setMessage(requestBody(utf8, "text/plain; charset=utf-8"), true); editor.selection = utf8;
            invoke(manual, "urlEncode"); assertEquals("%C3%A9", text(body(manual.getRequest())));
            editor.setMessage(requestBody(utf8, "text/plain; charset=utf-8"), true); editor.selection = null;
            invoke(manual, "encodeBodyWithCharset", new Class[]{String.class}, "UTF-16");
            assertEquals("é", new String(body(manual.getRequest()), StandardCharsets.UTF_16));
            byte[] prepared = (byte[])invoke(manual, "buildRequestBytesForSending", new Class[]{byte[].class}, (Object)manual.getRequest());
            assertArrayEquals(body(manual.getRequest()), body(prepared));
        });
    }

    @Test public void dirtyExpansionAndDeliberateContentLengthRemainCompatible() throws Exception {
        edt(() -> {
            byte[] original = requestBody(bytes("a{{dirty(3)}}b{{dirtynull(2)}}c"), "text/plain");
            byte[] prepared = (byte[])invoke(manual, "buildRequestBytesForSending", new Class[]{byte[].class}, (Object)original);
            byte[] expanded = body(prepared);
            assertEquals(8, expanded.length); assertEquals('a', expanded[0]); assertEquals('b', expanded[4]);
            assertEquals(0, expanded[5]); assertEquals(0, expanded[6]); assertEquals('c', expanded[7]);
            for (int i = 1; i <= 3; i++) assertTrue(expanded[i] >= '0' && expanded[i] <= '9');
            assertTrue(text(prepared).contains("Content-Length: 8\r\n"));
            byte[] deliberate = bytes("POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 999\r\n\r\na{{dirty(3)}}");
            assertTrue(text((byte[])invoke(manual, "buildRequestBytesForSending", new Class[]{byte[].class}, (Object)deliberate))
                    .contains("Content-Length: 999\r\n"));
        });
    }

    @Test public void failedTextConversionRetainsBytesAndEncodedBodiesAreNotConverted() throws Exception {
        edt(() -> {
            Editor editor = (Editor)field(manual, "requestViewer");
            byte[] original = requestBody(new byte[]{(byte)255}, "text/plain; charset=utf-8");
            editor.setMessage(original, true); editor.selection = new byte[]{(byte)255};
            invoke(manual, "toFullwidth"); assertArrayEquals(original, manual.getRequest());
            for (String encoding : new String[]{"Transfer-Encoding: chunked", "Transfer-Encoding:", "Content-Encoding: br"}) {
                original = bytes("POST /x HTTP/1.1\r\nHost: a.test\r\n" + encoding + "\r\n\r\n1\r\nA\r\n0\r\n\r\n");
                editor.setMessage(original, true); editor.selection = null;
                invoke(manual, "encodeBodyWithCharset", new Class[]{String.class}, "UTF-16");
                assertArrayEquals(original, manual.getRequest());
                for (String operation : new String[]{"gzipBody", "toFormUrlEncoded", "toMultipart", "toJsonBody"}) {
                    invoke(manual, operation); assertArrayEquals(original, manual.getRequest());
                }
            }
        });
    }

    @Test public void dashboardComparesDecodedEntitiesAndMarksShortResponsesFiltered() throws Exception {
        byte[] request = request("a.test", "/x");
        byte[] page = bytes("same content");
        java.io.ByteArrayOutputStream compressed = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(compressed)) { gzip.write(page); }
        byte[] header = bytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: " + compressed.size() + "\r\n\r\n");
        byte[] wire = Arrays.copyOf(header, header.length + compressed.size());
        System.arraycopy(compressed.toByteArray(), 0, wire, header.length, compressed.size());
        transport = (target, actual) -> exchange(target, actual, wire);
        IHttpRequestResponse original = exchange(service("a.test", 80, "http"), request, response(200, "same content"));
        new BypassMain().new Run_body_encoded_request(request, original, "send waf", false, 3, panel.sessionForInput()).run(); flush();
        edt(() -> {
            Bypass row = panel.getBypassTableModel().getBypassAt(0);
            assertEquals(Bypass.Outcome.FILTERED, row.outcome); assertArrayEquals(wire, row.requestResponse.getResponse());
            assertFalse(row.reason.contains("sim:"));
        });
        transport = (target, actual) -> exchange(target, actual, bytes("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nOK"));
        new BypassMain().new Run_body_encoded_request(request, exchange(service("a.test", 80, "http"), request, response(403, "denied")),
                "send waf", false, 3, panel.sessionForInput()).run(); flush();
        edt(() -> {
            Bypass row = panel.getBypassTableModel().getBypassAt(1);
            assertEquals(Bypass.Outcome.FILTERED, row.outcome); assertTrue(row.reason.contains("incomplete"));
            assertEquals(200, row.status);
        });
    }

    private static byte[] body(byte[] request) { return Arrays.copyOfRange(request, bodyOffset(request), request.length); }
    private static byte[] requestBody(byte[] body, String contentType) {
        byte[] header = bytes("POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Type: " + contentType + "\r\nContent-Length: " + body.length + "\r\n\r\n");
        byte[] result = Arrays.copyOf(header, header.length + body.length);
        System.arraycopy(body, 0, result, header.length, body.length); return result;
    }
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    private MainPanel panel;
    private ManualWafPanel manual;
    private ConfigLoader loader;
    private IBurpExtenderCallbacks oldCallbacks, oldBurpCallbacks;
    private IExtensionHelpers oldHelpers;
    private MainPanel oldPanel;
    private ConfigLoader oldLoader;
    private Map<String, Object> oldConfig;
    private String oldLang;
    private boolean oldAuto;
    private volatile Transport transport = (service, request) -> exchange(service, request, response(200, "OK"));
    interface Transport { IHttpRequestResponse send(IHttpService service, byte[] request) throws Exception; }

    @Before public void setUp() throws Exception {
        oldCallbacks = Utils.callbacks; oldBurpCallbacks = BurpExtender.callbacks;
        oldHelpers = Utils.helpers; oldPanel = Utils.panel; oldLoader = Utils.getConfigLoader();
        oldConfig = Utils.configMap; oldLang = I18n.getLang(); oldAuto = Utils.isProxySelected;
        Utils.isProxySelected = false;
        I18n.setLang(I18n.EN);
        loader = new ConfigLoader(folder.getRoot().getAbsolutePath());
        Utils.setConfigLoader(loader); Utils.configMap = loader.loadConfig();
        Utils.helpers = (IExtensionHelpers) Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{IExtensionHelpers.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "buildHttpService": return service((String) args[0], (int) args[1], String.valueOf(args[2]));
                        case "analyzeRequest": {
                            IHttpService target = service("example.test", 80, "http");
                            byte[] request;
                            if (args.length == 2) { target = (IHttpService) args[0]; request = (byte[]) args[1]; }
                            else if (args[0] instanceof IHttpRequestResponse) {
                                target = ((IHttpRequestResponse) args[0]).getHttpService(); request = ((IHttpRequestResponse) args[0]).getRequest();
                            } else request = (byte[]) args[0];
                            String head = text(request).split("\r\n\r\n", 2)[0];
                            List<String> headers = Arrays.asList(head.split("\r\n"));
                            Map<String, Object> values = new HashMap<>();
                            values.put("getHeaders", headers); values.put("getMethod", headers.get(0).split(" ")[0]);
                            values.put("getUrl", RedirectPolicy.requestUrl(target, request));
                            values.put("getBodyOffset", bodyOffset(request));
                            return values(IRequestInfo.class, values);
                        }
                        case "analyzeResponse": {
                            byte[] response = (byte[]) args[0];
                            Map<String, Object> values = new HashMap<>();
                            values.put("getStatusCode", (short) Integer.parseInt(text(response).split(" ", 3)[1]));
                            values.put("getHeaders", Arrays.asList(text(response).split("\r\n\r\n", 2)[0].split("\r\n")));
                            values.put("getBodyOffset", bodyOffset(response));
                            values.put("getStatedMimeType", "text");
                            return values(IResponseInfo.class, values);
                        }
                        case "buildHttpMessage": {
                            byte[] header = bytes(String.join("\r\n", (List<String>) args[0]) + "\r\n\r\n");
                            byte[] body = args[1] == null ? new byte[0] : (byte[]) args[1];
                            byte[] result = Arrays.copyOf(header, header.length + body.length);
                            System.arraycopy(body, 0, result, header.length, body.length);
                            return result;
                        }
                        default: throw new AssertionError("Unexpected helper: " + method);
                    }
                });
        Utils.callbacks = (IBurpExtenderCallbacks) Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{IBurpExtenderCallbacks.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "createMessageEditor": return new Editor();
                        case "customizeUiComponent": return null;
                        case "makeHttpRequest": return transport.send((IHttpService) args[0], (byte[]) args[1]);
                        case "saveBuffersToTempFiles": {
                            IHttpRequestResponse rr = (IHttpRequestResponse) args[0];
                            Map<String, Object> values = new HashMap<>();
                            values.put("getHttpService", rr.getHttpService()); values.put("getRequest", rr.getRequest());
                            values.put("getResponse", rr.getResponse());
                            return values(IHttpRequestResponsePersisted.class, values);
                        }
                        default: throw new AssertionError("Unexpected callback: " + method);
                    }
                });
        BurpExtender.callbacks = Utils.callbacks;
        edt(() -> {
            panel = new MainPanel(); Utils.panel = panel; manual = panel.getManualWafPanel();
            ((javax.swing.Timer) field(manual, "inspectorTimer")).stop();
        });
    }

    @After public void tearDown() throws Exception {
        edt(() -> { if (panel != null) panel.dispose(); });
        Utils.shutdownSharedExecutor();
        Utils.callbacks = oldCallbacks; BurpExtender.callbacks = oldBurpCallbacks; Utils.helpers = oldHelpers;
        Utils.panel = oldPanel; Utils.setConfigLoader(oldLoader); Utils.configMap = oldConfig;
        I18n.setLang(oldLang); Utils.isProxySelected = oldAuto;
    }

    @Test public void equalLengthBodyAndHeaderChangesAreReportedAccurately() throws Exception {
        byte[] request = bytes("POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nAAAA");
        edt(() -> {
            manual.loadRequest(exchange(service("a.test", 80, "http"), request, null));
            String body = (String) invoke(manual, "buildRequestDiffSummary", new Class[]{byte[].class}, bytes(text(request).replace("AAAA", "BBBB")));
            assertTrue(body.contains("body changed (4 -> 4")); assertFalse(body.contains("headers changed"));
            String header = (String) invoke(manual, "buildRequestDiffSummary", new Class[]{byte[].class}, bytes(text(request).replace("a.test", "b.test")));
            assertEquals("headers changed", header);
        });
    }

    @Test public void historyRestoresBothSendersWithIndependentNetworkHostPortAndProtocol() throws Exception {
        edt(() -> {
            for (String sender : new String[]{"Burp", "Raw"}) {
                ManualWafPanel.HistoryEntry entry = new ManualWafPanel.HistoryEntry();
                entry.id = 3; entry.service = service("network.test", 8443, "https"); entry.sender = sender;
                entry.requestBytes = request("header.test", "/history"); entry.responseBytes = response(206, "old");
                histories().clear(); histories().add(entry);
                manual.loadRequest(exchange(service("b.test", 80, "http"), request("b.test", "/current"), null));
                invoke(manual, "loadHistoryRequest", new Class[]{int.class}, 0);
                assertEquals("network.test", ((JTextField) field(manual, "hostField")).getText());
                assertEquals("8443", ((JTextField) field(manual, "portField")).getText());
                assertTrue(((JCheckBox) field(manual, "httpsCheckBox")).isSelected());
                assertArrayEquals(entry.requestBytes, manual.getRequest()); assertArrayEquals(entry.responseBytes, manual.getResponse());
                assertEquals(sender.equals("Raw") ? ManualWafPanel.SenderMode.RAW : ManualWafPanel.SenderMode.BURP, field(manual, "senderMode"));
            }
        });
    }

    @Test public void selectingHistoryDoesNotSilentlyReplaceOnlyTheResponse() throws Exception {
        edt(() -> {
            manual.loadRequest(exchange(service("a.test", 80, "http"), request("a.test", "/"), response(200, "current")));
            ManualWafPanel.HistoryEntry history = new ManualWafPanel.HistoryEntry();
            history.service = service("b.test", 80, "http"); history.responseBytes = response(404, "history"); histories().add(history);
            byte[] before = manual.getResponse().clone();
            invoke(manual, "showHistoryEntry", new Class[]{int.class}, 0);
            assertArrayEquals(before, manual.getResponse());
        });
    }

    @Test public void cancellingAAndStartingBKeepsBInControlWhenAReturnsLate() throws Exception {
        CountDownLatch aEntered = new CountDownLatch(1), bEntered = new CountDownLatch(1);
        CountDownLatch releaseA = new CountDownLatch(1), releaseB = new CountDownLatch(1);
        transport = (target, req) -> {
            boolean a = text(req).startsWith("GET /A ");
            (a ? aEntered : bEntered).countDown();
            awaitIgnoringInterrupt(a ? releaseA : releaseB);
            return exchange(target, req, response(200, a ? "A late" : "B current"));
        };
        Thread[] threads = new Thread[2];
        try {
            edt(() -> { load("/A"); threads[0] = send(); });
            assertTrue(aEntered.await(2, TimeUnit.SECONDS));
            edt(() -> { invoke(manual, "cancelRequest"); load("/B"); threads[1] = send(); });
            assertTrue(bEntered.await(2, TimeUnit.SECONDS));
            releaseA.countDown(); join(threads[0]); flush();
            edt(() -> { assertFalse(((JButton) field(manual, "sendBtn")).isEnabled()); assertTrue(histories().isEmpty()); });
            releaseB.countDown(); join(threads[1]); flush();
            edt(() -> {
                assertTrue(text(manual.getResponse()).endsWith("B current")); assertEquals(1, histories().size());
                assertTrue(((JButton) field(manual, "sendBtn")).isEnabled());
                assertTrue(text(histories().get(0).requestBytes).startsWith("GET /B "));
            });
        } finally { releaseA.countDown(); releaseB.countDown(); for (Thread t : threads) if (t != null) join(t); }
    }

    @Test public void editedRequestAndTargetCannotMutateAnInFlightSnapshot() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        transport = (target, req) -> {
            entered.countDown(); awaitIgnoringInterrupt(release);
            assertEquals("a.test", target.getHost()); assertTrue(text(req).startsWith("GET /A "));
            return exchange(target, req, response(200, "snapshot"));
        };
        Thread[] thread = new Thread[1];
        try {
            edt(() -> { load("/A"); thread[0] = send(); }); assertTrue(entered.await(2, TimeUnit.SECONDS));
            edt(() -> {
                invoke(manual, "setRequestBytes", new Class[]{byte[].class}, request("b.test", "/B"));
                ((JTextField) field(manual, "hostField")).setText("b.test");
            });
            release.countDown(); join(thread[0]); flush();
            edt(() -> {
                assertTrue(text(manual.getRequest()).startsWith("GET /B "));
                assertEquals("a.test", histories().get(0).service.getHost());
                assertTrue(((JLabel) field(manual, "responseContextLabel")).getText().contains("previously sent"));
            });
        } finally { release.countDown(); if (thread[0] != null) join(thread[0]); }
    }

    @Test public void rawAndAutoRawDisableRedirectWhileBodyUnicodeKeepsBurpAvailable() throws Exception {
        edt(() -> {
            load("/A");
            invoke(manual, "setSenderMode", new Class[]{ManualWafPanel.SenderMode.class}, ManualWafPanel.SenderMode.RAW);
            assertFalse(((JCheckBox) field(manual, "followRedirectCheckBox")).isEnabled());
            invoke(manual, "setSenderMode", new Class[]{ManualWafPanel.SenderMode.class}, ManualWafPanel.SenderMode.AUTO);
            assertTrue(((JCheckBox) field(manual, "followRedirectCheckBox")).isEnabled());
            manual.loadRequest(exchange(service("a.test", 80, "http"), "GET /阮 HTTP/1.1\r\nHost: a.test\r\n\r\n".getBytes(StandardCharsets.UTF_8), null));
            assertFalse(((JCheckBox) field(manual, "followRedirectCheckBox")).isEnabled());
            manual.loadRequest(exchange(service("a.test", 80, "http"), "POST / HTTP/1.1\r\nHost: a.test\r\n\r\n中文".getBytes(StandardCharsets.UTF_8), null));
            assertTrue(((JCheckBox) field(manual, "followRedirectCheckBox")).isEnabled());
        });
    }

    @Test public void manualRedirectUsesRelativePathAndStopsBeforeCrossOriginRequest() throws Exception {
        List<String> paths = Collections.synchronizedList(new ArrayList<>());
        transport = (target, req) -> {
            String path = text(req).split(" ")[1]; paths.add(path);
            byte[] resp = paths.size() == 1 ? bytes("HTTP/1.1 302 Found\r\nLocation: next\r\n\r\n")
                    : bytes("HTTP/1.1 302 Found\r\nLocation: http://other.test/\r\n\r\n");
            return exchange(target, req, resp);
        };
        Thread[] thread = new Thread[1];
        edt(() -> { load("/dir/page"); ((JCheckBox) field(manual, "followRedirectCheckBox")).setSelected(true); thread[0] = send(); });
        join(thread[0]); flush();
        assertEquals(Arrays.asList("/dir/page", "/dir/next"), paths);
        edt(() -> {
            assertTrue(((JLabel) field(manual, "statusLabel")).getText().contains("Different host"));
            assertEquals("a.test", histories().get(0).service.getHost());
            assertTrue(text(histories().get(0).requestBytes).startsWith("GET /dir/next "));
        });
    }

    @Test public void allFailedRunCompletesAndClearRejectsOldCountersAndResults() throws Exception {
        ScanSession old = panel.sessionForInput();
        panel.addAllRequestNum(old, 2); panel.addErrorRequestNum(old, 2); flush();
        edt(() -> { assertEquals(100, ((JProgressBar) field(panel, "progressBar")).getValue()); panel.clearResults(); });
        panel.addFinishRequestNum(old, 1); panel.addAllRequestNum(old, 3); flush();
        edt(() -> {
            assertEquals("0", ((JLabel) field(panel, "allRequestNumberText")).getText());
            assertEquals("0", ((JLabel) field(panel, "finishRequestNumberText")).getText());
            assertFalse(((JProgressBar) field(panel, "progressBar")).isIndeterminate());
        });
    }

    @Test public void dashboardRecordsRedirectPartialContentFilteredAndFailedOutcomes() throws Exception {
        ScanSession session = panel.sessionForInput(); BypassMain bypass = new BypassMain();
        IHttpService service = service("a.test", 80, "http");
        IHttpRequestResponse original = exchange(service, request("a.test", "/admin"), response(403, "denied"));
        short[] statuses = {200, 206, 301, 302, 303, 304, 307, 308, 405, 415, 403};
        panel.addAllRequestNum(session, statuses.length + 1);
        for (short status : statuses) {
            transport = (target, req) -> exchange(target, req, response(status, "denied"));
            bypass.new Run_body_encoded_request(original.getRequest(), original, "send waf", false, 3, session).run();
        }
        transport = (target, req) -> null;
        bypass.new Run_body_encoded_request(original.getRequest(), original, "send waf", false, 3, session).run();
        flush();
        edt(() -> {
            assertEquals(statuses.length + 1, panel.getBypassTableModel().getRowCount());
            for (int i = 0; i < 8; i++) assertEquals(Bypass.Outcome.SIGNAL, panel.getBypassTableModel().getBypassAt(i).outcome);
            assertEquals(Bypass.Outcome.FILTERED, panel.getBypassTableModel().getBypassAt(10).outcome);
            assertEquals(Bypass.Outcome.ERROR, panel.getBypassTableModel().getBypassAt(11).outcome);
            assertEquals(100, ((JProgressBar) field(panel, "progressBar")).getValue());
        });
    }

    @Test public void dashboardInFlightCompletionCannotRefillClearedResults() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        transport = (target, req) -> { entered.countDown(); awaitIgnoringInterrupt(release); return exchange(target, req, response(200, "late")); };
        ScanSession old = panel.sessionForInput(); panel.addAllRequestNum(old, 1);
        IHttpRequestResponse original = exchange(service("a.test", 80, "http"), request("a.test", "/A"), response(403, "denied"));
        Thread thread = new Thread(new BypassMain().new Run_body_encoded_request(original.getRequest(), original, "auto", false, 3, old));
        try {
            thread.start(); assertTrue(entered.await(2, TimeUnit.SECONDS));
            edt(() -> panel.clearResults());
            ScanSession fresh = panel.sessionForInput(); panel.addAllRequestNum(fresh, 1);
            release.countDown(); join(thread); flush();
            edt(() -> { assertEquals(0, panel.getBypassTableModel().getRowCount()); assertEquals("0", ((JLabel) field(panel, "finishRequestNumberText")).getText()); });
        } finally { release.countDown(); join(thread); }
    }

    @Test public void contextMenuAcceptsEmptySelectionAndNavigatesOnManualLoad() throws Exception {
        IContextMenuInvocation empty = values(IContextMenuInvocation.class, Collections.singletonMap("getSelectedMessages", new IHttpRequestResponse[0]));
        assertTrue(new BypassMain().createMenuItems(empty).isEmpty());
        IHttpRequestResponse request = exchange(service("a.test", 80, "http"), request("a.test", "/loaded"), null);
        IContextMenuInvocation invocation = values(IContextMenuInvocation.class, Collections.singletonMap("getSelectedMessages", new IHttpRequestResponse[]{request}));
        edt(() -> new BypassMain().createMenuItems(invocation).get(2).doClick()); flush();
        edt(() -> assertSame(manual, ((JTabbedPane) field(panel, "tabs")).getSelectedComponent()));
    }

    @Test public void successfulWafSaveUsesInlineFeedbackAndInvalidReloadRetainsLiveRules() throws Exception {
        edt(() -> {
            ConfigPanel config = (ConfigPanel) field(panel, "configPanel");
            ((JCheckBox) field(config, "cbUtf16")).setSelected(false);
            ((JCheckBox) field(config, "cbGzip")).setSelected(false);
            ((JCheckBox) field(config, "cbMultipart")).setSelected(false);
            invoke(config, "saveOptions");
            assertFalse((Boolean) Utils.getWafBodyCharsetOptions().get("utf_16"));
            assertFalse((Boolean) Utils.getWafBodyTransformOptions().get("gzip"));
            assertFalse((Boolean) Utils.getWafContentTypeSpoofOptions().get("multipart"));
        });
        Map<String, Object> live = Utils.configMap;
        Files.write(Paths.get(loader.getConfigFilePath()), bytes("profiles: [broken"));
        edt(() -> {
            try { invoke(field(panel, "configPanel"), "reload"); }
            catch (java.awt.HeadlessException expected) { }
            assertSame(live, Utils.configMap);
        });
    }

    @Test public void newResultsPreserveSelectedRequestAndKeyboardSelectionUpdatesBothViewers() throws Exception {
        BypassMain bypass = new BypassMain();
        ScanSession session = panel.sessionForInput();
        IHttpRequestResponse a = exchange(service("a.test", 80, "http"), request("a.test", "/A"), response(403, "denied"));
        IHttpRequestResponse b = exchange(service("a.test", 80, "http"), request("a.test", "/B"), response(403, "denied"));
        transport = (target, req) -> exchange(target, req, response(200, text(req).split(" ")[1]));
        bypass.new Run_body_encoded_request(a.getRequest(), a, "send waf", false, 3, session).run();
        flush();
        edt(() -> ((BypassTable) field(panel, "bypassTable")).setRowSelectionInterval(0, 0));
        bypass.new Run_body_encoded_request(b.getRequest(), b, "send waf", false, 3, session).run();
        flush();
        edt(() -> {
            BypassTable table = (BypassTable) field(panel, "bypassTable");
            assertEquals(0, table.getSelectedRow());
            assertTrue(text(table.getRequest()).startsWith("GET /A "));
            table.getSelectionModel().setSelectionInterval(1, 1);
            assertTrue(text(table.getRequest()).startsWith("GET /B "));
            assertTrue(text(table.getResponse()).endsWith("/B"));
        });
    }

    @Test public void dashboardUsesTheSharedRedirectContractAndKeepsFinalRequestResponsePaired() throws Exception {
        List<String> paths = Collections.synchronizedList(new ArrayList<>());
        transport = (target, req) -> {
            paths.add(text(req).split(" ")[1]);
            return exchange(target, req, paths.size() == 1
                    ? bytes("HTTP/1.1 303 See Other\r\nLocation: next\r\n\r\n")
                    : bytes("HTTP/1.1 302 Found\r\nLocation: http://a.test:81/private\r\n\r\n"));
        };
        IHttpRequestResponse original = exchange(service("a.test", 80, "http"),
                bytes("POST /dir/page HTTP/1.1\r\nHost: a.test\r\nAuthorization: test\r\nContent-Length: 4\r\n\r\nBODY"), response(403, "denied"));
        new BypassMain().new Run_body_encoded_request(original.getRequest(), original, "send waf", true, 3, panel.sessionForInput()).run();
        flush();
        assertEquals(Arrays.asList("/dir/page", "/dir/next"), paths);
        edt(() -> {
            Bypass row = panel.getBypassTableModel().getBypassAt(0);
            assertEquals("/dir/page", row.url.getPath());
            assertTrue(text(row.requestResponse.getRequest()).startsWith("GET /dir/next "));
            assertFalse(text(row.requestResponse.getRequest()).contains("BODY"));
            assertTrue(row.redirectTooltip.contains("Different host, port or protocol"));
            assertTrue(text(row.requestResponse.getResponse()).contains("a.test:81"));
        });
    }

    @Test public void selectionFeedbackAndHistoryToggleOperateOnActualPanels() throws Exception {
        edt(() -> {
            load("/admin");
            JButton encode = (JButton) button(manual, "Base64 Encode");
            assertFalse(encode.isEnabled());
            assertTrue(encode.getToolTipText().contains("Select text"));
            Editor editor = (Editor) field(manual, "requestViewer");
            editor.selection = bytes("admin");
            invoke(manual, "refreshRequestInspector");
            assertTrue(encode.isEnabled());
            assertTrue(((JLabel) field(manual, "scopeLabel")).getText().contains("5 bytes"));
            encode.doClick();
            assertTrue(text(manual.getRequest()).contains("/YWRtaW4="));
            assertTrue(((JLabel) field(manual, "statusLabel")).getText().contains("Undo available"));
            invoke(manual, "undo");
            assertTrue(text(manual.getRequest()).contains("/admin"));
            JToggleButton toggle = (JToggleButton) button(manual, "Show History");
            toggle.doClick();
            assertFalse(toggle.isSelected());
            if (Boolean.getBoolean("bypass.workflow.previews")) {
                panel.showManualWaf();
                preview(panel, "manual-collapsed.png", 960, 700);
            }
            toggle.doClick();
            assertTrue(toggle.isSelected());
        });
    }

    @Test public void renderUpdatedPanelsWhenRequested() throws Exception {
        if (!Boolean.getBoolean("bypass.workflow.previews")) return;
        edt(() -> {
            load("/admin");
            for (int tab = 0; tab < 2; tab++) {
                ((JTabbedPane) field(panel, "tabs")).setSelectedIndex(tab);
                preview(panel, tab == 0 ? "dashboard.png" : "manual.png", 1440, 900);
            }
        });
    }

    private static void preview(JComponent panel, String name, int width, int height) {
        try {
            java.io.File output = new java.io.File("target/workflow-previews"); output.mkdirs();
            panel.setSize(width, height); layout(panel);
            java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(width, height, java.awt.image.BufferedImage.TYPE_INT_RGB);
            java.awt.Graphics2D graphics = image.createGraphics(); panel.printAll(graphics); graphics.dispose();
            javax.imageio.ImageIO.write(image, "png", new java.io.File(output, name));
        } catch (Exception e) { throw new AssertionError(e); }
    }

    private static AbstractButton button(java.awt.Container parent, String text) {
        for (Component child : parent.getComponents()) {
            if (child instanceof AbstractButton && text.equals(((AbstractButton) child).getText())) return (AbstractButton) child;
            if (child instanceof java.awt.Container) {
                AbstractButton found = button((java.awt.Container) child, text);
                if (found != null) return found;
            }
        }
        return null;
    }

    private void load(String path) { manual.loadRequest(exchange(service("a.test", 80, "http"), request("a.test", path), null)); }
    private Thread send() { invoke(manual, "sendRequest"); return (Thread) field(field(manual, "activeSend"), "thread"); }
    private List<ManualWafPanel.HistoryEntry> histories() { return (List<ManualWafPanel.HistoryEntry>) field(manual, "historyEntries"); }
    private static IHttpService service(String host, int port, String protocol) { return RedirectPolicyTest.service(host, port, protocol); }
    private static byte[] request(String host, String path) { return bytes("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"); }
    private static byte[] response(int status, String body) { return bytes("HTTP/1.1 " + status + " Status\r\nContent-Type: text/plain\r\n\r\n" + body); }
    private static IHttpRequestResponse exchange(IHttpService service, byte[] request, byte[] response) { return new BypassMain.SimpleHttpRequestResponse(service, request, response); }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.ISO_8859_1); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.ISO_8859_1); }
    private static int bodyOffset(byte[] bytes) { int end = text(bytes).indexOf("\r\n\r\n"); return end < 0 ? bytes.length : end + 4; }
    private static void edt(Runnable action) throws Exception { SwingUtilities.invokeAndWait(action); }
    private static void flush() throws Exception { edt(() -> {}); edt(() -> {}); edt(() -> {}); }
    private static void join(Thread t) throws Exception { t.join(3000); assertFalse("Transport did not finish", t.isAlive()); }
    private static void awaitIgnoringInterrupt(CountDownLatch latch) throws Exception {
        while (true) { try { if (!latch.await(5, TimeUnit.SECONDS)) throw new AssertionError("Latch timed out"); return; } catch (InterruptedException ignored) {} }
    }
    static Object field(Object owner, String name) {
        try { Field f = owner.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(owner); }
        catch (Exception e) { throw new AssertionError(e); }
    }
    static Object invoke(Object owner, String name) { return invoke(owner, name, new Class[0]); }
    static Object invoke(Object owner, String name, Class<?>[] types, Object... args) {
        try { Method m = owner.getClass().getDeclaredMethod(name, types); m.setAccessible(true); return m.invoke(owner, args); }
        catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException) throw (RuntimeException) e.getCause();
            if (e.getCause() instanceof Error) throw (Error) e.getCause();
            throw new AssertionError(e.getCause());
        } catch (Exception e) { throw new AssertionError(e); }
    }
    private static <T> T values(Class<T> type, Map<String, ?> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, (proxy, method, args) -> {
            if (!values.containsKey(method.getName())) throw new AssertionError("Unexpected stub call: " + method);
            return values.get(method.getName());
        }));
    }
    private static void layout(java.awt.Container c) { c.doLayout(); for (Component child : c.getComponents()) if (child instanceof java.awt.Container) layout((java.awt.Container) child); }
    private static class Editor implements IMessageEditor {
        private final JTextArea component = new JTextArea(); private byte[] message = new byte[0]; private byte[] selection;
        public Component getComponent() { return component; }
        public void setMessage(byte[] message, boolean request) { this.message = message.clone(); component.setText(text(message)); }
        public byte[] getMessage() { return message; }
        public boolean isMessageModified() { return false; }
        public byte[] getSelectedData() { return selection; }
    }
}

package Main;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IRequestInfo;
import burp.IResponseInfo;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class AutoScanTest {
    private boolean originalAutoScan;
    private IExtensionHelpers originalHelpers;
    private Map<String, Object> originalConfig;
    private final BlockingQueue<Scan> scans = new LinkedBlockingQueue<>();
    private final BypassMain listener = new BypassMain() {
        @Override
        protected void processHttp(IHttpRequestResponse[] messages, String tool, String profile, ScanSession session) {
            // Exercise the real Proxy listener without sending network requests.
            scans.add(new Scan(messages, tool, profile));
        }
    };

    @Before
    public void setUp() {
        originalAutoScan = Utils.isProxySelected;
        originalHelpers = Utils.helpers;
        originalConfig = Utils.configMap;
        Utils.isProxySelected = true;
        Utils.configMap = Collections.<String, Object>singletonMap("profiles",
                Collections.singletonMap(Utils.PROFILE_AUTO_ACCESS_BYPASS,
                        Collections.singletonMap("ignore_extensions", Arrays.asList("js", "css", "png"))));
    }

    @After
    public void tearDown() {
        Utils.isProxySelected = originalAutoScan;
        Utils.helpers = originalHelpers;
        Utils.configMap = originalConfig;
    }

    @Test
    public void onlyEnabledResponseListenerDispatchesAccessScans() throws Exception {
        for (int status : new int[]{401, 403}) {
            IInterceptedProxyMessage message = message(status, "/admin", new byte[]{1});
            listener.processProxyMessage(false, message);
            Scan scan = scans.poll(2, TimeUnit.SECONDS);
            assertNotNull("Expected AutoScan for status " + status, scan);
            assertEquals(1, scan.messages.length);
            assertSame(message.getMessageInfo(), scan.messages[0]);
            assertEquals("auto", scan.tool);
            assertEquals(Utils.PROFILE_AUTO_ACCESS_BYPASS, scan.profile);
        }
    }

    @Test
    public void disabledAutoScanAndRequestEventsAreIgnored() throws Exception {
        IInterceptedProxyMessage message = message(403, "/admin", new byte[]{1});
        Utils.isProxySelected = false;
        listener.processProxyMessage(false, message);
        Utils.isProxySelected = true;
        listener.processProxyMessage(true, message);
        assertNull(scans.poll(100, TimeUnit.MILLISECONDS));
    }

    @Test
    public void otherStatusCodesAndMissingResponsesAreIgnored() throws Exception {
        for (int status : new int[]{200, 302, 404, 500}) {
            listener.processProxyMessage(false, message(status, "/admin", new byte[]{1}));
        }
        listener.processProxyMessage(false, message(403, "/admin", null));
        assertNull(scans.poll(100, TimeUnit.MILLISECONDS));
    }

    @Test
    public void configuredStaticExtensionsAreIgnoredRegardlessOfCaseOrQuery() throws Exception {
        for (String path : new String[]{"/app.js", "/style.CSS", "/logo.PNG?version=2"}) {
            listener.processProxyMessage(false, message(403, path, new byte[]{1}));
        }
        assertNull(scans.poll(100, TimeUnit.MILLISECONDS));
    }

    @Test
    public void directoryNamesAndQueryParametersDoNotCauseStaticResourceFiltering() throws Exception {
        for (String path : new String[]{"/assets.css/admin", "/private.json?download=logo.png"}) {
            listener.processProxyMessage(false, message(403, path, new byte[]{1}));
            assertNotNull("Expected AutoScan for " + path, scans.poll(2, TimeUnit.SECONDS));
        }
    }

    private IInterceptedProxyMessage message(int status, String path, byte[] response) throws Exception {
        IResponseInfo responseInfo = stub(IResponseInfo.class,
                Collections.singletonMap("getStatusCode", (short) status));
        IRequestInfo requestInfo = stub(IRequestInfo.class,
                Collections.singletonMap("getUrl", new URL("http://example.test" + path)));
        Map<String, Object> helperResults = new HashMap<>();
        helperResults.put("analyzeResponse", responseInfo);
        helperResults.put("analyzeRequest", requestInfo);
        Utils.helpers = stub(IExtensionHelpers.class, helperResults);
        IHttpRequestResponse messageInfo = stub(IHttpRequestResponse.class,
                Collections.singletonMap("getResponse", response));
        return stub(IInterceptedProxyMessage.class, Collections.singletonMap("getMessageInfo", messageInfo));
    }

    private static <T> T stub(Class<T> type, Map<String, ?> results) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> {
                    if (!results.containsKey(method.getName())) {
                        throw new AssertionError("Unexpected call: " + method);
                    }
                    return results.get(method.getName());
                }));
    }

    private static class Scan {
        final IHttpRequestResponse[] messages;
        final String tool;
        final String profile;

        Scan(IHttpRequestResponse[] messages, String tool, String profile) {
            this.messages = messages;
            this.tool = tool;
            this.profile = profile;
        }
    }
}

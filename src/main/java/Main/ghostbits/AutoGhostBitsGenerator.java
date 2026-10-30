package Main.ghostbits;

import Main.Utils;
import Main.RequestBodyPolicy;
import Main.TextCodec;

import java.nio.charset.Charset;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Auto WAF 的 Ghost Bits 变体生成器。
 *
     * 默认只做“原请求已有内容”的低 8 位等价变形，保持低位还原后语义不变：
 *  - eq: 只对已有可疑 token 做低 8 位等价变形
 *  - parser: 只对已有 percent-hex / unicode-escape / x-escape 等解析结构做差异变形
 *
 * YAML templates 是完整漏洞链/场景探测，必须显式开启；默认不应替换业务路径。
 * selection/header_value 类模板在没有用户选区或明确 header 参数时容易误伤，自动模式跳过。
 */
public class AutoGhostBitsGenerator {

    private static final Pattern RFC2231_FILENAME = Pattern.compile("(?i)filename\\*\\s*=\\s*([\\w\\-]+)''([^;\\r\\n\"]+)");
    private static final Pattern PLAIN_FILENAME = Pattern.compile("(?i)filename\\s*=\\s*\"([^\"\\r\\n]*)\"");
    private static final Pattern JSON_STRING = Pattern.compile("\"((?:\\\\.|[^\"\\\\])*)\"");
    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u([0-9A-Fa-f]{4})");
    private static final Pattern HEX_ESCAPE_LOW_ZERO = Pattern.compile("\\\\x([0-9A-Fa-f])0");

    private final GhostBitsRule rule;
    private final GhostBitsEngine engine;
    private final Map<String, Object> options;

    public AutoGhostBitsGenerator(GhostBitsRule rule, Map<String, Object> options) {
        this.rule = rule == null ? new GhostBitsRule(null, null, null) : rule;
        this.engine = new GhostBitsEngine(this.rule);
        this.options = options;
    }

    public List<GhostBitsAutoVariant> generate(byte[] originalRequest) {
        List<GhostBitsAutoVariant> result = new ArrayList<>();
        if (originalRequest == null || originalRequest.length == 0 || !boolOption(options, "enabled", false)) {
            return result;
        }

        boolean rawSocketEnabled = boolOption(options, "raw_socket", true);
        int maxVariants = intOption(options, "max_variants", 10);
        if (maxVariants <= 0) {
            return result;
        }

        Map<String, Object> templateOptions = mapOption(options, "templates");
        for (GhostBitsRule.Template template : rule.getTemplates().values()) {
            if (result.size() >= maxVariants) {
                break;
            }
            if (!boolOption(templateOptions, template.getId(), false)) {
                continue;
            }

            String target = normalizeTarget(template.getTarget());
            String rendered = engine.renderTemplate(template.getId());
            if (rendered == null || rendered.isEmpty()) {
                continue;
            }

            byte[] mutated = null;
            if ("path".equals(target)) {
                mutated = applyPath(originalRequest, rendered.getBytes(StandardCharsets.UTF_8));
            } else if ("filename".equals(target)) {
                mutated = applyFilename(originalRequest, rendered.getBytes(StandardCharsets.UTF_8),
                        requiresRfc2231Filename(template));
            } else {
                // selection/header_value 等模板需要人工选区或更精确的 header 参数，第一版自动模式跳过。
                continue;
            }
            if (mutated == null || Arrays.equals(originalRequest, mutated)) {
                continue;
            }

            boolean rawRequired = rawSocketEnabled
                    && (template.requiresRawSender() || containsNonAsciiBeforeBody(mutated));
            String reason = buildReason(template, target, rendered, rawRequired, rawSocketEnabled);
            result.add(new GhostBitsAutoVariant(mutated, template.getId(), template.getLabel(),
                    target, rawRequired, reason));
        }

        if (result.size() < maxVariants) {
            addParserDifferentialVariants(originalRequest, result, maxVariants, rawSocketEnabled);
        }

        if (result.size() < maxVariants) {
            addGenericEquivalentVariants(originalRequest, result, maxVariants, rawSocketEnabled);
        }

        return result;
    }

    private void addParserDifferentialVariants(byte[] originalRequest,
                                               List<GhostBitsAutoVariant> result,
                                               int maxVariants,
                                               boolean rawSocketEnabled) {
        byte[] targetBytes = extractPathBytes(originalRequest);
        if (targetBytes != null && targetBytes.length > 0 && result.size() < maxVariants) {
            String target = new String(targetBytes, StandardCharsets.UTF_8);
            if (Arrays.equals(target.getBytes(StandardCharsets.UTF_8), targetBytes)) {
                addParserTargetVariant(originalRequest, result, maxVariants, rawSocketEnabled, target);
            }
        }

        if (result.size() < maxVariants) {
            addParserBodyVariant(originalRequest, result, maxVariants, rawSocketEnabled);
        }
    }

    private void addParserTargetVariant(byte[] originalRequest,
                                        List<GhostBitsAutoVariant> result,
                                        int maxVariants,
                                        boolean rawSocketEnabled,
                                        String target) {
        TextMutation mutation = mutateParserStructures(target);
        if (mutation == null || mutation.value.equals(target)) {
            return;
        }
        byte[] mutated = applyPath(originalRequest, mutation.value.getBytes(StandardCharsets.UTF_8));
        if (mutated == null || Arrays.equals(originalRequest, mutated)) {
            return;
        }
        boolean rawRequired = rawSocketEnabled && containsNonAsciiBeforeBody(mutated);
        result.add(new GhostBitsAutoVariant(mutated,
                "parser_" + mutation.scope,
                "Parser " + mutation.token,
                "target",
                rawRequired,
                buildParserReason(mutation, rawRequired, rawSocketEnabled)));
    }

    private void addParserBodyVariant(byte[] originalRequest,
                                      List<GhostBitsAutoVariant> result,
                                      int maxVariants,
                                      boolean rawSocketEnabled) {
        TextRange body = extractTextBody(originalRequest);
        if (body == null || body.text.isEmpty()) {
            return;
        }
        TextMutation mutation = mutateParserStructures(body.text);
        if (mutation == null || mutation.value.equals(body.text)) {
            return;
        }
        byte[] encoded = encodeBodyMutation(body, mutation.value);
        if (encoded == null) return;
        byte[] replaced = replaceRange(originalRequest, body.start, body.end, encoded);
        byte[] mutated = updateContentLength(replaced);
        if (mutated == null || Arrays.equals(originalRequest, mutated)) {
            return;
        }
        boolean rawRequired = rawSocketEnabled && containsNonAsciiBeforeBody(mutated);
        result.add(new GhostBitsAutoVariant(mutated,
                "parser_" + mutation.scope,
                "Parser " + mutation.token,
                "body",
                rawRequired,
                buildParserReason(mutation, rawRequired, rawSocketEnabled)));
    }

    private void addGenericEquivalentVariants(byte[] originalRequest,
                                              List<GhostBitsAutoVariant> result,
                                              int maxVariants,
                                              boolean rawSocketEnabled) {
        Map<String, Object> generic = mapOption(options, "generic");
        if (!boolOption(generic, "enabled", false)) {
            return;
        }
        Map<String, Object> strategies = mapOption(generic, "strategies");
        int variantCount = intOption(generic, "variant_count", 3);
        if (variantCount <= 0) {
            return;
        }

        Set<String> seen = new LinkedHashSet<>();
        List<GhostBitsCodec.EncodeStrategy> enabledStrategies = orderedGenericStrategies(strategies);
        for (int i = 0; i < variantCount && result.size() < maxVariants; i++) {
            for (GhostBitsCodec.EncodeStrategy strategy : enabledStrategies) {
                if (result.size() >= maxVariants) return;
                addEquivalentTargetVariant(originalRequest, result, maxVariants, rawSocketEnabled, strategy, seen);
            }
            for (GhostBitsCodec.EncodeStrategy strategy : enabledStrategies) {
                if (result.size() >= maxVariants) return;
                addEquivalentFilenameVariant(originalRequest, result, maxVariants, rawSocketEnabled, strategy, seen);
            }
            for (GhostBitsCodec.EncodeStrategy strategy : enabledStrategies) {
                if (result.size() >= maxVariants) return;
                addEquivalentBodyVariant(originalRequest, result, maxVariants, rawSocketEnabled, strategy, seen);
            }
        }
    }

    private void addEquivalentTargetVariant(byte[] originalRequest,
                                            List<GhostBitsAutoVariant> result,
                                            int maxVariants,
                                            boolean rawSocketEnabled,
                                            GhostBitsCodec.EncodeStrategy strategy,
                                            Set<String> seen) {
        byte[] targetBytes = extractPathBytes(originalRequest);
        if (targetBytes == null || targetBytes.length == 0) {
            return;
        }
        String target = new String(targetBytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(target.getBytes(StandardCharsets.UTF_8), targetBytes)) {
            return;
        }
        TextMutation mutation = encodeRequestTargetValues(target, strategy);
        if (mutation == null || mutation.value.equals(target)
                || !target.equals(GhostBitsEngine.foldToAscii(mutation.value))
                || !seen.add("target:" + mutation.value)) {
            return;
        }
        byte[] mutated = applyPath(originalRequest, mutation.value.getBytes(StandardCharsets.UTF_8));
        if (mutated == null || Arrays.equals(originalRequest, mutated)) {
            return;
        }
        boolean rawRequired = rawSocketEnabled && containsNonAsciiBeforeBody(mutated);
        result.add(new GhostBitsAutoVariant(mutated,
                "eq_" + strategy.name().toLowerCase(),
                "Equivalent " + strategy.name().toLowerCase(),
                mutation.scope,
                rawRequired,
                buildEquivalentReason(strategy, mutation, rawRequired, rawSocketEnabled)));
    }

    private void addEquivalentFilenameVariant(byte[] originalRequest,
                                              List<GhostBitsAutoVariant> result,
                                              int maxVariants,
                                              boolean rawSocketEnabled,
                                              GhostBitsCodec.EncodeStrategy strategy,
                                              Set<String> seen) {
        String filename = extractFilename(originalRequest);
        if (filename == null || !shouldMutateValue(filename)) {
            return;
        }
        String encoded = GhostBitsCodec.encode(filename, strategy, engine);
        if (encoded.equals(filename) || !filename.equals(GhostBitsEngine.foldToAscii(encoded))
                || !seen.add("filename:" + encoded)) {
            return;
        }
        byte[] mutated = applyFilename(originalRequest, encoded.getBytes(StandardCharsets.UTF_8));
        if (mutated == null || Arrays.equals(originalRequest, mutated)) {
            return;
        }
        boolean rawRequired = rawSocketEnabled && containsNonAsciiBeforeBody(mutated);
        TextMutation mutation = new TextMutation(encoded, "filename", detectToken(filename));
        result.add(new GhostBitsAutoVariant(mutated,
                "eq_" + strategy.name().toLowerCase(),
                "Equivalent " + strategy.name().toLowerCase(),
                "filename",
                rawRequired,
                buildEquivalentReason(strategy, mutation, rawRequired, rawSocketEnabled)));
    }

    private void addEquivalentBodyVariant(byte[] originalRequest,
                                          List<GhostBitsAutoVariant> result,
                                          int maxVariants,
                                          boolean rawSocketEnabled,
                                          GhostBitsCodec.EncodeStrategy strategy,
                                          Set<String> seen) {
        TextRange body = extractTextBody(originalRequest);
        if (body == null || body.text.isEmpty()) {
            return;
        }
        String contentType = headerValue(originalRequest, "Content-Type");
        TextMutation mutation = null;
        if (contentType != null && contentType.toLowerCase().contains("application/x-www-form-urlencoded")) {
            mutation = encodeFormValues(body.text, strategy);
        } else if (contentType != null && contentType.toLowerCase().contains("json")) {
            mutation = encodeJsonStringToken(body.text, strategy);
        }
        if (mutation == null || mutation.value.equals(body.text)
                || !body.text.equals(GhostBitsEngine.foldToAscii(mutation.value))
                || !seen.add("body:" + mutation.value)) {
            return;
        }
        byte[] encoded = encodeBodyMutation(body, mutation.value);
        if (encoded == null) return;
        byte[] replaced = replaceRange(originalRequest, body.start, body.end, encoded);
        byte[] mutated = updateContentLength(replaced);
        if (mutated == null || Arrays.equals(originalRequest, mutated)) {
            return;
        }
        boolean rawRequired = rawSocketEnabled && containsNonAsciiBeforeBody(mutated);
        result.add(new GhostBitsAutoVariant(mutated,
                "eq_" + strategy.name().toLowerCase(),
                "Equivalent " + strategy.name().toLowerCase(),
                mutation.scope,
                rawRequired,
                buildEquivalentReason(strategy, mutation, rawRequired, rawSocketEnabled)));
    }

    private TextMutation encodeRequestTargetValues(String target,
                                                   GhostBitsCodec.EncodeStrategy strategy) {
        if (target == null || target.isEmpty()) {
            return null;
        }
        int queryIdx = target.indexOf('?');
        String path = queryIdx >= 0 ? target.substring(0, queryIdx) : target;
        String query = queryIdx >= 0 ? target.substring(queryIdx + 1) : null;
        if (query == null || query.isEmpty()) {
            return null;
        }

        StringBuilder out = new StringBuilder(target.length());
        out.append(path);
        TextMutation queryMutation = encodeQueryValues(query, strategy);
        if (queryMutation == null) {
            return null;
        }
        out.append('?').append(queryMutation.value);
        return new TextMutation(out.toString(), "query", queryMutation.token);
    }

    private TextMutation encodeQueryValues(String query, GhostBitsCodec.EncodeStrategy strategy) {
        StringBuilder out = new StringBuilder(query.length());
        int pairStart = 0;
        String firstToken = null;
        boolean changed = false;
        for (int i = 0; i <= query.length(); i++) {
            if (i == query.length() || query.charAt(i) == '&') {
                if (i > pairStart) {
                    TextMutation pair = encodeQueryPair(query.substring(pairStart, i), strategy);
                    if (pair != null) {
                        out.append(pair.value);
                        changed = true;
                        if (firstToken == null) {
                            firstToken = pair.token;
                        }
                    } else {
                        out.append(query, pairStart, i);
                    }
                }
                if (i < query.length()) {
                    out.append('&');
                }
                pairStart = i + 1;
            }
        }
        return changed ? new TextMutation(out.toString(), "query", firstToken) : null;
    }

    private TextMutation encodeQueryPair(String pair, GhostBitsCodec.EncodeStrategy strategy) {
        int eq = pair.indexOf('=');
        if (eq < 0) {
            return null;
        }
        String name = pair.substring(0, eq + 1);
        String value = pair.substring(eq + 1);
        if (!shouldMutateValue(value)) {
            return null;
        }
        String encoded = GhostBitsCodec.encode(value, strategy, engine);
        return encoded.equals(value) ? null : new TextMutation(name + encoded, "query", detectToken(value));
    }

    private TextMutation encodeFormValues(String form, GhostBitsCodec.EncodeStrategy strategy) {
        TextMutation mutation = encodeQueryValues(form, strategy);
        return mutation == null ? null : new TextMutation(mutation.value, "form", mutation.token);
    }

    private TextMutation encodeJsonStringToken(String json, GhostBitsCodec.EncodeStrategy strategy) {
        Matcher m = JSON_STRING.matcher(json);
        StringBuffer out = new StringBuffer();
        boolean changed = false;
        String firstToken = null;
        while (m.find()) {
            String value = m.group(1);
            if (!changed && shouldMutateValue(value)) {
                String encoded = GhostBitsCodec.encode(value, strategy, engine);
                if (!encoded.equals(value)) {
                    m.appendReplacement(out, Matcher.quoteReplacement("\"" + encoded + "\""));
                    changed = true;
                    firstToken = detectToken(value);
                    continue;
                }
            }
            m.appendReplacement(out, Matcher.quoteReplacement(m.group(0)));
        }
        m.appendTail(out);
        return changed ? new TextMutation(out.toString(), "json", firstToken) : null;
    }

    private TextMutation mutateParserStructures(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        String percent = mutateLoosePercentHex(text);
        if (!percent.equals(text)) {
            return new TextMutation(percent, "percent_hex", "percent-hex");
        }
        Matcher x = HEX_ESCAPE_LOW_ZERO.matcher(text);
        if (x.find()) {
            String mutated = x.replaceFirst(Matcher.quoteReplacement("\\x" + x.group(1) + "J"));
            return new TextMutation(mutated, "x_escape", "\\xHH");
        }
        Matcher u = UNICODE_ESCAPE.matcher(text);
        if (u.find()) {
            String escaped = u.group(1);
            String unicodeDigits = asciiDigitsToArabicIndic(escaped);
            if (!unicodeDigits.equals(escaped)) {
                String mutated = text.substring(0, u.start(1)) + unicodeDigits + text.substring(u.end(1));
                return new TextMutation(mutated, "u_escape", "\\uXXXX");
            }
        }
        return null;
    }

    private String mutateLoosePercentHex(String text) {
        return text.replaceAll("(?i)%2e", "%2>")
                .replaceAll("(?i)%6e", "%6>");
    }

    private String asciiDigitsToArabicIndic(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        boolean changed = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                sb.append((char) ('\u0660' + (c - '0')));
                changed = true;
            } else {
                sb.append(c);
            }
        }
        return changed ? sb.toString() : s;
    }

    private boolean shouldMutateValue(String value) {
        return detectToken(value) != null;
    }

    private String detectToken(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String lower = value.toLowerCase();
        if (lower.contains("../") || lower.contains("..\\")
                || lower.contains("%2e") || lower.contains("%u002e")
                || lower.contains("%2f") || lower.contains("%5c")) {
            return "traversal";
        }
        if (lower.contains("@type")) {
            return "@type";
        }
        if (containsClassToken(lower)) {
            return "class";
        }
        if (lower.contains("runtime") || lower.contains("jndi") || lower.contains("ldap://")) {
            return "java";
        }
        if (lower.contains("union") || lower.contains("select") || lower.contains(" or ")
                || lower.contains("'or") || lower.contains("\"or")) {
            return "sqli";
        }
        if (lower.contains("<script") || lower.contains("javascript:")) {
            return "xss";
        }
        if (lower.contains(".jsp") || lower.contains(".jspx") || lower.contains(".php")
                || lower.contains(".asp") || lower.contains(".aspx")) {
            return "extension";
        }
        if (lower.contains("%0d%0a") || lower.contains("\\r\\n")) {
            return "crlf";
        }
        return null;
    }

    private boolean containsClassToken(String lower) {
        if (lower == null) {
            return false;
        }
        return Pattern.compile("(^|[^a-z0-9_])class($|[^a-z0-9_])|classloader").matcher(lower).find();
    }

    private String extractFilename(byte[] request) {
        String text = new String(request, StandardCharsets.ISO_8859_1);
        Matcher m = RFC2231_FILENAME.matcher(text);
        if (m.find()) {
            return m.group(2);
        }
        m = PLAIN_FILENAME.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    private TextRange extractTextBody(byte[] request) {
        if (!RequestBodyPolicy.isEditable(request)) return null;
        int headerEnd = findHeaderEnd(request);
        if (headerEnd < 0 || headerEnd >= request.length) {
            return null;
        }
        byte[] body = Arrays.copyOfRange(request, headerEnd, request.length);
        try {
            Charset charset = RequestBodyPolicy.charset(RequestBodyPolicy.headers(request));
            return new TextRange(headerEnd, request.length, TextCodec.decode(body, charset), charset);
        } catch (CharacterCodingException | IllegalArgumentException invalid) {
            return null;
        }
    }

    private byte[] encodeBodyMutation(TextRange body, String value) {
        try {
            byte[] encoded = TextCodec.encode(value, body.charset);
            return value.equals(TextCodec.decode(encoded, body.charset)) ? encoded : null;
        } catch (CharacterCodingException invalid) {
            return null;
        }
    }

    private String headerValue(byte[] request, String headerName) {
        int headerEnd = findHeaderEnd(request);
        if (headerEnd <= 0 || headerName == null) {
            return null;
        }
        String headerText = new String(request, 0, headerEnd, StandardCharsets.ISO_8859_1);
        String[] lines = headerText.split("\\r?\\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(headerName)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private List<GhostBitsCodec.EncodeStrategy> orderedGenericStrategies(Map<String, Object> strategies) {
        List<GhostBitsCodec.EncodeStrategy> result = new ArrayList<>();
        addStrategyIfEnabled(result, strategies, "minimal", GhostBitsCodec.EncodeStrategy.MINIMAL);
        addStrategyIfEnabled(result, strategies, "full", GhostBitsCodec.EncodeStrategy.FULL);
        addStrategyIfEnabled(result, strategies, "letters", GhostBitsCodec.EncodeStrategy.LETTERS);
        addStrategyIfEnabled(result, strategies, "digits", GhostBitsCodec.EncodeStrategy.DIGITS);
        addStrategyIfEnabled(result, strategies, "symbols", GhostBitsCodec.EncodeStrategy.SYMBOLS);
        return result;
    }

    private void addStrategyIfEnabled(List<GhostBitsCodec.EncodeStrategy> out,
                                      Map<String, Object> strategies,
                                      String key,
                                      GhostBitsCodec.EncodeStrategy strategy) {
        if (boolOption(strategies, key, false)) {
            out.add(strategy);
        }
    }

    private byte[] extractPathBytes(byte[] request) {
        int lineEnd = firstLineEnd(request);
        if (lineEnd <= 0) {
            return null;
        }
        int firstSpace = -1;
        int secondSpace = -1;
        for (int i = 0; i < lineEnd; i++) {
            if (request[i] == ' ') {
                if (firstSpace < 0) {
                    firstSpace = i;
                } else {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0 || secondSpace <= firstSpace + 1) {
            return null;
        }
        return Arrays.copyOfRange(request, firstSpace + 1, secondSpace);
    }

    private byte[] applyPath(byte[] request, byte[] payload) {
        int lineEnd = firstLineEnd(request);
        if (lineEnd <= 0) {
            return null;
        }

        int firstSpace = -1;
        int secondSpace = -1;
        for (int i = 0; i < lineEnd; i++) {
            if (request[i] == ' ') {
                if (firstSpace < 0) {
                    firstSpace = i;
                } else {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0 || secondSpace <= firstSpace + 1) {
            return null;
        }
        return replaceRange(request, firstSpace + 1, secondSpace, payload);
    }

    private byte[] applyFilename(byte[] request, byte[] payload) {
        return applyFilename(request, payload, false);
    }

    private byte[] applyFilename(byte[] request, byte[] payload, boolean forceRfc2231) {
        String text = new String(request, StandardCharsets.ISO_8859_1);
        Matcher m = RFC2231_FILENAME.matcher(text);
        int valueStart = -1;
        int valueEnd = -1;
        if (m.find()) {
            valueStart = m.start(2);
            valueEnd = m.end(2);
        } else {
            m = PLAIN_FILENAME.matcher(text);
            if (m.find()) {
                if (m.start() >= findHeaderEnd(request) && !RequestBodyPolicy.isEditable(request)) return null;
                if (forceRfc2231) {
                    valueStart = m.start();
                    valueEnd = m.end();
                    byte[] attr = ("filename*=\"UTF-8''" + new String(payload, StandardCharsets.UTF_8) + "\"")
                            .getBytes(StandardCharsets.UTF_8);
                    byte[] replaced = replaceRange(request, valueStart, valueEnd, attr);
                    return updateContentLength(replaced);
                } else {
                    valueStart = m.start(1);
                    valueEnd = m.end(1);
                }
            }
        }
        if (valueStart < 0 || valueEnd < valueStart) {
            return null;
        }
        if (valueStart >= findHeaderEnd(request) && !RequestBodyPolicy.isEditable(request)) return null;
        byte[] replaced = replaceRange(request, valueStart, valueEnd, payload);
        return updateContentLength(replaced);
    }

    private boolean requiresRfc2231Filename(GhostBitsRule.Template template) {
        if (template == null) {
            return false;
        }
        String id = template.getId() == null ? "" : template.getId().toLowerCase();
        String category = template.getCategory() == null ? "" : template.getCategory().toLowerCase();
        return id.contains("tomcat") || category.contains("tomcat");
    }

    private byte[] replaceRange(byte[] source, int start, int end, byte[] replacement) {
        if (source == null || replacement == null || start < 0 || end < start || end > source.length) {
            return null;
        }
        byte[] out = new byte[source.length - (end - start) + replacement.length];
        System.arraycopy(source, 0, out, 0, start);
        System.arraycopy(replacement, 0, out, start, replacement.length);
        System.arraycopy(source, end, out, start + replacement.length, source.length - end);
        return out;
    }

    private byte[] updateContentLength(byte[] request) {
        int headerEnd = findHeaderEnd(request);
        if (headerEnd <= 0) {
            return request;
        }
        int bodyLen = request.length - headerEnd;
        String headerText = new String(request, 0, headerEnd, StandardCharsets.ISO_8859_1);
        String[] lines = headerText.split("\\r?\\n", -1);
        boolean updated = false;
        StringBuilder headers = new StringBuilder();
        for (String line : lines) {
            if (line == null || line.isEmpty()) {
                continue;
            }
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
                headers.append("Content-Length: ").append(bodyLen).append("\r\n");
                updated = true;
            } else {
                headers.append(line).append("\r\n");
            }
        }
        if (!updated && bodyLen > 0) {
            headers.append("Content-Length: ").append(bodyLen).append("\r\n");
        }
        headers.append("\r\n");
        byte[] headerBytes = headers.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[headerBytes.length + bodyLen];
        System.arraycopy(headerBytes, 0, out, 0, headerBytes.length);
        System.arraycopy(request, headerEnd, out, headerBytes.length, bodyLen);
        return out;
    }

    private String buildReason(GhostBitsRule.Template template, String target, String rendered,
                               boolean rawRequired, boolean rawSocketEnabled) {
        StringBuilder sb = new StringBuilder();
        sb.append("ghost:template; id:").append(template.getId())
                .append("; target:").append(target)
                .append("; sender:").append(rawRequired ? "raw" : "burp");
        if (!rawSocketEnabled && (template.requiresRawSender() || containsNonAscii(rendered))) {
            sb.append("; raw disabled");
        }
        String folded = GhostBitsEngine.foldToAscii(rendered);
        if (!folded.equals(rendered)) {
            sb.append("; fold:").append(compact(rendered))
                    .append(" -> ").append(compact(escape(folded)));
        }
        if (!template.getNotes().isEmpty()) {
            sb.append("; ").append(template.getNotes());
        }
        return limitReason(sb.toString());
    }

    private String buildEquivalentReason(GhostBitsCodec.EncodeStrategy strategy,
                                         TextMutation mutation,
                                         boolean rawRequired,
                                         boolean rawSocketEnabled) {
        StringBuilder sb = new StringBuilder();
        sb.append("ghost:eq")
                .append("; scope:").append(mutation.scope)
                .append("; token:").append(mutation.token == null ? "-" : mutation.token)
                .append("; sender:").append(rawRequired ? "raw" : "burp")
                .append("; strategy:").append(strategy.name().toLowerCase());
        if (!rawSocketEnabled && containsNonAscii(mutation.value)) {
            sb.append("; raw disabled");
        }
        String folded = GhostBitsEngine.foldToAscii(mutation.value);
        if (!folded.equals(mutation.value)) {
            sb.append("; fold:").append(compact(mutation.value))
                    .append(" -> ").append(compact(escape(folded)));
        }
        return limitReason(sb.toString());
    }

    private String buildParserReason(TextMutation mutation,
                                     boolean rawRequired,
                                     boolean rawSocketEnabled) {
        StringBuilder sb = new StringBuilder();
        sb.append("ghost:parser")
                .append("; scope:").append(mutation.scope)
                .append("; token:").append(mutation.token == null ? "-" : mutation.token)
                .append("; sender:").append(rawRequired ? "raw" : "burp");
        if (!rawSocketEnabled && containsNonAscii(mutation.value)) {
            sb.append("; raw disabled");
        }
        sb.append("; parser-diff only, not vulnerability confirmation");
        return limitReason(sb.toString());
    }

    private static String compact(String value) {
        if (value == null) {
            return "";
        }
        return value.length() > 36 ? value.substring(0, 33) + "..." : value;
    }

    private static String limitReason(String reason) {
        if (reason == null) {
            return "";
        }
        return reason.length() > 220 ? reason.substring(0, 217) + "..." : reason;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }

    private static String normalizeTarget(String target) {
        return target == null ? "selection" : target.trim().toLowerCase();
    }

    private static int firstLineEnd(byte[] bytes) {
        if (bytes == null) {
            return -1;
        }
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == '\n') {
                return i > 0 && bytes[i - 1] == '\r' ? i - 1 : i;
            }
        }
        return -1;
    }

    private static int findHeaderEnd(byte[] bytes) {
        if (bytes == null) return -1;
        for (int i = 0; i + 3 < bytes.length; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n'
                    && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                return i + 4;
            }
        }
        for (int i = 0; i + 1 < bytes.length; i++) {
            if (bytes[i] == '\n' && bytes[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1;
    }

    public static boolean containsNonAsciiBeforeBody(byte[] request) {
        int headerEnd = findHeaderEnd(request);
        int upper = headerEnd > 0 ? headerEnd : (request == null ? 0 : request.length);
        for (int i = 0; i < upper; i++) {
            if ((request[i] & 0xFF) > 0x7F) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsNonAscii(String value) {
        if (value == null) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7F) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOption(Map<String, Object> source, String key) {
        if (source == null) {
            return java.util.Collections.emptyMap();
        }
        Object value = source.get(key);
        if (value instanceof Map) {
            return (Map<String, Object>) value;
        }
        return java.util.Collections.emptyMap();
    }

    private static boolean boolOption(Map<String, Object> source, String key, boolean defaultValue) {
        if (source == null || !source.containsKey(key)) {
            return defaultValue;
        }
        Object value = source.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return Boolean.parseBoolean(String.valueOf(value));
    }

    private static int intOption(Map<String, Object> source, String key, int defaultValue) {
        if (source == null || !source.containsKey(key)) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(String.valueOf(source.get(key)));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static class TextMutation {
        final String value;
        final String scope;
        final String token;

        TextMutation(String value, String scope, String token) {
            this.value = value == null ? "" : value;
            this.scope = scope == null ? "" : scope;
            this.token = token;
        }
    }

    private static class TextRange {
        final int start;
        final int end;
        final String text;
        final Charset charset;

        TextRange(int start, int end, String text, Charset charset) {
            this.start = start;
            this.end = end;
            this.text = text == null ? "" : text;
            this.charset = charset;
        }
    }
}

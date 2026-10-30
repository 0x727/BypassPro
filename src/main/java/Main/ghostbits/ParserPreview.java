package Main.ghostbits;

import java.net.URLDecoder;
import java.util.Locale;
import java.util.regex.*;

/** Local operation models only; these do not assert a target's parser or version. */
public final class ParserPreview {
    private ParserPreview() {}
    public static final class Result {
        public final String value, mechanism;
        Result(String value, String mechanism) { this.value = value; this.mechanism = mechanism; }
    }

    public static Result evaluate(String name, String payload) {
        String key = name.toLowerCase(Locale.ROOT);
        try {
            if (key.contains("fullwidth") || key.contains("jdk_urldecoder"))
                return new Result(URLDecoder.decode(payload, "UTF-8"), "JDK URLDecoder / Unicode hex digits");
            if (key.contains("tomcat"))
                return new Result(URLDecoder.decode(GhostBitsCodec.fold(payload, GhostBitsCodec.FoldMode.BIT_7), "UTF-8"),
                        "7-bit hex narrowing + percent decode");
            if (key.contains("jackson")) return new Result(unicodeEscapes(payload, true), "low-8-bit hex lookup");
            if (key.contains("fastjson") && (key.contains("unicode") || key.contains("\\u")))
                return new Result(unicodeEscapes(payload, false), "Character.digit(char, 16)");
            if (key.contains("unicode digits")) {
                StringBuilder digits = new StringBuilder();
                for (char c : payload.toCharArray()) {
                    int digit = Character.digit(c, 10);
                    digits.append(digit < 0 ? c : (char)('0' + digit));
                }
                return new Result(digits.toString(), "Character.digit(char, 10)");
            }
            if (key.contains("jetty"))
                return new Result(URLDecoder.decode(payload.replaceAll("(?i)%2>", "%2e"), "UTF-8"),
                        "loose %2> hex model");
            if (key.contains("fastjson") && (key.contains("x_escape") || key.contains("\\x"))) {
                Matcher matcher = Pattern.compile("\\\\x(.)(.)").matcher(payload);
                StringBuffer result = new StringBuffer();
                while (matcher.find()) {
                    int high = asciiHex(matcher.group(1).charAt(0)), low = asciiHex(matcher.group(2).charAt(0));
                    matcher.appendReplacement(result, Matcher.quoteReplacement(String.valueOf((char)((high << 4) | low))));
                }
                matcher.appendTail(result);
                return new Result(result.toString(), "loose ASCII hex table (unfilled entries = 0)");
            }
        } catch (Exception invalid) {
            return new Result(null, name + ": model could not decode payload");
        }
        return new Result(null, name + ": no local parser model");
    }

    private static int asciiHex(char c) {
        if (c > 127) throw new IllegalArgumentException("non-ASCII table index");
        int digit = Character.digit(c, 16);
        return digit < 0 ? 0 : digit;
    }

    private static String unicodeEscapes(String payload, boolean narrow) {
        Matcher matcher = Pattern.compile("\\\\u(.{4})", Pattern.DOTALL).matcher(payload);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            int code = 0;
            for (char c : matcher.group(1).toCharArray()) {
                int digit = Character.digit(narrow ? (char)(c & 255) : c, 16);
                if (digit < 0) throw new IllegalArgumentException("invalid hex digit");
                code = (code << 4) | digit;
            }
            matcher.appendReplacement(result, Matcher.quoteReplacement(String.valueOf((char)code)));
        }
        matcher.appendTail(result);
        return result.toString();
    }
}

package Main.ghostbits;

import Main.I18n;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Pure Gh0st Bits codec logic used by Manual WAF UI.
 * This class intentionally has no Swing/Burp dependencies.
 */
public final class GhostBitsCodec {

    public enum EncodeStrategy { MINIMAL, FULL, LETTERS, DIGITS, SYMBOLS }

    public enum FoldMode { BIT_8, BIT_7 }

    private static final int[] CHINESE_HIGH_BYTES = {
            0x4E, 0x5B, 0x6C, 0x70, 0x75, 0x76, 0x7A, 0x80, 0x85, 0x90, 0x95
    };

    private GhostBitsCodec() {
    }

    public static String encode(String source, EncodeStrategy strategy) {
        return encode(source, strategy, null);
    }

    public static String encode(String source, EncodeStrategy strategy, GhostBitsEngine engine) {
        if (source == null || source.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(source.length());
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            if (shouldEncode(c, strategy)) {
                sb.append(pickGhostChar(c, engine));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static boolean shouldEncode(char c, EncodeStrategy strategy) {
        if (c > 0x7F) {
            return false;
        }
        boolean letter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        boolean digit = c >= '0' && c <= '9';
        boolean special = !letter && !digit;
        switch (strategy) {
            case FULL:
                return true;
            case LETTERS:
                return letter;
            case DIGITS:
                return digit;
            case SYMBOLS:
                return special;
            case MINIMAL:
            default:
                return c == '.' || c == '/' || c == '\\' || c == '%' || c == '@'
                        || c == ':' || c == ';' || c == '?' || c == '&' || c == '='
                        || c == '\'' || c == '"' || c == '<' || c == '>'
                        || c == '\r' || c == '\n';
        }
    }

    public static boolean mayEncodeLineBreak(EncodeStrategy strategy) {
        return strategy == EncodeStrategy.FULL
                || strategy == EncodeStrategy.SYMBOLS
                || strategy == EncodeStrategy.MINIMAL;
    }

    public static boolean containsLineBreak(String text) {
        return text != null && (text.indexOf('\r') >= 0 || text.indexOf('\n') >= 0);
    }

    public static char pickChineseGhostChar(char target) {
        int high = CHINESE_HIGH_BYTES[ThreadLocalRandom.current().nextInt(CHINESE_HIGH_BYTES.length)];
        return (char) ((high << 8) | (target & 0xFF));
    }

    public static char pickGhostChar(char target, GhostBitsEngine engine) {
        if (engine != null) {
            List<String> candidates = engine.findCandidates(String.valueOf(target));
            if (!candidates.isEmpty()) {
                String chosen = candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
                if (!chosen.isEmpty()) {
                    return chosen.charAt(0);
                }
            }
        }
        return pickChineseGhostChar(target);
    }

    public static String fold(String text, FoldMode mode) {
        if (text == null) {
            return "";
        }
        if (mode == FoldMode.BIT_7) {
            StringBuilder sb = new StringBuilder(text.length());
            for (int i = 0; i < text.length(); i++) {
                sb.append((char) (text.charAt(i) & 0x7F));
            }
            return sb.toString();
        }
        return GhostBitsEngine.foldToAscii(text);
    }

    public static List<String> buildSevenBitCandidates(char target) {
        List<String> candidates = new ArrayList<>();
        int low = target & 0x7F;
        for (int high = 0x01; high <= 0xFF; high++) {
            int code = (high << 8) | low;
            if (code >= 0xD800 && code <= 0xDFFF) {
                continue;
            }
            candidates.add(String.valueOf((char) code));
        }
        return candidates;
    }

    public static String foldModeLabel(FoldMode mode) {
        return mode == FoldMode.BIT_7 ? "7-bit ch & 0x7F" : "8-bit ch & 0xFF";
    }

    public static String buildFoldPreviewReport(String text, FoldMode mode) {
        String folded = fold(text, mode);
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.t("ghost.original")).append(escape(text)).append('\n');
        sb.append(I18n.t("ghost.mode")).append(foldModeLabel(mode)).append('\n');
        sb.append(I18n.t("ghost.restored")).append(escape(folded)).append("\n\n");
        int max = Math.min(text == null ? 0 : text.length(), 48);
        for (int i = 0; i < max; i++) {
            char c = text.charAt(i);
            int foldedByte = mode == FoldMode.BIT_7 ? c & 0x7F : c & 0xFF;
            sb.append(escape(String.valueOf(c)))
                    .append(" U+").append(String.format("%04X", (int) c))
                    .append(" -> 0x").append(String.format("%02X", foldedByte))
                    .append(" -> ").append(escape(String.valueOf((char) foldedByte)))
                    .append('\n');
        }
        if (text != null && text.length() > max) {
            sb.append("... ").append(text.length() - max).append(" chars omitted\n");
        }
        return sb.toString();
    }

    public static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '\r') sb.append("\\r");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\t') sb.append("\\t");
            else sb.append(c);
        }
        return sb.toString();
    }

    public static boolean containsNonAscii(String s) {
        if (s == null) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0x7F) {
                return true;
            }
        }
        return false;
    }
}

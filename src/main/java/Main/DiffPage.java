package Main;


/**
 * 响应相似度计算（基于 @pmiaowu HostCollision）
 */
public class DiffPage {
    private static final int MAX_COMPARE_LEN = 8000;

    /**
     * 返回经过过滤无用的数据以后两个字符串的相似度
     *
     * @param str
     * @param target
     * @return
     */
    public static double getRatio(String str, String target) {
        return getRatio(str, target, null);
    }

    public static double getRatio(String str, String target, String contentType) {
        str = normalizeForCompare(str, contentType);
        target = normalizeForCompare(target, contentType);
        return similarity(str, target);
    }

    /**
     * 返回经过过滤的页面内容，不包含脚本、样式和/或注释
     * 或所有HTML标签
     * 调用 getFilteredPageContent("<html><title>foobar</title></style><body>test</body></html>")
     * 返回内容: foobartest
     *
     * @param htmlStr
     * @return String
     */
    public static String getFilteredPageContent(String htmlStr) {
        if (htmlStr == null) return "";
        // 将实体字符串转义返回 如: "&lt;"="<", "&gt;"=">", "&quot;"="\"", "&nbsp;"=" ", "&amp;"="&"
        htmlStr = htmlStr.replace("&lt;", "<");
        htmlStr = htmlStr.replace("&gt;", ">");
        htmlStr = htmlStr.replace("&quot;", "\"");
        htmlStr = htmlStr.replace("&nbsp;", " ");
        htmlStr = htmlStr.replace("&amp;", "&");

        //定义script的正则表达式，去除js可以防止注入
        String scriptRegex = "<script[^>]*?>[\\s\\S]*?<\\/script>";
        //定义style的正则表达式，去除style样式，防止css代码过多时只截取到css样式代码
        String styleRegex = "<style[^>]*?>[\\s\\S]*?<\\/style>";
        //定义HTML标签的正则表达式，去除标签，只提取文字内容
        String htmlRegex = "<[^>]+>";
        // 定义一些特殊字符的正则表达式 如：&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        String specialRegex1 = "\\&[a-zA-Z]{1,10};";
        // 定义一些特殊字符的正则表达式 如：&#xe625;
        String specialRegex2 = "\\&#[a-zA-Z0-9]{1,10};";
        //定义空格,回车,换行符,制表符
        String spaceRegex = "\\s+";

        // 过滤script标签
        htmlStr = htmlStr.replaceAll(scriptRegex, "");
        // 过滤style标签
        htmlStr = htmlStr.replaceAll(styleRegex, "");
        // 过滤html标签
        htmlStr = htmlStr.replaceAll(htmlRegex, "");
        // 去除特殊字符
        htmlStr = htmlStr.replaceAll(specialRegex1, "");
        htmlStr = htmlStr.replaceAll(specialRegex2, "");
        // 过滤空格等
        htmlStr = htmlStr.replaceAll(spaceRegex, "");

        return sampleForCompare(htmlStr.trim());
    }

    private static String normalizeForCompare(String body, String contentType) {
        if (body == null) {
            return "";
        }

        String ct = contentType == null ? "" : contentType.toLowerCase();
        String s = body;

        if (looksLikeJson(ct, s)) {
            s = normalizeJsonText(s);
        } else if (looksLikeHtml(ct, s)) {
            s = normalizeHtmlStructure(s);
        } else {
            s = normalizePlainText(s);
        }

        s = normalizeDynamicTokens(s);
        return sampleForCompare(s);
    }

    private static String sampleForCompare(String s) {
        if (s.length() <= MAX_COMPARE_LEN) {
            return s;
        }
        // 取分布在全文中的四段，保留局部结构并限制比较成本。
        int chunk = MAX_COMPARE_LEN / 4;
        StringBuilder sample = new StringBuilder(MAX_COMPARE_LEN);
        for (int i = 0; i < 4; i++) {
            int start = (int)((long)(s.length() - chunk) * i / 3);
            sample.append(s, start, start + chunk);
        }
        return sample.toString();
    }

    private static boolean looksLikeJson(String contentType, String body) {
        if (contentType.contains("json")) {
            return true;
        }
        String t = body.trim();
        return t.startsWith("{") || t.startsWith("[");
    }

    private static boolean looksLikeHtml(String contentType, String body) {
        if (contentType.contains("html")) {
            return true;
        }
        String t = body.trim().toLowerCase();
        return t.startsWith("<!doctype") || t.startsWith("<html") || t.contains("<body") || t.contains("<head");
    }

    private static String normalizeHtmlStructure(String htmlStr) {
        if (htmlStr == null) {
            return "";
        }

        // 先做基础过滤（脚本/样式/注释），保留标签结构（不移除所有标签）
        String s = htmlStr;
        s = s.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&nbsp;", " ")
                .replace("&amp;", "&");

        s = s.replaceAll("(?is)<!--.*?-->", "");
        s = s.replaceAll("(?is)<script[^>]*?>[\\s\\S]*?<\\/script>", "");
        s = s.replaceAll("(?is)<style[^>]*?>[\\s\\S]*?<\\/style>", "");

        // 抹平属性：<div class="a" id=1> -> <div>
        s = s.replaceAll("(?is)<\\s*([a-z0-9]+)(?:\\s[^>]*)?>", "<$1>");
        s = s.replaceAll("(?is)<\\s*/\\s*([a-z0-9]+)\\s*>", "</$1>");

        // 去特殊实体与空白
        s = s.replaceAll("\\&[a-zA-Z]{1,10};", "");
        s = s.replaceAll("\\&#[a-zA-Z0-9]{1,10};", "");
        s = s.replaceAll("\\s+", "");
        return s.trim();
    }

    private static String normalizeJsonText(String json) {
        if (json == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(json.length());
        boolean inString = false, escaped = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                out.append(c);
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') inString = false;
            } else if (c == '"') {
                inString = true;
                out.append(c);
            } else if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String normalizePlainText(String text) {
        if (text == null) {
            return "";
        }
        String s = text;
        s = s.replaceAll("\\s+", "");
        return s.trim();
    }

    private static String normalizeDynamicTokens(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }

        String r = s;
        // UUID
        r = r.replaceAll("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{UUID}");
        // 13位/10位时间戳等长数字（避免把短数字如分页 size=10 误杀）
        r = r.replaceAll("\\b\\d{10,19}\\b", "{NUM}");
        // 长 hex
        r = r.replaceAll("(?i)\\b[0-9a-f]{16,}\\b", "{HEX}");
        // base64-like 长串
        r = r.replaceAll("\\b[A-Za-z0-9+/=_-]{24,}\\b", "{TOKEN}");
        return r;
    }

    private static double similarity(String a, String b) {
        if (a.equals(b)) {
            return 1;
        }
        if (a.isEmpty() || b.isEmpty()) {
            return 0;
        }

        int maxLen = Math.max(a.length(), b.length());
        if (maxLen > 2000) {
            return jaccardNGram(a, b, 5);
        }
        return getSimilarityRatio(a, b);
    }

    private static double jaccardNGram(String a, String b, int n) {
        if (a.length() < n || b.length() < n) {
            return a.equals(b) ? 1 : 0;
        }
        java.util.HashSet<Integer> sa = new java.util.HashSet<>();
        java.util.HashSet<Integer> sb = new java.util.HashSet<>();
        int limitA = a.length() - n + 1;
        int limitB = b.length() - n + 1;
        for (int i = 0; i < limitA; i++) {
            sa.add(a.substring(i, i + n).hashCode());
        }
        for (int i = 0; i < limitB; i++) {
            sb.add(b.substring(i, i + n).hashCode());
        }
        if (sa.isEmpty() && sb.isEmpty()) {
            return 1;
        }
        int inter = 0;
        for (Integer x : sa) {
            if (sb.contains(x)) {
                inter++;
            }
        }
        int union = sa.size() + sb.size() - inter;
        return union == 0 ? 1 : (double) inter / union;
    }

    /**
     * 两个字符串相似度匹配
     *
     * @param str
     * @param target
     * @return double
     */
    public static double getSimilarityRatio(String str, String target) {
        if (str.equals(target)) {
            return 1;
        }

        int d[][]; // 矩阵
        int n = str.length();
        int m = target.length();
        int i; // 遍历str的
        int j; // 遍历target的
        char ch1; // str的
        char ch2; // target的
        int temp; // 记录相同字符,在某个矩阵位置值的增量,不是0就是1
        if (n == 0 || m == 0) {
            return 0;
        }
        d = new int[n + 1][m + 1];
        for (i = 0; i <= n; i++) { // 初始化第一列
            d[i][0] = i;
        }

        for (j = 0; j <= m; j++) { // 初始化第一行
            d[0][j] = j;
        }

        for (i = 1; i <= n; i++) { // 遍历str
            ch1 = str.charAt(i - 1);
            // 去匹配target
            for (j = 1; j <= m; j++) {
                ch2 = target.charAt(j - 1);
                if (ch1 == ch2 || ch1 == ch2 + 32 || ch1 + 32 == ch2) {
                    temp = 0;
                } else {
                    temp = 1;
                }
                // 左边+1,上边+1, 左上角+temp取最小
                d[i][j] = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + temp);
            }
        }

        return (1 - (double) d[n][m] / Math.max(str.length(), target.length()));
    }
}

package Main;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConfigLoader {
    private static final String CONFIG_DIR_NAME = ".config/BypassPro";
    private static final String CONFIG_FILE_NAME = "BypassPro-config.yaml";
    private static final String CLASSPATH_RESOURCE = "BypassPro-config.yaml";

    private final Yaml yaml;
    private String lastError;

    public String getLastError() { return lastError; }
    private final String configDirPath;
    private final String configFilePath;

    public ConfigLoader() {
        this(determineConfigDirPath());
    }

    ConfigLoader(String configDirPath) {
        this.yaml = createSecureYaml();
        this.configDirPath = configDirPath;
        this.configFilePath = this.configDirPath + File.separator + CONFIG_FILE_NAME;

        File dir = new File(this.configDirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            dir.mkdirs();
        }

        File cfg = new File(this.configFilePath);
        if (!cfg.exists() || !cfg.isFile()) {
            initConfig();
        }
    }

    public String getConfigFilePath() {
        return configFilePath;
    }

    public synchronized Map<String, Object> loadConfig() {
        lastError = null;
        Path p = Paths.get(configFilePath);
        if (!Files.exists(p)) {
            lastError = "Configuration file does not exist";
            return Collections.emptyMap();
        }

        try (InputStream in = Files.newInputStream(p)) {
            Map<String, Object> m = yaml.load(in);
            if (m == null || m.isEmpty()) throw new IllegalArgumentException("Configuration is empty");
            return m;
        } catch (Exception e) {
            lastError = e.getMessage();
            return Collections.emptyMap();
        }
    }

    public boolean initConfig() {
        return copyDefaultConfigToFile(this.configFilePath);
    }

    public String readConfigText() {
        Path p = Paths.get(configFilePath);
        if (!Files.exists(p)) {
            return "";
        }
        try {
            byte[] bytes = Files.readAllBytes(p);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 保存 general 配置
     */
    public boolean saveGeneralConfig(int threads, double similarityThreshold) {
        return saveGeneralConfig(threads, readExistingMaxRedirects(), similarityThreshold, null);
    }

    /**
     * 保存 general 配置（含语言）。lang 为 null 时不修改语言字段。
     */
    public boolean saveGeneralConfig(int threads, double similarityThreshold, String lang) {
        return saveGeneralConfig(threads, readExistingMaxRedirects(), similarityThreshold, lang);
    }

    /**
     * 保存 general 配置（含 Follow Redirect 最大跳转次数）。
     */
    public synchronized boolean saveGeneralConfig(int threads, int maxRedirects, double similarityThreshold, String lang) {
        lastError = null;
        try {
            if (threads < 1 || threads > 100 || maxRedirects < 1 || maxRedirects > 10
                    || !Double.isFinite(similarityThreshold) || similarityThreshold < 0 || similarityThreshold > 1) {
                lastError = "Invalid threads, redirect limit or similarity threshold";
                return false;
            }
            String raw = readConfigText();
            if (raw == null || raw.trim().isEmpty()) {
                lastError = "Configuration is empty or unreadable; restore it or use Init before saving";
                return false;
            }
            String patched = patchGeneralSection(raw, threads, maxRedirects, similarityThreshold, lang);
            Map<String, Object> expected = new LinkedHashMap<>();
            expected.put("threads", threads);
            expected.put("max_redirects", maxRedirects);
            expected.put("similarity_threshold", similarityThreshold);
            if (lang != null && !lang.isEmpty()) expected.put("lang", lang);
            if (!containsValues(safeMap(yaml.load(patched)).get("general"), expected)) {
                lastError = "Saved settings did not match submitted values; original file was retained";
                return false;
            }
            return writeConfigText(patched);
        } catch (Exception e) {
            lastError = e.getMessage();
            return false;
        }
    }

    /**
     * 保存 WAF Options 到配置文件
     * @param options WAF 的 options Map
     * @return 是否保存成功
     */
    @SuppressWarnings("unchecked")
    public synchronized boolean saveWafOptions(Map<String, Object> options) {
        lastError = null;
        try {
            String raw = readConfigText();
            if (raw == null || raw.trim().isEmpty()) {
                lastError = "Configuration is empty or unreadable; restore it or use Init before saving";
                return false;
            }
            String patched = patchWafOptionsSection(raw, options);
            Map<String, Object> saved = patched == null ? Collections.emptyMap() : safeMap(yaml.load(patched));
            Object savedOptions = safeMap(safeMap(saved.get("profiles")).get(Utils.PROFILE_AUTO_WAF_BYPASS)).get("options");
            if (patched == null || !containsValues(savedOptions, options)) {
                lastError = "Saved options did not match the submitted values; original file was retained";
                return false;
            }
            return writeConfigText(patched);
        } catch (Exception e) {
            lastError = e.getMessage();
            return false;
        }
    }

    private boolean writeConfigText(String text) {
        try {
            Path p = Paths.get(configFilePath);
            if (!(yaml.load(text) instanceof Map)) {
                lastError = "Configuration must be a YAML mapping";
                return false;
            }
            Path temp = Files.createTempFile(p.getParent(), "BypassPro-", ".yaml.tmp");
            try {
                Files.write(temp, text.getBytes(StandardCharsets.UTF_8));
                try {
                    Files.move(temp, p, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                            java.nio.file.StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                    Files.move(temp, p, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temp);
            }
            return true;
        } catch (Exception e) {
            lastError = e.getMessage();
            return false;
        }
    }

    private String patchGeneralSection(String raw, int threads, int maxRedirects, double similarityThreshold, String lang) {
        ArrayList<String> lines = new ArrayList<>();
        Collections.addAll(lines, raw.split("\\r?\\n", -1));

        int generalIdx = findTopLevelKey(lines, "general");
        if (generalIdx < 0) {
            StringBuilder sb = new StringBuilder(raw.length() + 128);
            sb.append("general:\n");
            sb.append("  threads: ").append(threads).append("\n");
            sb.append("  max_redirects: ").append(maxRedirects).append("\n");
            sb.append("  similarity_threshold: ").append(similarityThreshold).append("\n");
            if (lang != null && !lang.isEmpty()) {
                sb.append("  lang: ").append(lang).append("\n");
            }
            sb.append("\n");
            sb.append(raw);
            return sb.toString();
        }

        int end = findTopLevelSectionEnd(lines, generalIdx);
        patchScalarInSection(lines, generalIdx + 1, end, 2, "threads", String.valueOf(threads));
        end = findTopLevelSectionEnd(lines, generalIdx);
        patchScalarAfterKeyInSection(lines, generalIdx + 1, end, 2,
                "max_redirects", String.valueOf(maxRedirects), "threads");
        end = findTopLevelSectionEnd(lines, generalIdx);
        patchScalarInSection(lines, generalIdx + 1, end, 2, "similarity_threshold", String.valueOf(similarityThreshold));
        if (lang != null && !lang.isEmpty()) {
            end = findTopLevelSectionEnd(lines, generalIdx);
            patchScalarInSection(lines, generalIdx + 1, end, 2, "lang", lang);
        }
        return String.join("\n", lines);
    }

    @SuppressWarnings("unchecked")
    private int readExistingMaxRedirects() {
        try {
            Map<String, Object> config = loadConfig();
            Object generalObj = config.get("general");
            if (generalObj instanceof Map) {
                Object maxObj = ((Map<String, Object>) generalObj).get("max_redirects");
                if (maxObj instanceof Number) {
                    int value = ((Number) maxObj).intValue();
                    if (value >= 1 && value <= 10) {
                        return value;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return 3;
    }

    private String patchWafOptionsSection(String raw, Map<String, Object> options) {
        if (options == null || options.isEmpty()) {
            return raw;
        }
        ArrayList<String> lines = new ArrayList<>();
        Collections.addAll(lines, raw.split("\\r?\\n", -1));

        int profilesIdx = findTopLevelKey(lines, "profiles");
        if (profilesIdx < 0) {
            return null;
        }
        int profilesEnd = findTopLevelSectionEnd(lines, profilesIdx);
        int wafIdx = findChildKey(lines, profilesIdx + 1, profilesEnd, 2, Utils.PROFILE_AUTO_WAF_BYPASS);
        if (wafIdx < 0) {
            return null;
        }
        int wafEnd = findSectionEndByIndent(lines, wafIdx, 2);
        int optionsIdx = findChildKey(lines, wafIdx + 1, wafEnd, 4, "options");
        if (optionsIdx < 0) {
            return null;
        }
        patchOptionMap(lines, optionsIdx, 4, options);
        return String.join("\n", lines);
    }

    // Recompute the section boundary after every insertion. Keep user comments and unrelated rules.
    private void patchOptionMap(ArrayList<String> lines, int parent, int indent, Map<String, Object> values) {
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            String key = entry.getKey();
            if (key == null || !key.matches("[A-Za-z0-9_]+"))
                throw new IllegalArgumentException("Invalid option key");
            int end = findSectionEndByIndent(lines, parent, indent);
            Object value = entry.getValue();
            if (value instanceof Map) {
                int child = findChildKey(lines, parent + 1, end, indent + 2, key);
                if (child < 0) {
                    child = end;
                    lines.add(child, repeatSpace(indent + 2) + key + ":");
                }
                patchOptionMap(lines, child, indent + 2, safeMap(value));
            } else if (value instanceof Boolean || value instanceof Number) {
                patchScalarInSection(lines, parent + 1, end, indent + 2, key, value.toString());
            } else {
                throw new IllegalArgumentException("Unsupported option value: " + key);
            }
        }
    }

    private boolean containsValues(Object actual, Map<String, Object> expected) {
        if (!(actual instanceof Map) || expected == null) return false;
        Map<?, ?> map = (Map<?, ?>) actual;
        for (Map.Entry<String, Object> entry : expected.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                if (!containsValues(map.get(entry.getKey()), safeMap(value))) return false;
            } else if (!java.util.Objects.equals(value, map.get(entry.getKey()))) return false;
        }
        return true;
    }

    private Map<String, Object> safeMap(Object o) {
        if (o instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) o;
            return m;
        }
        return Collections.emptyMap();
    }

    private static int findTopLevelKey(ArrayList<String> lines, String key) {
        String prefix = key + ":";
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }

    private static int findChildKey(ArrayList<String> lines, int start, int end, int indent, String key) {
        String prefix = repeatSpace(indent) + key + ":";
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }

    private static int findTopLevelSectionEnd(ArrayList<String> lines, int startIdx) {
        for (int i = startIdx + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.isEmpty() || line.startsWith("#")) continue;
            // 顶层 key：非空白开头且包含 ":"
            if (!Character.isWhitespace(line.charAt(0)) && line.contains(":")) {
                return i;
            }
        }
        return lines.size();
    }

    private static int findSectionEndByIndent(ArrayList<String> lines, int startIdx, int indent) {
        for (int i = startIdx + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            if (line.trim().isEmpty() || line.trim().startsWith("#")) continue;
            int leading = countLeadingSpaces(line);
            if (leading <= indent && !line.startsWith("#")) {
                return i;
            }
        }
        return lines.size();
    }

    private static void patchScalarInSection(ArrayList<String> lines, int start, int end, int indent, String key, String value) {
        // 将注释前的空白保留在 tail 中，避免数值/布尔值与 # 连成字符串。
        Pattern p = Pattern.compile("^" + Pattern.quote(repeatSpace(indent) + key) + "\\s*:\\s*([^#]*?)([ \\t]*(?:#.*)?)$");
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            Matcher m = p.matcher(line);
            if (m.find()) {
                String tail = m.group(2) == null ? "" : m.group(2);
                if (tail.startsWith("#")) tail = " " + tail;
                lines.set(i, repeatSpace(indent) + key + ": " + value + tail);
                return;
            }
        }
        // 未找到：插入到 section 末尾前
        int insertAt = Math.min(end, lines.size());
        lines.add(insertAt, repeatSpace(indent) + key + ": " + value);
    }

    private static void patchScalarAfterKeyInSection(ArrayList<String> lines, int start, int end, int indent,
                                                     String key, String value, String afterKey) {
        Pattern target = Pattern.compile("^" + Pattern.quote(repeatSpace(indent) + key) + "\\s*:\\s*([^#]*?)([ \\t]*(?:#.*)?)$");
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line == null) continue;
            Matcher m = target.matcher(line);
            if (m.find()) {
                String tail = m.group(2) == null ? "" : m.group(2);
                if (tail.startsWith("#")) tail = " " + tail;
                lines.set(i, repeatSpace(indent) + key + ": " + value + tail);
                return;
            }
        }

        Pattern anchor = Pattern.compile("^" + Pattern.quote(repeatSpace(indent) + afterKey) + "\\s*:");
        for (int i = start; i < end && i < lines.size(); i++) {
            String line = lines.get(i);
            if (line != null && anchor.matcher(line).find()) {
                lines.add(i + 1, repeatSpace(indent) + key + ": " + value);
                return;
            }
        }
        int insertAt = Math.min(end, lines.size());
        lines.add(insertAt, repeatSpace(indent) + key + ": " + value);
    }

    private static int countLeadingSpaces(String s) {
        int c = 0;
        while (c < s.length() && s.charAt(c) == ' ') c++;
        return c;
    }

    private static String repeatSpace(int n) {
        if (n <= 0) return "";
        char[] buf = new char[n];
        for (int i = 0; i < n; i++) buf[i] = ' ';
        return new String(buf);
    }

    private Yaml createSecureYaml() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setProcessComments(false);
        loaderOptions.setAllowRecursiveKeys(false);

        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

        Representer representer = new Representer(dop);
        return new Yaml(new SafeConstructor(loaderOptions), representer, dop);
    }

    private static String determineConfigDirPath() {
        String userConfigPath = System.getProperty("user.home") + File.separator + CONFIG_DIR_NAME;
        if (isValidConfigDir(userConfigPath)) {
            return userConfigPath;
        }

        String jarConfigPath = getJarConfigPath();
        if (jarConfigPath != null && isValidConfigDir(jarConfigPath)) {
            return jarConfigPath;
        }

        return userConfigPath;
    }

    private static boolean isValidConfigDir(String path) {
        File f = new File(path);
        return f.exists() && f.isDirectory();
    }

    private static String getJarConfigPath() {
        try {
            URL location = Utils.class.getProtectionDomain().getCodeSource().getLocation();
            if (location == null) {
                return null;
            }
            URI uri = location.toURI();
            File base = new File(uri);
            File dir = base.isDirectory() ? base : base.getParentFile();
            if (dir == null) {
                return null;
            }
            return dir.getAbsolutePath() + File.separator + CONFIG_DIR_NAME;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean copyDefaultConfigToFile(String targetFilePath) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(CLASSPATH_RESOURCE);
        if (inputStream == null) {
            return false;
        }
        File targetFile = new File(targetFilePath);

        try (InputStream in = inputStream; OutputStream out = new FileOutputStream(targetFile)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

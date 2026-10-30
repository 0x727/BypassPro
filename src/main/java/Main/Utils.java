package Main;

import Main.ghostbits.GhostBitsEngine;
import Main.ghostbits.GhostBitsRule;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class Utils {
    public static final String PROFILE_AUTO_ACCESS_BYPASS = "auto_access_bypass";
    public static final String PROFILE_AUTO_WAF_BYPASS = "auto_waf_bypass";
    public static final String PROFILE_MANUAL_WAF_BYPASS = "manual_waf_bypass";

    static boolean gotBurp = false;
    public static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    @SuppressWarnings("unused")
    private static PrintWriter stderr;
    static MainPanel panel;
    public static long count = 0;
    // Auto Scan 开关
    public static volatile boolean isProxySelected = false;
    public static Map<String, Object> configMap = null;
    private static ConfigLoader configLoader;
    private static volatile ThreadPoolExecutor sharedExecutor;
    private static ThreadPoolExecutor scanDispatcher;
    private static volatile int sharedExecutorThreads = -1;

    public static void setConfigLoader(ConfigLoader loader) {
        configLoader = loader;
    }

    public static ConfigLoader getConfigLoader() {
        return configLoader;
    }

    public static void setConfigMap(Map<String, Object> config) {

        if (config == null) {
            Utils.configMap = Collections.emptyMap();
            System.out.println("!! config为null,已清空当前规则");
            return;
        }
        Utils.configMap = config;
        if (config.isEmpty()) {
            System.out.println("!! config内容为空,已清空当前规则");
        }

    }

    /**
     * 当前版配置只支持 profiles.auto_access_bypass / profiles.auto_waf_bypass / profiles.manual_waf_bypass。
     */
    public static Map<String, Object> getProfileConfig(String profile) {
        if (configMap == null) {
            return Collections.emptyMap();
        }

        Object profilesObj = configMap.get("profiles");
        if (profilesObj instanceof Map) {
            Map<?, ?> profiles = (Map<?, ?>) profilesObj;
            Object p = profiles.get(profile);
            if (p instanceof Map) {
                return castStringObjectMap(p);
            }
        }

        return Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castStringObjectMap(Object o) {
        return (Map<String, Object>) o;
    }

    /**
     * 获取指定 profile 的 options
     * @param profile profile 名称
     * @return options Map，如果不存在返回 emptyMap
     */
    public static Map<String, Object> getProfileOptions(String profile) {
        Map<String, Object> profileConfig = getProfileConfig(profile);
        if (profileConfig == null || profileConfig.isEmpty()) {
            return Collections.emptyMap();
        }

        Object optionsObj = profileConfig.get("options");
        if (optionsObj instanceof Map) {
            return castStringObjectMap(optionsObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 WAF options 中的 body_charset 配置
     * @return body_charset Map，包含各种字符集的 true/false
     */
    public static Map<String, Object> getWafBodyCharsetOptions() {
        Map<String, Object> options = getProfileOptions(PROFILE_AUTO_WAF_BYPASS);
        Object charsetObj = options.get("body_charset");
        if (charsetObj instanceof Map) {
            return castStringObjectMap(charsetObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 WAF options 中的 body_transform 配置
     * @return body_transform Map
     */
    public static Map<String, Object> getWafBodyTransformOptions() {
        Map<String, Object> options = getProfileOptions(PROFILE_AUTO_WAF_BYPASS);
        Object transformObj = options.get("body_transform");
        if (transformObj instanceof Map) {
            return castStringObjectMap(transformObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 Ghost Bits 规则。
     * Ghost Bits 缺失时应返回空规则，由调用方决定是否提示用户。
     */
    public static GhostBitsRule getGhostBitsRule() {
        return GhostBitsRule.fromMap(getGhostBitsRuleMap());
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getGhostBitsRuleMap() {
        if (configMap == null) {
            return Collections.emptyMap();
        }
        Object profilesObj = configMap.get("profiles");
        if (profilesObj instanceof Map) {
            Map<String, Object> profiles = (Map<String, Object>) profilesObj;
            Object manualObj = profiles.get(PROFILE_MANUAL_WAF_BYPASS);
            if (manualObj instanceof Map) {
                Object gb = ((Map<String, Object>) manualObj).get("ghost_bits");
                if (gb instanceof Map) {
                    return castStringObjectMap(gb);
                }
            }
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 Ghost Bits 引擎（每次都重新构造，规则量很小不在乎开销，方便配置热更新）。
     */
    public static GhostBitsEngine getGhostBitsEngine() {
        return new GhostBitsEngine(getGhostBitsRule());
    }

    /**
     * 获取 WAF options 中的 content_type_spoof 配置
     * @return content_type_spoof Map
     */
    public static Map<String, Object> getWafContentTypeSpoofOptions() {
        Map<String, Object> options = getProfileOptions(PROFILE_AUTO_WAF_BYPASS);
        Object ctObj = options.get("content_type_spoof");
        if (ctObj instanceof Map) {
            return castStringObjectMap(ctObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 WAF options 中的 ghost_bits 配置。
     */
    public static Map<String, Object> getWafGhostBitsOptions() {
        Map<String, Object> options = getProfileOptions(PROFILE_AUTO_WAF_BYPASS);
        Object ghostObj = options.get("ghost_bits");
        if (ghostObj instanceof Map) {
            return castStringObjectMap(ghostObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取 general 配置
     */
    public static Map<String, Object> getGeneralConfig() {
        if (configMap == null) {
            return Collections.emptyMap();
        }
        Object generalObj = configMap.get("general");
        if (generalObj instanceof Map) {
            return castStringObjectMap(generalObj);
        }
        return Collections.emptyMap();
    }

    /**
     * 获取配置的线程数
     */
    public static int getConfigThreads(int defaultValue) {
        Map<String, Object> general = getGeneralConfig();
        Object threadsObj = general.get("threads");
        if (threadsObj instanceof Number) {
            return ((Number) threadsObj).intValue();
        }
        return defaultValue;
    }

    /**
     * 获取 Follow Redirect 最大跳转次数
     */
    public static int getConfigMaxRedirects(int defaultValue) {
        Map<String, Object> general = getGeneralConfig();
        Object maxRedirectsObj = general.get("max_redirects");
        if (maxRedirectsObj instanceof Number) {
            int value = ((Number) maxRedirectsObj).intValue();
            if (value >= 1 && value <= 10) {
                return value;
            }
        }
        return defaultValue;
    }

    /**
     * 获取配置的相似度阈值
     */
    public static double getConfigSimilarityThreshold(double defaultValue) {
        Map<String, Object> general = getGeneralConfig();
        Object thresholdObj = general.get("similarity_threshold");
        if (thresholdObj instanceof Number) {
            return ((Number) thresholdObj).doubleValue();
        }
        return defaultValue;
    }

    /**
     * 获取配置的界面语言。zh/en，缺省 zh。
     */
    public static String getConfigLang() {
        Map<String, Object> general = getGeneralConfig();
        Object langObj = general.get("lang");
        if (langObj == null) {
            return I18n.ZH;
        }
        String s = langObj.toString().trim().toLowerCase();
        return I18n.EN.equals(s) ? I18n.EN : I18n.ZH;
    }

    /**
     * 获取 Auto-权限绕过的 ignore_extensions 列表
     */
    @SuppressWarnings("unchecked")
    public static List<String> getIgnoreExtensions() {
        Map<String, Object> ac = getProfileConfig(PROFILE_AUTO_ACCESS_BYPASS);
        Object extObj = ac.get("ignore_extensions");
        if (extObj instanceof List) {
            return (List<String>) extObj;
        }
        return Collections.emptyList();
    }

    public static void setBurpPresent(IBurpExtenderCallbacks incallbacks) {
        gotBurp = true;
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    public static void out(String message) {
        if (gotBurp) {
            stdout.println(message);
        }
        else {
            System.out.println(message);
        }

    }

    public static void setPanel(MainPanel inpanel) {
        panel = inpanel;
    }

    /**
     * 全局共享线程池（避免每次扫描创建大量线程池导致资源耗尽）
     */
    public static synchronized ExecutorService getSharedExecutor(int threads) {
        int n = Math.max(1, Math.min(100, threads));
        if (sharedExecutor == null || sharedExecutor.isShutdown()) {
            sharedExecutor = new ThreadPoolExecutor(n, n, 0L, TimeUnit.MILLISECONDS,
                    new LinkedBlockingQueue<>(100), daemonFactory("BypassPro-Worker-"),
                    new ThreadPoolExecutor.AbortPolicy());
            sharedExecutorThreads = n;
        } else if (sharedExecutorThreads != n && sharedExecutor.getActiveCount() == 0 && sharedExecutor.getQueue().isEmpty()) {
            // A changed limit applies after current work drains; never create overlapping pools.
            if (n > sharedExecutorThreads) {
                sharedExecutor.setMaximumPoolSize(n);
                sharedExecutor.setCorePoolSize(n);
            } else {
                sharedExecutor.setCorePoolSize(n);
                sharedExecutor.setMaximumPoolSize(n);
            }
            sharedExecutorThreads = n;
        }
        return sharedExecutor;
    }

    private static ThreadFactory daemonFactory(String prefix) {
        AtomicInteger sequence = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + sequence.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    static synchronized boolean dispatchScan(Runnable action) {
        if (scanDispatcher == null || scanDispatcher.isShutdown())
            scanDispatcher = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                    new LinkedBlockingQueue<>(100), daemonFactory("BypassPro-Prepare-"));
        try { scanDispatcher.execute(action); return true; }
        catch (java.util.concurrent.RejectedExecutionException e) { return false; }
    }

    static void submitScan(ExecutorService executor, ScanSession session, Runnable action) {
        if (session.cancelled) return;
        Runnable guarded = () -> {
            if (session.cancelled) return;
            session.started();
            if (panel != null) panel.refreshScan(session);
            try { action.run(); }
            finally {
                session.ended();
                if (panel != null) panel.refreshScan(session);
            }
        };
        // Backpressure is confined to the single preparation thread, never a Burp/EDT sender.
        while (!session.cancelled && !executor.isShutdown()) {
            try { executor.execute(guarded); return; }
            catch (java.util.concurrent.RejectedExecutionException e) {
                try { TimeUnit.MILLISECONDS.sleep(25); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); return; }
            }
        }
    }

    static synchronized void discardPendingScans() {
        if (scanDispatcher != null) scanDispatcher.getQueue().clear();
        if (sharedExecutor != null) sharedExecutor.getQueue().clear();
    }

    public static synchronized void shutdownSharedExecutor() {
        isProxySelected = false;
        if (scanDispatcher != null) scanDispatcher.shutdownNow();
        if (sharedExecutor != null) sharedExecutor.shutdownNow();
        scanDispatcher = null;
        sharedExecutor = null;
        sharedExecutorThreads = -1;
    }

    public static String getBodyTitle(String s) {
        String regex;
        String title = "";
        final List<String> list = new ArrayList<String>();
        regex = "<title>.*?</title>";
        final Pattern pa = Pattern.compile(regex, Pattern.CANON_EQ);
        final Matcher ma = pa.matcher(s);
        while (ma.find()) {
            list.add(ma.group());
        }

        for (int i = 0; i < list.size(); i++) {
            title = title + list.get(i);
        }

        return title.replaceAll("<.*?>", "");
    }
    public static Map<String, Object> loadConfig(String filename){
        if (configLoader != null) {
            return configLoader.loadConfig();
        }
        Map<String, Object> yamlMap=null;
        // 读取YAML文件
        try (InputStream inputStream = BypassMain.class.getResourceAsStream(filename)) {
            if (inputStream == null) {
                return Collections.emptyMap();
            }
            LoaderOptions loaderOptions = new LoaderOptions();
            loaderOptions.setAllowDuplicateKeys(false);
            Yaml yaml = new Yaml(new SafeConstructor(loaderOptions));
            // 将YAML文件的内容加载为Map对象
            yamlMap = yaml.load(inputStream);
        } catch (Exception exception) {
            System.out.println("配置文件加载失败，请检查配置文件 BypassPro-config.yaml");
            exception.printStackTrace();
        }
        return yamlMap;

    }


}

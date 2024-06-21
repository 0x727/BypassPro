package Main;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {

    static boolean gotBurp = false;
    public static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static MainPanel panel;
    public static long count = 0;
    //主动扫描 默认为faulse
    public static boolean isProxySelected = false;
    public static Map<String, Object> configMap = null;
    public static void setConfigMap(Map<String, Object> config) {

        if (config.isEmpty()){
            System.out.println("!! config内容为空,将保持原来的payload");
            return;
        }
        Utils.configMap = config;

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
        Map<String, Object> yamlMap=null;
        // 读取YAML文件
        try {
            InputStream inputStream = BypassMain.class.getResourceAsStream(filename);

            Yaml yaml = new Yaml();
            // 将YAML文件的内容加载为Map对象
            yamlMap = yaml.load(inputStream);
            inputStream.close();
        } catch (Exception exception) {
            System.out.println("配置文件加载失败，请检查配置文件 BypassPro-config.yaml");
            exception.printStackTrace();
        }
        return yamlMap;

    }


}

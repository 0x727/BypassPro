package burp;

import Main.*;
import java.io.PrintWriter;
import java.util.Map;
import javax.swing.ToolTipManager;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private PrintWriter stdout;
    public static IBurpExtenderCallbacks callbacks;
    private MainPanel panel;
    private String NAME = "BypassPro";
    private String VERSION = "5.2";

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        BurpExtender.callbacks = callbacks;
        Utils.setBurpPresent(callbacks);

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("BypassPro");

        // 加载配置
        ConfigLoader configLoader = new ConfigLoader();
        Utils.setConfigLoader(configLoader);
        Map<String, Object> config = configLoader.loadConfig();
        Utils.setConfigMap(config);

        // 初始化国际化
        I18n.setLang(Utils.getConfigLang());

        // tooltip 鼠标移开才消失（默认 4 秒太短，多行内容看不完）
        ToolTipManager tipManager = ToolTipManager.sharedInstance();
        tipManager.setDismissDelay(Integer.MAX_VALUE);
        tipManager.setInitialDelay(300);
        tipManager.setReshowDelay(100);

        this.panel = new MainPanel();
        Utils.setPanel(this.panel);
        callbacks.addSuiteTab(this.panel);

        BypassMain bypassMain = new BypassMain();

        callbacks.registerContextMenuFactory(bypassMain);
        callbacks.registerProxyListener(bypassMain);
        callbacks.registerExtensionStateListener(this);

        banner();

    }

    @Override
    public void extensionUnloaded() {
        // 释放全局线程池，避免 Burp 资源泄漏
        javax.swing.SwingUtilities.invokeLater(() -> { if (panel != null) panel.dispose(); });
        Utils.shutdownSharedExecutor();
    }

    private void banner() {
        this.stdout.println("===================================");
        this.stdout.println(String.format("%s loaded success", NAME));
        this.stdout.println(String.format("version: %s", VERSION));
        this.stdout.println("hooray195,  0cat");
        this.stdout.println("===================================");
    }

}

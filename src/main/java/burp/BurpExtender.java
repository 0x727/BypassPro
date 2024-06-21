package burp;

import Main.*;
import java.io.PrintWriter;
import java.util.Map;

public class BurpExtender implements IBurpExtender {
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    private MainPanel panel;
    private String NAME = "BypassPro";
    private String VERSION = "3.0";


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {


        this.callbacks = callbacks;
        Utils.setBurpPresent(callbacks);


        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("BypassPro");
        this.helpers = callbacks.getHelpers();


        this.panel = new MainPanel();
        Utils.setPanel(this.panel);
        callbacks.addSuiteTab(this.panel);

        BypassMain bypassMain = new BypassMain();

        callbacks.registerContextMenuFactory(bypassMain);
        callbacks.registerProxyListener(bypassMain);

        // 加载配置文件
        Map<String, Object> config = Utils.loadConfig("/BypassPro-config.yaml");
        Utils.setConfigMap(config);

        banner();

    }

    private void banner() {
        this.stdout.println("===================================");
        this.stdout.println(String.format("%s loaded success", NAME));
        this.stdout.println(String.format("version: %s", VERSION));
        this.stdout.println("0x727-hooray195,  0cat");
        this.stdout.println("===================================");
    }

}
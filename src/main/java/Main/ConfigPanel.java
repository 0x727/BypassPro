package Main;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;
import java.awt.*;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ConfigPanel extends JPanel {
    private final JTextField configPathText;
    private final JLabel formatLabel;
    private final JLabel saveStatus = new JLabel(" ");
    private final JTextArea accessControlTextArea;
    private final JTextArea wafRulesTextArea;
    private final JTextArea manualWafTextArea;
    private final JTextArea rawTextArea;
    private final Yaml yamlDumper;

    // General Options
    private final JTextField tfThreads;
    private final JTextField tfMaxRedirects;
    private final JTextField tfSimilarityThreshold;
    private final JComboBox<String> cbLang;

    // WAF Options 复选框
    private final JCheckBox cbUtf16;
    private final JCheckBox cbUtf16be;
    private final JCheckBox cbUtf16le;
    private final JCheckBox cbUtf32;
    private final JCheckBox cbUtf32be;
    private final JCheckBox cbUtf32le;
    private final JCheckBox cbIbm037;
    private final JCheckBox cbGzip;
    private final JCheckBox cbFormUrlencoded;
    private final JCheckBox cbMultipart;
    private final JCheckBox cbTextPlain;
    private final JCheckBox cbGhostEnabled;
    private final JCheckBox cbGhostRawSocket;
    private final JTextField tfGhostMaxVariants;
    private final JCheckBox cbGhostSpringStaticLfi;
    private final JCheckBox cbGhostJettyLooseHex;
    private final JCheckBox cbGhostTomcatJspUpload;
    private final JCheckBox cbGhostFullwidthTraversal;
    private final JCheckBox cbGhostFastjsonXEscape;
    private final JCheckBox cbGhostAngusSmtpCrlf;
    private final JCheckBox cbGhostFastjsonUnicodeDigit;
    private final JCheckBox cbGhostJacksonCharToHex;
    private final JCheckBox cbGhostBcelGhostBits;
    private final JCheckBox cbGhostJdkUrldecoderUnicodeDigit;
    private final JCheckBox cbGhostTomcatUrlHexGhost;
    private final JCheckBox cbGhostGenericEnabled;
    private final JCheckBox cbGhostGenericMinimal;
    private final JCheckBox cbGhostGenericFull;
    private final JCheckBox cbGhostGenericLetters;
    private final JCheckBox cbGhostGenericDigits;
    private final JCheckBox cbGhostGenericSymbols;
    private final JTextField tfGhostGenericVariantCount;

    public ConfigPanel() {
        setLayout(new BorderLayout());
        add(saveStatus, BorderLayout.SOUTH);
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top panel: config path + buttons
        JPanel top = new JPanel(new BorderLayout(8, 0));
        JLabel pathLabel = new JLabel(I18n.t("config.path_label"));
        configPathText = new JTextField();
        configPathText.setEditable(false);

        formatLabel = new JLabel("");

        JButton reloadButton = new JButton(I18n.t("config.btn.reload"));
        JButton reinitButton = new JButton(I18n.t("config.btn.reinit"));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(formatLabel);
        buttons.add(reinitButton);
        buttons.add(reloadButton);

        top.add(pathLabel, BorderLayout.WEST);
        top.add(configPathText, BorderLayout.CENTER);
        top.add(buttons, BorderLayout.EAST);

        this.yamlDumper = createYamlDumper();

        // General Options
        tfThreads = new JTextField(5);
        tfMaxRedirects = new JTextField(5);
        tfSimilarityThreshold = new JTextField(5);
        cbLang = new JComboBox<>(new String[]{I18n.ZH, I18n.EN});

        // Access Control Tab - 只有 Rules
        accessControlTextArea = createReadOnlyTextArea();
        JScrollPane acScrollPane = new JScrollPane(accessControlTextArea);
        acScrollPane.setBorder(BorderFactory.createTitledBorder(I18n.t("config.rules.access_control")));

        // WAF Tab - Rules + Options
        wafRulesTextArea = createReadOnlyTextArea();
        manualWafTextArea = createReadOnlyTextArea();

        // 创建 WAF Options 复选框
        cbUtf16 = new JCheckBox("UTF-16");
        cbUtf16be = new JCheckBox("UTF-16BE");
        cbUtf16le = new JCheckBox("UTF-16LE");
        cbUtf32 = new JCheckBox("UTF-32");
        cbUtf32be = new JCheckBox("UTF-32BE");
        cbUtf32le = new JCheckBox("UTF-32LE");
        cbIbm037 = new JCheckBox("IBM037");
        cbGzip = new JCheckBox("Gzip");
        cbFormUrlencoded = new JCheckBox("form-urlencoded");
        cbMultipart = new JCheckBox("multipart");
        cbTextPlain = new JCheckBox("text/plain");
        cbGhostEnabled = new JCheckBox(I18n.t("config.waf.ghost_enabled"));
        cbGhostRawSocket = new JCheckBox(I18n.t("config.waf.ghost_raw_socket"));
        tfGhostMaxVariants = new JTextField(4);
        cbGhostSpringStaticLfi = new JCheckBox("spring_static_lfi");
        cbGhostJettyLooseHex = new JCheckBox("jetty_loose_hex");
        cbGhostTomcatJspUpload = new JCheckBox("tomcat_jsp_upload");
        cbGhostFullwidthTraversal = new JCheckBox("fullwidth_traversal");
        cbGhostFastjsonXEscape = new JCheckBox("fastjson_x_escape");
        cbGhostAngusSmtpCrlf = new JCheckBox("angus_smtp_crlf");
        cbGhostFastjsonUnicodeDigit = new JCheckBox("fastjson_unicode_digit");
        cbGhostJacksonCharToHex = new JCheckBox("jackson_char_to_hex");
        cbGhostBcelGhostBits = new JCheckBox("bcel_ghost_bits");
        cbGhostJdkUrldecoderUnicodeDigit = new JCheckBox("jdk_urldecoder_unicode_digit");
        cbGhostTomcatUrlHexGhost = new JCheckBox("tomcat_url_hex_ghost");
        cbGhostGenericEnabled = new JCheckBox(I18n.t("config.waf.ghost_generic_enabled"));
        cbGhostGenericMinimal = new JCheckBox("minimal");
        cbGhostGenericFull = new JCheckBox("full");
        cbGhostGenericLetters = new JCheckBox("letters");
        cbGhostGenericDigits = new JCheckBox("digits");
        cbGhostGenericSymbols = new JCheckBox("symbols");
        tfGhostGenericVariantCount = new JTextField(4);

        JPanel generalPanel = createGeneralPanel();
        JPanel wafPanel = createWafPanel();
        JScrollPane manualWafScrollPane = new JScrollPane(manualWafTextArea);
        manualWafScrollPane.setBorder(BorderFactory.createTitledBorder(
                I18n.t("config.rules.manual_waf") + I18n.t("config.read_only_hint")));

        // Raw Tab
        rawTextArea = createReadOnlyTextArea();
        JScrollPane rawScrollPane = new JScrollPane(rawTextArea);
        rawScrollPane.setBorder(BorderFactory.createTitledBorder(I18n.t("config.tab.raw")));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab(I18n.t("config.tab.general"), generalPanel);
        tabs.addTab(I18n.t("config.tab.access_control"), acScrollPane);
        tabs.addTab(I18n.t("config.tab.waf"), wafPanel);
        tabs.addTab(I18n.t("config.tab.manual_waf") + I18n.t("config.read_only_suffix"), manualWafScrollPane);
        tabs.addTab(I18n.t("config.tab.raw"), rawScrollPane);

        add(top, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);

        reloadButton.addActionListener(e -> reload());
        reinitButton.addActionListener(e -> reinit());

        refreshView();
    }

    private JPanel createGeneralPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder(I18n.t("config.general.title")));

        JPanel threadsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        threadsPanel.add(new JLabel(I18n.t("config.general.threads")));
        threadsPanel.add(tfThreads);
        optionsPanel.add(threadsPanel);

        JPanel redirectPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        redirectPanel.add(new JLabel(I18n.t("config.general.max_redirects")));
        redirectPanel.add(tfMaxRedirects);
        redirectPanel.add(new JLabel(I18n.t("config.general.max_redirects.hint")));
        optionsPanel.add(redirectPanel);

        JPanel thresholdPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        thresholdPanel.add(new JLabel(I18n.t("config.general.threshold")));
        thresholdPanel.add(tfSimilarityThreshold);
        thresholdPanel.add(new JLabel(I18n.t("config.general.threshold.hint")));
        optionsPanel.add(thresholdPanel);

        JPanel langPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        langPanel.add(new JLabel(I18n.t("config.general.lang")));
        langPanel.add(cbLang);
        langPanel.add(new JLabel(I18n.t("config.general.lang.hint")));
        optionsPanel.add(langPanel);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton(I18n.t("config.btn.save_general"));
        saveButton.addActionListener(e -> saveGeneralOptions());
        buttonPanel.add(saveButton);
        optionsPanel.add(buttonPanel);

        JTextArea helpText = new JTextArea();
        helpText.setEditable(false);
        helpText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        helpText.setText(I18n.t("config.general.help"));
        helpText.setBorder(BorderFactory.createTitledBorder(I18n.t("config.waf.help")));

        panel.add(optionsPanel, BorderLayout.NORTH);
        panel.add(helpText, BorderLayout.CENTER);

        return panel;
    }

    private void saveGeneralOptions() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("config.dialog.no_loader"),
                    I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            int threads = Integer.parseInt(tfThreads.getText().trim());
            int maxRedirects = Integer.parseInt(tfMaxRedirects.getText().trim());
            double threshold = Double.parseDouble(tfSimilarityThreshold.getText().trim());
            String lang = (String) cbLang.getSelectedItem();
            String oldLang = I18n.getLang();

            if (threads < 1 || threads > 100) {
                JOptionPane.showMessageDialog(this,
                        I18n.t("config.dialog.threads_range"),
                        I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (maxRedirects < 1 || maxRedirects > 10) {
                JOptionPane.showMessageDialog(this,
                        I18n.t("config.dialog.max_redirects_range"),
                        I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (!Double.isFinite(threshold) || threshold < 0 || threshold > 1) {
                JOptionPane.showMessageDialog(this,
                        I18n.t("config.dialog.threshold_range"),
                        I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
                return;
            }

            boolean success = loader.saveGeneralConfig(threads, maxRedirects, threshold, lang);
            if (success) {
                Map<String, Object> config = loader.loadConfig();
                Utils.setConfigMap(config);
                // 注意：故意不在此调用 I18n.setLang(lang)。
                // 已渲染的 Swing 组件无法整体热切换语言（Tab 标题、Border、按钮、tooltip
                // 都是构造时一次性赋值），如果立即 setLang 会出现"部分弹窗用新语言、面板用旧语言"
                // 的混乱状态。改为：仅写入 YAML，下次插件启动生效，弹窗 hint 提示用户重启。
                refreshView();
                if (Utils.panel != null) {
                    Utils.panel.updateFromConfig();
                }
                String msg = I18n.t("config.dialog.general_saved");
                if (lang != null && !lang.equalsIgnoreCase(oldLang)) {
                    msg = msg + "\n\n" + I18n.t("config.lang.restart_hint");
                }
                saveStatus.setText(msg.replace("\n", " "));
            } else {
                JOptionPane.showMessageDialog(this,
                        I18n.t("config.dialog.general_save_failed") + "\n" + String.valueOf(loader.getLastError()),
                        I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("config.dialog.invalid_number"),
                    I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createWafPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Rules area (top)
        JScrollPane rulesScroll = new JScrollPane(wafRulesTextArea);
        rulesScroll.setBorder(BorderFactory.createTitledBorder(I18n.t("config.rules.waf")));
        rulesScroll.setPreferredSize(new Dimension(0, 300));

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(),
                I18n.t("config.waf.options.title"),
                TitledBorder.LEFT,
                TitledBorder.TOP));

        JPanel charsetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        charsetPanel.setBorder(BorderFactory.createTitledBorder(I18n.t("config.waf.body_charset")));
        charsetPanel.add(cbUtf16);
        charsetPanel.add(cbUtf16be);
        charsetPanel.add(cbUtf16le);
        charsetPanel.add(cbUtf32);
        charsetPanel.add(cbUtf32be);
        charsetPanel.add(cbUtf32le);
        charsetPanel.add(cbIbm037);

        JPanel transformPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        transformPanel.setBorder(BorderFactory.createTitledBorder(I18n.t("config.waf.body_transform")));
        transformPanel.add(cbGzip);

        JPanel ctPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        ctPanel.setBorder(BorderFactory.createTitledBorder(I18n.t("config.waf.content_type_spoof")));
        ctPanel.add(cbFormUrlencoded);
        ctPanel.add(cbMultipart);
        ctPanel.add(cbTextPlain);

        JPanel ghostPanel = new JPanel();
        ghostPanel.setLayout(new BoxLayout(ghostPanel, BoxLayout.Y_AXIS));
        ghostPanel.setBorder(BorderFactory.createTitledBorder(I18n.t("config.waf.ghost_bits")));

        JPanel ghostMainPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        ghostMainPanel.add(cbGhostEnabled);
        ghostMainPanel.add(cbGhostRawSocket);
        ghostMainPanel.add(new JLabel(I18n.t("config.waf.ghost_max_variants")));
        ghostMainPanel.add(tfGhostMaxVariants);

        JPanel ghostTemplatePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        ghostTemplatePanel.add(new JLabel(I18n.t("config.waf.ghost_templates")));
        ghostTemplatePanel.add(cbGhostSpringStaticLfi);
        ghostTemplatePanel.add(cbGhostJettyLooseHex);
        ghostTemplatePanel.add(cbGhostTomcatJspUpload);
        ghostTemplatePanel.add(cbGhostFullwidthTraversal);
        ghostTemplatePanel.add(cbGhostFastjsonXEscape);
        ghostTemplatePanel.add(cbGhostAngusSmtpCrlf);
        ghostTemplatePanel.add(cbGhostFastjsonUnicodeDigit);
        ghostTemplatePanel.add(cbGhostJacksonCharToHex);
        ghostTemplatePanel.add(cbGhostBcelGhostBits);
        ghostTemplatePanel.add(cbGhostJdkUrldecoderUnicodeDigit);
        ghostTemplatePanel.add(cbGhostTomcatUrlHexGhost);

        JPanel ghostGenericPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        ghostGenericPanel.add(new JLabel(I18n.t("config.waf.ghost_generic")));
        ghostGenericPanel.add(cbGhostGenericEnabled);
        ghostGenericPanel.add(new JLabel(I18n.t("config.waf.ghost_generic_variants")));
        ghostGenericPanel.add(tfGhostGenericVariantCount);
        ghostGenericPanel.add(cbGhostGenericMinimal);
        ghostGenericPanel.add(cbGhostGenericFull);
        ghostGenericPanel.add(cbGhostGenericLetters);
        ghostGenericPanel.add(cbGhostGenericDigits);
        ghostGenericPanel.add(cbGhostGenericSymbols);

        ghostPanel.add(ghostMainPanel);
        ghostPanel.add(ghostTemplatePanel);
        ghostPanel.add(ghostGenericPanel);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton(I18n.t("config.btn.save_options"));
        saveButton.addActionListener(e -> saveOptions());
        buttonPanel.add(saveButton);

        optionsPanel.add(charsetPanel);
        optionsPanel.add(transformPanel);
        optionsPanel.add(ctPanel);
        optionsPanel.add(ghostPanel);
        optionsPanel.add(buttonPanel);

        panel.add(rulesScroll, BorderLayout.CENTER);
        panel.add(optionsPanel, BorderLayout.SOUTH);

        return panel;
    }

    public void refreshView() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader != null) {
            configPathText.setText(loader.getConfigFilePath());
            rawTextArea.setText(loader.readConfigText());

            Map<String, Object> root = loader.loadConfig();
            if (root == null) {
                root = Collections.emptyMap();
            }

            Object profilesObj = root.get("profiles");
            if (profilesObj instanceof Map) {
                formatLabel.setText(I18n.t("config.format.profiles"));
            } else {
                formatLabel.setText(I18n.t("config.format.legacy"));
            }

            // 加载 General 配置
            loadGeneralOptions();

            Map<String, Object> ac = Utils.getProfileConfig(Utils.PROFILE_AUTO_ACCESS_BYPASS);
            Map<String, Object> waf = Utils.getProfileConfig(Utils.PROFILE_AUTO_WAF_BYPASS);
            Map<String, Object> manualWaf = Utils.getProfileConfig(Utils.PROFILE_MANUAL_WAF_BYPASS);
            Map<String, Object> ghostBits = Utils.getGhostBitsRuleMap();
            accessControlTextArea.setText(toYaml(filterRulesOnly(ac)));
            wafRulesTextArea.setText(toYaml(filterRulesOnly(waf)));
            // 直接从原始文件截取 manual_waf_bypass 段，避免 SnakeYAML 重新序列化时
            // 把 "\n" 等特殊字符键变成 ? |2+ 这种难看的格式
            String rawConfigText = loader.readConfigText();
            String rawManualWaf = extractRawSection(rawConfigText, "manual_waf_bypass");
            if (rawManualWaf != null && !rawManualWaf.isEmpty()) {
                manualWafTextArea.setText(rawManualWaf);
            } else {
                manualWafTextArea.setText(toYaml(manualWaf.isEmpty()
                        ? Collections.singletonMap("ghost_bits", ghostBits)
                        : manualWaf));
            }

            // 加载 WAF Options 到复选框
            loadWafOptions(waf);
        } else {
            configPathText.setText("");
            formatLabel.setText("");
            accessControlTextArea.setText("");
            wafRulesTextArea.setText("");
            manualWafTextArea.setText("");
            rawTextArea.setText("");
            resetGeneralOptions();
            resetWafOptions();
        }
    }

    private void loadGeneralOptions() {
        int threads = Utils.getConfigThreads(5);
        int maxRedirects = Utils.getConfigMaxRedirects(3);
        double threshold = Utils.getConfigSimilarityThreshold(0.85);
        String lang = Utils.getConfigLang();
        tfThreads.setText(String.valueOf(threads));
        tfMaxRedirects.setText(String.valueOf(maxRedirects));
        tfSimilarityThreshold.setText(String.valueOf(threshold));
        cbLang.setSelectedItem(lang);
    }

    private void resetGeneralOptions() {
        tfThreads.setText("5");
        tfMaxRedirects.setText("3");
        tfSimilarityThreshold.setText("0.85");
        cbLang.setSelectedItem(I18n.ZH);
    }

    private Map<String, Object> filterRulesOnly(Map<String, Object> profile) {
        if (profile == null) return Collections.emptyMap();
        Map<String, Object> rules = new LinkedHashMap<>();
        if (profile.containsKey("suffix")) rules.put("suffix", profile.get("suffix"));
        if (profile.containsKey("headers")) rules.put("headers", profile.get("headers"));
        if (profile.containsKey("prefix")) rules.put("prefix", profile.get("prefix"));
        if (profile.containsKey("boundary_insert")) rules.put("boundary_insert", profile.get("boundary_insert"));
        return rules;
    }

    @SuppressWarnings("unchecked")
    private void loadWafOptions(Map<String, Object> waf) {
        resetWafOptions();
        if (waf == null) return;

        Object optionsObj = waf.get("options");
        if (!(optionsObj instanceof Map)) return;
        Map<String, Object> options = (Map<String, Object>) optionsObj;

        // Body Charset
        Object charsetObj = options.get("body_charset");
        if (charsetObj instanceof Map) {
            Map<String, Object> charset = (Map<String, Object>) charsetObj;
            cbUtf16.setSelected(Boolean.TRUE.equals(charset.get("utf_16")));
            cbUtf16be.setSelected(Boolean.TRUE.equals(charset.get("utf_16be")));
            cbUtf16le.setSelected(Boolean.TRUE.equals(charset.get("utf_16le")));
            cbUtf32.setSelected(Boolean.TRUE.equals(charset.get("utf_32")));
            cbUtf32be.setSelected(Boolean.TRUE.equals(charset.get("utf_32be")));
            cbUtf32le.setSelected(Boolean.TRUE.equals(charset.get("utf_32le")));
            cbIbm037.setSelected(Boolean.TRUE.equals(charset.get("ibm037")));
        }

        // Body Transform
        Object transformObj = options.get("body_transform");
        if (transformObj instanceof Map) {
            Map<String, Object> transform = (Map<String, Object>) transformObj;
            cbGzip.setSelected(Boolean.TRUE.equals(transform.get("gzip")));
        }

        // Content-Type Spoof
        Object ctObj = options.get("content_type_spoof");
        if (ctObj instanceof Map) {
            Map<String, Object> ct = (Map<String, Object>) ctObj;
            cbFormUrlencoded.setSelected(Boolean.TRUE.equals(ct.get("form_urlencoded")));
            cbMultipart.setSelected(Boolean.TRUE.equals(ct.get("multipart")));
            cbTextPlain.setSelected(Boolean.TRUE.equals(ct.get("text_plain")));
        }

        Object ghostObj = options.get("ghost_bits");
        if (ghostObj instanceof Map) {
            Map<String, Object> ghost = (Map<String, Object>) ghostObj;
            cbGhostEnabled.setSelected(Boolean.TRUE.equals(ghost.get("enabled")));
            cbGhostRawSocket.setSelected(Boolean.TRUE.equals(ghost.get("raw_socket")));
            Object maxVariantsObj = ghost.get("max_variants");
            if (maxVariantsObj instanceof Number) {
                tfGhostMaxVariants.setText(String.valueOf(((Number) maxVariantsObj).intValue()));
            } else if (maxVariantsObj != null) {
                tfGhostMaxVariants.setText(maxVariantsObj.toString());
            }

            Object templatesObj = ghost.get("templates");
            if (templatesObj instanceof Map) {
                Map<String, Object> templates = (Map<String, Object>) templatesObj;
                cbGhostSpringStaticLfi.setSelected(Boolean.TRUE.equals(templates.get("spring_static_lfi")));
                cbGhostJettyLooseHex.setSelected(Boolean.TRUE.equals(templates.get("jetty_loose_hex")));
                cbGhostTomcatJspUpload.setSelected(Boolean.TRUE.equals(templates.get("tomcat_jsp_upload")));
                cbGhostFullwidthTraversal.setSelected(Boolean.TRUE.equals(templates.get("fullwidth_traversal")));
                cbGhostFastjsonXEscape.setSelected(Boolean.TRUE.equals(templates.get("fastjson_x_escape")));
                cbGhostAngusSmtpCrlf.setSelected(Boolean.TRUE.equals(templates.get("angus_smtp_crlf")));
                cbGhostFastjsonUnicodeDigit.setSelected(Boolean.TRUE.equals(templates.get("fastjson_unicode_digit")));
                cbGhostJacksonCharToHex.setSelected(Boolean.TRUE.equals(templates.get("jackson_char_to_hex")));
                cbGhostBcelGhostBits.setSelected(Boolean.TRUE.equals(templates.get("bcel_ghost_bits")));
                cbGhostJdkUrldecoderUnicodeDigit.setSelected(Boolean.TRUE.equals(templates.get("jdk_urldecoder_unicode_digit")));
                cbGhostTomcatUrlHexGhost.setSelected(Boolean.TRUE.equals(templates.get("tomcat_url_hex_ghost")));
            }

            Object genericObj = ghost.get("generic");
            if (genericObj instanceof Map) {
                Map<String, Object> generic = (Map<String, Object>) genericObj;
                cbGhostGenericEnabled.setSelected(Boolean.TRUE.equals(generic.get("enabled")));
                Object variantCountObj = generic.get("variant_count");
                if (variantCountObj instanceof Number) {
                    tfGhostGenericVariantCount.setText(String.valueOf(((Number) variantCountObj).intValue()));
                } else if (variantCountObj != null) {
                    tfGhostGenericVariantCount.setText(variantCountObj.toString());
                }
                Object strategiesObj = generic.get("strategies");
                if (strategiesObj instanceof Map) {
                    Map<String, Object> strategies = (Map<String, Object>) strategiesObj;
                    cbGhostGenericMinimal.setSelected(Boolean.TRUE.equals(strategies.get("minimal")));
                    cbGhostGenericFull.setSelected(Boolean.TRUE.equals(strategies.get("full")));
                    cbGhostGenericLetters.setSelected(Boolean.TRUE.equals(strategies.get("letters")));
                    cbGhostGenericDigits.setSelected(Boolean.TRUE.equals(strategies.get("digits")));
                    cbGhostGenericSymbols.setSelected(Boolean.TRUE.equals(strategies.get("symbols")));
                }
            }
        }
    }

    private void resetWafOptions() {
        cbUtf16.setSelected(false);
        cbUtf16be.setSelected(false);
        cbUtf16le.setSelected(false);
        cbUtf32.setSelected(false);
        cbUtf32be.setSelected(false);
        cbUtf32le.setSelected(false);
        cbIbm037.setSelected(false);
        cbGzip.setSelected(false);
        cbFormUrlencoded.setSelected(false);
        cbMultipart.setSelected(false);
        cbTextPlain.setSelected(false);
        cbGhostEnabled.setSelected(false);
        cbGhostRawSocket.setSelected(false);
        tfGhostMaxVariants.setText("10");
        cbGhostSpringStaticLfi.setSelected(false);
        cbGhostJettyLooseHex.setSelected(false);
        cbGhostTomcatJspUpload.setSelected(false);
        cbGhostFullwidthTraversal.setSelected(false);
        cbGhostFastjsonXEscape.setSelected(false);
        cbGhostAngusSmtpCrlf.setSelected(false);
        cbGhostFastjsonUnicodeDigit.setSelected(false);
        cbGhostJacksonCharToHex.setSelected(false);
        cbGhostBcelGhostBits.setSelected(false);
        cbGhostJdkUrldecoderUnicodeDigit.setSelected(false);
        cbGhostTomcatUrlHexGhost.setSelected(false);
        cbGhostGenericEnabled.setSelected(false);
        cbGhostGenericMinimal.setSelected(false);
        cbGhostGenericFull.setSelected(false);
        cbGhostGenericLetters.setSelected(false);
        cbGhostGenericDigits.setSelected(false);
        cbGhostGenericSymbols.setSelected(false);
        tfGhostGenericVariantCount.setText("3");
    }

    private void saveOptions() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("config.dialog.no_loader"),
                    I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 构建 options Map
        Map<String, Object> options = new LinkedHashMap<>();

        Map<String, Object> bodyCharset = new LinkedHashMap<>();
        bodyCharset.put("utf_16", cbUtf16.isSelected());
        bodyCharset.put("utf_16be", cbUtf16be.isSelected());
        bodyCharset.put("utf_16le", cbUtf16le.isSelected());
        bodyCharset.put("utf_32", cbUtf32.isSelected());
        bodyCharset.put("utf_32be", cbUtf32be.isSelected());
        bodyCharset.put("utf_32le", cbUtf32le.isSelected());
        bodyCharset.put("ibm037", cbIbm037.isSelected());
        options.put("body_charset", bodyCharset);

        Map<String, Object> bodyTransform = new LinkedHashMap<>();
        bodyTransform.put("gzip", cbGzip.isSelected());
        options.put("body_transform", bodyTransform);

        Map<String, Object> contentTypeSpoof = new LinkedHashMap<>();
        contentTypeSpoof.put("form_urlencoded", cbFormUrlencoded.isSelected());
        contentTypeSpoof.put("multipart", cbMultipart.isSelected());
        contentTypeSpoof.put("text_plain", cbTextPlain.isSelected());
        options.put("content_type_spoof", contentTypeSpoof);

        int maxVariants;
        int genericVariantCount;
        try {
            maxVariants = Integer.parseInt(tfGhostMaxVariants.getText().trim());
            if (maxVariants < 0 || maxVariants > 1000) {
                throw new NumberFormatException("out of range");
            }
            genericVariantCount = Integer.parseInt(tfGhostGenericVariantCount.getText().trim());
            if (genericVariantCount < 0 || genericVariantCount > 1000) {
                throw new NumberFormatException("out of range");
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("config.dialog.invalid_number"),
                    I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }

        Map<String, Object> ghostBits = new LinkedHashMap<>();
        ghostBits.put("enabled", cbGhostEnabled.isSelected());
        ghostBits.put("raw_socket", cbGhostRawSocket.isSelected());
        ghostBits.put("max_variants", maxVariants);

        Map<String, Object> ghostTemplates = new LinkedHashMap<>();
        ghostTemplates.put("spring_static_lfi", cbGhostSpringStaticLfi.isSelected());
        ghostTemplates.put("jetty_loose_hex", cbGhostJettyLooseHex.isSelected());
        ghostTemplates.put("tomcat_jsp_upload", cbGhostTomcatJspUpload.isSelected());
        ghostTemplates.put("fullwidth_traversal", cbGhostFullwidthTraversal.isSelected());
        ghostTemplates.put("fastjson_x_escape", cbGhostFastjsonXEscape.isSelected());
        ghostTemplates.put("angus_smtp_crlf", cbGhostAngusSmtpCrlf.isSelected());
        ghostTemplates.put("fastjson_unicode_digit", cbGhostFastjsonUnicodeDigit.isSelected());
        ghostTemplates.put("jackson_char_to_hex", cbGhostJacksonCharToHex.isSelected());
        ghostTemplates.put("bcel_ghost_bits", cbGhostBcelGhostBits.isSelected());
        ghostTemplates.put("jdk_urldecoder_unicode_digit", cbGhostJdkUrldecoderUnicodeDigit.isSelected());
        ghostTemplates.put("tomcat_url_hex_ghost", cbGhostTomcatUrlHexGhost.isSelected());
        ghostBits.put("templates", ghostTemplates);

        Map<String, Object> ghostGeneric = new LinkedHashMap<>();
        ghostGeneric.put("enabled", cbGhostGenericEnabled.isSelected());
        Map<String, Object> genericStrategies = new LinkedHashMap<>();
        genericStrategies.put("minimal", cbGhostGenericMinimal.isSelected());
        genericStrategies.put("full", cbGhostGenericFull.isSelected());
        genericStrategies.put("letters", cbGhostGenericLetters.isSelected());
        genericStrategies.put("digits", cbGhostGenericDigits.isSelected());
        genericStrategies.put("symbols", cbGhostGenericSymbols.isSelected());
        ghostGeneric.put("strategies", genericStrategies);
        ghostGeneric.put("variant_count", genericVariantCount);
        ghostBits.put("generic", ghostGeneric);
        options.put("ghost_bits", ghostBits);

        boolean success = loader.saveWafOptions(options);
        if (success) {
            Map<String, Object> config = loader.loadConfig();
            Utils.setConfigMap(config);
            refreshView();
            saveStatus.setText(I18n.t("config.dialog.options_saved"));
        } else {
            JOptionPane.showMessageDialog(this,
                    I18n.t("config.dialog.options_save_failed") + "\n" + String.valueOf(loader.getLastError()),
                    I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void reload() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) return;
        Map<String, Object> config = loader.loadConfig();
        if (loader.getLastError() != null) {
            saveStatus.setText(I18n.t("config.reload_failed"));
            saveStatus.setToolTipText(loader.getLastError());
            JOptionPane.showMessageDialog(this, I18n.t("config.reload_failed") + "\n" + loader.getLastError(),
                    I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        Utils.setConfigMap(config);
        refreshView();
        notifyManualWafConfigChanged();
        if (Utils.panel != null) Utils.panel.updateFromConfig();
        saveStatus.setText(I18n.t("config.reloaded"));
        saveStatus.setToolTipText(null);
    }

    private void reinit() {
        ConfigLoader loader = Utils.getConfigLoader();
        if (loader == null) {
            return;
        }

        int retCode = JOptionPane.showConfirmDialog(this,
                I18n.t("dialog.reinit.confirm"),
                I18n.t("dialog.reinit.title"),
                JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            boolean ok = loader.initConfig();
            if (ok) {
                Map<String, Object> config = loader.loadConfig();
                Utils.setConfigMap(config);
                refreshView();
                notifyManualWafConfigChanged();
                System.out.println("reinit success...");
            }
        }
    }

    private void notifyManualWafConfigChanged() {
        if (Utils.panel != null && Utils.panel.getManualWafPanel() != null) {
            Utils.panel.getManualWafPanel().refreshGhostTemplates();
        }
    }

    /**
     * 从原始 YAML 文本中提取指定 key 的完整块（包含该 key 所在行及其所有子内容）。
     * key 可以位于任意缩进层级（如 profiles 下的 manual_waf_bypass）。
     * 遇到同缩进或更浅缩进的非空行则停止收集。
     */
    private String extractRawSection(String rawText, String sectionKey) {
        if (rawText == null || rawText.isEmpty() || sectionKey == null) {
            return null;
        }
        String[] lines = rawText.split("\n", -1);
        String suffix = sectionKey + ":";
        int startLine = -1;
        int keyIndent = -1;
        // 在任意缩进层级查找 key
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.equals(suffix) || trimmed.startsWith(suffix + " ") || trimmed.startsWith(suffix + "\t")) {
                keyIndent = indentOf(lines[i]);
                startLine = i;
                break;
            }
        }
        if (startLine < 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(lines[startLine]);
        for (int i = startLine + 1; i < lines.length; i++) {
            String line = lines[i];
            // 空行或纯空白行继续收集
            if (line.isEmpty() || line.trim().isEmpty()) {
                sb.append('\n').append(line);
                continue;
            }
            // 注释行：如果缩进比 key 深则属于本节，否则可能是上级注释，停止
            if (line.trim().startsWith("#")) {
                if (indentOf(line) > keyIndent) {
                    sb.append('\n').append(line);
                    continue;
                }
                break;
            }
            // 遇到同缩进或更浅缩进的非空行，说明进入了下一个同级/上级节
            if (indentOf(line) <= keyIndent) {
                break;
            }
            sb.append('\n').append(line);
        }
        return sb.toString();
    }

    private static int indentOf(String line) {
        int n = 0;
        for (int i = 0; i < line.length(); i++) {
            if (line.charAt(i) == ' ') {
                n++;
            } else if (line.charAt(i) == '\t') {
                n += 2; // tab 按 2 空格计
            } else {
                break;
            }
        }
        return n;
    }

    private JTextArea createReadOnlyTextArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setTabSize(2);
        return ta;
    }

    private Yaml createYamlDumper() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setProcessComments(false);
        loaderOptions.setAllowRecursiveKeys(false);

        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        dop.setPrettyFlow(true);
        dop.setIndent(2);
        dop.setNonPrintableStyle(DumperOptions.NonPrintableStyle.ESCAPE);

        Representer representer = new Representer(dop) {
            @Override
            protected Node representSequence(Tag tag, Iterable<?> sequence,
                                             DumperOptions.FlowStyle flowStyle) {
                int size = sequence instanceof List ? ((List<?>) sequence).size() : -1;
                if (size >= 0 && size <= 2) {
                    return super.representSequence(tag, sequence, DumperOptions.FlowStyle.FLOW);
                }
                return super.representSequence(tag, sequence, flowStyle);
            }
        };
        return new Yaml(new SafeConstructor(loaderOptions), representer, dop);
    }

    private String toYaml(Object o) {
        try {
            return yamlDumper.dump(o == null ? Collections.emptyMap() : o);
        } catch (Exception e) {
            return "";
        }
    }
}

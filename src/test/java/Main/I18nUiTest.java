package Main;

import Main.ghostbits.GhostBitsCodec;
import Main.ghostbits.GhostBitsRule;
import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class I18nUiTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private String originalLang;
    private IBurpExtenderCallbacks originalCallbacks;
    private Map<String, Object> originalConfig;
    private ConfigLoader originalLoader;
    private final List<ManualWafPanel> panels = new ArrayList<>();
    private static final Pattern HAN = Pattern.compile("[\\p{IsHan}]");

    @Before
    public void setUp() {
        originalLang = I18n.getLang();
        originalCallbacks = Utils.callbacks;
        originalConfig = Utils.configMap;
        originalLoader = Utils.getConfigLoader();
        ConfigLoader loader = new ConfigLoader(folder.getRoot().getAbsolutePath());
        Utils.setConfigLoader(loader);
        Utils.configMap = loader.loadConfig();
        Utils.callbacks = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
                IBurpExtenderCallbacks.class.getClassLoader(), new Class<?>[]{IBurpExtenderCallbacks.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("createMessageEditor")) return new EditorStub();
                    throw new AssertionError("Unexpected Burp call: " + method);
                });
    }

    @After
    public void tearDown() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (ManualWafPanel panel : panels) {
                try {
                    Field field = ManualWafPanel.class.getDeclaredField("inspectorTimer");
                    field.setAccessible(true);
                    ((Timer) field.get(panel)).stop();
                } catch (ReflectiveOperationException e) {
                    throw new AssertionError(e);
                }
            }
        });
        I18n.setLang(originalLang);
        Utils.callbacks = originalCallbacks;
        Utils.configMap = originalConfig;
        Utils.setConfigLoader(originalLoader);
    }

    @Test
    public void englishPanelsHaveTranslatedLabelsAndTooltips() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            I18n.setLang(I18n.EN);
            ManualWafPanel manual = createManualPanel();
            ConfigPanel config = new ConfigPanel();
            List<String> text = new ArrayList<>();
            collectText(manual, text);
            collectText(config, text);
            assertTrue(text.contains("Insert at caret"));
            assertTrue(text.contains("Ghost Restore:"));
            assertTrue(text.contains("Templates:"));
            assertTrue(text.contains("Manual-WAF Bypass (read-only)"));
            for (String item : text) assertEnglish(item);
            savePreview(manual, "manual-en.png");
            savePreview(config, "config-en.png");
        });
    }

    @Test
    public void chinesePanelsKeepTheirLocalizedLabels() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            I18n.setLang(I18n.ZH);
            ManualWafPanel manual = createManualPanel();
            ConfigPanel config = new ConfigPanel();
            List<String> text = new ArrayList<>();
            collectText(manual, text);
            collectText(config, text);
            assertTrue(text.contains("光标处插入"));
            assertTrue(text.contains("Ghost 还原:"));
            assertTrue(text.contains("模板:"));
            assertTrue(text.contains("Manual-WAF绕过 (只读)"));
            savePreview(manual, "manual-zh.png");
            savePreview(config, "config-zh.png");
        });
    }

    @Test
    public void traversalAndGhostButtonsKeepTheirOwnTooltips() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            I18n.setLang(I18n.EN);
            List<String> text = new ArrayList<>();
            collectText(createManualPanel(), text);
            assertTrue(text.stream().anyMatch(s -> s.startsWith("Traversal: .%u002e\n")));
            assertTrue(text.stream().anyMatch(s -> s.startsWith(".%u002e\n")));
            assertTrue(text.stream().anyMatch(s -> s.startsWith("fastjson \\x4_\n") && s.contains("\\x")));
            assertTrue(text.stream().anyMatch(s -> s.startsWith("HTTP/1.0\n") && s.contains("protocol")));
        });
    }

    @Test
    public void formattedMessagesPreserveLiteralPercentSignsAndArguments() {
        I18n.setLang(I18n.EN);
        assertEquals("All (3 matches)", I18n.t("dialog.scope.all", 3));
        assertEquals("Match 2: ...a%20b...", I18n.t("dialog.scope.occurrence", 2, "a%20b"));
        String tomcat = I18n.t("dialog.tomcat_hex_input", "6a");
        assertTrue(tomcat.contains("Tomcat %HH"));
        assertTrue(tomcat.contains("literal characters 6a"));
        assertFalse(tomcat.contains("%s"));
        assertTrue(I18n.t("dialog.force_url_encode").contains("%XX"));
        assertEquals("Header not found: X-Test", I18n.t("dialog.header_missing", "X-Test"));
        I18n.setLang(I18n.ZH);
        assertEquals("全部 (3 处)", I18n.t("dialog.scope.all", 3));
        assertTrue(I18n.t("dialog.tomcat_hex_input", "6a").contains("字符 6a"));
    }

    @Test
    public void customTemplateProseIsNotReplacedByBuiltInTranslations() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            I18n.setLang(I18n.EN);
            GhostBitsRule.Template template = new GhostBitsRule.Template("spring_static_lfi", "", "",
                    "我的自定义模板", "selection", "原始内容", "any", "自定义说明 %s 不应被翻译");
            try {
                Method method = ManualWafPanel.class.getDeclaredMethod("ghostTemplateTooltip", GhostBitsRule.Template.class);
                method.setAccessible(true);
                String tooltip = (String) method.invoke(createManualPanel(), template);
                assertTrue(tooltip.startsWith("我的自定义模板\n"));
                assertTrue(tooltip.contains("Notes: 自定义说明 %s 不应被翻译"));
                assertEquals("原始内容", template.getPattern());
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test
    public void foldReportsTranslateLabelsWithoutChangingPayloadCharacters() {
        I18n.setLang(I18n.EN);
        String english = GhostBitsCodec.buildFoldPreviewReport("瘍瘊", GhostBitsCodec.FoldMode.BIT_8);
        assertTrue(english.startsWith("Original: 瘍瘊\nMode: 8-bit"));
        assertTrue(english.contains("Ghost restore: \\r\\n"));
        I18n.setLang(I18n.ZH);
        String chinese = GhostBitsCodec.buildFoldPreviewReport("瘍瘊", GhostBitsCodec.FoldMode.BIT_8);
        assertTrue(chinese.startsWith("原文: 瘍瘊\n模式: 8-bit"));
        assertEquals(english.substring(english.indexOf("\n\n")), chinese.substring(chinese.indexOf("\n\n")));
    }

    private ManualWafPanel createManualPanel() {
        ManualWafPanel panel = new ManualWafPanel();
        panels.add(panel);
        return panel;
    }

    private static void assertEnglish(String text) {
        // These are literal payload examples, not untranslated UI prose.
        String prose = text.replace("阮严灵丰丰甲来", "").replace("瘍瘊", "")
                .replace("陪", "").replace("鸶繡", "");
        assertFalse("Untranslated UI text: " + text, HAN.matcher(prose).find());
        assertFalse("Unresolved translation key: " + text,
                text.matches("(?:config|dialog|manual|tooltip|row|btn)\\.[a-z_.]+"));
    }

    private static void collectText(Component component, List<String> result) {
        if (component instanceof JLabel) addText(result, ((JLabel) component).getText());
        if (component instanceof AbstractButton) addText(result, ((AbstractButton) component).getText());
        if (component instanceof JComponent) {
            addText(result, ((JComponent) component).getToolTipText());
            collectBorder(((JComponent) component).getBorder(), result);
        }
        if (component instanceof JTabbedPane) {
            JTabbedPane tabs = (JTabbedPane) component;
            for (int i = 0; i < tabs.getTabCount(); i++) addText(result, tabs.getTitleAt(i));
        }
        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) collectText(child, result);
        }
    }

    private static void collectBorder(Border border, List<String> result) {
        if (border instanceof TitledBorder) addText(result, ((TitledBorder) border).getTitle());
        if (border instanceof CompoundBorder) {
            collectBorder(((CompoundBorder) border).getInsideBorder(), result);
            collectBorder(((CompoundBorder) border).getOutsideBorder(), result);
        }
    }

    private static void addText(List<String> result, String text) {
        if (text != null && !text.isEmpty()) result.add(text);
    }

    private static void savePreview(JComponent panel, String name) {
        if (!Boolean.getBoolean("bypass.i18n.previews")) return;
        try {
            panel.setSize(1500, 850);
            layoutTree(panel);
            BufferedImage image = new BufferedImage(1500, 850, BufferedImage.TYPE_INT_RGB);
            Graphics2D graphics = image.createGraphics();
            panel.printAll(graphics);
            graphics.dispose();
            File dir = new File("target/i18n-previews");
            assertTrue(dir.isDirectory() || dir.mkdirs());
            ImageIO.write(image, "png", new File(dir, name));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) {
            if (child instanceof Container) layoutTree((Container) child);
        }
    }

    private static class EditorStub implements IMessageEditor {
        private final JTextArea component = new JTextArea();
        private byte[] message = new byte[0];
        @Override public Component getComponent() { return component; }
        @Override public void setMessage(byte[] message, boolean isRequest) { this.message = message; }
        @Override public byte[] getMessage() { return message; }
        @Override public boolean isMessageModified() { return false; }
        @Override public byte[] getSelectedData() { return null; }
    }
}

package Main;

import Main.ghostbits.GhostBitsEngine;
import Main.ghostbits.GhostBitsCodec;
import Main.ghostbits.GhostBitsRule;
import Main.ghostbits.RawSocketSender;
import Main.ghostbits.ParserPreview;
import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Stack;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

/**
 * Manual WAF Bypass Panel
 */
public class ManualWafPanel extends JPanel implements IMessageEditorController {

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private JTable historyTable;
    private HistoryTableModel historyModel;
    private final List<HistoryEntry> historyEntries = new ArrayList<>();
    private int historySeq = 0;
    private static final int MAX_HISTORY_SIZE = 50;
    private static final int MAX_UNDO_STEPS = 20;
    private static final int MAX_REDO_STEPS = 20;

    private IHttpService currentHttpService;
    private byte[] currentResponseBytes = new byte[0];
    private byte[] originalRequest = new byte[0];
    private IHttpService originalHttpService;
    private byte[] capturedResponseBytes = new byte[0];
    private byte[] baselineResponseBytes = new byte[0];
    private byte[] baselineDisplayedRequestBytes = new byte[0];
    private byte[] currentDisplayedRequestBytes = new byte[0];
    private IHttpService baselineHttpService;
    private SendRun baselineRun;
    private String baselineCheckText = I18n.t("baseline.not_checked");
    private String currentComparisonText = "";
    private String currentResponseSteps = "";
    private JComboBox<String> responseChoice;
    private JLabel baselineStatusLabel;
    private JLabel responseComparisonLabel;
    private JLabel operationSequenceLabel;
    private JButton replayOriginalBtn;
    private JButton restoreOriginalBtn;
    private JToggleButton historyToggle;
    private JPanel baselineDetails;

    private final Stack<RequestState> undoStack = new Stack<>();
    private final Stack<RequestState> redoStack = new Stack<>();
    private List<String> transformations = new ArrayList<>();
    private byte[] transformationBytes = new byte[0];

    private static final class RequestState {
        final byte[] bytes;
        final List<String> transformations;
        RequestState(byte[] bytes, List<String> transformations) {
            this.bytes = bytes.clone();
            this.transformations = new ArrayList<>(transformations);
        }
    }

    private JTextField hostField;
    private JTextField portField;
    private JCheckBox httpsCheckBox;
    private JCheckBox followRedirectCheckBox;
    private JButton sendBtn;
    private JButton sendDropdownBtn;
    private JButton cancelBtn;
    private JButton undoBtn;
    private JButton redoBtn;
    private JLabel statusLabel;
    private volatile SendRun activeSend;
    private byte[] lastSubmittedRequest = new byte[0];
    private byte[] responseRequestBytes = new byte[0];
    private JLabel responseContextLabel;
    private JLabel scopeLabel;
    private final List<JButton> selectionButtons = new ArrayList<>();

    private static final class SendRun {
        final IHttpService service;
        final byte[] editorBytes;
        final byte[] wireBytes;
        final boolean raw;
        final boolean followRedirect;
        final int maxRedirects;
        final boolean baseline;
        final String steps;
        final IHttpRequestResponse reference;
        final boolean referenceIsReplay;
        final long startNs = System.nanoTime();
        volatile boolean cancelled;
        Thread thread;
        SendRun(IHttpService service, byte[] editor, byte[] wire, boolean raw, boolean follow, int max,
                boolean baseline, String steps, IHttpRequestResponse reference, boolean referenceIsReplay) {
            this.service = service;
            this.editorBytes = editor.clone();
            this.wireBytes = wire.clone();
            this.raw = raw;
            this.followRedirect = follow && !raw;
            this.maxRedirects = max;
            this.baseline = baseline;
            this.steps = steps;
            this.reference = reference;
            this.referenceIsReplay = referenceIsReplay;
        }
    }
    private JLabel inspectorRequestLineLabel;
    private JLabel inspectorMetaLabel;
    private JLabel inspectorFlagsLabel;
    private JLabel inspectorHintsLabel;
    private JLabel inspectorDiffLabel;
    private JLabel ghostSelectionFoldLabel;
    private JLabel ghostPreviewRiskLabel;
    private String parserPreviewName, parserPreviewPayload;
    private byte[] parserPreviewBytes;
    private Timer inspectorTimer;
    private byte[] lastInspectorBytes = new byte[0];
    private byte[] lastInspectorSelectionBytes = new byte[0];
    private Integer pendingRequestCaretPosition = null;

    private static final Pattern TAG_DIRTY = Pattern.compile("\\{\\{\\s*dirty\\((\\d+)\\)\\s*\\}\\}");
    private static final Pattern TAG_DIRTY_NULL = Pattern.compile("\\{\\{\\s*dirtynull\\((\\d+)\\)\\s*\\}\\}");

    /** 发送策略：AUTO 根据请求内容是否含非 ASCII 自动选 */
    enum SenderMode {
        AUTO, BURP, RAW
    }

    private SenderMode senderMode = SenderMode.AUTO;

    /**
     * Atoms 区注入策略。
     * SELECTION 历史命名保留，语义为"光标处插入"（caret-or-fallback）：
     * 优先用 JTextComponent 的 caret 位置插入；Hex 视图等拿不到 caret 时回退到选区路径。
     */
    enum AtomTarget {
        SELECTION, SUFFIX, SEG_PREFIX, SEG_SUFFIX, INTERLEAVE, REPLACE_SPACE
    }

    private AtomTarget atomTarget = AtomTarget.SELECTION;

    private GhostBitsCodec.FoldMode ghostFoldMode = GhostBitsCodec.FoldMode.BIT_8;
    private JToggleButton ghostFold8BitBtn;
    private JToggleButton ghostFold7BitBtn;
    private JPanel ghostTemplatePathRow;

    public ManualWafPanel() {
        setLayout(new BorderLayout());

        JPanel toolbar = createToolbar();

        // Request | Response
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.5);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setPreferredSize(new Dimension(500, 0));
        requestPanel.setMinimumSize(new Dimension(180, 0));
        requestViewer = Utils.callbacks.createMessageEditor(this, true);
        requestPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);
        operationSequenceLabel = new JLabel(I18n.t("manual.steps", I18n.t("manual.steps.original")));
        JPanel requestHeading = createEditorHeading();
        requestHeading.add(operationSequenceLabel, BorderLayout.CENTER);
        requestPanel.add(requestHeading, BorderLayout.NORTH);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setPreferredSize(new Dimension(500, 0));
        responsePanel.setMinimumSize(new Dimension(180, 0));
        responseChoice = new JComboBox<>(new String[]{I18n.t("manual.response.latest"), I18n.t("manual.response.baseline")});
        responseChoice.setPrototypeDisplayValue(I18n.t("manual.response.baseline") + "      ");
        responseViewer = Utils.callbacks.createMessageEditor(new IMessageEditorController() {
            public IHttpService getHttpService() { return responseChoice.getSelectedIndex() == 1 ? baselineHttpService : currentHttpService; }
            public byte[] getRequest() { return responseChoice.getSelectedIndex() == 1 ? baselineDisplayedRequestBytes : currentDisplayedRequestBytes; }
            public byte[] getResponse() { return responseChoice.getSelectedIndex() == 1 ? baselineResponseBytes : currentResponseBytes; }
        }, false);
        responsePanel.add(responseViewer.getComponent(), BorderLayout.CENTER);
        responseContextLabel = new JLabel(I18n.t("manual.response.none_short"));
        responseContextLabel.setToolTipText(I18n.t("manual.response.empty"));
        JPanel responseHeading = createEditorHeading();
        responseChoice.addActionListener(e -> showSelectedResponse());
        responseHeading.add(responseChoice, BorderLayout.WEST);
        responseHeading.add(responseContextLabel, BorderLayout.CENTER);
        baselineStatusLabel = new JLabel(baselineCheckText);
        baselineDetails = new JPanel();
        baselineDetails.setLayout(new BoxLayout(baselineDetails, BoxLayout.Y_AXIS));
        baselineDetails.setBorder(new EmptyBorder(3, 8, 3, 8));
        baselineStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        baselineDetails.add(baselineStatusLabel);
        responseComparisonLabel = new JLabel();
        responseComparisonLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        responseComparisonLabel.setVisible(false);
        baselineDetails.add(responseComparisonLabel);
        baselineDetails.setVisible(false);
        responsePanel.add(responseHeading, BorderLayout.NORTH);

        mainSplit.setLeftComponent(requestPanel);
        mainSplit.setRightComponent(responsePanel);
        JPanel exchangePanel = new JPanel(new BorderLayout());
        exchangePanel.add(mainSplit, BorderLayout.CENTER);
        exchangePanel.add(baselineDetails, BorderLayout.SOUTH);

        // Bottom: Tools | History
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplit.setResizeWeight(0.6);
        JPanel toolsPanel = createBypassToolsPanel();
        toolsPanel.setPreferredSize(new Dimension(600, 200));
        toolsPanel.setMinimumSize(new Dimension(300, 100));
        bottomSplit.setLeftComponent(toolsPanel);
        JPanel historyPanel = createHistoryPanel();
        historyPanel.setPreferredSize(new Dimension(340, 200));
        bottomSplit.setRightComponent(historyPanel);
        historyToggle.addActionListener(e -> {
            historyPanel.setVisible(historyToggle.isSelected());
            bottomSplit.setDividerSize(historyToggle.isSelected() ? 8 : 0);
            bottomSplit.setDividerLocation(historyToggle.isSelected() ? 0.65 : 1.0);
        });
        bottomSplit.setPreferredSize(new Dimension(0, 200));

        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setTopComponent(exchangePanel);
        verticalSplit.setBottomComponent(bottomSplit);
        verticalSplit.setResizeWeight(0.76);

        add(toolbar, BorderLayout.NORTH);
        add(verticalSplit, BorderLayout.CENTER);
        add(createStatusPanel(), BorderLayout.SOUTH);

        setupShortcuts();
        startRequestInspectorTimer();
        updateUndoRedoButtons();
        replayOriginalBtn.setEnabled(false);
        restoreOriginalBtn.setEnabled(false);
        updateTransformationLabel();
    }

    private JPanel createEditorHeading() {
        JPanel heading = new JPanel(new BorderLayout(8, 0)) {
            @Override
            public Dimension getPreferredSize() {
                Dimension preferred = super.getPreferredSize();
                int controlHeight = responseChoice == null ? 0 : responseChoice.getPreferredSize().height;
                Insets padding = getInsets();
                preferred.height = Math.max(controlHeight, operationSequenceLabel.getPreferredSize().height)
                        + padding.top + padding.bottom;
                return preferred;
            }
        };
        heading.setBorder(new EmptyBorder(4, 6, 4, 6));
        return heading;
    }

    private JPanel createStatusPanel() {
        JPanel statusPanel = new JPanel(new BorderLayout(12, 0));
        statusPanel.setBorder(new EmptyBorder(4, 8, 4, 8));
        statusLabel = new JLabel(I18n.t("status.ready"));
        statusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        statusPanel.add(statusLabel, BorderLayout.CENTER);
        scopeLabel = new JLabel(I18n.t("manual.scope.none"));
        statusPanel.add(scopeLabel, BorderLayout.EAST);
        return statusPanel;
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout(0, 6));
        toolbar.setBorder(new EmptyBorder(5, 8, 5, 8));

        JPanel actions = new WrappingToolbar();
        JPanel sendActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JPanel editActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        sendBtn = new JButton("Send");
        sendBtn.setBackground(new Color(255, 102, 51));
        sendBtn.setForeground(Color.WHITE);
        sendBtn.setFocusPainted(false);
        sendBtn.setToolTipText(I18n.t("manual.send.auto_tip"));
        sendBtn.addActionListener(e -> sendRequest());

        sendDropdownBtn = new JButton("▾");
        sendDropdownBtn.setBackground(new Color(255, 102, 51));
        sendDropdownBtn.setForeground(Color.WHITE);
        sendDropdownBtn.setFocusPainted(false);
        sendDropdownBtn.setMargin(new Insets(2, 4, 2, 4));
        sendDropdownBtn.setToolTipText(I18n.t("manual.send.choose_mode"));
        sendDropdownBtn.addActionListener(e -> showSendModeMenu(sendDropdownBtn));

        cancelBtn = new JButton("Cancel");
        cancelBtn.setEnabled(false);
        cancelBtn.addActionListener(e -> cancelRequest());

        undoBtn = new JButton("←");
        redoBtn = new JButton("→");
        restoreOriginalBtn = new JButton(I18n.t("manual.restore_original"));
        replayOriginalBtn = new JButton(I18n.t("manual.replay_original"));
        replayOriginalBtn.setToolTipText(I18n.t("manual.replay_original.tip"));
        replayOriginalBtn.addActionListener(e -> sendRequest(true));
        undoBtn.setToolTipText(I18n.t("manual.undo"));
        redoBtn.setToolTipText(I18n.t("manual.redo"));
        restoreOriginalBtn.setToolTipText(I18n.t("manual.reset"));
        undoBtn.addActionListener(e -> undo());
        redoBtn.addActionListener(e -> redo());
        restoreOriginalBtn.addActionListener(e -> reset());

        followRedirectCheckBox = new JCheckBox("Follow Redirect");
        followRedirectCheckBox.setToolTipText(I18n.t("manual.follow_redirect"));

        sendActions.add(sendBtn);
        sendActions.add(sendDropdownBtn);
        sendActions.add(replayOriginalBtn);
        sendActions.add(cancelBtn);
        editActions.add(undoBtn);
        editActions.add(redoBtn);
        editActions.add(restoreOriginalBtn);
        actions.add(sendActions);
        actions.add(editActions);
        historyToggle = new JToggleButton(I18n.t("manual.history.toggle"), true);
        actions.add(historyToggle);

        JPanel target = new JPanel(new GridBagLayout());
        GridBagConstraints cell = new GridBagConstraints();
        cell.gridy = 0;
        cell.insets = new Insets(0, 0, 0, 6);
        cell.anchor = GridBagConstraints.WEST;
        target.add(new JLabel("Host:"), cell);
        hostField = new JTextField(16);
        hostField.setToolTipText(I18n.t("manual.network_target"));
        cell.weightx = 1;
        cell.fill = GridBagConstraints.HORIZONTAL;
        target.add(hostField, cell);
        cell.weightx = 0;
        cell.fill = GridBagConstraints.NONE;
        target.add(new JLabel(I18n.t("label.port")), cell);
        portField = new JTextField(5);
        target.add(portField, cell);
        httpsCheckBox = new JCheckBox("HTTPS");
        target.add(httpsCheckBox, cell);
        target.add(followRedirectCheckBox, cell);

        toolbar.add(target, BorderLayout.NORTH);
        toolbar.add(actions, BorderLayout.CENTER);
        return toolbar;
    }

    private final class WrappingToolbar extends JPanel {
        WrappingToolbar() { super(new FlowLayout(FlowLayout.LEFT, 6, 3)); }

        @Override
        public Dimension getPreferredSize() {
            Dimension preferred = super.getPreferredSize();
            int width = ManualWafPanel.this.getWidth();
            if (getParent() != null) {
                Insets padding = getParent().getInsets();
                width -= padding.left + padding.right;
            }
            if (width <= 0) return preferred;
            int rowWidth = 0, rowHeight = 0, height = 6;
            for (Component component : getComponents()) {
                if (!component.isVisible()) continue;
                Dimension item = component.getPreferredSize();
                if (rowWidth > 0 && rowWidth + 6 + item.width > width - 12) {
                    height += rowHeight + 3;
                    rowWidth = 0;
                    rowHeight = 0;
                }
                rowWidth += (rowWidth == 0 ? 0 : 6) + item.width;
                rowHeight = Math.max(rowHeight, item.height);
            }
            preferred.height = height + rowHeight;
            return preferred;
        }
    }

    private void showSendModeMenu(Component anchor) {
        JPopupMenu menu = new JPopupMenu();

        JRadioButtonMenuItem auto = new JRadioButtonMenuItem(
                I18n.t("manual.send.auto"), senderMode == SenderMode.AUTO);
        auto.addActionListener(e -> setSenderMode(SenderMode.AUTO));

        JRadioButtonMenuItem burp = new JRadioButtonMenuItem(
                "Send (Burp)", senderMode == SenderMode.BURP);
        burp.addActionListener(e -> setSenderMode(SenderMode.BURP));

        JRadioButtonMenuItem raw = new JRadioButtonMenuItem(
                "Send (Raw Socket)", senderMode == SenderMode.RAW);
        raw.addActionListener(e -> setSenderMode(SenderMode.RAW));

        ButtonGroup bg = new ButtonGroup();
        bg.add(auto);
        bg.add(burp);
        bg.add(raw);

        menu.add(auto);
        menu.add(burp);
        menu.add(raw);
        menu.addSeparator();
        JMenuItem hint = new JMenuItem(I18n.t("manual.send.raw_hint"));
        hint.setEnabled(false);
        menu.add(hint);

        menu.show(anchor, 0, anchor.getHeight());
    }

    private void setSenderMode(SenderMode mode) {
        this.senderMode = mode;
        updateRedirectAvailability();
        if (sendBtn != null) {
            switch (mode) {
                case BURP:
                    sendBtn.setText("Send (Burp)");
                    break;
                case RAW:
                    sendBtn.setText("Send (Raw)");
                    break;
                default:
                    sendBtn.setText("Send");
            }
        }
    }

    /**
     * AUTO 模式只检查请求行 + 头部是否含非 ASCII。
     * 不看 body，避免被 JSON 中文 / 二进制上传 / gzip / UTF-16 编码 body 误伤。
     * Ghost Bits 真正依赖 char->byte 低位还原的位置都在 request line / headers。
     */
    private boolean shouldUseRawSocket(byte[] requestBytes) {
        if (senderMode == SenderMode.RAW)
            return true;
        if (senderMode == SenderMode.BURP)
            return false;
        // AUTO
        if (requestBytes == null)
            return false;

        // 找到 \r\n\r\n 的位置作为头部结束（兼容 \n\n）
        int headerEnd = findHeaderEnd(requestBytes);
        int upper = headerEnd > 0 ? headerEnd : requestBytes.length;

        for (int i = 0; i < upper; i++) {
            if ((requestBytes[i] & 0xFF) > 0x7F)
                return true;
        }
        return false;
    }

    /**
     * 返回头部结束位置（含分隔符末尾偏移），找不到返回 -1。
     */
    private static int findHeaderEnd(byte[] bytes) {
        if (bytes == null)
            return -1;
        for (int i = 0; i + 3 < bytes.length; i++) {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n'
                    && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                return i + 4;
            }
        }
        for (int i = 0; i + 1 < bytes.length; i++) {
            if (bytes[i] == '\n' && bytes[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1;
    }

    private void updateRedirectAvailability() {
        if (followRedirectCheckBox == null) return;
        boolean raw = shouldUseRawSocket(getRequestBytes());
        followRedirectCheckBox.setEnabled(!raw);
        followRedirectCheckBox.setToolTipText(I18n.t(raw ? "manual.redirect.raw" : "manual.redirect.same_origin"));
    }

    private void cancelRequest() {
        SendRun run = activeSend;
        if (run == null) return;
        run.cancelled = true;
        activeSend = null;
        if (run.thread != null) run.thread.interrupt();
        restoreSendControls();
        statusLabel.setText(I18n.t("manual.cancel.detached"));
        responseContextLabel.setText(I18n.t("manual.cancel.detached"));
    }

    private boolean isCurrent(SendRun run) {
        return activeSend == run && !run.cancelled;
    }

    private void restoreSendControls() {
        sendBtn.setEnabled(true);
        replayOriginalBtn.setEnabled(originalRequest.length > 0);
        setSenderMode(senderMode);
        cancelBtn.setEnabled(false);
    }

    public void dispose() {
        cancelRequest();
        if (inspectorTimer != null) inspectorTimer.stop();
    }

    private void setupShortcuts() {
        if (requestViewer == null)
            return;
        Component editorComponent = requestViewer.getComponent();
        addCtrlEnterListener(editorComponent);
    }

    private void addCtrlEnterListener(Component comp) {
        if (comp instanceof JComponent) {
            JComponent jc = (JComponent) comp;
            KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
            KeyStroke metaEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.META_DOWN_MASK);

            String actionName = "BypassProManualWafSendRequest";

            jc.getInputMap(JComponent.WHEN_FOCUSED).put(ctrlEnter, actionName);
            jc.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(ctrlEnter, actionName);
            jc.getInputMap(JComponent.WHEN_FOCUSED).put(metaEnter, actionName);
            jc.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(metaEnter, actionName);

            jc.getActionMap().put(actionName, new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (sendBtn != null && sendBtn.isEnabled()) {
                        sendRequest();
                    }
                }
            });
        }

        if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                addCtrlEnterListener(child);
            }
        }
    }

    private JPanel createBypassToolsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Bypass Tools"));

        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        tabs.addTab("Obfuscation & Noise", createObfuscationNoisePanel());
        tabs.addTab("Data Encoding", createDataEncodingPanel());
        tabs.addTab("Char Mutation", createUnicodeNormalizationPanel());
        tabs.addTab("Header Bypass", createHeaderSpoofPanel());
        tabs.addTab("Body Bypass", createBodyTransformPanel());
        tabs.addTab("Gh0st Bits", createGhostBitsPanel());

        inspectorRequestLineLabel = createInspectorLine("Request: -");
        inspectorMetaLabel = createInspectorLine("Meta: -");
        inspectorFlagsLabel = createInspectorLine("Flags: -");
        inspectorHintsLabel = createInspectorLine("Payload hints: -");
        inspectorDiffLabel = createInspectorLine("Diff: -");

        Color separatorColor = UIManager.getColor("Separator.foreground");
        if (separatorColor == null) {
            separatorColor = new Color(90, 90, 90);
        }

        JPanel current = new JPanel(new GridLayout(2, 1, 2, 0));
        current.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, separatorColor),
                new EmptyBorder(5, 6, 5, 6)));

        JPanel currentTop = new JPanel(new GridLayout(1, 2, 12, 0));
        currentTop.add(inspectorRequestLineLabel);
        currentTop.add(inspectorMetaLabel);

        JPanel currentBottom = new JPanel(new BorderLayout(12, 0));
        currentBottom.add(inspectorFlagsLabel, BorderLayout.WEST);
        currentBottom.add(inspectorHintsLabel, BorderLayout.CENTER);
        currentBottom.add(inspectorDiffLabel, BorderLayout.EAST);

        current.add(currentTop);
        current.add(currentBottom);

        panel.add(tabs, BorderLayout.CENTER);
        panel.add(current, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createObfuscationNoisePanel() {
        JPanel outer = new JPanel(new BorderLayout());
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(2, 6, 2, 6));

        content.add(createSectionSeparator("Noise Atoms"));

        // ── Noise 作用方式（仅控制 Atoms 区）──
        JPanel targetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JLabel targetLabel = new JLabel(I18n.t("label.noise_target"));
        targetLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        targetPanel.add(targetLabel);

        ButtonGroup targetGroup = new ButtonGroup();
        String[] targets = {"SELECTION", "SUFFIX", "SEG_PREFIX", "SEG_SUFFIX", "INTERLEAVE", "REPLACE_SPACE"};
        for (String target : targets) {
            String labelKey = "tooltip.noise." + target.toLowerCase(Locale.ROOT) + ".title";
            JRadioButton rb = new JRadioButton(I18n.t(labelKey), "SELECTION".equals(target));
            rb.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
            final String val = target;
            rb.setToolTipText(noiseTargetTooltip(val));
            rb.addActionListener(e -> atomTarget = AtomTarget.valueOf(val));
            targetGroup.add(rb);
            targetPanel.add(rb);
        }
        targetPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        targetPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(targetPanel);

        // ── Atoms 区（受 Target 控制）──
        JPanel atomsPanel = createToolCategoryPanel();
        addToolRow(atomsPanel, "Control Chars",
                atomButton("%00"), atomButton("%09"), atomButton("%0a"),
                atomButton("%0d"), atomButton("%20"), atomButton("%0b"),
                atomButton("%0c"));
        addToolRow(atomsPanel, "Space-like",
                atomButton("%a0"), atomButton("%2b"));
        addToolRow(atomsPanel, "Wrappers",
                atomButton("/**/"));
        addToolRow(atomsPanel, "Generated",
                toolButton("Dirty(N)", this::insertDirtyData),
                toolButton("Null(N)", this::insertNullBytes));
        atomsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(atomsPanel);

        // ── Path 专用变形，不受 Noise 作用方式控制 ──
        content.add(createSectionSeparator("Path Mutations"));

        // ── Path Mutations 区（不受 Noise 作用方式控制，每个按钮自带位置语义）──
        JPanel payloadsPanel = createToolCategoryPanel();
        addToolRow(payloadsPanel, "Traversal",
                toolButton("....//", tooltip("Traversal: ....//",
                        I18n.t("tooltip.traversal.selection", "../", "....//"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.path.standard_traversal")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "....//"))),
                toolButton("..%252f", tooltip("Traversal: ..%252f",
                        I18n.t("tooltip.traversal.selection", "../", "..%252f"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.path.double_decode")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "..%252f"))),
                toolButton("..%c0%af", tooltip("Traversal: ..%c0%af",
                        I18n.t("tooltip.traversal.selection", "../", "..%c0%af"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.path.overlong")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "..%c0%af"))),
                toolButton(".%u002e", tooltip("Traversal: .%u002e",
                        I18n.t("tooltip.traversal.selection", "../", ".%u002e/"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.traversal.u002e.usage")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", ".%u002e/"))),
                toolButton("..\\\\", tooltip("Traversal: ..\\\\",
                        I18n.t("tooltip.traversal.selection", "../", "..\\\\"),
                        I18n.t("tooltip.traversal.no_selection", "../"),
                        I18n.t("tooltip.traversal.backslash.usage")),
                        () -> replaceInSelectionOrPath(s -> s.replace("../", "..\\\\"))));
        addToolRow(payloadsPanel, "Suffix",
                toolButton(".js", tooltip("Suffix: .js",
                        I18n.t("tooltip.path.suffix_selection", ".js"),
                        I18n.t("tooltip.path.append_end"),
                        I18n.t("tooltip.path.static_suffix")),
                        () -> appendPathSuffix(".js")),
                toolButton(".css", tooltip("Suffix: .css",
                        I18n.t("tooltip.path.suffix_selection", ".css"),
                        I18n.t("tooltip.path.append_end"),
                        I18n.t("tooltip.path.static_suffix")),
                        () -> appendPathSuffix(".css")),
                toolButton(";.js", tooltip("Suffix: ;.js",
                        I18n.t("tooltip.path.suffix_selection", ";.js"),
                        I18n.t("tooltip.path.append_end"),
                        I18n.t("tooltip.path.semicolon_static")),
                        () -> appendPathSuffix(";.js")),
                toolButton("/.", tooltip("Suffix: /.",
                        I18n.t("tooltip.path.suffix_selection", "/."),
                        I18n.t("tooltip.path.append_end"),
                        I18n.t("tooltip.path.normalization")),
                        () -> appendPathSuffix("/.")),
                toolButton("?", tooltip("Suffix: ?",
                        I18n.t("tooltip.path.suffix_selection", "?"),
                        I18n.t("tooltip.path.append_end"),
                        I18n.t("tooltip.path.query_boundary")),
                        () -> appendPathSuffix("?")));
        addToolRow(payloadsPanel, "Segment",
                toolButton("//", tooltip("Segment: //",
                        I18n.t("tooltip.path.prefix_selection", "//"),
                        I18n.t("tooltip.path.prefix_default", "//"),
                        I18n.t("tooltip.path.double_slash")),
                        () -> prefixEachPathSegment("//")),
                toolButton("/./", tooltip("Segment: /./",
                        I18n.t("tooltip.path.prefix_selection", "/./"),
                        I18n.t("tooltip.path.prefix_default", "/./"),
                        I18n.t("tooltip.path.current_directory")),
                        () -> prefixEachPathSegment("/./")),
                toolButton("/%2e/", tooltip("Segment: /%2e/",
                        I18n.t("tooltip.path.prefix_selection", "/%2e/"),
                        I18n.t("tooltip.path.prefix_default", "/%2e/"),
                        I18n.t("tooltip.path.encoded_directory")),
                        () -> prefixEachPathSegment("/%2e/")),
                toolButton(";/", tooltip("Segment: ;/",
                        I18n.t("tooltip.path.prefix_selection", ";/"),
                        I18n.t("tooltip.path.prefix_default", ";/"),
                        I18n.t("tooltip.path.semicolon_segment")),
                        () -> prefixEachPathSegment(";/")),
                toolButton("./", tooltip("Segment: ./",
                        I18n.t("tooltip.path.prefix_selection", "./"),
                        I18n.t("tooltip.path.prefix_default", "./"),
                        I18n.t("tooltip.path.current_directory")),
                        () -> prefixEachPathSegment("./")),
                toolButton(".;/", tooltip("Segment: .;/",
                        I18n.t("tooltip.path.prefix_selection", ".;/"),
                        I18n.t("tooltip.path.prefix_default", ".;/"),
                        I18n.t("tooltip.path.dot_semicolon")),
                        () -> prefixEachPathSegment(".;/")),
                toolButton("%2e/", tooltip("Segment: %2e/",
                        I18n.t("tooltip.path.prefix_selection", "%2e/"),
                        I18n.t("tooltip.path.prefix_default", "%2e/"),
                        I18n.t("tooltip.path.encoded_dot")),
                        () -> prefixEachPathSegment("%2e/")),
                toolButton("%252e/", tooltip("Segment: %252e/",
                        I18n.t("tooltip.path.prefix_selection", "%252e/"),
                        I18n.t("tooltip.path.prefix_default", "%252e/"),
                        I18n.t("tooltip.path.double_encoded_dot")),
                        () -> prefixEachPathSegment("%252e/")),
                toolButton("..%5c/", tooltip("Segment: ..%5c/",
                        I18n.t("tooltip.path.prefix_selection", "..%5c/"),
                        I18n.t("tooltip.path.prefix_default", "..%5c/"),
                        I18n.t("tooltip.path.encoded_backslash")),
                        () -> prefixEachPathSegment("..%5c/")));
        addToolRow(payloadsPanel, "Boundary",
                toolButton(";", tooltip("Boundary: ;",
                        I18n.t("tooltip.path.suffix_selection", ";"),
                        I18n.t("tooltip.path.append_default", ";"),
                        I18n.t("tooltip.path.matrix_boundary")),
                        () -> appendEachPathSegment(";")),
                toolButton(".;", tooltip("Boundary: .;",
                        I18n.t("tooltip.path.suffix_selection", ".;"),
                        I18n.t("tooltip.path.append_default", ".;"),
                        I18n.t("tooltip.path.dot_semicolon_parse")),
                        () -> appendEachPathSegment(".;")),
                toolButton("..;", tooltip("Boundary: ..;",
                        I18n.t("tooltip.path.suffix_selection", "..;"),
                        I18n.t("tooltip.path.append_default", "..;"),
                        I18n.t("tooltip.path.double_dot_semicolon")),
                        () -> appendEachPathSegment("..;")),
                toolButton(";param=1", tooltip("Boundary: ;param=1",
                        I18n.t("tooltip.path.suffix_selection", ";param=1"),
                        I18n.t("tooltip.path.append_default", ";param=1"),
                        I18n.t("tooltip.path.matrix_params")),
                        () -> appendEachPathSegment(";param=1")),
                toolButton(";jsessionid=1", tooltip("Boundary: ;jsessionid=1",
                        I18n.t("tooltip.path.suffix_selection", ";jsessionid=1"),
                        I18n.t("tooltip.path.append_default", ";jsessionid=1"),
                        I18n.t("tooltip.path.java_session")),
                        () -> appendEachPathSegment(";jsessionid=1")),
                toolButton(";foo=bar", tooltip("Boundary: ;foo=bar",
                        I18n.t("tooltip.path.suffix_selection", ";foo=bar"),
                        I18n.t("tooltip.path.append_default", ";foo=bar"),
                        I18n.t("tooltip.path.semicolon_params")),
                        () -> appendEachPathSegment(";foo=bar")));
        payloadsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(payloadsPanel);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(12);
        outer.add(scroll, BorderLayout.CENTER);
        return outer;
    }

    /** Atoms 区按钮：根据当前 Target 策略决定插入行为 */
    private JButton atomButton(String text) {
        return toolButton(text, atomTooltip(text), () -> applyAtom(text));
    }

    private void applyAtom(String atom) {
        switch (atomTarget) {
            case SUFFIX:
                // 强制追加到 path 末尾，不受选区影响
                mutateRequestPath(path -> {
                    int q = path.indexOf('?');
                    if (q >= 0) {
                        return path.substring(0, q) + atom + path.substring(q);
                    }
                    return path + atom;
                });
                break;
            case SEG_PREFIX:
                // 强制给每个 path segment 加前缀，不受选区影响
                mutateRequestPath(path -> mutatePathOnly(path, seg -> seg.isEmpty() ? seg : atom + seg));
                break;
            case SEG_SUFFIX:
                // 强制给每个 path segment 加后缀，不受选区影响
                mutateRequestPath(path -> mutatePathOnly(path, seg -> seg.isEmpty() ? seg : seg + atom));
                break;
            case INTERLEAVE:
                transformSelection(s -> {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < s.length(); i++) {
                        sb.append(s.charAt(i));
                        if (i < s.length() - 1)
                            sb.append(atom);
                    }
                    return sb.toString();
                });
                break;
            case REPLACE_SPACE:
                if (hasSelectedRequestBytes()) {
                    transformSelection(s -> s.replace(" ", atom));
                } else {
                    // 无选区时替换 path 中的空格
                    mutateRequestPath(path -> path.replace(" ", atom));
                }
                break;
            case SELECTION:
            default:
                insertAt(atom);
                break;
        }
    }

    /** 带标题的分割线 */
    private JPanel createSectionSeparator(String title) {
        JPanel sep = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("── " + resolveSectionTitle(title) + " ──");
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        label.setForeground(new Color(120, 120, 120));
        sep.add(label);
        return sep;
    }

    private JPanel createHeaderSpoofPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Client IP",
                toolButton("XFF 127.0.0.1", () -> upsertRequestHeader("X-Forwarded-For", "127.0.0.1")),
                toolButton("X-Real-IP", () -> upsertRequestHeader("X-Real-IP", "127.0.0.1")),
                toolButton("X-Client-IP", () -> upsertRequestHeader("X-Client-IP", "127.0.0.1")),
                toolButton("X-Remote-Addr", () -> upsertRequestHeader("X-Remote-Addr", "127.0.0.1")),
                toolButton("CF-Connecting-IP", () -> upsertRequestHeader("CF-Connecting-IP", "127.0.0.1")),
                toolButton("Forwarded",
                        () -> upsertRequestHeader("Forwarded", "for=127.0.0.1;proto=http;host=127.0.0.1")));
        addToolRow(p, "Source Trust",
                toolButton("X-Custom-IP", () -> upsertRequestHeader("X-Custom-IP-Authorization", "127.0.0.1")),
                toolButton("Referer local", () -> upsertRequestHeader("Referer", "http://127.0.0.1")),
                toolButton("X-Host local", () -> upsertRequestHeader("X-Host", "127.0.0.1")),
                toolButton("XF Host local", () -> upsertRequestHeader("X-Forwarded-Host", "127.0.0.1")),
                toolButton("X-Original-URL", () -> upsertRequestHeader("X-Original-URL", "/")),
                toolButton("HTTP/1.0", this::switchToHttp10));
        return wrapToolPanel(p);
    }

    private JPanel createBodyTransformPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Type Spoof",
                toolButton("form", () -> setRequestContentType("application/x-www-form-urlencoded")),
                toolButton("text", () -> setRequestContentType("text/plain")),
                toolButton("json", () -> setRequestContentType("application/json")),
                toolButton("xml", () -> setRequestContentType("application/xml")));
        addToolRow(p, "Body Convert",
                toolButton("To Form", this::toFormUrlEncoded),
                toolButton("To Multipart", this::toMultipart),
                toolButton("To JSON", this::toJsonBody));
        addToolRow(p, "Body Wrap",
                toolButton("Gzip body", this::gzipBody));
        return wrapToolPanel(p);
    }

    private JPanel createDataEncodingPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "URL",
                selectionButton("URL Encode", this::urlEncode),
                selectionButton("Path Encode", this::pathUrlEncode),
                selectionButton("Double URL", this::doubleUrlEncode),
                selectionButton("Mixed Encode", this::mixedUrlEncode),
                selectionButton("Unicode 转义", this::toUnicodeEscape));
        addToolRow(p, "Base64",
                selectionButton("Base64 Encode", this::base64Encode));
        addToolRow(p, "Unicode Encoding",
                toolButton("UTF-16", () -> encodeBodyWithCharset("UTF-16")),
                toolButton("UTF-16BE", () -> encodeBodyWithCharset("UTF-16BE")),
                toolButton("UTF-16LE", () -> encodeBodyWithCharset("UTF-16LE")),
                toolButton("UTF-32", () -> encodeBodyWithCharset("UTF-32")),
                toolButton("UTF-32BE", () -> encodeBodyWithCharset("UTF-32BE")),
                toolButton("UTF-32LE", () -> encodeBodyWithCharset("UTF-32LE")));
        addToolRow(p, "EBCDIC Encoding",
                toolButton("IBM037", () -> encodeBodyWithCharset("IBM037")),
                toolButton("cp290", () -> encodeBodyWithCharset("cp290")));
        addToolRow(p, "Charset Params",
                toolButton("charset first", () -> moveCharsetParam(true)),
                toolButton("charset last", () -> moveCharsetParam(false)));
        return wrapToolPanel(p);
    }

    private JPanel createUnicodeNormalizationPanel() {
        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Unicode",
                selectionButton("Fullwidth", this::toFullwidth),
                selectionButton("Homoglyph", this::toHomoglyph),
                selectionButton("Zero Width", this::insertZeroWidth));
        addToolRow(p, "Case",
                selectionButton("Upper", this::toUpper),
                selectionButton("Lower", this::toLower),
                selectionButton("Random", this::toRandomCase));
        return wrapToolPanel(p);
    }

    private JPanel createGhostBitsPanel() {
        JPanel outer = new JPanel(new BorderLayout());

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(2, 6, 2, 6));

        JPanel p = createToolCategoryPanel();
        addToolRow(p, "Ghost Encode",
                selectionButton("Minimal", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.MINIMAL)),
                selectionButton("Full", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.FULL)),
                selectionButton("Letters", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.LETTERS)),
                selectionButton("Digits", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.DIGITS)),
                selectionButton("Symbols", () -> encodeGhostSelection(GhostBitsCodec.EncodeStrategy.SYMBOLS)),
                selectionButton("Shuffle", this::randomizeGhostSelection));
        ghostFold8BitBtn = createFoldModeToggle("8-bit", GhostBitsCodec.FoldMode.BIT_8, true);
        ghostFold7BitBtn = createFoldModeToggle("7-bit", GhostBitsCodec.FoldMode.BIT_7, false);
        ButtonGroup foldGroup = new ButtonGroup();
        foldGroup.add(ghostFold8BitBtn);
        foldGroup.add(ghostFold7BitBtn);
        addToolRow(p, "Fold Check",
                selectionButton("Preview", this::showFoldPreview),
                selectionButton("Candidates", this::showGhostCandidates),
                ghostFold8BitBtn, ghostFold7BitBtn);
        addToolRow(p, "Common Payload",
                toolButton(".%u002e", () -> applyGhostSequence(".%u002e", "Path traversal chain: .%u002e -> ..")),
                toolButton("CRLF", () -> applyGhostSequence("\r\n", "CRLF pair for header/SMTP boundaries")),
                toolButton(".jsp", () -> applyGhostSequence(".jsp", "JSP suffix: Ghost restore -> .jsp")),
                toolButton("@type", () -> applyGhostSequence("@type", "JSON key: @type")),
                toolButton("class", () -> applyGhostSequence("class", "Java/Spring key: class")));
        addToolRow(p, "JSON Parser",
                toolButton("fastjson \\x4_", this::applyFastjsonLooseHexSelection),
                toolButton("fastjson \\u", this::applyFastjsonUnicodeSelection),
                toolButton("jackson \\u", this::applyJacksonUnicodeSelection),
                toolButton("Unicode Digits", this::applyUnicodeDigitsSelection));
        addToolRow(p, "URL/File Parser",
                toolButton("Jetty %2>", this::applyJettyLooseHexSelection),
                toolButton("Fullwidth URL", this::applyFullwidthUrlSelection),
                toolButton("Tomcat %HH", this::applyTomcatSevenBitHexSelection));
        ghostTemplatePathRow = addTemplateWrapRow(p, "Templates",
                createAllGhostTemplateButtons());
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(p);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(12);

        outer.add(scroll, BorderLayout.CENTER);
        outer.add(createGhostCompactPreviewPanel(), BorderLayout.SOUTH);
        return outer;
    }

    private JPanel createGhostCompactPreviewPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 1, 2, 1));
        Color separatorColor = UIManager.getColor("Separator.foreground");
        if (separatorColor == null) {
            separatorColor = new Color(90, 90, 90);
        }
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, separatorColor),
                new EmptyBorder(4, 6, 3, 6)));

        ghostSelectionFoldLabel = createGhostPreviewLine(
                I18n.t("ghost.selection_fold") + ": " + I18n.t("ghost.risk.select"));
        ghostPreviewRiskLabel = createGhostPreviewLine(I18n.t("ghost.risk") + ": -");

        panel.add(ghostSelectionFoldLabel);
        panel.add(ghostPreviewRiskLabel);
        return panel;
    }

    private JLabel createGhostPreviewLine(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        label.setBorder(new EmptyBorder(0, 2, 0, 2));
        return label;
    }

    private JPanel createToolCategoryPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new EmptyBorder(4, 6, 4, 6));
        return p;
    }

    private JPanel wrapToolPanel(JPanel content) {
        JPanel outer = new JPanel(new BorderLayout());
        outer.add(content, BorderLayout.NORTH);
        return outer;
    }

    /**
     * 配置变更后刷新 Templates 行按钮（由 ConfigPanel reload/reinit 调用）。
     */
    public void refreshGhostTemplates() {
        if (ghostTemplatePathRow == null) {
            return;
        }
        ghostTemplatePathRow.removeAll();
        for (JComponent btn : createAllGhostTemplateButtons()) {
            ghostTemplatePathRow.add(btn);
        }
        ghostTemplatePathRow.revalidate();
        ghostTemplatePathRow.repaint();
    }

    private JComponent[] createAllGhostTemplateButtons() {
        Map<String, GhostBitsRule.Template> templates = Utils.getGhostBitsRule().getTemplates();
        List<JComponent> buttons = new ArrayList<>();
        for (GhostBitsRule.Template t : templates.values()) {
            buttons.add(toolButton(templateButtonText(t), ghostTemplateTooltip(t), () -> applyGhostTemplate(t)));
        }
        if (buttons.isEmpty()) {
            JButton empty = toolButton("No templates",
                    I18n.t("tooltip.no_templates"), () -> {
                    });
            empty.setEnabled(false);
            return new JComponent[] { empty };
        }
        return buttons.toArray(new JComponent[0]);
    }

    private String templateButtonText(GhostBitsRule.Template t) {
        String label = I18n.t(t.getLabel());
        if (label == null || label.trim().isEmpty()) {
            label = t.getId();
        }
        if (label == null || label.trim().isEmpty()) {
            label = "template";
        }
        return label.length() > 22 ? label.substring(0, 19) + "..." : label;
    }

    private String ghostTemplateTooltip(GhostBitsRule.Template t) {
        String label = t.getLabel() == null || t.getLabel().isEmpty() ? t.getId() : I18n.t(t.getLabel());
        return tooltip(label,
                I18n.t("template.source", t.getId()),
                I18n.t("template.target", t.getTarget()),
                I18n.t("template.sender", "raw".equalsIgnoreCase(t.getSender()) ? "Raw Socket recommended" : "Burp OK / Raw OK"),
                I18n.t("template.action"),
                I18n.t("template.notes", t.getNotes() == null || t.getNotes().isEmpty() ? "-" : I18n.t(t.getNotes())));
    }

    private JPanel addToolRow(JPanel panel, String label, JComponent... items) {
        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0;
        left.gridy = panel.getComponentCount() / 2;
        left.anchor = GridBagConstraints.WEST;
        left.insets = new Insets(2, 0, 2, 8);

        JLabel rowLabel = new JLabel(resolveRowLabel(label) + ":");
        rowLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        panel.add(rowLabel, left);

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        for (JComponent item : items)
            row.add(item);

        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1;
        right.gridy = left.gridy;
        right.weightx = 1.0;
        right.fill = GridBagConstraints.HORIZONTAL;
        right.anchor = GridBagConstraints.WEST;
        right.insets = new Insets(2, 0, 2, 0);
        panel.add(row, right);
        return row;
    }

    private static final int TEMPLATE_COLS = 4;

    private JPanel addTemplateWrapRow(JPanel panel, String label, JComponent... items) {
        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0;
        left.gridy = panel.getComponentCount() / 2;
        left.anchor = GridBagConstraints.NORTHWEST;
        left.insets = new Insets(4, 0, 2, 8);

        JLabel rowLabel = new JLabel(resolveRowLabel(label) + ":");
        rowLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        panel.add(rowLabel, left);

        int rows = Math.max(1, (items.length + TEMPLATE_COLS - 1) / TEMPLATE_COLS);
        JPanel row = new JPanel(new GridLayout(rows, TEMPLATE_COLS, 4, 3));
        for (JComponent item : items)
            row.add(item);

        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1;
        right.gridy = left.gridy;
        right.weightx = 1.0;
        right.fill = GridBagConstraints.HORIZONTAL;
        right.anchor = GridBagConstraints.WEST;
        right.insets = new Insets(2, 0, 2, 0);
        panel.add(row, right);
        return row;
    }

    private JButton toolButton(String text, Runnable action) {
        return toolButton(text, defaultTooltip(text), action);
    }

    /**
     * 把传入的稳定按钮文本 key 转换为当前语言下的显示文本。
     * 转换规则：尝试 I18n 查 "btn.{slug}"，失败则原样返回。
     * 调用方传入的是稳定文本 key（如 "Minimal" / "URL Encode" / "Unicode 转义"），
     * tooltip 查询、case 匹配都可以继续按原始 key 运作。
     */
    private static String resolveBtnText(String key) {
        if (key == null || key.isEmpty()) {
            return key;
        }
        String lookup = "btn." + slugifyForI18n(key);
        String t = I18n.t(lookup);
        return t.equals(lookup) ? key : t;
    }

    private static String resolveRowLabel(String key) {
        if (key == null || key.isEmpty()) {
            return key;
        }
        String lookup = "row." + slugifyForI18n(key);
        String t = I18n.t(lookup);
        return t.equals(lookup) ? key : t;
    }

    private static String resolveSectionTitle(String key) {
        if (key == null || key.isEmpty()) {
            return key;
        }
        String lookup = "sec." + slugifyForI18n(key);
        String t = I18n.t(lookup);
        return t.equals(lookup) ? key : t;
    }

    /** 用于生成 i18n key 的简单 slug，统一委托给 {@link I18n#slug(String)}。 */
    private static String slugifyForI18n(String s) {
        return I18n.slug(s);
    }

    private JButton selectionButton(String text, Runnable action) {
        JButton button = toolButton(text, action);
        button.putClientProperty("selectionTooltip", button.getToolTipText());
        selectionButtons.add(button);
        updateSelectionButton(button, false);
        return button;
    }

    private void updateSelectionButton(JButton button, boolean selected) {
        button.setEnabled(selected);
        String original = (String) button.getClientProperty("selectionTooltip");
        button.setToolTipText(selected ? original : I18n.t("manual.selection.required") + "\n" + original);
    }

    private JButton toolButton(String text, String tooltip, Runnable action) {
        // text 作为稳定 key，UI 显示用当前语言版本
        String displayText = resolveBtnText(text);
        JButton btn = new JButton(displayText) {
            @Override
            public JToolTip createToolTip() {
                JToolTip tip = new MultiLineToolTip();
                tip.setComponent(this);
                return tip;
            }
        };
        btn.setMargin(new Insets(3, 7, 3, 7));
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        btn.setFocusPainted(false);
        if (tooltip != null && !tooltip.isEmpty()) {
            btn.setToolTipText(tooltip);
        }
        btn.addActionListener(e -> {
            byte[] before = getRequestBytes().clone();
            runRequestMutation(action, displayText);
            byte[] after = getRequestBytes();
            if (!Arrays.equals(before, after))
                statusLabel.setText(I18n.t("manual.mutation", displayText, before.length, after.length));
        });
        return btn;
    }

    private String tooltip(String title, String... lines) {
        StringBuilder sb = new StringBuilder(title);
        for (String line : lines) {
            sb.append('\n').append(line);
        }
        return sb.toString();
    }

    /**
     * 根据按钮文本（稳定 key，如 "Minimal" / "URL Encode" / "Unicode 转义"）从 I18n 拼接 tooltip。
     * 约定 I18n 中存在 "tooltip.{slug}.title" 和 "tooltip.{slug}.desc" 两条 key。
     * desc 中可包含 \n 用于多行展示。
     * 未注册时返回 null，由调用方提供通用或当前操作专用的提示。
     */
    private String i18nTooltipFor(String key) {
        String slug = slugifyForI18n(key);
        if (slug.isEmpty()) {
            return null;
        }
        String titleKey = "tooltip." + slug + ".title";
        String descKey = "tooltip." + slug + ".desc";
        String title = I18n.t(titleKey);
        String desc = I18n.t(descKey);
        if (title.equals(titleKey) && desc.equals(descKey)) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(title.equals(titleKey) ? key : title);
        if (!desc.equals(descKey)) {
            for (String line : desc.split("\n")) {
                sb.append('\n').append(line);
            }
        }
        return sb.toString();
    }

    private String noiseTargetTooltip(String target) {
        // 复用 i18n：tooltip.noise.{key}.title / .desc1 / .desc2
        // 切语言只需在 I18nKeys 里维护对应 key，这里不必再写两套字符串
        String slug;
        switch (target) {
            case "SELECTION":
                slug = "selection";
                break;
            case "SUFFIX":
                slug = "suffix";
                break;
            case "SEG_PREFIX":
                slug = "seg_prefix";
                break;
            case "SEG_SUFFIX":
                slug = "seg_suffix";
                break;
            case "INTERLEAVE":
                slug = "interleave";
                break;
            case "REPLACE_SPACE":
                slug = "replace_space";
                break;
            default:
                return null;
        }
        return tooltip(
                I18n.t("tooltip.noise." + slug + ".title"),
                I18n.t("tooltip.noise." + slug + ".desc1"),
                I18n.t("tooltip.noise." + slug + ".desc2"));
    }

    private String atomTooltip(String atom) {
        String key = "tooltip.atom." + atom;
        String description = I18n.t(key);
        if (description.equals(key)) {
            description = I18n.t("tooltip.atom.generic");
        }
        return tooltip("Noise Atom: " + atom, description);
    }

    private String defaultTooltip(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        // 优先从 I18n 取双语 tooltip。注册了 "tooltip.{slug}.title" / ".desc" 的按钮走这条路径。
        String i18nTooltip = i18nTooltipFor(text);
        if (i18nTooltip != null) {
            return i18nTooltip;
        }
        return tooltip(resolveBtnText(text), I18n.t("tooltip.default.desc"));
    }

    private static class MultiLineToolTip extends JToolTip {
        private static final int PAD_X = 8;
        private static final int PAD_Y = 5;
        private static final int GAP = 2;

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            String[] lines = getLines();
            int width = 0;
            for (String line : lines) {
                width = Math.max(width, fm.stringWidth(line));
            }
            int height = lines.length * fm.getHeight() + Math.max(0, lines.length - 1) * GAP;
            Insets insets = getInsets();
            return new Dimension(width + PAD_X * 2 + insets.left + insets.right,
                    height + PAD_Y * 2 + insets.top + insets.bottom);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setColor(getBackground());
                g2.fillRect(0, 0, getWidth(), getHeight());
                g2.setFont(getFont());
                g2.setColor(getForeground());
                FontMetrics fm = g2.getFontMetrics();
                Insets insets = getInsets();
                int x = insets.left + PAD_X;
                int y = insets.top + PAD_Y + fm.getAscent();
                for (String line : getLines()) {
                    g2.drawString(line, x, y);
                    y += fm.getHeight() + GAP;
                }
            } finally {
                g2.dispose();
            }
        }

        private String[] getLines() {
            String text = getTipText();
            if (text == null || text.isEmpty()) {
                return new String[] { "" };
            }
            return text.split("\\R", -1);
        }
    }

    private JLabel createInspectorLine(String text) {
        JLabel label = new JLabel(text) {
            @Override
            public String getToolTipText() { return getText(); }
        };
        label.setToolTipText(text);
        label.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private void startRequestInspectorTimer() {
        inspectorTimer = new Timer(400, e -> refreshRequestInspector());
        inspectorTimer.setInitialDelay(200);
        inspectorTimer.start();
    }

    private void refreshRequestInspector() {
        if (inspectorRequestLineLabel == null || requestViewer == null)
            return;
        byte[] req = getRequestBytes();
        byte[] sel = getSelectedRequestBytes();
        byte[] safeReq = req == null ? new byte[0] : req;
        byte[] safeSel = sel == null ? new byte[0] : sel;
        boolean sameReq = Arrays.equals(safeReq, lastInspectorBytes);
        boolean sameSelection = Arrays.equals(safeSel, lastInspectorSelectionBytes);
        for (JButton button : selectionButtons) updateSelectionButton(button, safeSel.length > 0);
        if (scopeLabel != null) scopeLabel.setText(safeSel.length > 0
                ? I18n.t("manual.scope.selection", safeSel.length) : I18n.t("manual.scope.none"));
        if (activeSend != null) {
            statusLabel.setText(I18n.t("manual.sending.elapsed", (System.nanoTime() - activeSend.startNs) / 1000000000L));
        }
        reconcileTransformations(safeReq);
        updateTransformationLabel();
        replayOriginalBtn.setEnabled(activeSend == null && originalRequest.length > 0);
        restoreOriginalBtn.setEnabled(originalRequest.length > 0 && !Arrays.equals(safeReq, originalRequest));
        if (sameReq && sameSelection) return;

        if (!sameReq) {
            lastInspectorBytes = Arrays.copyOf(safeReq, safeReq.length);
            updateRequestInspector(lastInspectorBytes);
            updateRedirectAvailability();
            if (activeSend == null) showSelectedResponse();
        }
        if (!sameSelection) {
            lastInspectorSelectionBytes = Arrays.copyOf(safeSel, safeSel.length);
            updateGhostCompactPreview(lastInspectorSelectionBytes);
        }
    }

    private void updateRequestInspector(byte[] req) {
        if (req == null || req.length == 0) {
            inspectorRequestLineLabel.setText("Request: -");
            inspectorMetaLabel.setText("Meta: -");
            inspectorFlagsLabel.setText("Flags: -");
            inspectorHintsLabel.setText("Payload hints: -");
            inspectorDiffLabel.setText("Diff: -");
            return;
        }

        String requestLine = firstLine(req);
        inspectorRequestLineLabel.setText("Request: " + truncateForInspector(requestLine, 110));

        int headerEnd = findHeaderEnd(req);
        int bodyLen = headerEnd > 0 ? Math.max(0, req.length - headerEnd) : 0;
        String contentType = headerValueFromRequest(req, "Content-Type");
        String cl = headerValueFromRequest(req, "Content-Length");
        inspectorMetaLabel.setText("Meta: " + req.length + " bytes"
                + " | body " + bodyLen
                + (cl == null ? "" : " | CL " + cl)
                + (contentType == null ? "" : " | " + truncateForInspector(contentType, 48)));

        List<String> flags = new ArrayList<>();
        if (shouldUseRawSocket(req))
            flags.add("Raw recommended");
        if (containsNonAsciiBeforeBody(req))
            flags.add("non-ASCII line/header");
        if (contentType != null && contentType.toLowerCase().contains("multipart"))
            flags.add("multipart");
        if (new String(req, StandardCharsets.ISO_8859_1).toLowerCase().contains("filename"))
            flags.add("filename");
        if (isContentLengthTampered(req))
            flags.add("CL tampered");
        inspectorFlagsLabel.setText("Flags: " + (flags.isEmpty() ? "-" : String.join(", ", flags)));

        String text = new String(req, StandardCharsets.UTF_8);
        String hints = buildParserIntent(text);
        inspectorHintsLabel
                .setText(I18n.t("inspector.payload_hints") + ": " + (I18n.t("inspector.custom_payload").equals(hints) ? "-" : truncateForInspector(hints, 110)));

        inspectorDiffLabel.setText("Diff: " + buildRequestDiffSummary(req));
    }

    private String foldModeTag() {
        return "[" + GhostBitsCodec.foldModeLabel(ghostFoldMode) + "]";
    }

    private void updateGhostCompactPreview(byte[] selectedBytes) {
        if (ghostSelectionFoldLabel == null) {
            return;
        }
        if (parserPreviewPayload != null && !findAllOccurrences(getRequestBytes(), parserPreviewBytes).isEmpty()) {
            showParserPreview(parserPreviewName, parserPreviewPayload, parserPreviewBytes);
            return;
        }
        parserPreviewPayload = null;
        if (selectedBytes == null || selectedBytes.length == 0) {
            ghostSelectionFoldLabel.setText(I18n.t("ghost.selection_fold") + " " + foldModeTag()
                    + ": " + I18n.t("ghost.risk.select"));
            ghostPreviewRiskLabel.setText(I18n.t("ghost.risk") + ": -");
            ghostPreviewRiskLabel.setForeground(UIManager.getColor("Label.foreground"));
            return;
        }

        String selected = new String(selectedBytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(selected.getBytes(StandardCharsets.UTF_8), selectedBytes)) {
            ghostSelectionFoldLabel
                    .setText(I18n.t("ghost.selection_fold") + ": non UTF-8 bytes (" + selectedBytes.length + ")");
            ghostPreviewRiskLabel.setText(I18n.t("ghost.risk") + ": " + I18n.t("ghost.risk.unsupported"));
            ghostPreviewRiskLabel.setForeground(new Color(170, 70, 20));
            return;
        }

        String folded = GhostBitsCodec.fold(selected, ghostFoldMode);
        updateGhostSelectionFoldPreview(selected, folded, false);
    }

    private void updateGhostSelectionFoldPreview(String selected, String folded, boolean rawRecommended) {
        parserPreviewPayload = null;
        if (ghostSelectionFoldLabel == null || ghostPreviewRiskLabel == null) {
            return;
        }
        String safeSelected = selected == null ? "" : selected;
        String safeFolded = folded == null ? "" : folded;
        String decoded = decodeUrlForPreview(safeFolded);
        String risk = ghostFoldRisk(safeSelected, safeFolded, decoded);
        if (rawRecommended) {
            risk = "-".equals(risk) ? "Raw Socket recommended" : risk + " | Raw Socket recommended";
        }

        ghostSelectionFoldLabel.setText(I18n.t("ghost.selection_fold") + " " + foldModeTag() + ": "
                + truncateForInspector(escape(safeSelected), 42)
                + " -> " + truncateForInspector(escape(safeFolded), 42)
                + " -> URL: " + truncateForInspector(escape(decoded), 42));
        ghostPreviewRiskLabel.setText(I18n.t("ghost.risk") + ": " + risk);
        ghostPreviewRiskLabel.setForeground("-".equals(risk)
                ? UIManager.getColor("Label.foreground")
                : new Color(190, 70, 30));
    }

    private String decodeUrlForPreview(String folded) {
        if (folded == null || folded.isEmpty()) {
            return "";
        }
        try {
            return URLDecoder.decode(folded, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return folded;
        }
    }

    private String ghostFoldRisk(String selected, String folded, String decoded) {
        if (selected == null || selected.isEmpty()) {
            return "-";
        }
        List<String> risks = new ArrayList<>();
        for (int i = 0; i < selected.length(); i++) {
            char original = selected.charAt(i);
            char low = i < folded.length() ? folded.charAt(i) : 0;
            if (original == low) {
                continue;
            }
            switch (low) {
                case '.':
                    risks.add(". path");
                    break;
                case '/':
                case '\\':
                    risks.add("separator");
                    break;
                case '%':
                    risks.add("% decode");
                    break;
                case '\r':
                case '\n':
                    risks.add("CRLF");
                    break;
                case '@':
                    risks.add("@ key");
                    break;
                case '<':
                case '>':
                case '\'':
                case '"':
                    risks.add("syntax");
                    break;
                case ':':
                case ';':
                    risks.add("delimiter");
                    break;
                default:
                    break;
            }
        }
        if (decoded != null && !decoded.equals(folded)) {
            if (decoded.contains(".."))
                risks.add("URL -> ..");
            if (decoded.indexOf('\r') >= 0 || decoded.indexOf('\n') >= 0)
                risks.add("URL -> CRLF");
        }
        if (risks.isEmpty()) {
            return "-";
        }
        return truncateForInspector(String.join(", ", uniqueStrings(risks)), 54);
    }

    private List<String> uniqueStrings(List<String> values) {
        List<String> unique = new ArrayList<>();
        for (String value : values) {
            if (!unique.contains(value)) {
                unique.add(value);
            }
        }
        return unique;
    }

    private static String firstLine(byte[] req) {
        int end = -1;
        for (int i = 0; i < req.length; i++) {
            if (req[i] == '\n') {
                end = i;
                break;
            }
        }
        if (end < 0)
            end = Math.min(req.length, 160);
        if (end > 0 && req[end - 1] == '\r')
            end--;
        return new String(req, 0, end, StandardCharsets.UTF_8);
    }

    private String headerValueFromRequest(byte[] req, String name) {
        int headerEnd = findHeaderEnd(req);
        int upper = headerEnd > 0 ? headerEnd : req.length;
        String headers = new String(req, 0, upper, StandardCharsets.ISO_8859_1);
        String[] lines = headers.split("\\r?\\n");
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0)
                continue;
            if (line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private boolean containsNonAsciiBeforeBody(byte[] req) {
        int headerEnd = findHeaderEnd(req);
        int upper = headerEnd > 0 ? headerEnd : req.length;
        for (int i = 0; i < upper; i++) {
            if ((req[i] & 0xFF) > 0x7F)
                return true;
        }
        return false;
    }

    private String buildRequestDiffSummary(byte[] req) {
        return requestDiffSummary(originalRequest, req);
    }

    static String requestDiffSummary(byte[] originalRequest, byte[] req) {
        if (originalRequest == null || originalRequest.length == 0) return I18n.t("diff.no_original");
        if (Arrays.equals(originalRequest, req)) return I18n.t("diff.unchanged");
        List<String> parts = new ArrayList<>();
        if (!firstLine(originalRequest).equals(firstLine(req))) parts.add(I18n.t("diff.line"));
        int oldEnd = findHeaderEnd(originalRequest), newEnd = findHeaderEnd(req);
        oldEnd = oldEnd < 0 ? originalRequest.length : oldEnd;
        newEnd = newEnd < 0 ? req.length : newEnd;
        int oldLineEnd = firstLineEnd(originalRequest), newLineEnd = firstLineEnd(req);
        if (!Arrays.equals(Arrays.copyOfRange(originalRequest, oldLineEnd, oldEnd),
                Arrays.copyOfRange(req, newLineEnd, newEnd))) parts.add(I18n.t("diff.headers"));
        if (!Arrays.equals(Arrays.copyOfRange(originalRequest, oldEnd, originalRequest.length),
                Arrays.copyOfRange(req, newEnd, req.length)))
            parts.add(I18n.t("diff.body", originalRequest.length - oldEnd, req.length - newEnd));
        return String.join(", ", parts);
    }

    private static int firstLineEnd(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) if (bytes[i] == '\n') return i + 1;
        return bytes.length;
    }

    private String truncateForInspector(String value, int max) {
        if (value == null)
            return "-";
        if (value.length() <= max)
            return value;
        return value.substring(0, Math.max(0, max - 3)) + "...";
    }

    private String buildParserIntent(String payload) {
        if (payload == null || payload.isEmpty()) {
            return I18n.t("inspector.empty_payload");
        }
        List<String> hints = new ArrayList<>();
        if (payload.contains("阮严灵丰丰甲来"))
            hints.add("阮严灵丰丰甲来 => .%u002e");
        if (payload.contains("陪sp"))
            hints.add("陪sp => jsp");
        if (payload.contains("瘍瘊"))
            hints.add("瘍瘊 => \\r\\n");
        if (payload.contains("%2>"))
            hints.add("%2> => %2E => .");
        if (payload.contains("%6>"))
            hints.add("%6> => %6E => n");
        if (payload.contains("%64"))
            hints.add("%64 => d");
        if (hints.isEmpty()) {
            String folded = GhostBitsEngine.foldToAscii(payload);
            if (!folded.equals(payload)) {
                hints.add("low-byte => " + escape(folded));
            }
        }
        return hints.isEmpty() ? I18n.t("inspector.custom_payload") : String.join("; ", hints);
    }

    private JPanel createHistoryPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEtchedBorder());
        panel.setMinimumSize(new Dimension(240, 0));
        JPanel heading = new JPanel(new BorderLayout(10, 0));
        heading.setBorder(new EmptyBorder(4, 6, 4, 6));
        heading.add(new JLabel("History"), BorderLayout.WEST);
        JLabel hint = new JLabel(I18n.t("manual.history.short_hint"));
        hint.setHorizontalAlignment(SwingConstants.RIGHT);
        hint.setToolTipText(I18n.t("manual.history.hint"));
        heading.add(hint, BorderLayout.CENTER);
        panel.add(heading, BorderLayout.NORTH);

        historyModel = new HistoryTableModel();
        historyTable = new JTable(historyModel);
        historyTable.setAutoCreateRowSorter(true);
        historyTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {36, 65, 60, 180, 55, 80, 90, 80, 200};
        for (int i = 0; i < widths.length; i++) {
            historyTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        // 状态、方法和路径优先可见；通道、耗时及网络目标可横向查看。
        historyTable.moveColumn(4, 1);
        historyTable.moveColumn(2, 6);
        historyTable.getTableHeader().setToolTipText(I18n.t("manual.history.hint"));

        // 单击：选中历史记录并显示摘要
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = historyTable.getSelectedRow();
                if (row >= 0) {
                    int modelRow = historyTable.convertRowIndexToModel(row);
                    showHistoryEntry(modelRow);
                }
            }
        });

        // 双击：加载请求到编辑器
        historyTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                if (evt.getClickCount() == 2) {
                    int row = historyTable.rowAtPoint(evt.getPoint());
                    if (row >= 0) {
                        int modelRow = historyTable.convertRowIndexToModel(row);
                        loadHistoryRequest(modelRow);
                    }
                }
            }

            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                showHistoryPopup(evt);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                showHistoryPopup(evt);
            }
        });

        panel.add(new JScrollPane(historyTable), BorderLayout.CENTER);
        return panel;
    }

    private void showHistoryPopup(java.awt.event.MouseEvent evt) {
        if (!evt.isPopupTrigger())
            return;
        int row = historyTable.rowAtPoint(evt.getPoint());
        if (row < 0)
            return;
        historyTable.setRowSelectionInterval(row, row);
        int modelRow = historyTable.convertRowIndexToModel(row);

        JPopupMenu popup = new JPopupMenu();
        JMenuItem loadItem = new JMenuItem(I18n.t("manual.history.load"));
        loadItem.addActionListener(e -> loadHistoryRequest(modelRow));
        popup.add(loadItem);

        JMenuItem deleteItem = new JMenuItem(I18n.t("manual.history.delete"));
        deleteItem.addActionListener(e -> {
            if (modelRow >= 0 && modelRow < historyEntries.size()) {
                historyEntries.remove(modelRow);
                historyModel.fireTableDataChanged();
            }
        });
        popup.add(deleteItem);

        popup.show(evt.getComponent(), evt.getX(), evt.getY());
    }

    private void loadHistoryRequest(int index) {
        if (index < 0 || index >= historyEntries.size()) return;
        HistoryEntry entry = historyEntries.get(index);
        IHttpService service = entry.service != null ? entry.service
                : entry.requestResponse == null ? null : entry.requestResponse.getHttpService();
        if (service == null) {
            statusLabel.setText(I18n.t("manual.history.no_target"));
            return;
        }
        if (!confirmReplaceRequest(entry.requestBytes)) return;
        loadRequest(new BypassMain.SimpleHttpRequestResponse(service, entry.requestBytes, entry.responseBytes));
        setSenderMode("Raw".equals(entry.sender) ? SenderMode.RAW : SenderMode.BURP);
        statusLabel.setText(I18n.t("status.history_loaded", entry.id));
    }

    private boolean confirmReplaceRequest(byte[] incoming) {
        byte[] current = getRequestBytes();
        if (current.length == 0 || Arrays.equals(current, incoming) || Arrays.equals(current, originalRequest)
                || Arrays.equals(current, lastSubmittedRequest)) return true;
        return JOptionPane.showConfirmDialog(this, I18n.t("manual.replace.confirm"),
                I18n.t("dialog.tip.title"), JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION;
    }

    public boolean acceptRequest(IHttpRequestResponse message) {
        if (message == null || !confirmReplaceRequest(message.getRequest())) return false;
        loadRequest(message);
        return true;
    }

    private void replaceInSelectionOrPath(java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel != null && sel.length > 0) {
            transformSelection(transformer);
            return;
        }
        String path = getRequestPath();
        if (path != null && transformer.apply(path).equals(path)) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.path_no_target"),
                    I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        mutateRequestPath(transformer);
    }

    private void appendPathSuffix(String suffix) {
        if (hasSelectedRequestBytes()) {
            transformSelection(s -> s + suffix);
            return;
        }
        mutateRequestPath(path -> {
            if ("?".equals(suffix)) {
                return path.contains("?") ? path + "&" : path + "?";
            }
            int q = path.indexOf('?');
            if (q >= 0) {
                return path.substring(0, q) + suffix + path.substring(q);
            }
            return path + suffix;
        });
    }

    private void prefixEachPathSegment(String prefix) {
        if (hasSelectedRequestBytes()) {
            transformSelection(s -> prefix + s);
            return;
        }
        mutateRequestPath(path -> mutatePathOnly(path, segment -> segment.isEmpty() ? segment : prefix + segment));
    }

    private void appendEachPathSegment(String suffix) {
        if (hasSelectedRequestBytes()) {
            transformSelection(s -> s + suffix);
            return;
        }
        mutateRequestPath(path -> mutatePathOnly(path, segment -> segment.isEmpty() ? segment : segment + suffix));
    }

    private boolean hasSelectedRequestBytes() {
        byte[] sel = getSelectedRequestBytes();
        return sel != null && sel.length > 0;
    }

    private String mutatePathOnly(String path, java.util.function.Function<String, String> segmentMutator) {
        int q = path.indexOf('?');
        String pathOnly = q >= 0 ? path.substring(0, q) : path;
        String query = q >= 0 ? path.substring(q) : "";
        String[] parts = pathOnly.split("/", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0)
                out.append('/');
            out.append(segmentMutator.apply(parts[i]));
        }
        return out + query;
    }

    private void mutateRequestPath(java.util.function.Function<String, String> transformer) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int lineEnd = -1;
        for (int i = 0; i < req.length; i++) {
            if (req[i] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd <= 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_line_missing"), I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int realLineEnd = lineEnd;
        if (realLineEnd > 0 && req[realLineEnd - 1] == '\r')
            realLineEnd--;

        int firstSpace = -1;
        int secondSpace = -1;
        for (int i = 0; i < realLineEnd; i++) {
            if (req[i] == ' ') {
                if (firstSpace < 0)
                    firstSpace = i;
                else {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.path_not_found"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int pathStart = firstSpace + 1;
        int pathEnd = secondSpace;
        String path = new String(req, pathStart, pathEnd - pathStart, StandardCharsets.ISO_8859_1);
        String mutated = transformer.apply(path);
        byte[] replacement = mutated.getBytes(StandardCharsets.ISO_8859_1);

        byte[] out = new byte[req.length - (pathEnd - pathStart) + replacement.length];
        System.arraycopy(req, 0, out, 0, pathStart);
        System.arraycopy(replacement, 0, out, pathStart, replacement.length);
        System.arraycopy(req, pathEnd, out, pathStart + replacement.length, req.length - pathEnd);
        setRequestBytes(out);
    }

    private String getRequestPath() {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            return null;
        }

        int lineEnd = -1;
        for (int i = 0; i < req.length; i++) {
            if (req[i] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd <= 0) {
            return null;
        }
        int realLineEnd = lineEnd;
        if (realLineEnd > 0 && req[realLineEnd - 1] == '\r')
            realLineEnd--;

        int firstSpace = -1;
        int secondSpace = -1;
        for (int i = 0; i < realLineEnd; i++) {
            if (req[i] == ' ') {
                if (firstSpace < 0)
                    firstSpace = i;
                else {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0) {
            return null;
        }
        return new String(req, firstSpace + 1, secondSpace - firstSpace - 1, StandardCharsets.ISO_8859_1);
    }

    private void upsertRequestHeader(String name, String value) {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        updateOrAddHeader(headers, name, value);
        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private void setRequestContentType(String value) {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        updateOrAddHeader(headers, "Content-Type", value);
        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private void moveCharsetParam(boolean first) {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        int idx = findHeaderIndex(headers, "Content-Type");
        if (idx < 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.content_type_missing"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String line = headers.get(idx);
        int colon = line.indexOf(':');
        if (colon < 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.content_type_invalid"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String value = line.substring(colon + 1).trim();
        String reordered = reorderCharsetParam(value, first);
        if (reordered == null) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.charset_missing"),
                    I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        headers.set(idx, "Content-Type: " + reordered);
        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private String reorderCharsetParam(String contentType, boolean first) {
        if (contentType == null || contentType.trim().isEmpty()) {
            return null;
        }
        String[] rawParts = contentType.split(";");
        if (rawParts.length < 2) {
            return null;
        }
        String mediaType = rawParts[0].trim();
        List<String> params = new ArrayList<>();
        String charset = null;
        for (int i = 1; i < rawParts.length; i++) {
            String p = rawParts[i].trim();
            if (p.isEmpty())
                continue;
            if (p.toLowerCase().startsWith("charset=")) {
                charset = p;
            } else {
                params.add(p);
            }
        }
        if (charset == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(mediaType);
        if (first) {
            sb.append("; ").append(charset);
        }
        for (String p : params) {
            sb.append("; ").append(p);
        }
        if (!first) {
            sb.append("; ").append(charset);
        }
        return sb.toString();
    }

    // --- Transform ---

    private void urlEncode() {
        transformSelectionWithNoChangeOption(
                s -> {
                    try {
                        return URLEncoder.encode(s, "ISO-8859-1");
                    } catch (UnsupportedEncodingException e) {
                        return s;
                    }
                },
                I18n.t("dialog.force_url_encode"),
                this::percentEncodeAllBytes);
    }

    private void pathUrlEncode() {
        transformSelectionWithNoChangeOption(
                this::encodePathValue,
                I18n.t("dialog.force_path_encode"),
                this::percentEncodeAllBytes);
    }

    private String percentEncodeAllBytes(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.ISO_8859_1)) {
            sb.append(String.format("%%%02X", b & 0xFF));
        }
        return sb.toString();
    }

    private String encodePathValue(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.ISO_8859_1);
        StringBuilder sb = new StringBuilder();
        for (byte raw : bytes) {
            int b = raw & 0xFF;
            char c = (char) b;
            if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~'
                    || c == '/') {
                sb.append(c);
            } else {
                sb.append(String.format("%%%02X", b));
            }
        }
        return sb.toString();
    }

    private void doubleUrlEncode() {
        transformSelectionWithNoChangeOption(
                s -> {
                    try {
                        return URLEncoder.encode(URLEncoder.encode(s, "ISO-8859-1"), "ISO-8859-1");
                    } catch (UnsupportedEncodingException e) {
                        return s;
                    }
                },
                I18n.t("dialog.force_double_encode"),
                s -> {
                    try {
                        return URLEncoder.encode(percentEncodeAllBytes(s), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        return s;
                    }
                });
    }

    private void mixedUrlEncode() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            int eligible = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (isAsciiAlphaNum(c)) {
                    eligible++;
                    if (eligible % 2 == 0) {
                        for (byte b : String.valueOf(c).getBytes(StandardCharsets.UTF_8)) {
                            sb.append(String.format("%%%02X", b & 0xFF));
                        }
                    } else {
                        sb.append(c);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        });
    }

    private boolean isAsciiAlphaNum(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9');
    }

    private void base64Encode() {
        byte[] selected = getSelectedRequestBytes();
        if (selected.length > 0) replaceOccurrenceInRequest(selected, Base64.getEncoder().encode(selected));
    }

    private void toUnicodeEscape() {
        transformTextSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                sb.append(String.format("\\u%04x", (int) c));
            }
            return sb.toString();
        });
    }

    private void insertDirtyData() {
        String input = JOptionPane.showInputDialog(this, I18n.t("dialog.dirty_length"), "Dirty Data",
                JOptionPane.QUESTION_MESSAGE);
        if (input == null || input.trim().isEmpty())
            return;
        try {
            int count = Integer.parseInt(input.trim());
            if (count <= 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.positive_number"), I18n.t("dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            insertAtCaretOrFallback(("{{dirty(" + count + ")}}").getBytes(StandardCharsets.ISO_8859_1));
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.valid_number"), I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private void insertNullBytes() {
        String input = JOptionPane.showInputDialog(this, I18n.t("dialog.null_count"), "Null Bytes", JOptionPane.QUESTION_MESSAGE);
        if (input == null || input.trim().isEmpty())
            return;
        try {
            int count = Integer.parseInt(input.trim());
            if (count <= 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.positive_number"), I18n.t("dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            insertAtCaretOrFallback(("{{dirtynull(" + count + ")}}").getBytes(StandardCharsets.ISO_8859_1));
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.valid_number"), I18n.t("dialog.error.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private static class RequestParts {
        String headers;
        String body;
        String lineEnd;
    }

    private RequestParts splitRequestText(String requestText) {
        RequestParts parts = new RequestParts();
        int bodyStart = requestText.indexOf("\r\n\r\n");
        String lineEnd = "\r\n";
        int sepLen = 4;
        if (bodyStart < 0) {
            bodyStart = requestText.indexOf("\n\n");
            lineEnd = "\n";
            sepLen = 2;
        }
        if (bodyStart < 0)
            return null;
        parts.lineEnd = lineEnd;
        parts.headers = requestText.substring(0, bodyStart);
        parts.body = requestText.substring(bodyStart + sepLen);
        return parts;
    }

    private String removeHeaderLine(String headers, String headerName, String lineEnd) {
        String[] lines = headers.split("\\r?\\n", -1);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                continue;
            }
            if (sb.length() > 0)
                sb.append(lineEnd);
            sb.append(line);
        }
        return sb.toString();
    }

    private String upsertHeaderLine(String headers, String headerName, String headerValue, String lineEnd) {
        String[] lines = headers.split("\\r?\\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean found = false;
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                if (!found) {
                    if (sb.length() > 0)
                        sb.append(lineEnd);
                    sb.append(headerName).append(": ").append(headerValue);
                    found = true;
                }
                continue;
            }
            if (sb.length() > 0)
                sb.append(lineEnd);
            sb.append(line);
        }
        if (!found) {
            if (sb.length() > 0)
                sb.append(lineEnd);
            sb.append(headerName).append(": ").append(headerValue);
        }
        return sb.toString();
    }

    private static class BodyField {
        final String name;
        final String value;

        BodyField(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    private void gzipBody() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.request_content_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (!canTransformBody(request)) return;
            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);

            if (body.length == 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.body_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            // 1) Header 检查
            for (String h : headers) {
                String hl = h.toLowerCase();
                if (hl.startsWith("content-encoding:") && hl.contains("gzip")) {
                    JOptionPane.showMessageDialog(this, I18n.t("dialog.gzip_already_header"), I18n.t("dialog.tip.title"),
                            JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
            }

            // 2) Magic bytes 检查：1F 8B
            if (body.length >= 2 && (body[0] & 0xFF) == 0x1F && (body[1] & 0xFF) == 0x8B) {
                int ret = JOptionPane.showConfirmDialog(
                        this,
                        I18n.t("dialog.gzip_confirm"),
                        I18n.t("dialog.warning.title"),
                        JOptionPane.YES_NO_OPTION);
                if (ret != JOptionPane.YES_OPTION)
                    return;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
                gzip.write(body);
            }
            byte[] gzipped = baos.toByteArray();

            updateOrAddHeader(headers, "Content-Encoding", "gzip");
            removeHeaderIgnoreCase(headers, "Transfer-Encoding");
            removeHeaderIgnoreCase(headers, "Content-Length");
            headers.add("Content-Length: " + gzipped.length);

            byte[] newRequest = Utils.helpers.buildHttpMessage(headers, gzipped);
            setRequestBytes(newRequest);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.error.gzip", e.getMessage()), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toFormUrlEncoded() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.request_content_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (!canTransformBody(request)) return;
            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
            List<BodyField> fields = extractBodyFields(headers, body);
            if (fields.isEmpty()) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.no_convertible_params"), I18n.t("dialog.tip.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            Charset cs = charsetFromHeaders(headers);
            byte[] newBody = buildFormBody(fields, cs);
            replaceBodyAndContentType(headers, newBody, "application/x-www-form-urlencoded; charset=" + cs.name());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.error.form", e.getMessage()), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toMultipart() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.request_content_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (!canTransformBody(request)) return;
            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);

            if (body.length == 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.body_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            String currentCT = contentTypeFromHeaders(headers);
            if (currentCT.toLowerCase().contains("multipart/form-data")) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.multipart_already"), I18n.t("dialog.tip.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String boundary = "----BypassProBoundary" + System.currentTimeMillis();
            List<BodyField> fields = extractBodyFields(headers, body);
            if (fields.isEmpty()) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.no_convertible_params"), I18n.t("dialog.tip.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            Charset cs = charsetFromHeaders(headers);
            byte[] multipartBody = buildMultipartBody(fields, boundary, cs);
            replaceBodyAndContentType(headers, multipartBody, "multipart/form-data; boundary=" + boundary);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.error.multipart", e.getMessage()), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toJsonBody() {
        try {
            byte[] request = getRequestBytes();
            if (request == null || request.length == 0) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.request_content_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }

            if (!canTransformBody(request)) return;
            IRequestInfo info = Utils.helpers.analyzeRequest(request);
            List<String> headers = new ArrayList<>(info.getHeaders());
            byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
            if (contentTypeFromHeaders(headers).toLowerCase(Locale.ROOT).contains("json")) return;
            List<BodyField> fields = extractBodyFields(headers, body);
            if (fields.isEmpty()) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.no_convertible_params"), I18n.t("dialog.tip.title"),
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            byte[] jsonBody = buildJsonBody(fields);
            replaceBodyAndContentType(headers, jsonBody, "application/json");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.error.json", e.getMessage()), I18n.t("dialog.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private List<BodyField> extractBodyFields(List<String> headers, byte[] body) throws Exception {
        List<BodyField> fields = new ArrayList<>();
        if (body == null || body.length == 0) {
            return fields;
        }
        String ctRaw = contentTypeFromHeaders(headers);
        String ct = ctRaw.toLowerCase();
        Charset cs = charsetFromHeaders(headers);
        if (ct.contains("application/x-www-form-urlencoded")) {
            fields.addAll(parseFormFields(TextCodec.decode(body, cs), cs));
        } else if (ct.contains("multipart/form-data")) {
            fields.addAll(parseMultipartFields(new String(body, StandardCharsets.ISO_8859_1),
                    boundaryFromContentType(ctRaw), cs));
        } else if (ct.contains("json")) {
            fields.addAll(parseFlatJsonFields(TextCodec.decode(body, cs)));
        }
        return fields;
    }

    private List<BodyField> parseFormFields(String body, Charset cs) throws Exception {
        List<BodyField> fields = new ArrayList<>();
        if (body == null || body.trim().isEmpty()) {
            return fields;
        }
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            if (pair == null || pair.isEmpty())
                continue;
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], cs.name());
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], cs.name()) : "";
            fields.add(new BodyField(key, value));
        }
        return fields;
    }

    private List<BodyField> parseMultipartFields(String body, String boundary, Charset cs) {
        List<BodyField> fields = new ArrayList<>();
        if (body == null || body.isEmpty() || boundary == null || boundary.isEmpty()) {
            return fields;
        }
        String marker = "--" + boundary;
        String[] parts = body.split(Pattern.quote(marker));
        Pattern namePattern = Pattern.compile("(?i)\\bname=\"([^\"]*)\"");
        Pattern filenamePattern = Pattern.compile("(?i)(?:^|;)\\s*filename\\*?\\s*=");
        for (String part : parts) {
            if (part == null || part.isEmpty() || part.startsWith("--"))
                continue;
            int sep = part.indexOf("\r\n\r\n");
            int sepLen = 4;
            if (sep < 0) {
                sep = part.indexOf("\n\n");
                sepLen = 2;
            }
            if (sep < 0)
                continue;
            String partHeaders = part.substring(0, sep);
            if (filenamePattern.matcher(partHeaders).find())
                throw new IllegalArgumentException(I18n.t("dialog.body_file_conversion"));
            Matcher m = namePattern.matcher(partHeaders);
            if (!m.find())
                continue;
            String name = m.group(1);
            String value = part.substring(sep + sepLen);
            value = value.replaceFirst("\\r?\\n$", "");
            fields.add(new BodyField(name, new String(value.getBytes(StandardCharsets.ISO_8859_1), cs)));
        }
        return fields;
    }

    private List<BodyField> parseFlatJsonFields(String body) {
        List<BodyField> fields = new ArrayList<>();
        if (body == null)
            return fields;
        String s = body.trim();
        if (!s.startsWith("{") || !s.endsWith("}")) {
            return fields;
        }
        s = s.substring(1, s.length() - 1).trim();
        if (s.isEmpty())
            return fields;

        List<String> pairs = splitTopLevelJsonPairs(s);
        for (String pair : pairs) {
            int colon = findJsonColon(pair);
            if (colon <= 0)
                continue;
            String key = unquoteJsonScalar(pair.substring(0, colon).trim());
            String value = unquoteJsonScalar(pair.substring(colon + 1).trim());
            if (key != null && value != null) {
                fields.add(new BodyField(key, value));
            }
        }
        return fields;
    }

    private List<String> splitTopLevelJsonPairs(String s) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inString = false;
        boolean escape = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                cur.append(c);
                escape = false;
                continue;
            }
            if (c == '\\') {
                cur.append(c);
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                cur.append(c);
                continue;
            }
            if (!inString && (c == '{' || c == '[')) {
                throw new IllegalArgumentException(I18n.t("dialog.body_nested_json"));
            }
            if (c == ',' && !inString) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0)
            out.add(cur.toString());
        return out;
    }

    private int findJsonColon(String s) {
        boolean inString = false;
        boolean escape = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (c == ':' && !inString)
                return i;
        }
        return -1;
    }

    private String unquoteJsonScalar(String s) {
        if (s == null || s.isEmpty())
            return null;
        if (s.startsWith("[") || s.startsWith("{"))
            return null;
        if ("null".equals(s))
            return "";
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            return unescapeJsonString(s.substring(1, s.length() - 1));
        }
        return s;
    }

    private String unescapeJsonString(String s) {
        StringBuilder out = new StringBuilder();
        boolean escape = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!escape) {
                if (c == '\\')
                    escape = true;
                else
                    out.append(c);
                continue;
            }
            switch (c) {
                case '"':
                    out.append('"');
                    break;
                case '\\':
                    out.append('\\');
                    break;
                case '/':
                    out.append('/');
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    if (i + 4 < s.length()) {
                        try {
                            out.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                            break;
                        } catch (NumberFormatException ignored) {
                        }
                    }
                    out.append('u');
                    break;
                default:
                    out.append(c);
                    break;
            }
            escape = false;
        }
        if (escape)
            out.append('\\');
        return out.toString();
    }

    private byte[] buildFormBody(List<BodyField> fields, Charset cs) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        for (BodyField f : fields) {
            if (sb.length() > 0)
                sb.append('&');
            sb.append(URLEncoder.encode(f.name, cs.name()));
            sb.append('=');
            sb.append(URLEncoder.encode(f.value, cs.name()));
        }
        return sb.toString().getBytes(cs);
    }

    private byte[] buildMultipartBody(List<BodyField> fields, String boundary, Charset cs) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (BodyField f : fields) {
            out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.write(("Content-Disposition: form-data; name=\"" + escapeMultipartName(f.name) + "\"\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            out.write(("Content-Type: text/plain; charset=" + cs.name() + "\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.write(f.value.getBytes(cs));
            out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
        }
        out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.ISO_8859_1));
        return out.toByteArray();
    }

    private byte[] buildJsonBody(List<BodyField> fields) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        for (int i = 0; i < fields.size(); i++) {
            BodyField f = fields.get(i);
            if (i > 0)
                sb.append(',');
            sb.append('"').append(escapeJson(f.name)).append('"');
            sb.append(':');
            sb.append('"').append(escapeJson(f.value)).append('"');
        }
        sb.append('}');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String escapeJson(String s) {
        if (s == null)
            return "";
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') out.append('\\').append(c);
            else if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.toString();
    }

    private String escapeMultipartName(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private void replaceBodyAndContentType(List<String> headers, byte[] body, String contentType) {
        removeHeaderIgnoreCase(headers, "Content-Type");
        headers.add("Content-Type: " + contentType);
        removeHeaderIgnoreCase(headers, "Transfer-Encoding");
        removeHeaderIgnoreCase(headers, "Content-Length");
        headers.add("Content-Length: " + body.length);
        setRequestBytes(Utils.helpers.buildHttpMessage(headers, body));
    }

    private String contentTypeFromHeaders(List<String> headers) {
        if (headers == null)
            return "";
        for (String h : headers) {
            if (h != null && h.toLowerCase().startsWith("content-type:")) {
                return h.substring("content-type:".length()).trim();
            }
        }
        return "";
    }

    private Charset charsetFromHeaders(List<String> headers) {
        return RequestBodyPolicy.charset(String.join("\r\n", headers));
    }

    private boolean canTransformBody(byte[] request) {
        if (RequestBodyPolicy.isEditable(request)) return true;
        statusLabel.setText(I18n.t("manual.body_encoded"));
        return false;
    }

    private String boundaryFromContentType(String ct) {
        if (ct == null)
            return null;
        Matcher m = Pattern.compile("(?i)boundary\\s*=\\s*\"?([^\";\\r\\n]+)").matcher(ct);
        return m.find() ? m.group(1).trim() : null;
    }

    private void encodeBodyWithCharset(String charsetName) {
        byte[] sel = getSelectedRequestBytes();
        if (sel != null && sel.length > 0) {
            try {
                Charset charset = Charset.forName(charsetName);
                Charset source = isSelectionLikelyRequestLineOrHeader(sel) ? StandardCharsets.UTF_8
                        : RequestBodyPolicy.charset(RequestBodyPolicy.headers(getRequestBytes()));
                String selected = TextCodec.decode(sel, source);
                replaceOccurrenceInRequest(sel, TextCodec.encode(selected, charset));
                if (statusLabel != null) {
                    statusLabel.setText(I18n.t("status.applied_selection", charsetName));
                }
            } catch (Exception e) {
                statusLabel.setText(I18n.t("manual.text_failed"));
            }
            return;
        }

        String text = getRequestTextISO();
        try {
            RequestParts parts = splitRequestText(text);
            if (parts == null) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.body_missing"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            String lineEnd = parts.lineEnd;
            String headers = parts.headers;
            if (!RequestBodyPolicy.isEditable(headers)) {
                statusLabel.setText(I18n.t("manual.body_encoded"));
                return;
            }
            byte[] expanded = buildBodyBytesWithTags(parts.body, StandardCharsets.ISO_8859_1);
            String body = TextCodec.decode(expanded, RequestBodyPolicy.charset(headers));

            if (body.isEmpty()) {
                JOptionPane.showMessageDialog(this, I18n.t("dialog.body_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            Charset charset = Charset.forName(charsetName);
            byte[] encoded = TextCodec.encode(body, charset);

            String newHeaders = headers;
            if (newHeaders.toLowerCase().contains("content-type:")) {
                String[] lines = newHeaders.split("\\r?\\n", -1);
                StringBuilder sb = new StringBuilder();
                boolean ctDone = false;
                for (String line : lines) {
                    if (!ctDone && line.toLowerCase().startsWith("content-type:")) {
                        String normalized = line.replaceAll("(?i);\\s*charset=[^;\\r\\n]*", "");
                        normalized = normalized + "; charset=" + charsetName;
                        if (sb.length() > 0)
                            sb.append(lineEnd);
                        sb.append(normalized);
                        ctDone = true;
                    } else {
                        if (sb.length() > 0)
                            sb.append(lineEnd);
                        sb.append(line);
                    }
                }
                newHeaders = sb.toString();
            }
            newHeaders = removeHeaderLine(newHeaders, "Transfer-Encoding", lineEnd);
            newHeaders = upsertHeaderLine(newHeaders, "Content-Length", String.valueOf(encoded.length), lineEnd);

            String newRequest = newHeaders + lineEnd + lineEnd + new String(encoded, StandardCharsets.ISO_8859_1);
            setRequestTextISO(newRequest);
            if (statusLabel != null) {
                statusLabel.setText(I18n.t("status.applied_body", charsetName));
            }
        } catch (Exception e) {
            statusLabel.setText(I18n.t("manual.text_failed"));
        }
    }

    private void toUpper() {
        transformSelection(s -> asciiCase(s, true));
    }

    private void toLower() {
        transformSelection(s -> asciiCase(s, false));
    }

    private static String asciiCase(String text, boolean upper) {
        StringBuilder result = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            if (upper && c >= 'a' && c <= 'z') c -= 32;
            else if (!upper && c >= 'A' && c <= 'Z') c += 32;
            result.append(c);
        }
        return result.toString();
    }

    private void toRandomCase() {
        transformSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                sb.append(asciiCase(String.valueOf(c), Math.random() > 0.5));
            }
            return sb.toString();
        });
    }

    private void toFullwidth() {
        transformTextSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                if (c >= '!' && c <= '~')
                    sb.append((char) (c - '!' + '！'));
                else if (c == ' ')
                    sb.append('　');
                else
                    sb.append(c);
            }
            return sb.toString();
        });
    }

    private void toHomoglyph() {
        transformTextSelection(s -> {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                sb.append(toHomoglyphChar(c));
            }
            return sb.toString();
        });
    }

    private char toHomoglyphChar(char c) {
        switch (c) {
            case 'a':
                return 'а';
            case 'e':
                return 'е';
            case 'o':
                return 'о';
            case 'p':
                return 'р';
            case 'c':
                return 'с';
            case 'x':
                return 'х';
            case 'y':
                return 'у';
            case 'i':
                return 'і';
            case 'j':
                return 'ј';
            case 's':
                return 'ѕ';
            case 'A':
                return 'А';
            case 'B':
                return 'В';
            case 'C':
                return 'С';
            case 'E':
                return 'Е';
            case 'H':
                return 'Н';
            case 'I':
                return 'І';
            case 'K':
                return 'К';
            case 'M':
                return 'М';
            case 'O':
                return 'О';
            case 'P':
                return 'Р';
            case 'T':
                return 'Т';
            case 'X':
                return 'Х';
            case 'Y':
                return 'Ү';
            default:
                return c;
        }
    }

    private void insertZeroWidth() {
        transformTextSelection(s -> {
            if (s.length() <= 1) {
                return s;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                sb.append(s.charAt(i));
                if (i < s.length() - 1) {
                    sb.append('\u200B');
                }
            }
            return sb.toString();
        });
    }

    private void insertAt(String text) {
        insertAtCaretOrFallback(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void switchToHttp10() {
        byte[] request = getRequestBytes();
        if (request == null || request.length == 0)
            return;

        IRequestInfo info = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(info.getHeaders());
        if (!headers.isEmpty()) {
            String reqLine = headers.get(0);
            reqLine = reqLine.replaceAll("HTTP/1\\.[0-9]", "HTTP/1.0");
            headers.set(0, reqLine);
        }

        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i).toLowerCase();
            if (h.startsWith("connection:") ||
                    h.startsWith("proxy-connection:") ||
                    h.startsWith("keep-alive:") ||
                    h.startsWith("transfer-encoding:")) {
                headers.remove(i);
            }
        }

        boolean hasConnClose = false;
        for (String h : headers) {
            if (h.toLowerCase().startsWith("connection:") && h.toLowerCase().contains("close")) {
                hasConnClose = true;
                break;
            }
        }
        if (!hasConnClose) {
            headers.add("Connection: close");
        }

        byte[] body = Arrays.copyOfRange(request, info.getBodyOffset(), request.length);
        byte[] newRequest = Utils.helpers.buildHttpMessage(headers, body);
        setRequestBytes(newRequest);
    }

    // ------------------------------------------------------------------
    // Ghost Bits 操作
    // ------------------------------------------------------------------

    private void encodeGhostSelection(GhostBitsCodec.EncodeStrategy strategy) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.ghost_select_original"),
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        try {
            Charset source = isSelectionLikelyRequestLineOrHeader(sel) ? StandardCharsets.UTF_8
                    : RequestBodyPolicy.charset(RequestBodyPolicy.headers(getRequestBytes()));
            String selected = TextCodec.decode(sel, source);
            if (GhostBitsCodec.containsLineBreak(selected) && GhostBitsCodec.mayEncodeLineBreak(strategy)) {
                int ret = JOptionPane.showConfirmDialog(this,
                        I18n.t("dialog.ghost_line_breaks"),
                        "Gh0st Bits", JOptionPane.YES_NO_OPTION);
                if (ret != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            String encoded = GhostBitsCodec.encode(selected, strategy, Utils.getGhostBitsEngine());
            if (encoded.equals(selected)) {
                if (statusLabel != null) {
                    statusLabel.setText(I18n.t("status.ghost_no_change"));
                }
                return;
            }
            boolean rawRecommended = GhostBitsCodec.containsNonAscii(encoded) && isSelectionLikelyRequestLineOrHeader(sel);
            if (!replaceOccurrenceInRequest(sel, TextCodec.encode(encoded, source))) {
                return;
            }
            updateGhostStatus(encoded, GhostBitsCodec.fold(encoded, ghostFoldMode),
                    rawRecommended);
        } catch (java.nio.charset.CharacterCodingException | IllegalArgumentException invalid) {
            statusLabel.setText(I18n.t("manual.text_failed"));
        }
    }

    private void randomizeGhostSelection() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.ghost_select_shuffle"),
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Gh0st Bits");
        if (selected == null) {
            return;
        }

        int mask = ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7 ? 0x7F : 0xFF;
        StringBuilder sb = new StringBuilder(selected.length());
        for (int i = 0; i < selected.length(); i++) {
            char c = selected.charAt(i);
            if (c > 0x7F) {
                sb.append(randomHighByte(c, mask));
            } else {
                sb.append(c);
            }
        }
        String encoded = sb.toString();

        String folded = GhostBitsCodec.fold(encoded, ghostFoldMode);
        boolean rawRecommended = GhostBitsCodec.containsNonAscii(encoded)
                && isSelectionLikelyRequestLineOrHeader(sel);

        String msg = buildShufflePreview(selected, encoded, folded, rawRecommended);
        int ret = JOptionPane.showConfirmDialog(this, msg,
                I18n.t("tooltip.shuffle.title"), JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (ret != JOptionPane.OK_OPTION) {
            return;
        }

        if (!replaceOccurrenceInRequest(sel, encoded.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        updateGhostStatus(encoded, folded, rawRecommended);
    }

    private String buildShufflePreview(String before, String after, String folded, boolean rawRecommended) {
        StringBuilder sb = new StringBuilder();
        String foldedBefore = GhostBitsCodec.fold(before, ghostFoldMode);
        sb.append("Fold:   ").append(GhostBitsCodec.foldModeLabel(ghostFoldMode)).append('\n');
        sb.append('\n');
        sb.append(I18n.t("ghost.shuffle.before")).append(truncateForPreview(before)).append('\n');
        sb.append(I18n.t("ghost.shuffle.after")).append(truncateForPreview(after)).append('\n');
        sb.append('\n');
        sb.append(I18n.t("ghost.fold.before")).append(truncateForPreview(escape(foldedBefore))).append('\n');
        sb.append(I18n.t("ghost.fold.after")).append(truncateForPreview(escape(folded)));
        if (foldedBefore.equals(folded)) {
            sb.append(I18n.t("ghost.fold.unchanged"));
        } else {
            sb.append(I18n.t("ghost.fold.changed"));
        }
        sb.append('\n');
        if (rawRecommended) {
            sb.append('\n').append("Send: Raw Socket recommended");
        }
        return sb.toString();
    }

    private static String truncateForPreview(String s) {
        if (s == null) return "";
        if (s.length() > 80) return s.substring(0, 77) + "...";
        return s;
    }

    private static char randomHighByte(char c, int mask) {
        int low = c & mask;
        int oldHigh = c >> 8;
        int newHigh;
        do {
            newHigh = 1 + ThreadLocalRandom.current().nextInt(0xFF);
        } while (newHigh == oldHigh);
        int code = (newHigh << 8) | low;
        if (code >= 0xD800 && code <= 0xDFFF) {
            code = (0x4E << 8) | low;
        }
        return (char) code;
    }

    private String decodeSelectedUtf8(byte[] selectedBytes, String title) {
        if (selectedBytes == null) {
            return "";
        }
        String selected = new String(selectedBytes, StandardCharsets.UTF_8);
        if (!Arrays.equals(selected.getBytes(StandardCharsets.UTF_8), selectedBytes)) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.ghost_invalid_utf8"),
                    title, JOptionPane.INFORMATION_MESSAGE);
            return null;
        }
        return selected;
    }

    private JToggleButton createFoldModeToggle(String text, GhostBitsCodec.FoldMode mode, boolean selected) {
        String displayText = resolveBtnText(text);
        String i18nTip = i18nTooltipFor(text);
        String tooltip = i18nTip != null ? i18nTip : defaultTooltip(text);
        JToggleButton btn = new JToggleButton(displayText, selected) {
            @Override
            public JToolTip createToolTip() {
                JToolTip tip = new MultiLineToolTip();
                tip.setComponent(this);
                return tip;
            }
        };
        btn.setMargin(new Insets(3, 7, 3, 7));
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        btn.setFocusPainted(false);
        if (tooltip != null && !tooltip.isEmpty()) {
            btn.setToolTipText(tooltip);
        }
        btn.addActionListener(e -> setGhostFoldMode(mode));
        return btn;
    }

    private void setGhostFoldMode(GhostBitsCodec.FoldMode mode) {
        ghostFoldMode = mode == null ? GhostBitsCodec.FoldMode.BIT_8 : mode;
        if (ghostFold8BitBtn != null) {
            ghostFold8BitBtn.setSelected(ghostFoldMode == GhostBitsCodec.FoldMode.BIT_8);
        }
        if (ghostFold7BitBtn != null) {
            ghostFold7BitBtn.setSelected(ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7);
        }
        updateGhostCompactPreview(getSelectedRequestBytes());
        if (statusLabel != null) {
            statusLabel.setText("Gh0st Bits restore mode: " + GhostBitsCodec.foldModeLabel(ghostFoldMode));
        }
    }

    private void updateGhostStatus(String encoded, String folded, boolean rawRecommended) {
        if (statusLabel == null) {
            return;
        }
        String msg = "Ghost Restore OK: " + compactForStatus(encoded) + " -> " + compactForStatus(escape(folded));
        if (rawRecommended) {
            msg += " | Send: Raw Socket recommended";
        }
        statusLabel.setText(msg);
        updateGhostSelectionFoldPreview(encoded, folded, rawRecommended);
    }

    private String compactForStatus(String s) {
        if (s == null) {
            return "";
        }
        String value = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
        if (value.length() > 60) {
            return value.substring(0, 57) + "...";
        }
        return value;
    }

    private void applyGhostSequence(String foldedValue, String note) {
        String encoded = encodeGhostPayloadVariant(foldedValue);
        applyFixedGhostSequence(encoded, note);
    }

    private String encodeGhostPayloadVariant(String foldedValue) {
        if (foldedValue == null || foldedValue.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(foldedValue.length());
        for (int i = 0; i < foldedValue.length(); i++) {
            char c = foldedValue.charAt(i);
            if (ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7) {
                List<String> candidates = GhostBitsCodec.buildSevenBitCandidates(c);
                if (candidates.isEmpty()) {
                    sb.append(c);
                } else {
                    String chosen = candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
                    sb.append(chosen);
                }
            } else {
                sb.append(GhostBitsCodec.pickGhostChar(c, null));
            }
        }
        return sb.toString();
    }

    private void applyFixedGhostSequence(String encoded, String note) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.select_replacement"),
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        boolean rawRecommended = GhostBitsCodec.containsNonAscii(encoded) && isSelectionLikelyRequestLineOrHeader(sel);
        if (!replaceOccurrenceInRequest(sel, encoded.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        updateGhostStatus(encoded, GhostBitsCodec.fold(encoded, ghostFoldMode), rawRecommended);
        if (note != null && !note.isEmpty() && statusLabel != null) {
            statusLabel.setText(statusLabel.getText() + " | " + note);
        }
    }

    private void applyParserDiffSelection(String payload, String statusText) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.select_replacement"),
                    "Gh0st Bits", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!replaceOccurrenceInRequest(sel, payload.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        if (statusLabel != null) {
            statusLabel.setText(statusText);
        }
        updateGhostSelectionFoldPreview(payload, GhostBitsCodec.fold(payload, ghostFoldMode), false);
    }

    private void applyJettyLooseHexSelection() {
        transformParserBypassSelection("Jetty %2>", this::toJettyLooseHexDots);
    }

    private String toJettyLooseHexDots(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        boolean changed = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') {
                sb.append("%2>");
                changed = true;
                continue;
            }
            if (c == '%' && i + 2 < s.length() && s.charAt(i + 1) == '2'
                    && (s.charAt(i + 2) == 'e' || s.charAt(i + 2) == 'E')) {
                sb.append("%2>");
                i += 2;
                changed = true;
                continue;
            }
            sb.append(c);
        }
        if (!changed) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.jetty_select"),
                    "ParserBypass", JOptionPane.INFORMATION_MESSAGE);
        }
        return changed ? sb.toString() : s;
    }

    private void applyFastjsonLooseHexSelection() {
        transformParserBypassSelection("fastjson \\x4_", s -> {
            if (s.contains("@")) {
                return s.replace("@", "\\x4J");
            }
            if (s.contains("\\x40")) {
                return s.replace("\\x40", "\\x4J");
            }
            return "\\x4J" + s;
        });
    }

    private void applyFastjsonUnicodeSelection() {
        transformParserBypassSelection("fastjson \\u", s -> {
            if (s.contains("\\u")) {
                return replaceAsciiDigitsWithUnicodeDigits(s);
            }
            return toUnicodeEscapeWithUnicodeDigits(s);
        });
    }

    private void applyJacksonUnicodeSelection() {
        transformParserBypassSelection("jackson \\u", s -> {
            if (s.contains("\\u")) {
                return ghostifyUnicodeEscapeHexDigits(s);
            }
            return toJacksonGhostUnicodeEscape(s);
        });
    }

    private void applyUnicodeDigitsSelection() {
        transformParserBypassSelection("Unicode Digits", this::replaceAsciiDigitsWithUnicodeDigits);
    }

    private void applyFullwidthUrlSelection() {
        transformParserBypassSelection("Fullwidth URL", this::toFullwidthUrlPayload);
    }

    private void applyTomcatSevenBitHexSelection() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.tomcat_select"),
                    "ParserBypass", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Tomcat %HH");
        if (selected == null) {
            return;
        }
        if (looksLikeRawHexBytes(selected)) {
            int choice = JOptionPane.showOptionDialog(this,
                    I18n.t("dialog.tomcat_hex_input", selected),
                    "Tomcat %HH",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,
                    new Object[]{I18n.t("dialog.cancel"), I18n.t("dialog.encode_original")},
                    I18n.t("dialog.cancel"));
            if (choice != 1) {
                return;
            }
        }
        String replaced = toTomcatSevenBitPercentHex(selected);
        if (replaced == null || replaced.equals(selected)) {
            if (statusLabel != null) {
                statusLabel.setText("ParserBypass: Tomcat %HH did not change selection");
            }
            return;
        }
        if (!replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        if (statusLabel != null) {
            statusLabel.setText("ParserBypass: Tomcat %HH applied | input is raw char, not 6a hex text");
        }
        showParserPreview("Tomcat %HH", replaced);
    }

    private boolean looksLikeRawHexBytes(String s) {
        if (s == null || s.length() != 2) {
            return false;
        }
        return isAsciiHex(s.charAt(0)) && isAsciiHex(s.charAt(1));
    }

    private boolean isAsciiHex(char c) {
        return (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
    }

    private void transformParserBypassSelection(String name, java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.select_parser"),
                    "ParserBypass", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        try {
            Charset source = isSelectionLikelyRequestLineOrHeader(sel) ? StandardCharsets.UTF_8
                    : RequestBodyPolicy.charset(RequestBodyPolicy.headers(getRequestBytes()));
            String selected = TextCodec.decode(sel, source);
            String replaced = transformer.apply(selected);
            if (replaced == null || replaced.equals(selected)) {
                if (statusLabel != null) {
                    statusLabel.setText("ParserBypass: " + name + " did not change selection");
                }
                return;
            }
            byte[] encoded = TextCodec.encode(replaced, source);
            if (!replaceOccurrenceInRequest(sel, encoded)) {
                return;
            }
            if (statusLabel != null) {
                statusLabel.setText("ParserBypass: " + name + " applied");
            }
            showParserPreview(name, replaced, encoded);
        } catch (java.nio.charset.CharacterCodingException | IllegalArgumentException invalid) {
            statusLabel.setText(I18n.t("manual.text_failed"));
        }
    }

    private void showParserPreview(String name, String payload) {
        showParserPreview(name, payload, payload.getBytes(StandardCharsets.UTF_8));
    }

    private void showParserPreview(String name, String payload, byte[] bytes) {
        parserPreviewName = name;
        parserPreviewPayload = payload;
        parserPreviewBytes = bytes;
        ParserPreview.Result preview = ParserPreview.evaluate(name, payload);
        ghostSelectionFoldLabel.setText(I18n.t("parser.preview") + ": " + truncateForInspector(escape(payload), 42)
                + " -> " + (preview.value == null ? "?" : truncateForInspector(escape(preview.value), 42)));
        ghostPreviewRiskLabel.setText(preview.mechanism + " | " + I18n.t("parser.local_model"));
        ghostPreviewRiskLabel.setForeground(UIManager.getColor("Label.foreground"));
    }

    private String replaceAsciiDigitsWithUnicodeDigits(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        char[] unicodeDigits = {
                '\u0660', '\u0661', '\u0662', '\u0663', '\u0664',
                '\u0665', '\u0666', '\u0667', '\u0668', '\u0669'
        };
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                sb.append(unicodeDigits[c - '0']);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String toUnicodeEscapeWithUnicodeDigits(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() * 6);
        for (int i = 0; i < s.length(); i++) {
            String hex = String.format("%04x", (int) s.charAt(i));
            sb.append("\\u").append(replaceAsciiDigitsWithUnicodeDigits(hex));
        }
        return sb.toString();
    }

    private String toJacksonGhostUnicodeEscape(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() * 6);
        GhostBitsEngine engine = Utils.getGhostBitsEngine();
        for (int i = 0; i < s.length(); i++) {
            sb.append("\\u").append(ghostEncodeHexDigits(String.format("%04x", (int) s.charAt(i)), engine));
        }
        return sb.toString();
    }

    private String ghostifyUnicodeEscapeHexDigits(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        GhostBitsEngine engine = Utils.getGhostBitsEngine();
        for (int i = 0; i < s.length(); i++) {
            if (i + 5 < s.length() && s.charAt(i) == '\\' && s.charAt(i + 1) == 'u'
                    && isFourAsciiHexDigits(s, i + 2)) {
                sb.append("\\u");
                sb.append(ghostEncodeHexDigits(s.substring(i + 2, i + 6), engine));
                i += 5;
            } else {
                sb.append(s.charAt(i));
            }
        }
        return sb.toString();
    }

    private boolean isFourAsciiHexDigits(String s, int start) {
        if (s == null || start < 0 || start + 4 > s.length()) {
            return false;
        }
        for (int i = start; i < start + 4; i++) {
            if (s.charAt(i) > 0x7F || Character.digit(s.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private String ghostEncodeHexDigits(String hex, GhostBitsEngine engine) {
        StringBuilder sb = new StringBuilder(hex.length());
        for (int i = 0; i < hex.length(); i++) {
            char c = Character.toLowerCase(hex.charAt(i));
            if (c <= 0x7F && Character.digit(c, 16) >= 0) {
                sb.append(GhostBitsCodec.pickGhostChar(c, engine));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String toTomcatSevenBitPercentHex(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() * 3);
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        for (byte raw : bytes) {
            String hex = String.format("%02x", raw & 0xFF);
            sb.append('%')
                    .append(pickSevenBitGhostChar(hex.charAt(0)))
                    .append(pickSevenBitGhostChar(hex.charAt(1)));
        }
        return sb.toString();
    }

    private char pickSevenBitGhostChar(char target) {
        List<String> candidates = GhostBitsCodec.buildSevenBitCandidates(target);
        if (candidates.isEmpty()) {
            return target;
        }
        String chosen = candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
        return chosen.isEmpty() ? target : chosen.charAt(0);
    }

    private String toFullwidthUrlPayload(String s) {
        if (s == null || s.isEmpty()) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                sb.append(c);
            } else if (c >= '!' && c <= '~') {
                sb.append((char) (c - '!' + '！'));
            } else if (c == ' ') {
                sb.append('　');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private boolean isSelectionLikelyRequestLineOrHeader(byte[] sel) {
        byte[] req = getRequestBytes();
        if (req == null || sel == null || sel.length == 0) {
            return false;
        }
        int headerEnd = findHeaderEnd(req);
        Integer selectedIndex = resolveSelectionIndex(req, sel);
        if (selectedIndex != null) return headerEnd < 0 || selectedIndex < headerEnd;
        List<Integer> positions = findAllOccurrences(req, sel);
        for (int pos : positions) {
            if (headerEnd < 0 || pos < headerEnd) {
                return true;
            }
        }
        return false;
    }

    private void showGhostCandidates() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.select_ascii"),
                    I18n.t("dialog.tip.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = decodeSelectedUtf8(sel, "Candidates");
        if (selected == null) {
            return;
        }
        if (selected.length() != 1) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.candidates.single_char_only"),
                    I18n.t("dialog.candidates.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (selected.charAt(0) > 0x7F) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.candidates.ascii_only"),
                    I18n.t("dialog.candidates.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        List<String> candidates = ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7
                ? GhostBitsCodec.buildSevenBitCandidates(selected.charAt(0))
                : Utils.getGhostBitsEngine().findCandidates(selected);
        showGhostLookup(selected, candidates);
    }

    private void showGhostLookup(String target, List<String> candidates) {
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.t("ghost.character")).append(escape(target)).append("  0x")
                .append(String.format("%02X", target.charAt(0) & 0xFF)).append('\n');
        sb.append(I18n.t("ghost.mode")).append(GhostBitsCodec.foldModeLabel(ghostFoldMode)).append("\n\n");
        int max = Math.min(candidates.size(), 24);
        for (int i = 0; i < max; i++) {
            String c = candidates.get(i);
            int code = c.charAt(0);
            int low = ghostFoldMode == GhostBitsCodec.FoldMode.BIT_7 ? code & 0x7F : code & 0xFF;
            sb.append(c)
                    .append("  U+").append(String.format("%04X", code))
                    .append("  -> 0x").append(String.format("%02X", low))
                    .append(" -> ").append(escape(String.valueOf((char) low)))
                    .append('\n');
        }
        JOptionPane.showMessageDialog(this, sb.toString(),
                I18n.t("dialog.candidates.title"), JOptionPane.INFORMATION_MESSAGE);
    }

    private void applyGhostTemplate(GhostBitsRule.Template t) {
        if (t == null) {
            return;
        }
        String rendered = Utils.getGhostBitsEngine().renderTemplate(t.getId());
        if (rendered == null || rendered.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.template_empty", t.getId()),
                    "Gh0st Bits Template", JOptionPane.WARNING_MESSAGE);
            return;
        }

        byte[] before = getRequestBytes();
        byte[] payload = rendered.getBytes(StandardCharsets.UTF_8);
        String target = t.getTarget() == null ? "selection" : t.getTarget().toLowerCase();
        switch (target) {
            case "path":
                applyTemplateToPath(t, payload, rendered);
                break;
            case "filename":
                applyTemplateToFilename(t, payload, rendered);
                break;
            case "header":
            case "header_value":
                applyTemplateToHeaderValue(t, payload, rendered);
                break;
            case "selection":
            default:
                applyTemplateToSelection(t, payload, rendered);
                break;
        }

        byte[] after = getRequestBytes();
        if (before != null && after != null && Arrays.equals(before, after)) {
            return;
        }
        boolean rawRecommended = t.requiresRawSender()
                || (GhostBitsCodec.containsNonAscii(rendered) && ("path".equals(target) || "header".equals(target)
                        || "header_value".equals(target)));
        updateGhostStatus(rendered, GhostBitsCodec.fold(rendered, ghostFoldMode), rawRecommended);
        String id = t.getId();
        if (id.contains("unicode_digit") || id.contains("fullwidth") || id.contains("loose_hex")
                || id.contains("x_escape") || id.contains("char_to_hex") || id.equals("tomcat_url_hex_ghost"))
            showParserPreview(id, rendered);
        if (statusLabel != null) {
            statusLabel.setText(statusLabel.getText() + " | Template: " + I18n.t(t.getLabel()));
        }
    }

    /**
     * target=path: 自动替换请求行中的 path，不需要用户先选中。
     */
    private void applyTemplateToPath(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 找请求行: 第一个 \r\n 之前
        int lineEnd = -1;
        for (int i = 0; i + 1 < req.length; i++) {
            if (req[i] == '\r' && req[i + 1] == '\n') {
                lineEnd = i;
                break;
            }
            if (req[i] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd <= 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_line_missing"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 请求行格式: METHOD SP PATH SP HTTP/x.y
        int firstSpace = -1, secondSpace = -1;
        for (int i = 0; i < lineEnd; i++) {
            if (req[i] == ' ') {
                if (firstSpace < 0)
                    firstSpace = i;
                else if (secondSpace < 0) {
                    secondSpace = i;
                    break;
                }
            }
        }
        if (firstSpace < 0 || secondSpace < 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.path_not_found"), I18n.t("dialog.tip.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        int pathStart = firstSpace + 1;
        int pathEnd = secondSpace;

        // 拼装新请求字节
        byte[] out = new byte[req.length - (pathEnd - pathStart) + payload.length];
        System.arraycopy(req, 0, out, 0, pathStart);
        System.arraycopy(payload, 0, out, pathStart, payload.length);
        System.arraycopy(req, pathEnd, out, pathStart + payload.length, req.length - pathEnd);

        setRequestBytes(out);
        if (statusLabel != null) {
            statusLabel.setText("Template applied (path) | " + I18n.t(t.getLabel()));
        }
    }

    /**
     * target=filename: 在 multipart body 里找 filename="..." 或 filename*=... 的取值并替换。
     */
    private void applyTemplateToFilename(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        String text = new String(req, StandardCharsets.ISO_8859_1);
        // 优先匹配 RFC2231 形式 filename*=charset''value
        Pattern rfc2231 = Pattern.compile("(?i)filename\\*\\s*=\\s*([\\w\\-]+)''([^;\\r\\n\"]+)");
        Matcher m = rfc2231.matcher(text);
        int valueStart = -1, valueEnd = -1;
        byte[] replacement = payload;
        if (m.find()) {
            valueStart = m.start(2);
            valueEnd = m.end(2);
        } else {
            // 普通 filename="value"
            Pattern plain = Pattern.compile("(?i)filename\\s*=\\s*\"([^\"\\r\\n]*)\"");
            m = plain.matcher(text);
            if (m.find()) {
                if (requiresRfc2231FilenameTemplate(t)) {
                    valueStart = m.start();
                    valueEnd = m.end();
                    replacement = ("filename*=\"UTF-8''" + rendered + "\"").getBytes(StandardCharsets.UTF_8);
                } else {
                    valueStart = m.start(1);
                    valueEnd = m.end(1);
                }
            }
        }

        if (valueStart < 0) {
            int ret = JOptionPane.showConfirmDialog(this,
                    I18n.t("dialog.filename_fallback"),
                    I18n.t("dialog.filename_missing.title"), JOptionPane.YES_NO_OPTION);
            if (ret == JOptionPane.YES_OPTION) {
                applyTemplateToSelection(t, payload, rendered);
            }
            return;
        }

        byte[] out = new byte[req.length - (valueEnd - valueStart) + replacement.length];
        System.arraycopy(req, 0, out, 0, valueStart);
        System.arraycopy(replacement, 0, out, valueStart, replacement.length);
        System.arraycopy(req, valueEnd, out, valueStart + replacement.length, req.length - valueEnd);

        setRequestBytes(out);
        if (statusLabel != null) {
            statusLabel.setText("Template applied (filename) | " + I18n.t(t.getLabel()));
        }
    }

    private boolean requiresRfc2231FilenameTemplate(GhostBitsRule.Template t) {
        if (t == null) {
            return false;
        }
        String id = t.getId() == null ? "" : t.getId().toLowerCase();
        String category = t.getCategory() == null ? "" : t.getCategory().toLowerCase();
        return id.contains("tomcat") || category.contains("tomcat");
    }

    /**
     * target=header_value: 让用户选/输入 header 名，把它的 value 替换成 payload。
     */
    private void applyTemplateToHeaderValue(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] req = getRequestBytes();
        if (req == null || req.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.request_empty"), I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // 收集已有 header 名给用户选择
        int headerEnd = findHeaderEnd(req);
        int upper = headerEnd > 0 ? headerEnd : req.length;
        String headerSection = new String(req, 0, upper, StandardCharsets.ISO_8859_1);
        String[] lines = headerSection.split("\\r?\\n", -1);
        java.util.List<String> headerNames = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon > 0)
                headerNames.add(line.substring(0, colon));
        }

        Object[] options = headerNames.toArray();
        Object choice = options.length == 0
                ? JOptionPane.showInputDialog(this, I18n.t("dialog.header_name"), I18n.t(t.getLabel()),
                        JOptionPane.QUESTION_MESSAGE)
                : JOptionPane.showInputDialog(this, I18n.t("dialog.header_choose"),
                        I18n.t(t.getLabel()), JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        if (choice == null)
            return;
        String headerName = choice.toString().trim();
        if (headerName.isEmpty())
            return;

        // 找到对应行并替换 value
        Pattern p = Pattern.compile("(?im)^" + Pattern.quote(headerName) + "\\s*:\\s*([^\\r\\n]*)");
        String full = new String(req, StandardCharsets.ISO_8859_1);
        Matcher mm = p.matcher(full);
        if (!mm.find()) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.header_missing", headerName),
                    I18n.t("dialog.tip.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        int valueStart = mm.start(1);
        int valueEnd = mm.end(1);

        byte[] out = new byte[req.length - (valueEnd - valueStart) + payload.length];
        System.arraycopy(req, 0, out, 0, valueStart);
        System.arraycopy(payload, 0, out, valueStart, payload.length);
        System.arraycopy(req, valueEnd, out, valueStart + payload.length, req.length - valueEnd);

        setRequestBytes(out);
        if (statusLabel != null) {
            statusLabel.setText("Template applied (header " + headerName + ") | " + I18n.t(t.getLabel()));
        }
    }

    /**
     * target=selection: 严格按选中文本替换；没选区则弹预览。
     */
    private void applyTemplateToSelection(GhostBitsRule.Template t, byte[] payload, String rendered) {
        byte[] sel = getSelectedRequestBytes();
        if (sel != null && sel.length > 0) {
            replaceOccurrenceInRequest(sel, payload);
            return;
        }
        JOptionPane.showMessageDialog(this,
                I18n.t("dialog.template_preview", t.getTarget(), rendered),
                "Template Preview", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showFoldPreview() {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this,
                    I18n.t("dialog.ghost_select_preview"),
                    "Fold Preview", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String text = decodeSelectedUtf8(sel, "Fold Preview");
        if (text == null) {
            return;
        }
        String folded = GhostBitsCodec.fold(text, ghostFoldMode);
        JOptionPane.showMessageDialog(this, GhostBitsCodec.buildFoldPreviewReport(text, ghostFoldMode),
                "Fold Preview", JOptionPane.INFORMATION_MESSAGE);
        updateGhostStatus(text, folded, false);
    }

    private static String escape(String s) {
        if (s == null)
            return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '\r')
                sb.append("\\r");
            else if (c == '\n')
                sb.append("\\n");
            else if (c == '\t')
                sb.append("\\t");
            else
                sb.append(c);
        }
        return sb.toString();
    }

    private void transformSelection(java.util.function.Function<String, String> transformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.select_transform"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String selected = new String(sel, StandardCharsets.ISO_8859_1);
        String replaced = transformer.apply(selected);
        if (replaced == null || replaced.equals(selected)) {
            String msg = I18n.t("dialog.selection_unchanged");
            if (statusLabel != null) statusLabel.setText(msg);
            return;
        }
        try {
            replaceOccurrenceInRequest(sel, TextCodec.encode(replaced, StandardCharsets.ISO_8859_1));
        } catch (java.nio.charset.CharacterCodingException invalid) {
            statusLabel.setText(I18n.t("manual.text_failed"));
        }
    }

    private void transformTextSelection(java.util.function.Function<String, String> transformer) {
        byte[] selected = getSelectedRequestBytes();
        if (selected.length == 0) return;
        try {
            Charset source = isSelectionLikelyRequestLineOrHeader(selected) ? StandardCharsets.UTF_8
                    : RequestBodyPolicy.charset(RequestBodyPolicy.headers(getRequestBytes()));
            String text = TextCodec.decode(selected, source);
            String replacement = transformer.apply(text);
            if (replacement != null && !replacement.equals(text))
                replaceOccurrenceInRequest(selected, TextCodec.encode(replacement, source));
        } catch (Exception invalid) {
            statusLabel.setText(I18n.t("manual.text_failed"));
        }
    }

    private void transformSelectionWithNoChangeOption(
            java.util.function.Function<String, String> transformer,
            String prompt,
            java.util.function.Function<String, String> fallbackTransformer) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.select_transform"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Integer selectionIdx = resolveSelectionIndex(getRequestBytes(), sel);
        String selected = new String(sel, StandardCharsets.ISO_8859_1);
        String replaced = transformer.apply(selected);
        if (replaced == null || replaced.equals(selected)) {
            ReplacementScope scope = chooseReplacementScope(sel, selectionIdx);
            if (scope == null) {
                return;
            }
            int ret = JOptionPane.showConfirmDialog(this, prompt,
                    I18n.t("dialog.tip.title"), JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (ret != JOptionPane.YES_OPTION) {
                if (statusLabel != null)
                    statusLabel.setText("No change: operation left selection unchanged");
                return;
            }
            replaced = fallbackTransformer.apply(selected);
            if (replaced == null || replaced.equals(selected)) {
                if (statusLabel != null)
                    statusLabel.setText("No change: fallback left selection unchanged");
                return;
            }
            applyReplacementScope(sel, replaced.getBytes(StandardCharsets.ISO_8859_1), scope);
            return;
        }
        replaceOccurrenceInRequest(sel, replaced.getBytes(StandardCharsets.ISO_8859_1));
    }

    private void runRequestMutation(Runnable action, String name) {
        byte[] before = getRequestBytes().clone();
        reconcileTransformations(before);
        CaretSnapshot caret = captureRequestCaret();
        pendingRequestCaretPosition = null;
        action.run();
        byte[] after = getRequestBytes();
        if (!Arrays.equals(before, after)) {
            pushUndo(before);
            redoStack.clear();
            if (Arrays.equals(after, originalRequest)) transformations.clear();
            else transformations.add(name);
            transformationBytes = after.clone();
            updateUndoRedoButtons();
            if (pendingRequestCaretPosition != null) {
                restoreRequestCaretAt(pendingRequestCaretPosition, after.length);
            } else {
                restoreRequestCaret(caret, after.length);
            }
        }
        pendingRequestCaretPosition = null;
        refreshRequestInspector();
    }

    private void reconcileTransformations(byte[] request) {
        if (Arrays.equals(request, transformationBytes)) return;
        if (Arrays.equals(request, originalRequest)) transformations.clear();
        else if (transformations.isEmpty() || !I18n.t("manual.steps.edit").equals(transformations.get(transformations.size() - 1)))
            transformations.add(I18n.t("manual.steps.edit"));
        transformationBytes = request.clone();
    }

    private String transformationSummary() {
        return transformations.isEmpty() ? I18n.t("manual.steps.original") : String.join(" → ", transformations);
    }

    private void updateTransformationLabel() {
        if (operationSequenceLabel == null) return;
        String steps = I18n.t("manual.steps", transformationSummary());
        operationSequenceLabel.setText(getRequestBytes().length == 0 ? I18n.t("manual.request.empty_short")
                : truncateForInspector(steps, 110));
        operationSequenceLabel.setToolTipText(steps + " | " + I18n.t("manual.steps.tip"));
    }

    private void restoreRequestState(RequestState state) {
        setRequestBytes(state.bytes);
        transformations = new ArrayList<>(state.transformations);
        transformationBytes = state.bytes.clone();
    }

    private static boolean sameTarget(IHttpService first, IHttpService second) {
        return first != null && second != null && first.getHost().equalsIgnoreCase(second.getHost())
                && first.getPort() == second.getPort() && first.getProtocol().equalsIgnoreCase(second.getProtocol());
    }

    private boolean baselineSettingsMatch(IHttpService service, boolean raw, boolean follow, int max) {
        return baselineRun != null && sameTarget(baselineRun.service, service) && baselineRun.raw == raw
                && baselineRun.followRedirect == (follow && !raw) && (!follow || raw || baselineRun.maxRedirects == max);
    }

    private void showSelectedResponse() {
        boolean baseline = responseChoice.getSelectedIndex() == 1;
        responseViewer.setMessage(baseline ? baselineResponseBytes : currentResponseBytes, false);
        String context = baseline ? I18n.t("manual.response.baseline")
                : I18n.t(currentResponseBytes.length == 0 ? "manual.response.none_short"
                : Arrays.equals(getRequestBytes(), responseRequestBytes) ? "manual.response.current_short" : "manual.response.previous_short");
        if (baseline && baselineRun != null) context += " | " + targetText(baselineRun.service) + " | " + (baselineRun.raw ? "Raw" : "Burp");
        responseContextLabel.setText(truncateForInspector(context, 130));
        responseContextLabel.setToolTipText(currentResponseBytes.length == 0 && !baseline
                ? I18n.t(getRequestBytes().length == 0 ? "manual.response.empty" : "manual.response.not_sent")
                : context + (baseline ? "" : " | " + currentResponseSteps));
        responseComparisonLabel.setVisible(!baseline && !currentComparisonText.isEmpty());
        responseComparisonLabel.setText(truncateForInspector(currentComparisonText, 130));
        responseComparisonLabel.setToolTipText(currentComparisonText);
        baselineStatusLabel.setText(truncateForInspector(baselineCheckText, 130));
        baselineStatusLabel.setToolTipText(baselineCheckText);
        baselineDetails.setVisible(originalRequest.length > 0);
        baselineDetails.revalidate();
    }

    private void pushUndo(byte[] state) {
        if (state == null) {
            state = new byte[0];
        }
        undoStack.push(new RequestState(state, transformations));
        if (undoStack.size() > MAX_UNDO_STEPS) {
            undoStack.remove(0);
        }
    }

    private void pushRedo(byte[] state) {
        if (state == null) {
            state = new byte[0];
        }
        redoStack.push(new RequestState(state, transformations));
        if (redoStack.size() > MAX_REDO_STEPS) {
            redoStack.remove(0);
        }
    }

    private void updateUndoRedoButtons() {
        if (undoBtn != null) {
            undoBtn.setEnabled(!undoStack.isEmpty());
        }
        if (redoBtn != null) {
            redoBtn.setEnabled(!redoStack.isEmpty());
        }
    }

    private CaretSnapshot captureRequestCaret() {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return null;
        }
        CaretSnapshot snapshot = new CaretSnapshot();
        snapshot.editor = editor;
        snapshot.caret = editor.getCaretPosition();
        snapshot.selectionStart = editor.getSelectionStart();
        snapshot.selectionEnd = editor.getSelectionEnd();
        return snapshot;
    }

    private JTextComponent findRequestTextComponent() {
        if (requestViewer == null || requestViewer.getComponent() == null) {
            return null;
        }
        Component focus = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        if (focus instanceof JTextComponent && SwingUtilities.isDescendingFrom(focus, requestViewer.getComponent())) {
            return (JTextComponent) focus;
        }
        return findFirstTextComponent(requestViewer.getComponent());
    }

    private JTextComponent findFirstTextComponent(Component comp) {
        if (comp instanceof JTextComponent) {
            return (JTextComponent) comp;
        }
        if (comp instanceof Container) {
            for (Component child : ((Container) comp).getComponents()) {
                JTextComponent found = findFirstTextComponent(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private void restoreRequestCaret(CaretSnapshot snapshot, int newLength) {
        if (snapshot == null || snapshot.editor == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                int max = Math.max(0, Math.min(snapshot.editor.getDocument().getLength(), newLength));
                int start = Math.max(0, Math.min(snapshot.selectionStart, max));
                int end = Math.max(0, Math.min(snapshot.selectionEnd, max));
                int caret = Math.max(0, Math.min(snapshot.caret, max));
                snapshot.editor.requestFocusInWindow();
                if (start != end) {
                    snapshot.editor.select(start, end);
                } else {
                    snapshot.editor.setCaretPosition(caret);
                }
            } catch (Exception ignored) {
            }
        });
    }

    private void restoreRequestCaretAt(int position, int newLength) {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                int max = Math.max(0, Math.min(editor.getDocument().getLength(), newLength));
                int caret = Math.max(0, Math.min(position, max));
                editor.requestFocusInWindow();
                editor.setCaretPosition(caret);
            } catch (Exception ignored) {
            }
        });
    }

    private static class CaretSnapshot {
        JTextComponent editor;
        int caret;
        int selectionStart;
        int selectionEnd;
    }

    // --- Undo/Redo ---
    private void undo() {
        if (!undoStack.isEmpty()) {
            reconcileTransformations(getRequestBytes());
            CaretSnapshot caret = captureRequestCaret();
            pushRedo(getRequestBytes());
            RequestState prev = undoStack.pop();
            restoreRequestState(prev);
            restoreRequestCaret(caret, prev.bytes.length);
            updateUndoRedoButtons();
            refreshRequestInspector();
        }
    }

    private void redo() {
        if (!redoStack.isEmpty()) {
            reconcileTransformations(getRequestBytes());
            CaretSnapshot caret = captureRequestCaret();
            pushUndo(getRequestBytes());
            RequestState next = redoStack.pop();
            restoreRequestState(next);
            restoreRequestCaret(caret, next.bytes.length);
            updateUndoRedoButtons();
            refreshRequestInspector();
        }
    }

    private void reset() {
        if (originalRequest != null && originalRequest.length > 0) {
            byte[] before = getRequestBytes();
            if (Arrays.equals(before, originalRequest)) {
                return;
            }
            CaretSnapshot caret = captureRequestCaret();
            reconcileTransformations(before);
            pushUndo(before);
            redoStack.clear();
            setRequestBytes(originalRequest);
            transformations.clear();
            transformationBytes = originalRequest.clone();
            restoreRequestCaret(caret, originalRequest.length);
            updateUndoRedoButtons();
            refreshRequestInspector();
        }
    }

    // --- Send ---
    private void sendRequest() {
        sendRequest(false);
    }

    private void sendRequest(boolean baseline) {
        if (activeSend != null) return;
        String host = hostField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            statusLabel.setText(I18n.t("manual.port_range"));
            return;
        }
        byte[] editor = (baseline ? originalRequest : getRequestBytes()).clone();
        if (host.isEmpty() || editor.length == 0) {
            statusLabel.setText(I18n.t(host.isEmpty() ? "dialog.host_empty" : "dialog.request_content_empty"));
            return;
        }
        try {
            IHttpService service = Utils.helpers.buildHttpService(host, port, httpsCheckBox.isSelected() ? "https" : "http");
            reconcileTransformations(getRequestBytes());
            byte[] wire = baseline ? editor.clone() : buildRequestBytesForSending(editor);
            boolean raw = shouldUseRawSocket(wire);
            boolean follow = followRedirectCheckBox.isSelected();
            int max = Utils.getConfigMaxRedirects(3);
            boolean matchingReplay = baselineSettingsMatch(service, raw, follow, max);
            byte[] reference = matchingReplay
                    ? baselineResponseBytes
                    : baseline && !raw && sameTarget(originalHttpService, service) ? capturedResponseBytes : null;
            SendRun run = new SendRun(service, editor, wire, raw, follow, max, baseline,
                    baseline ? I18n.t("manual.steps.original") : transformationSummary(),
                    reference == null || reference.length == 0 ? null
                            : new BypassMain.SimpleHttpRequestResponse(service, originalRequest.clone(), reference.clone()), matchingReplay);
            activeSend = run;
            if (!baseline) {
                lastSubmittedRequest = editor.clone();
                currentHttpService = service;
            }
            sendBtn.setEnabled(false);
            replayOriginalBtn.setEnabled(false);
            sendBtn.setText("Sending...");
            cancelBtn.setEnabled(true);
            statusLabel.setText(I18n.t("status.sending"));
            responseContextLabel.setText(I18n.t("manual.response.waiting", targetText(service), wire.length,
                    run.raw ? "Raw" : "Burp"));
            responseContextLabel.setToolTipText(responseContextLabel.getText());
            run.thread = new Thread(() -> executeSend(run), "BypassPro-Manual");
            run.thread.setDaemon(true);
            run.thread.start();
        } catch (Exception e) {
            activeSend = null;
            restoreSendControls();
            statusLabel.setText("Error: " + e.getMessage());
        }
    }

    private void executeSend(SendRun run) {
        byte[] sent = run.wireBytes;
        byte[] response = new byte[0];
        byte[] firstResponse = new byte[0];
        String detail = "";
        StringBuilder chain = new StringBuilder();
        int redirects = 0;
        HttpResponse.Analysis received = null;
        try {
            if (!isCurrent(run)) return;
            if (run.raw) {
                RawSocketSender.RawResponse raw = new RawSocketSender().send(run.service.getHost(), run.service.getPort(),
                        "https".equalsIgnoreCase(run.service.getProtocol()), sent, 5000, 5000);
                sent = raw.getRequestBytesActuallySent();
                response = raw.getResponseBytes();
                firstResponse = response == null ? new byte[0] : response.clone();
                received = raw.getAnalysis();
                if (response == null || response.length == 0) detail = I18n.t("manual.no_response");
            } else {
                java.util.Set<String> visited = new java.util.HashSet<>();
                visited.add(RedirectPolicy.requestUrl(run.service, sent).toString());
                while (isCurrent(run)) {
                    IHttpRequestResponse rr = Utils.callbacks.makeHttpRequest(run.service, sent);
                    if (!isCurrent(run)) return;
                    response = rr == null ? null : rr.getResponse();
                    if (redirects == 0) firstResponse = response == null ? new byte[0] : response.clone();
                    if (response == null || response.length == 0) {
                        detail = I18n.t("manual.no_response");
                        break;
                    }
                    int code = responseStatus(response);
                    chain.append(code).append(" ").append(RedirectPolicy.requestUrl(run.service, sent)).append("\n");
                    if (!run.followRedirect || !RedirectPolicy.isRedirect(code)) break;
                    String location = getHeaderValue(response, "Location");
                    if (location == null || location.isEmpty()) break;
                    if (redirects >= run.maxRedirects) { detail = I18n.t("redirect.limit"); break; }
                    try {
                        java.net.URL next = RedirectPolicy.resolve(run.service, sent, location);
                        if (!visited.add(next.toString())) { detail = I18n.t("redirect.loop"); break; }
                        sent = RedirectPolicy.followRequest(sent, next, code);
                        redirects++;
                    } catch (Exception e) {
                        detail = I18n.t("redirect.stopped", e.getMessage());
                        break;
                    }
                }
            }
        } catch (Exception ex) {
            response = new byte[0];
            detail = "Error: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
        }
        final byte[] finalSent = sent.clone();
        final byte[] finalResponse = response == null ? new byte[0] : response.clone();
        if (received == null) received = HttpResponse.analyze(finalResponse, firstLine(finalSent).split(" ", 2)[0]);
        if (!received.complete && finalResponse.length > 0) detail += " | " + received.issue;
        final short finalStatus = (short)received.statusCode;
        final HttpResponse.Analysis finalAnalysis = received;
        final String comparison = run.baseline
                ? (received.complete ? "" : I18n.t("baseline.failed") + " | ")
                    + BypassMain.baselineSummary(run.reference, run.referenceIsReplay ? received
                        : HttpResponse.analyze(firstResponse, firstLine(run.wireBytes).split(" ", 2)[0]))
                : run.reference != null ? I18n.t("baseline.compare", BypassMain.responseMetrics(run.reference, received))
                    : I18n.t(baselineRun == null ? "baseline.not_checked" : "baseline.conditions_changed");
        final String finalDetail = detail;
        final String finalChain = chain.toString();
        final int finalRedirects = redirects;
        SwingUtilities.invokeLater(() -> {
            if (!isCurrent(run)) return;
            try {
                if (run.baseline) {
                    baselineResponseBytes = finalResponse;
                    baselineDisplayedRequestBytes = finalSent;
                    baselineHttpService = run.service;
                    baselineRun = finalAnalysis.complete ? run : null;
                    baselineCheckText = comparison + (finalRedirects > 0
                            ? " | " + I18n.t("baseline.final", finalStatus, finalResponse.length) : "");
                    currentComparisonText = currentResponseBytes.length == 0 ? ""
                            : I18n.t(finalAnalysis.complete ? "baseline.updated" : "baseline.not_checked");
                    responseChoice.setSelectedIndex(1);
                } else {
                    currentResponseBytes = finalResponse;
                    currentDisplayedRequestBytes = finalSent;
                    responseRequestBytes = run.editorBytes.clone();
                    currentComparisonText = comparison;
                    currentResponseSteps = I18n.t("manual.steps", run.steps);
                    responseChoice.setSelectedIndex(0);
                }
                HistoryEntry entry = new HistoryEntry();
                entry.id = ++historySeq;
                entry.time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                entry.durationMs = (System.nanoTime() - run.startNs) / 1000000L;
                entry.requestBytes = finalSent;
                entry.responseBytes = finalResponse;
                entry.service = run.service;
                entry.sender = run.raw ? "Raw" : "Burp";
                entry.length = finalResponse.length;
                entry.detail = (run.baseline ? I18n.t("manual.replay_original") : I18n.t("manual.steps", run.steps))
                        + " | " + comparison + (finalDetail.isEmpty() ? "" : " | " + finalDetail);
                entry.status = finalStatus;
                String[] first = firstLine(finalSent).split(" ", 3);
                entry.method = first.length > 0 ? first[0] : "";
                entry.path = first.length > 1 ? first[1] : "";
                entry.requestResponse = new BypassMain.SimpleHttpRequestResponse(run.service, finalSent, finalResponse);
                addHistoryEntry(entry);
                if (!run.baseline && !run.raw && finalResponse.length > 0) addToDataboard(entry.requestResponse, entry.detail);
                statusLabel.setText(String.format("[%s] Status: %d | %dms | Req: %dB | Resp: %dB | Redirects: %d %s",
                        entry.sender, entry.status, entry.durationMs, finalSent.length, finalResponse.length, finalRedirects, finalDetail));
                showSelectedResponse();
                responseContextLabel.setToolTipText(responseContextLabel.getToolTipText() + " | " + targetText(run.service)
                        + " | " + finalChain + entry.detail);
            } finally {
                activeSend = null;
                restoreSendControls();
            }
        });
    }

    private short responseStatus(byte[] response) {
        if (response == null || response.length == 0) return 0;
        return (short)HttpResponse.analyze(response, "").statusCode;
    }

    private static String targetText(IHttpService service) {
        return service == null ? "?" : service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }

    private String getHeaderValue(byte[] response, String headerName) {
        return response == null ? null : HttpResponse.analyze(response, "").header(headerName);
    }

    private String formatSize(int size) {
        if (size < 1024)
            return size + "B";
        if (size < 1024 * 1024)
            return String.format("%.1fKB", size / 1024.0);
        return String.format("%.1fMB", size / 1024.0 / 1024.0);
    }

    private void addHistoryEntry(HistoryEntry entry) {
        historyEntries.add(0, entry);
        if (historyEntries.size() > MAX_HISTORY_SIZE) {
            historyEntries.subList(MAX_HISTORY_SIZE, historyEntries.size()).clear();
        }
        historyModel.fireTableDataChanged();
    }

    private void addToDataboard(IHttpRequestResponse response, String detail) {
        try {
            byte[] respBytes = response.getResponse();
            if (respBytes == null)
                return;
            String method = Utils.helpers.analyzeRequest(response).getMethod();
            HttpResponse.Analysis analysis = HttpResponse.analyze(respBytes, method);
            short statusCode = (short)analysis.statusCode;
            HttpResponse.Text decoded = analysis.decodeText();
            String title = Utils.getBodyTitle(decoded.value == null ? "" : decoded.value);
            String reason = String.format("manual send; status:%d", statusCode);
            if (!detail.isEmpty()) reason += "; " + detail;
            if (!decoded.issue.isEmpty()) reason += "; " + decoded.issue;
            Utils.panel.getBypassTableModel().addBypass(new Bypass(
                    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                    method,
                    String.valueOf(respBytes.length),
                    Utils.callbacks.saveBuffersToTempFiles(response),
                    Utils.helpers.analyzeRequest(response).getUrl(),
                    statusCode,
                    analysis.header("Content-Type"),
                    title,
                    BypassMain.nextId(),
                    "manual waf",
                    reason));
        } catch (Exception ignored) {
        }
    }

    private void showHistoryEntry(int index) {
        if (index < 0 || index >= historyEntries.size()) return;
        HistoryEntry entry = historyEntries.get(index);
        statusLabel.setText(I18n.t("manual.history.selected", entry.id, targetText(entry.service))
                + (entry.detail == null || entry.detail.isEmpty() ? "" : " | " + entry.detail));
    }

    // --- Public API ---
    public void loadRequest(IHttpRequestResponse requestResponse) {
        if (requestResponse == null)
            return;
        cancelRequest();
        currentHttpService = requestResponse.getHttpService();
        originalHttpService = currentHttpService;
        baselineHttpService = currentHttpService;
        baselineRun = null;
        baselineCheckText = I18n.t("baseline.not_checked");
        currentComparisonText = "";
        currentResponseSteps = "";
        if (currentHttpService != null) {
            if (hostField != null)
                hostField.setText(currentHttpService.getHost());
            if (portField != null)
                portField.setText(String.valueOf(currentHttpService.getPort()));
            if (httpsCheckBox != null)
                httpsCheckBox.setSelected("https".equalsIgnoreCase(currentHttpService.getProtocol()));
        }

        byte[] req = requestResponse.getRequest() == null ? new byte[0] : requestResponse.getRequest();
        {
            requestViewer.setMessage(req.clone(), true);
            originalRequest = Arrays.copyOf(req, req.length);
            baselineDisplayedRequestBytes = req.clone();
            currentDisplayedRequestBytes = req.clone();
            transformations.clear();
            transformationBytes = req.clone();
            responseRequestBytes = req.clone();
            lastSubmittedRequest = new byte[0];
            undoStack.clear();
            redoStack.clear();
            updateUndoRedoButtons();
        }

        byte[] resp = requestResponse.getResponse();
        if (resp != null) {
            currentResponseBytes = resp.clone();
            responseViewer.setMessage(currentResponseBytes, false);
        } else {
            currentResponseBytes = new byte[0];
            responseViewer.setMessage(new byte[0], false);
        }
        capturedResponseBytes = currentResponseBytes.clone();
        baselineResponseBytes = currentResponseBytes.clone();
        responseChoice.setSelectedIndex(0);
        setSenderMode(SenderMode.AUTO);
        statusLabel.setText(I18n.t("manual.loaded", firstLine(getRequestBytes())));
        showSelectedResponse();
        refreshRequestInspector();
    }

    // --- IMessageEditorController ---
    @Override
    public IHttpService getHttpService() {
        return currentHttpService;
    }

    @Override
    public byte[] getRequest() {
        return getRequestBytes();
    }

    @Override
    public byte[] getResponse() {
        return currentResponseBytes;
    }

    // --- Bytes ---
    private byte[] getRequestBytes() {
        byte[] msg = requestViewer == null ? null : requestViewer.getMessage();
        return msg == null ? new byte[0] : msg;
    }

    private void setRequestBytes(byte[] msg) {
        if (msg == null)
            msg = new byte[0];
        if (requestViewer != null)
            requestViewer.setMessage(msg, true);
    }

    private String getRequestTextISO() {
        return new String(getRequestBytes(), StandardCharsets.ISO_8859_1);
    }

    private void setRequestTextISO(String text) {
        if (text == null)
            text = "";
        setRequestBytes(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private byte[] getSelectedRequestBytes() {
        if (requestViewer == null)
            return new byte[0];
        byte[] sel = requestViewer.getSelectedData();
        return sel == null ? new byte[0] : sel;
    }

    /**
     * 从 JTextComponent 拿用户当前框选的字节偏移 [start, end)。
     * 拿不到（Hex 视图、无焦点、无选区）时返回 null，调用方走降级路径。
     */
    private int[] getSelectionRange() {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return null;
        }
        int start = editor.getSelectionStart();
        int end = editor.getSelectionEnd();
        if (start == end) {
            return null;
        }
        return new int[] { start, end };
    }

    /**
     * 拿当前 request 编辑器的 caret 位置（字节偏移）。
     * 注意：JTextComponent.getCaretPosition() 返回字符偏移，但本工程
     * 在 ISO-8859-1 下用 1:1 字符<->字节映射，二者等价。
     * 拿不到（Hex 视图、无 JTextComponent）时返回 -1。
     */
    private int getRequestCaret() {
        JTextComponent editor = findRequestTextComponent();
        if (editor == null) {
            return -1;
        }
        return editor.getCaretPosition();
    }

    /** msg[offset..offset+target.length) == target 的逐字节比较。offset 越界返回 false。 */
    private static boolean bytesMatchAt(byte[] msg, int offset, byte[] target) {
        if (msg == null || target == null || offset < 0 || offset + target.length > msg.length) {
            return false;
        }
        for (int i = 0; i < target.length; i++) {
            if (msg[offset + i] != target[i]) {
                return false;
            }
        }
        return true;
    }

    private boolean replaceOccurrenceInRequest(byte[] target, byte[] replacement) {
        byte[] msg = getRequestBytes();
        ReplacementScope scope = chooseReplacementScope(target, resolveSelectionIndex(msg, target));
        if (scope == null) {
            return false;
        }
        applyReplacementScope(target, replacement, scope);
        return true;
    }

    private ReplacementScope chooseReplacementScope(byte[] target, Integer selectionIdx) {
        byte[] msg = getRequestBytes();
        List<Integer> positions = findAllOccurrences(msg, target);

        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.selection_not_found"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        // 唯一匹配：无需交互
        if (positions.size() == 1) {
            return ReplacementScope.single(positions.get(0));
        }

        if (selectionIdx != null && !bytesMatchAt(msg, selectionIdx, target)) {
            selectionIdx = null;
        }

        List<String> optionList = new ArrayList<>();
        String selectionOption = null;
        if (selectionIdx != null) {
            selectionOption = I18n.t("dialog.scope.selection");
            optionList.add(selectionOption);
        }
        String allOption = I18n.t("dialog.scope.all", positions.size());
        optionList.add(allOption);
        for (int i = 0; i < positions.size(); i++) {
            int pos = positions.get(i);
            String context = getContextSnippet(msg, pos, target.length, 20);
            optionList.add(I18n.t("dialog.scope.occurrence", i + 1, context));
        }
        String[] options = optionList.toArray(new String[0]);

        Object choice = JOptionPane.showInputDialog(
                this,
                I18n.t("dialog.scope.prompt", positions.size()),
                I18n.t("dialog.scope.title"),
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (choice == null) {
            return null;
        }

        String choiceStr = choice.toString();
        if (selectionOption != null && choiceStr.equals(selectionOption)) {
            return ReplacementScope.single(selectionIdx);
        }
        if (choiceStr.equals(allOption)) {
            return ReplacementScope.all();
        }
        int headerCount = (selectionOption != null ? 1 : 0) + 1;
        for (int i = 0; i < positions.size(); i++) {
            if (choiceStr.equals(options[headerCount + i])) {
                return ReplacementScope.single(positions.get(i));
            }
        }
        return null;
    }

    private void applyReplacementScope(byte[] target, byte[] replacement, ReplacementScope scope) {
        byte[] msg = getRequestBytes();
        if (scope.all) {
            List<Integer> positions = findAllOccurrences(msg, target);
            replaceAllOccurrences(msg, positions, target.length, replacement);
            return;
        }
        if (bytesMatchAt(msg, scope.index, target)) {
            replaceAtIndex(msg, scope.index, target.length, replacement);
        } else {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.selection_changed"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static class ReplacementScope {
        final boolean all;
        final int index;

        private ReplacementScope(boolean all, int index) {
            this.all = all;
            this.index = index;
        }

        static ReplacementScope all() {
            return new ReplacementScope(true, -1);
        }

        static ReplacementScope single(int index) {
            return new ReplacementScope(false, index);
        }
    }

    /**
     * 如果用户有明确选区，并且选区字节恰好等于 target，返回选区起点；否则返回 null。
     * 用于在多匹配弹框中作为"选区处"一键选项。
     * 降级场景：Hex 视图 / 多字节偏移不一致 / 选区字节对不上 target。
     */
    private Integer resolveSelectionIndex(byte[] msg, byte[] target) {
        int[] range = getSelectionRange();
        if (range == null) {
            return null;
        }
        int start = range[0];
        int len = range[1] - start;
        if (len != target.length) {
            return null;
        }
        if (!bytesMatchAt(msg, start, target)) {
            return null;
        }
        return start;
    }

    private void replaceAtIndex(byte[] msg, int idx, int targetLen, byte[] replacement) {
        byte[] out = new byte[msg.length - targetLen + replacement.length];
        System.arraycopy(msg, 0, out, 0, idx);
        System.arraycopy(replacement, 0, out, idx, replacement.length);
        System.arraycopy(msg, idx + targetLen, out, idx + replacement.length, msg.length - (idx + targetLen));
        pendingRequestCaretPosition = idx + replacement.length;
        setRequestBytes(out);
    }

    private void replaceAllOccurrences(byte[] msg, List<Integer> positions, int targetLen, byte[] replacement) {
        byte[] out = new byte[msg.length + positions.size() * (replacement.length - targetLen)];
        int source = 0, dest = 0;
        for (int pos : positions) {
            int span = pos - source;
            System.arraycopy(msg, source, out, dest, span);
            dest += span;
            System.arraycopy(replacement, 0, out, dest, replacement.length);
            dest += replacement.length;
            source = pos + targetLen;
        }
        System.arraycopy(msg, source, out, dest, msg.length - source);
        pendingRequestCaretPosition = out.length;
        setRequestBytes(out);
    }

    private List<Integer> findAllOccurrences(byte[] haystack, byte[] needle) {
        List<Integer> result = new ArrayList<>();
        if (haystack == null || needle == null || needle.length == 0 || haystack.length < needle.length) {
            return result;
        }
        int idx = 0;
        while (idx <= haystack.length - needle.length) {
            int found = indexOfFrom(haystack, needle, idx);
            if (found < 0)
                break;
            result.add(found);
            idx = found + needle.length; // 不允许重叠匹配
        }
        return result;
    }

    private static int indexOfFrom(byte[] haystack, byte[] needle, int fromIndex) {
        if (haystack == null || needle == null || needle.length == 0)
            return -1;
        outer: for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j])
                    continue outer;
            }
            return i;
        }
        return -1;
    }

    private String getContextSnippet(byte[] msg, int pos, int targetLen, int contextLen) {
        int start = Math.max(0, pos - contextLen);
        int end = Math.min(msg.length, pos + targetLen + contextLen);

        StringBuilder sb = new StringBuilder();
        if (start > 0)
            sb.append("");
        for (int i = start; i < pos; i++) {
            sb.append(safeChar(msg[i]));
        }
        sb.append("[");
        for (int i = pos; i < pos + targetLen && i < msg.length; i++) {
            sb.append(safeChar(msg[i]));
        }
        sb.append("]");
        for (int i = pos + targetLen; i < end; i++) {
            sb.append(safeChar(msg[i]));
        }
        if (end < msg.length)
            sb.append("");
        return sb.toString();
    }

    private char safeChar(byte b) {
        int c = b & 0xFF;
        if (c == '\r')
            return '↵';
        if (c == '\n')
            return '↓';
        if (c == '\t')
            return '→';
        if (c < 0x20 || c >= 0x7F)
            return '·';
        return (char) c;
    }

    /**
     * 纯生成插入入口：光标处插入（caret 优先），拿不到 caret 时回退选区路径。
     * 适用于 Dirty/Null/Atoms 区这类"插入物与选中内容无关"的按钮——选区不参与运算，
     * 不应该强制要求用户先选一段。Hex 视图等无 JTextComponent 的场景才走兜底。
     */
    private void insertAtCaretOrFallback(byte[] insert) {
        int caret = getRequestCaret();
        byte[] msg = getRequestBytes();
        if (caret >= 0 && caret <= msg.length) {
            performInsert(msg, caret, insert);
            return;
        }
        insertIntoSelectionOrWarn(insert, true);
    }

    private void insertIntoSelectionOrWarn(byte[] insert, boolean beforeSelection) {
        byte[] sel = getSelectedRequestBytes();
        if (sel == null || sel.length == 0) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.select_insertion"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        byte[] msg = getRequestBytes();
        List<Integer> positions = findAllOccurrences(msg, sel);

        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.t("dialog.selection_not_found"), I18n.t("dialog.tip.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int chosenIdx;
        if (positions.size() == 1) {
            chosenIdx = positions.get(0);
        } else {
            Integer selectionIdx = resolveSelectionIndex(msg, sel);
            List<String> optionList = new ArrayList<>();
            String selectionOption = null;
            if (selectionIdx != null) {
                selectionOption = I18n.t("dialog.scope.selection");
                optionList.add(selectionOption);
            }
            for (int i = 0; i < positions.size(); i++) {
                int pos = positions.get(i);
                String context = getContextSnippet(msg, pos, sel.length, 20);
                optionList.add(I18n.t("dialog.scope.occurrence", i + 1, context));
            }
            String[] options = optionList.toArray(new String[0]);

            Object choice = JOptionPane.showInputDialog(
                    this,
                    I18n.t("dialog.scope.prompt", positions.size()),
                    I18n.t("dialog.scope.title"),
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]);

            if (choice == null)
                return;

            String choiceStr = choice.toString();
            if (selectionOption != null && choiceStr.equals(selectionOption)) {
                chosenIdx = selectionIdx;
            } else {
                chosenIdx = -1;
                int headerCount = (selectionOption != null ? 1 : 0);
                for (int i = 0; i < positions.size(); i++) {
                    if (choiceStr.equals(options[headerCount + i])) {
                        chosenIdx = positions.get(i);
                        break;
                    }
                }
                if (chosenIdx < 0)
                    return;
            }
        }

        int insertPos = beforeSelection ? chosenIdx : (chosenIdx + sel.length);
        performInsert(msg, insertPos, insert);
    }

    /** 在 msg 的 insertPos 处插入 insert，设置光标到插入内容末尾，写回 request。 */
    private void performInsert(byte[] msg, int insertPos, byte[] insert) {
        byte[] out = new byte[msg.length + insert.length];
        System.arraycopy(msg, 0, out, 0, insertPos);
        System.arraycopy(insert, 0, out, insertPos, insert.length);
        System.arraycopy(msg, insertPos, out, insertPos + insert.length, msg.length - insertPos);
        pendingRequestCaretPosition = insertPos + insert.length;
        setRequestBytes(out);
    }

    // --- Dirty tags ---
    private byte[] buildRequestBytesForSending(byte[] originalRequestBytes) {
        if (originalRequestBytes == null)
            return new byte[0];

        SplitBytes split = splitRequestBytes(originalRequestBytes);
        if (split == null) {
            // 不是标准的 header/body 结构：只展开占位符，不做 CL 修正
            return expandWholeBytesWithTags(originalRequestBytes);
        }

        boolean tamperedCL = isContentLengthTampered(originalRequestBytes);

        // 展开 headers（通常很小）+ body（流式）
        String headersStr = new String(split.headersBytes, StandardCharsets.ISO_8859_1);
        headersStr = expandInlineTags(headersStr);

        String bodyStr = new String(split.bodyBytes, StandardCharsets.ISO_8859_1);
        byte[] bodyExpanded = buildBodyBytesWithTags(bodyStr, StandardCharsets.ISO_8859_1);

        // 只有占位符实际改变正文长度才更新普通报文的 CL；保留用户构造的 TE/CL 组合。
        if (!tamperedCL && !hasHeaderName(headersStr, "Transfer-Encoding")
                && bodyExpanded.length != split.bodyBytes.length) {
            headersStr = upsertHeaderLine(headersStr, "Content-Length", String.valueOf(bodyExpanded.length), split.lineEnd);
        }
        return concatRequest(headersStr.getBytes(StandardCharsets.ISO_8859_1), split.delimiterBytes, bodyExpanded);
    }

    private boolean hasHeaderName(String headers, String headerName) {
        if (headers == null)
            return false;
        String[] lines = headers.split("\\r?\\n", -1);
        for (String line : lines) {
            if (line.toLowerCase().startsWith(headerName.toLowerCase() + ":"))
                return true;
        }
        return false;
    }

    private boolean isContentLengthTampered(byte[] requestBytes) {
        SplitBytes split = splitRequestBytes(requestBytes);
        if (split == null)
            return false;
        String headers = new String(split.headersBytes, StandardCharsets.ISO_8859_1);
        String[] lines = headers.split("\\r?\\n", -1);
        int declared = -1;
        for (String line : lines) {
            if (line.toLowerCase().startsWith("content-length:")) {
                try {
                    declared = Integer.parseInt(line.split(":", 2)[1].trim());
                } catch (Exception e) {
                    return true; // 畸形 CL：视为篡改，不乱动
                }
                break;
            }
        }
        if (declared < 0)
            return false; // 没有 CL
        return declared != split.bodyBytes.length;
    }

    private byte[] expandWholeBytesWithTags(byte[] requestBytes) {
        String s = new String(requestBytes, StandardCharsets.ISO_8859_1);
        // headers/body 不明时，只做基础展开（headers 很可能存在 dirty）
        String expanded = expandInlineTags(s);
        return expanded.getBytes(StandardCharsets.ISO_8859_1);
    }

    private byte[] concatRequest(byte[] headersBytes, byte[] delimiterBytes, byte[] bodyBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(headersBytes);
            out.write(delimiterBytes);
            out.write(bodyBytes);
        } catch (Exception ignored) {
        }
        return out.toByteArray();
    }

    private static class SplitBytes {
        byte[] headersBytes;
        byte[] bodyBytes;
        byte[] delimiterBytes;
        String lineEnd;
    }

    private SplitBytes splitRequestBytes(byte[] requestBytes) {
        if (requestBytes == null)
            return null;
        int idx = indexOfBytes(requestBytes, new byte[] { '\r', '\n', '\r', '\n' });
        byte[] delimiter;
        String lineEnd;
        int sepLen;
        if (idx >= 0) {
            delimiter = new byte[] { '\r', '\n', '\r', '\n' };
            lineEnd = "\r\n";
            sepLen = 4;
        } else {
            idx = indexOfBytes(requestBytes, new byte[] { '\n', '\n' });
            if (idx < 0)
                return null;
            delimiter = new byte[] { '\n', '\n' };
            lineEnd = "\n";
            sepLen = 2;
        }
        SplitBytes split = new SplitBytes();
        split.headersBytes = Arrays.copyOfRange(requestBytes, 0, idx);
        split.bodyBytes = Arrays.copyOfRange(requestBytes, idx + sepLen, requestBytes.length);
        split.delimiterBytes = delimiter;
        split.lineEnd = lineEnd;
        return split;
    }

    private int indexOfBytes(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || needle.length == 0 || haystack.length < needle.length)
            return -1;
        outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j])
                    continue outer;
            }
            return i;
        }
        return -1;
    }

    private void updateOrAddHeader(List<String> headers, String name, String value) {
        if (headers == null || headers.isEmpty())
            return;
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                headers.set(i, name + ": " + value);
                return;
            }
        }
        headers.add(name + ": " + value);
    }

    private void removeHeaderIgnoreCase(List<String> headers, String name) {
        if (headers == null || headers.size() <= 1)
            return;
        for (int i = headers.size() - 1; i >= 1; i--) {
            String h = headers.get(i);
            if (h.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                headers.remove(i);
            }
        }
    }

    private int findHeaderIndex(List<String> headers, String name) {
        if (headers == null || name == null) {
            return -1;
        }
        for (int i = 1; i < headers.size(); i++) {
            String h = headers.get(i);
            if (h == null)
                continue;
            int colon = h.indexOf(':');
            if (colon <= 0)
                continue;
            if (h.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return i;
            }
        }
        return -1;
    }

    private String expandInlineTags(String input) {
        if (input == null || input.isEmpty())
            return input;
        String out = input;
        out = replaceDirtyTag(out, TAG_DIRTY, false);
        out = replaceDirtyTag(out, TAG_DIRTY_NULL, true);
        return out;
    }

    private String replaceDirtyTag(String input, Pattern pattern, boolean isNull) {
        Matcher m = pattern.matcher(input);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            int count;
            try {
                count = Integer.parseInt(m.group(1));
            } catch (Exception e) {
                count = 0;
            }
            if (count <= 0) {
                m.appendReplacement(sb, "");
                continue;
            }
            String replacement;
            if (isNull) {
                char[] zeros = new char[count];
                Arrays.fill(zeros, '\0');
                replacement = new String(zeros);
            } else {
                Random r = new Random();
                StringBuilder s = new StringBuilder(count);
                for (int i = 0; i < count; i++) {
                    s.append(r.nextInt(10));
                }
                replacement = s.toString();
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private byte[] buildBodyBytesWithTags(String body, Charset charsetForText) {
        if (body == null || body.isEmpty())
            return new byte[0];
        if (!body.contains("{{")) {
            return body.getBytes(charsetForText);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int idx = 0;
        while (idx < body.length()) {
            Matcher m1 = TAG_DIRTY.matcher(body);
            Matcher m2 = TAG_DIRTY_NULL.matcher(body);
            boolean f1 = m1.find(idx);
            boolean f2 = m2.find(idx);

            if (!f1 && !f2) {
                writeText(out, body.substring(idx), charsetForText);
                break;
            }

            Matcher chosen;
            boolean isNull;
            if (f1 && f2) {
                if (m1.start() <= m2.start()) {
                    chosen = m1;
                    isNull = false;
                } else {
                    chosen = m2;
                    isNull = true;
                }
            } else if (f1) {
                chosen = m1;
                isNull = false;
            } else {
                chosen = m2;
                isNull = true;
            }

            int start = chosen.start();
            int end = chosen.end();
            if (start > idx) {
                writeText(out, body.substring(idx, start), charsetForText);
            }

            int count;
            try {
                count = Integer.parseInt(chosen.group(1));
            } catch (Exception e) {
                count = 0;
            }
            if (count > 0) {
                if (isNull)
                    writeNullBytes(out, count);
                else
                    writeRandomDigits(out, count);
            }
            idx = end;
        }

        return out.toByteArray();
    }

    private void writeText(ByteArrayOutputStream out, String s, Charset cs) {
        if (s == null || s.isEmpty())
            return;
        try {
            out.write(s.getBytes(cs));
        } catch (Exception ignored) {
        }
    }

    private void writeNullBytes(ByteArrayOutputStream out, int count) {
        if (count <= 0)
            return;
        byte[] buf = new byte[Math.min(count, 8192)];
        int remaining = count;
        while (remaining > 0) {
            int n = Math.min(remaining, buf.length);
            out.write(buf, 0, n);
            remaining -= n;
        }
    }

    private void writeRandomDigits(ByteArrayOutputStream out, int count) {
        if (count <= 0)
            return;
        Random r = new Random();
        byte[] buf = new byte[Math.min(count, 8192)];
        int remaining = count;
        while (remaining > 0) {
            int n = Math.min(remaining, buf.length);
            for (int i = 0; i < n; i++)
                buf[i] = (byte) ('0' + r.nextInt(10));
            out.write(buf, 0, n);
            remaining -= n;
        }
    }

    // --- History ---
    static class HistoryEntry {
        int id;
        short status;
        int length;
        String time;
        String method;
        String path;
        long durationMs;
        byte[] requestBytes;
        byte[] responseBytes;
        IHttpRequestResponse requestResponse;
        IHttpService service;
        String detail;
        /** "Burp" / "Raw"，用于区分发送通道 */
        String sender = "Burp";
    }

    class HistoryTableModel extends AbstractTableModel {
        private final String[] columns = { "#", I18n.t("history.sender"), I18n.t("history.method"), I18n.t("history.path"),
                I18n.t("history.status"), I18n.t("history.length"), I18n.t("history.duration"),
                I18n.t("history.clock"), I18n.t("history.target") };

        @Override
        public int getRowCount() {
            return historyEntries.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int col) {
            return columns[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            HistoryEntry e = historyEntries.get(row);
            switch (col) {
                case 0:
                    return e.id;
                case 1:
                    return e.sender != null ? e.sender : "Burp";
                case 2:
                    return e.method != null ? e.method : "";
                case 3:
                    return e.path != null ? (e.path.length() > 40 ? e.path.substring(0, 37) + "..." : e.path) : "";
                case 4:
                    return e.status;
                case 5:
                    return e.length;
                case 6:
                    return e.durationMs;
                case 7:
                    return e.time;
                case 8:
                    return targetText(e.service);
                default:
                    return "";
            }
        }
    }
}

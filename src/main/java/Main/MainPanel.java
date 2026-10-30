package Main;

import burp.BurpExtender;
import burp.ITab;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * 主面板：Dashboard、Manual WAF 和 Config。
 */
public class MainPanel extends JPanel implements ITab {

    private static final double DEFAULT_SIMILARITY_THRESHOLD = 0.85;
    private static final int DEFAULT_THREAD_NUM = 5;

    private BypassTableModel bypassTableModel;
    private JTextField threadNumText;
    private JLabel allRequestNumberText;
    private JLabel finishRequestNumberText;
    private JLabel errorRequestNumText;
    private JCheckBox isAutoCheckBox;
    private JCheckBox followRedirectCheckBox;
    private ConfigPanel configPanel;
    private ManualWafPanel manualWafPanel;
    private JProgressBar progressBar;
    private JTabbedPane tabs;
    private JLabel scanStatus;
    private JLabel cancelledNumberText;
    private JLabel activeNumberText;
    private volatile ScanSession scanSession = new ScanSession();
    private volatile int configuredThreads = DEFAULT_THREAD_NUM;
    private volatile boolean followRedirect;
    private BypassTable bypassTable;

    @SuppressWarnings("unchecked")
    public MainPanel() {

        setLayout(new BorderLayout());

        // 主分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 结果表格
        bypassTableModel = new BypassTableModel();
        bypassTable = new BypassTable(bypassTableModel);
        JScrollPane scrollPane = new JScrollPane(bypassTable);
        splitPane.setLeftComponent(scrollPane);

        // Request/Response 双窗格
        JSplitPane httpSplitPane = new JSplitPane();
        httpSplitPane.setResizeWeight(0.50);
        // request
        JTabbedPane reqJTabbedPane = new JTabbedPane();
        reqJTabbedPane.add("Request", bypassTable.getRequestViewer().getComponent());
        // response
        JTabbedPane resJTabbedPane = new JTabbedPane();
        resJTabbedPane.add("Response", bypassTable.getResponseViewer().getComponent());
        httpSplitPane.add(reqJTabbedPane, "left");
        httpSplitPane.add(resJTabbedPane, "right");
        splitPane.setRightComponent(httpSplitPane);

        // 控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controlPanel.setBorder(new EmptyBorder(4, 8, 4, 8));

        controlPanel.add(new JLabel("AutoScan:"));
        isAutoCheckBox = new JCheckBox("", false);
        isAutoCheckBox.addActionListener(e -> {
            Utils.isProxySelected = isAutoCheckBox.isSelected();
            updateListeningStatus();
        });
        isAutoCheckBox.setToolTipText(I18n.t("dashboard.autoscan.tip"));
        controlPanel.add(isAutoCheckBox);

        controlPanel.add(new JLabel("Follow Redirect："));
        followRedirectCheckBox = new JCheckBox("", false);
        followRedirectCheckBox.setToolTipText(I18n.t("manual.redirect.same_origin"));
        followRedirectCheckBox.addActionListener(e -> followRedirect = followRedirectCheckBox.isSelected());
        controlPanel.add(followRedirectCheckBox);

        controlPanel.add(new JLabel("Threads:"));
        threadNumText = new JTextField(2);
        threadNumText.setText(String.valueOf(Utils.getConfigThreads(DEFAULT_THREAD_NUM)));
        configuredThreads = Math.max(1, Math.min(100, Utils.getConfigThreads(DEFAULT_THREAD_NUM)));
        threadNumText.setToolTipText(I18n.t("dashboard.threads.tip"));
        threadNumText.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { update(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { update(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
            private void update() {
                try { configuredThreads = Math.max(1, Math.min(100, Integer.parseInt(threadNumText.getText()))); }
                catch (NumberFormatException ignored) { }
            }
        });
        controlPanel.add(threadNumText);

        controlPanel.add(Box.createHorizontalStrut(8));

        JPanel counters = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        counters.setBorder(new EmptyBorder(0, 8, 0, 8));
        counters.add(new JLabel(I18n.t("dashboard.planned")));
        allRequestNumberText = new JLabel("0");
        counters.add(allRequestNumberText);

        counters.add(new JLabel(I18n.t("dashboard.completed")));
        finishRequestNumberText = new JLabel("0");
        counters.add(finishRequestNumberText);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setValue(0);
        progressBar.setBorderPainted(false);
        progressBar.setPreferredSize(new Dimension(120, 18));
        counters.add(progressBar);

        counters.add(Box.createHorizontalStrut(8));

        counters.add(new JLabel("Err:"));
        errorRequestNumText = new JLabel("0");
        counters.add(errorRequestNumText);

        counters.add(Box.createHorizontalStrut(8));

        counters.add(new JLabel(I18n.t("dashboard.active")));
        activeNumberText = new JLabel("0");
        counters.add(activeNumberText);
        counters.add(new JLabel(I18n.t("dashboard.cancelled")));
        cancelledNumberText = new JLabel("0");
        counters.add(cancelledNumberText);
        JButton stopButton = new JButton(I18n.t("dashboard.stop"));
        stopButton.addActionListener(e -> stopScans());
        stopButton.setToolTipText(I18n.t("dashboard.stop.tip"));
        controlPanel.add(stopButton);
        JButton clearButton = new JButton(I18n.t("dashboard.clear"));
        clearButton.setToolTipText(I18n.t("dashboard.clear.tip"));
        clearButton.addActionListener(e -> clearResults());
        controlPanel.add(clearButton);

        JPanel databoardPanel = new JPanel(new BorderLayout());
        JPanel heading = new JPanel(new BorderLayout());
        JPanel toolbar = new JPanel(null) {
            private boolean fitsOneRow(int width) {
                return width >= controlPanel.getPreferredSize().width + counters.getPreferredSize().width + 24;
            }

            @Override
            public Dimension getPreferredSize() {
                Dimension controls = controlPanel.getPreferredSize();
                Dimension stats = counters.getPreferredSize();
                int width = getParent() == null ? getWidth() : getParent().getWidth();
                int height = width <= 0 || fitsOneRow(width)
                        ? Math.max(controls.height, stats.height) : controls.height + stats.height;
                return new Dimension(controls.width + stats.width + 24, height);
            }

            @Override
            public void doLayout() {
                Dimension controls = controlPanel.getPreferredSize();
                Dimension stats = counters.getPreferredSize();
                boolean oneRow = fitsOneRow(getWidth());
                int rowHeight = oneRow ? Math.max(controls.height, stats.height) : controls.height;
                controlPanel.setBounds(0, (rowHeight - controls.height) / 2,
                        Math.min(getWidth(), controls.width), controls.height);
                counters.setBounds(Math.max(0, getWidth() - stats.width),
                        oneRow ? (rowHeight - stats.height) / 2 : controls.height,
                        Math.min(getWidth(), stats.width), stats.height);
            }
        };
        toolbar.add(controlPanel);
        toolbar.add(counters);
        heading.add(toolbar, BorderLayout.CENTER);
        scanStatus = new JLabel();
        scanStatus.setHorizontalAlignment(SwingConstants.RIGHT);
        scanStatus.setBorder(new EmptyBorder(3, 12, 6, 8));
        heading.add(scanStatus, BorderLayout.SOUTH);
        updateListeningStatus();
        databoardPanel.add(heading, BorderLayout.NORTH);
        databoardPanel.add(splitPane, BorderLayout.CENTER);
        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JComboBox<String> outcomeFilter = new JComboBox<>(new String[]{I18n.t("dashboard.signals"),
                I18n.t("dashboard.all"), I18n.t("dashboard.errors"), I18n.t("dashboard.filtered"), I18n.t("dashboard.baselines")});
        JTextField search = new JTextField(24);
        search.setToolTipText(I18n.t("dashboard.search"));
        JLabel retained = new JLabel();
        javax.swing.table.TableRowSorter<BypassTableModel> sorter =
                (javax.swing.table.TableRowSorter<BypassTableModel>) bypassTable.getRowSorter();
        RowFilter<BypassTableModel, Integer> rowFilter = new RowFilter<BypassTableModel, Integer>() {
                public boolean include(Entry<? extends BypassTableModel, ? extends Integer> entry) {
                    Bypass row = bypassTableModel.getBypassAt(entry.getIdentifier());
                    if (row == null) return false;
                    int mode = outcomeFilter.getSelectedIndex();
                    if (mode == 0 && row.outcome != Bypass.Outcome.SIGNAL && row.outcome != Bypass.Outcome.ERROR) return false;
                    if (mode == 2 && row.outcome != Bypass.Outcome.ERROR) return false;
                    if (mode == 3 && row.outcome != Bypass.Outcome.FILTERED) return false;
                    if (mode == 4 && row.outcome != Bypass.Outcome.BASELINE) return false;
                    String query = search.getText().trim().toLowerCase(java.util.Locale.ROOT);
                    return (row.url + " " + row.reason + " " + row.title + " " + row.tool)
                            .toLowerCase(java.util.Locale.ROOT).contains(query);
                }
        };
        Runnable updateRetained = () -> retained.setText(I18n.t("dashboard.retained",
                bypassTableModel.getRowCount(), bypassTableModel.getDiscardedCount()));
        Runnable updateFilter = () -> { sorter.setRowFilter(rowFilter); updateRetained.run(); };
        outcomeFilter.addActionListener(e -> { bypassTable.clearViewers(); updateFilter.run(); });
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { bypassTable.clearViewers(); updateFilter.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { bypassTable.clearViewers(); updateFilter.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateFilter.run(); }
        });
        bypassTableModel.addTableModelListener(e -> updateRetained.run());
        filters.add(outcomeFilter);
        filters.add(new JLabel(I18n.t("dashboard.search")));
        filters.add(search);
        filters.add(retained);
        updateFilter.run();
        databoardPanel.add(filters, BorderLayout.SOUTH);

        this.configPanel = new ConfigPanel();
        this.manualWafPanel = new ManualWafPanel();

        tabs = new JTabbedPane();
        tabs.addTab("Dashboard", databoardPanel);
        tabs.addTab("Manual WAF", this.manualWafPanel);
        tabs.addTab("Config", this.configPanel);

        add(tabs, BorderLayout.CENTER);

        BurpExtender.callbacks.customizeUiComponent(this);
    }

    public String getTabCaption() {

        return "BypassPro";
    }

    public Component getUiComponent() {

        return this;
    }

    public int getThreadNum() { return configuredThreads; }

    synchronized ScanSession sessionForInput() { return sessionForInput(false); }

    synchronized ScanSession sessionForInput(boolean automatic) {
        if (automatic && !Utils.isProxySelected) return null;
        if (scanSession.cancelled) scanSession = new ScanSession();
        return scanSession;
    }

    void refreshScan(ScanSession session) {
        SwingUtilities.invokeLater(() -> { if (session == scanSession) updateProgressBar(); });
    }

    void addAllRequestNum(ScanSession session, int num) { session.planned(num); refreshScan(session); }
    void addFinishRequestNum(ScanSession session, int num) { session.finished(num); refreshScan(session); }
    void addErrorRequestNum(ScanSession session, int num) { session.failed(num); refreshScan(session); }

    void addResult(ScanSession session, Bypass result) {
        SwingUtilities.invokeLater(() -> {
            if (session == scanSession && !session.cancelled) bypassTableModel.addBypass(result);
        });
    }

    synchronized void stopScans() {
        Utils.isProxySelected = false;
        scanSession.cancel();
        isAutoCheckBox.setSelected(false);
        Utils.discardPendingScans();
        updateProgressBar();
        scanStatus.setText(I18n.t("dashboard.stopped"));
    }

    synchronized void clearResults() {
        stopScans();
        scanSession = new ScanSession();
        bypassTableModel.clearAll();
        bypassTable.clearViewers();
        updateProgressBar();
        updateListeningStatus();
    }

    private void updateListeningStatus() {
        scanStatus.setText(I18n.t(Utils.isProxySelected ? "dashboard.listening" : "dashboard.idle"));
    }

    void preparationFailed(ScanSession session, String message) {
        SwingUtilities.invokeLater(() -> {
            if (session == scanSession && !session.cancelled) scanStatus.setText(I18n.t("dashboard.prepare_failed", message));
        });
    }

    void checkingBaseline(ScanSession session, String url) {
        SwingUtilities.invokeLater(() -> {
            if (session == scanSession && !session.cancelled) scanStatus.setText(I18n.t("baseline.checking", url));
        });
    }

    void baselineChecked(ScanSession session, String summary) {
        SwingUtilities.invokeLater(() -> {
            if (session == scanSession && !session.cancelled) scanStatus.setText(summary);
        });
    }

    void queueFull() {
        SwingUtilities.invokeLater(() -> scanStatus.setText(I18n.t("dashboard.queue_full")));
    }

    public void showManualWaf() { tabs.setSelectedComponent(manualWafPanel); }
    public void showDashboard() { tabs.setSelectedIndex(0); }

    public void dispose() {
        scanSession.cancel();
        manualWafPanel.dispose();
    }

    public BypassTableModel getBypassTableModel() {

        return bypassTableModel;
    }

    public void addAllRequestNum(int num) { addAllRequestNum(scanSession, num); }
    public void addFinishRequestNum(int num) { addFinishRequestNum(scanSession, num); }
    public void addErrorRequestNum(int num) { addErrorRequestNum(scanSession, num); }

    public double getSimilarityThreshold() {
        // 统一从 Config 中读取，Dashboard 不再单独维护阈值输入框
        return Utils.getConfigSimilarityThreshold(DEFAULT_SIMILARITY_THRESHOLD);
    }

    public boolean isFollowRedirectEnabled() {
        return followRedirect;
    }

    private void updateProgressBar() {
        int[] count = scanSession.counts();
        allRequestNumberText.setText(String.valueOf(count[0]));
        finishRequestNumberText.setText(String.valueOf(count[1]));
        errorRequestNumText.setText(String.valueOf(count[2]));
        cancelledNumberText.setText(String.valueOf(count[3]));
        activeNumberText.setText(String.valueOf(count[4]));
        progressBar.setIndeterminate(false);
        progressBar.setValue(count[0] == 0 ? 0 : (int) Math.min(100, 100L * (count[1] + count[2] + count[3]) / count[0]));
    }

    public JCheckBox getIsAutoCheckBox() {
        return isAutoCheckBox;
    }

    public void setIsAutoCheckBox(JCheckBox isAutoCheckBox) {
        this.isAutoCheckBox = isAutoCheckBox;
    }

    /**
     * 从配置文件更新 UI 默认值
     */
    public void updateFromConfig() {
        SwingUtilities.invokeLater(() -> {
            threadNumText.setText(String.valueOf(Utils.getConfigThreads(DEFAULT_THREAD_NUM)));
        });
    }

    public ManualWafPanel getManualWafPanel() {
        return manualWafPanel;
    }
}

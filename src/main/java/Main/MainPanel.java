package Main;

import burp.BurpExtender;
import burp.ITab;
import org.apache.commons.lang3.StringUtils;
import org.yaml.snakeyaml.Yaml;

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.InputStream;
import java.util.Map;
import javax.swing.*;

/**
 * Main display panel
 */
public class MainPanel extends JPanel implements ITab {

    private BypassTableModel bypassTableModel;
    private JTextField threadNumText;
    private JTextField allRequestNumberText;
    private JTextField finishRequestNumberText;
    private JTextField errorRequestNumText;
    private JCheckBox isAutoCheckBox;

    public MainPanel() {

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // main split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // table of log entries
        bypassTableModel = new BypassTableModel();
        BypassTable bypassTable = new BypassTable(bypassTableModel);
/*        // 设置某些单元格内容居中
        DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer();
        cellRenderer.setHorizontalAlignment((int) JTextField.CENTER_ALIGNMENT);
        bypassTable.getColumn("id").setCellRenderer(cellRenderer);*/

        JScrollPane scrollPane = new JScrollPane(bypassTable);

        splitPane.setLeftComponent(scrollPane);

        // tabs with request/response viewers
/*        JTabbedPane tabs = new JTabbedPane();
        tabs.setBorder(BorderFactory.createLineBorder(Color.black));
        tabs.addTab("Request", bypassTable.getRequestViewer().getComponent());
        tabs.addTab("Response", bypassTable.getResponseViewer().getComponent());
        splitPane.setRightComponent(tabs);*/

        // request response 双窗格显示
        JSplitPane httpSplitPane = new JSplitPane();
        httpSplitPane.setResizeWeight(0.50);
        // request
        JTabbedPane reqJTabbedPane = new JTabbedPane();
        reqJTabbedPane.add("Request",bypassTable.getRequestViewer().getComponent());
        // response
        JTabbedPane resJTabbedPane = new JTabbedPane();
        resJTabbedPane.add("Response", bypassTable.getResponseViewer().getComponent());
        httpSplitPane.add(reqJTabbedPane,"left");
        httpSplitPane.add(resJTabbedPane,"right");
        splitPane.setRightComponent(httpSplitPane);


        // 配置框 controlPanel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        isAutoCheckBox = new JCheckBox("Passive Scan", false);
        controlPanel.add(isAutoCheckBox);
        //构造一个监听器，响应checkBox事件
        ActionListener actionListener = new ActionListener(){
            public void actionPerformed(ActionEvent e) {
                if(isAutoCheckBox.isSelected())
                {
                    Utils.isProxySelected = true;
                } else
                {
                    Utils.isProxySelected = false;
                }
            }
        };
        isAutoCheckBox.addActionListener(actionListener);


        JLabel threadNumLabel = new JLabel("Thread Num:");
        controlPanel.add(threadNumLabel);

        threadNumText = new JTextField(10);
        threadNumText.setText("5");
        controlPanel.add(threadNumText);


        JLabel allRequestNumberLabel = new JLabel("AllRequest Num:");
        controlPanel.add(allRequestNumberLabel);
        allRequestNumberText = new JTextField(5);
        allRequestNumberText.setText("0");
        allRequestNumberText.setEditable(false);
        controlPanel.add(allRequestNumberText);

        JLabel finishNumberLabel = new JLabel("Finish Num:");
        controlPanel.add(finishNumberLabel);
        finishRequestNumberText = new JTextField(5);
        finishRequestNumberText.setText("0");
        finishRequestNumberText.setEditable(false);
        controlPanel.add(finishRequestNumberText);


        JLabel errorRequestNumLabel = new JLabel("Error Num:");
        controlPanel.add(errorRequestNumLabel);
        errorRequestNumText = new JTextField(5);
        errorRequestNumText.setText("0");
        errorRequestNumText.setEditable(false);
        controlPanel.add(errorRequestNumText);


        JButton clearButton = new JButton("Clear");

        controlPanel.add(clearButton);

        clearButton.addActionListener(e -> {
            bypassTableModel.getBypassArray().clear();
            bypassTableModel.fireTableDataChanged();
            allRequestNumberText.setText("0");
            finishRequestNumberText.setText("0");
            errorRequestNumText.setText("0");
            Utils.count = 0;
        });

        controlPanel.setAlignmentX(0);

        // 添加重载配置文件控件
        JButton reconfigButton = new JButton("reconfig");

        controlPanel.add(reconfigButton);

        reconfigButton.addActionListener(e -> {
            Map<String, Object> config = Utils.loadConfig("/BypassPro-config.yaml");
            Utils.setConfigMap(config);
            System.out.println("reconfig success...");

        });


        // todo:添加filter



        add(controlPanel);
        add(splitPane);

        BurpExtender.callbacks.customizeUiComponent(this);
    }

    public String getTabCaption() {

        return "BypassPro";
    }

    public Component getUiComponent() {

        return this;
    }

    public int getThreadNum() {

        if(StringUtils.isBlank(threadNumText.getText())) {
            return 5;
        }

        return Integer.parseInt(threadNumText.getText());
    }

    public BypassTableModel getBypassTableModel() {

        return bypassTableModel;
    }

    public void setAllRequestNumberText(int num) {
        allRequestNumberText.setText(String.valueOf(num));
    }

    public void addAllRequestNum(int num) {
        setAllRequestNumberText(Integer.parseInt(allRequestNumberText.getText()) + num);
    }

    public void addFinishRequestNum(int num) {
        finishRequestNumberText.setText(String.valueOf(Integer.parseInt(finishRequestNumberText.getText()) + num));
    }

    public void addErrorRequestNum(int num) {
        errorRequestNumText.setText(String.valueOf(Integer.parseInt(errorRequestNumText.getText()) + num));
    }


    public JCheckBox getIsAutoCheckBox() {
        return isAutoCheckBox;
    }

    public void setIsAutoCheckBox(JCheckBox isAutoCheckBox) {
        this.isAutoCheckBox = isAutoCheckBox;
    }
}

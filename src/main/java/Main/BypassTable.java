/*
 * MIT License
 *
 * Copyright (c) 2017 Nick Taylor
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package Main;

import burp.*;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.Component;

public class BypassTable extends JTable implements IMessageEditorController {

    private BypassTableModel bypassTableModel;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;

    BypassTable(BypassTableModel bypassTableModel) {

        super(bypassTableModel);
        this.bypassTableModel = bypassTableModel;
        this.requestViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        this.responseViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        configureColumns();
        setAutoCreateRowSorter(true);
        getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selected = getSelectedRow();
                display(selected < 0 ? null : bypassTableModel.getBypassAt(convertRowIndexToModel(selected)));
            }
        });
    }

    private void configureColumns() {
        setColumnWidth(0, 60, 80);    // id
        setColumnWidth(1, 80, 100);   // tool
        setColumnWidth(2, 120, 220);  // Title
        setColumnWidth(3, 60, 80);    // Method
        setColumnWidth(4, 70, 90);    // Length
        setColumnWidth(5, 220, 720);  // Request URL
        setColumnWidth(6, 80, 110);   // MIME Type
        setColumnWidth(7, 80, 100);   // HTTP Status
        setColumnWidth(8, 80, 110);   // Redirect
        setColumnWidth(9, 200, 360);  // Reason

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        int[] centeredColumns = {0, 1, 3, 4, 6, 7, 8};
        for (int col : centeredColumns) {
            getColumnModel().getColumn(col).setCellRenderer(centerRenderer);
        }

        getColumnModel().getColumn(8).setCellRenderer(new RedirectCellRenderer());
        getColumnModel().getColumn(9).setCellRenderer(new ReasonCellRenderer());
    }

    private void setColumnWidth(int columnIndex, int minWidth, int preferredWidth) {
        TableColumn column = getColumnModel().getColumn(columnIndex);
        column.setMinWidth(minWidth);
        column.setPreferredWidth(preferredWidth);
    }

    private class RedirectCellRenderer extends DefaultTableCellRenderer {
        RedirectCellRenderer() {
            setHorizontalAlignment(SwingConstants.CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String tooltip = null;
            int modelRow = table.convertRowIndexToModel(row);
            Bypass bypassEntry = bypassTableModel.getBypassAt(modelRow);
            if (bypassEntry != null && bypassEntry.redirectTooltip != null
                    && !bypassEntry.redirectTooltip.isEmpty()) {
                tooltip = bypassEntry.redirectTooltip;
            }
            setToolTipText(tooltip);
            return c;
        }
    }

    private class ReasonCellRenderer extends DefaultTableCellRenderer {
        ReasonCellRenderer() {
            setHorizontalAlignment(SwingConstants.LEFT);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String text = value == null ? "" : value.toString();
            setToolTipText(text.isEmpty() ? null : text);
            return c;
        }
    }


    public byte[] getRequest() {

        if (currentlyDisplayedItem == null || currentlyDisplayedItem.getRequest() == null) {
            return new byte[0];
        }
        return currentlyDisplayedItem.getRequest();
    }


    public byte[] getResponse() {

        if (currentlyDisplayedItem == null || currentlyDisplayedItem.getResponse() == null) {
            return new byte[0];
        }
        return currentlyDisplayedItem.getResponse();
    }

    public IHttpService getHttpService() {

        if (currentlyDisplayedItem == null) {
            return null;
        }
        return currentlyDisplayedItem.getHttpService();
    }

    private void display(Bypass entry) {
        currentlyDisplayedItem = entry == null ? null : entry.requestResponse;
        requestViewer.setMessage(getRequest(), true);
        responseViewer.setMessage(getResponse(), false);
    }

    void clearViewers() {
        clearSelection();
        currentlyDisplayedItem = null;
        requestViewer.setMessage(new byte[0], true);
        responseViewer.setMessage(new byte[0], false);
    }

    IMessageEditor getRequestViewer() {

        return requestViewer;
    }

    IMessageEditor getResponseViewer() {

        return responseViewer;
    }

}

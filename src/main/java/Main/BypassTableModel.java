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

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class BypassTableModel extends AbstractTableModel {

    private final List<Bypass> bypassArray = new ArrayList<>();
    private int discarded;
    private final Object lock = new Object();

    public void addBypass(Bypass b) {
        if (!javax.swing.SwingUtilities.isEventDispatchThread()) {
            javax.swing.SwingUtilities.invokeLater(() -> addBypass(b));
            return;
        }
        if (getRowCount() >= 5000) {
            synchronized (lock) { bypassArray.remove(0); discarded++; }
            fireTableRowsDeleted(0, 0);
        }
        int row;
        synchronized (lock) { row = bypassArray.size(); bypassArray.add(b); }
        fireTableRowsInserted(row, row);
    }

    public void clearAll() {
        if (!javax.swing.SwingUtilities.isEventDispatchThread()) {
            javax.swing.SwingUtilities.invokeLater(this::clearAll);
            return;
        }
        synchronized (lock) { bypassArray.clear(); discarded = 0; }
        fireTableDataChanged();
    }

    int getDiscardedCount() { synchronized (lock) { return discarded; } }

    public int getRowCount() {
        synchronized (lock) {
            return bypassArray.size();
        }
    }

    public int getColumnCount() {
        return 10;
    }

    @Override
    public String getColumnName(int columnIndex) {

        switch (columnIndex) {
            case 0:
                return "id";
            case 1:
                return "tool";
            case 2:
                return "Title";
            case 3:
                return "Method";
            case 4:
                return "Length";
            case 5:
                return "Request URL";
            case 6:
                return "MIME Type";
            case 7:
                return "HTTP Status";
            case 8:
                return "Redirect";
            case 9:
                return "Reason";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {

        switch (columnIndex) {
            case 0:
                return Long.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            case 4:
                return String.class;
            case 5:
                return String.class;
            case 6:
                return String.class;
            case 7:
                return Short.class;
            case 8:
                return String.class;
            case 9:
                return String.class;
            default:
                return Object.class;
        }
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        Bypass bypassEntry;
        synchronized (lock) {
            if (rowIndex < 0 || rowIndex >= bypassArray.size()) {
                return "";
            }
            bypassEntry = bypassArray.get(rowIndex);
        }
        switch (columnIndex) {
            case 0:
                return bypassEntry.id;
            case 1:
                return bypassEntry.tool;
            case 2:
                return bypassEntry.title;
            case 3:
                return bypassEntry.method;
            case 4:
                return bypassEntry.length;
            case 5:
                return bypassEntry.url == null ? "" : bypassEntry.url.toString();
            case 6:
                return bypassEntry.mimeType;
            case 7:
                return bypassEntry.status;
            case 8:
                return bypassEntry.redirect;
            case 9:
                return bypassEntry.reason == null ? "" : bypassEntry.reason;
            default:
                return "";
        }
    }

    public Bypass getBypassAt(int index) {
        synchronized (lock) {
            if (index < 0 || index >= bypassArray.size()) {
                return null;
            }
            return bypassArray.get(index);
        }
    }

    @Deprecated
    public List<Bypass> getBypassArray() {
        return bypassArray;
    }

}

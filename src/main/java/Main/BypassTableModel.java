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

    private final List<Bypass> bypassArray = new ArrayList();


    public int getRowCount() {

        return bypassArray.size();
    }

    public int getColumnCount() {

        return 9;
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
                return "Time";
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
            default:
                return Object.class;
        }
    }

    public Object getValueAt(int rowIndex, int columnIndex) {

        Bypass bypassEntry = bypassArray.get(rowIndex);

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
                return bypassEntry.url.toString();
            case 6:
                return bypassEntry.mimeType;
            case 7:
                return bypassEntry.status;
            case 8:
                return bypassEntry.timestamp;
            default:
                return "";
        }
    }

    public List<Bypass> getBypassArray() {

        return bypassArray;
    }

}


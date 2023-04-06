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
        getColumnModel().getColumn(0).setMinWidth(80);
        getColumnModel().getColumn(1).setMinWidth(100);
        getColumnModel().getColumn(2).setMinWidth(150);
        getColumnModel().getColumn(3).setMinWidth(100);
        getColumnModel().getColumn(4).setMinWidth(100);
        getColumnModel().getColumn(5).setPreferredWidth(1100);
        getColumnModel().getColumn(6).setMinWidth(100);
        getColumnModel().getColumn(7).setMinWidth(80);
        getColumnModel().getColumn(8).setMinWidth(120);
        setAutoCreateRowSorter(true);
    }


    public byte[] getRequest() {

        return currentlyDisplayedItem.getRequest();
    }


    public byte[] getResponse() {

        return currentlyDisplayedItem.getResponse();
    }

    public IHttpService getHttpService() {

        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        Bypass bypassEntry = bypassTableModel.getBypassArray().get(convertRowIndexToModel(row));
        requestViewer.setMessage(bypassEntry.requestResponse.getRequest(), true);
        responseViewer.setMessage(bypassEntry.requestResponse.getResponse(), false);
        currentlyDisplayedItem = bypassEntry.requestResponse;

        super.changeSelection(row, col, toggle, extend);
    }

    IMessageEditor getRequestViewer() {

        return requestViewer;
    }

    IMessageEditor getResponseViewer() {

        return responseViewer;
    }

}

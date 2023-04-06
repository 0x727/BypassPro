![](https://avatars.githubusercontent.com/u/87968663?s=200&v=4)

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。
# 介绍
作者：[p0desta](https://github.com/p0desta/)，[Y0!0](https://github.com/hooray195)，[0cat ](https://github.com/0cat-r) 

团队：[0x727](https://github.com/0x727)，未来一段时间将陆续开源工具，地址：[https://github.com/0x727](https://github.com/0x727)

定位：协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点

语言：Java11

功能：权限绕过的自动化bypass的burpsuite插件。

此项目是基于p0desta师傅的项目[https://github.com/p0desta/AutoBypass403-BurpSuite](https://github.com/p0desta/AutoBypass403-BurpSuite)进行二开的。用于权限绕过，403bypass等的自动化bypass的Burpsuite插件。感谢p0desta师傅的开源，本二开项目已经过p0desta师傅本人允许开源。

# 新增加的功能

1. 新增被动扫描功能

![image.png](https://cdn.nlark.com/yuque/0/2023/png/22658608/1680773992648-7076f536-a848-4f2a-a1f6-fe88bf530d72.png#averageHue=%23f5f3f1&clientId=ud59bccca-0a4a-4&from=paste&height=66&id=udf6d3a34&name=image.png&originHeight=82&originWidth=525&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=3932&status=done&style=none&taskId=u8f8caa7e-a1c2-4269-8f71-182e01050e1&title=&width=420)

2. 对被动扫描和主动扫描的逻辑做重新判断
3. 增加字段tool 和id 可以判断哪些是被动流量 哪些是主动流量
4. 添加了/public/..;的fuzz
5. 被动扫描下，对如下静态文件后缀进行过滤，不进行绕过

`js,css,png,gif,jpg,mp4,mp3,tif,swf,wmv,map,zip,exe,so,rar,gz,iso,avi,pdf,doc`

6. 增加了request/response 双窗格显示

![](https://cdn.nlark.com/yuque/0/2023/png/22658608/1680772585348-ac7607e4-8e92-4d02-97d5-e1887389e06d.png#averageHue=%23f9f7f5&clientId=ud59bccca-0a4a-4&from=paste&id=u8be2f93a&originHeight=1341&originWidth=2471&originalType=url&ratio=1.25&rotation=0&showTitle=false&status=done&style=none&taskId=u54d79313-8266-4827-91e5-0731a49a37c&title=)

# 用法
被动扫描：勾选上之后，proxy 流量中出现403 301 404 302 的时候去自动bypass 
主动扫描：取消勾选之后，可以在proxy 流量中选择一些右键发送到BypassPro 去自动fuzz
当状态码是200，415，405则会进行回显，页面相似度80%以下进行回显
![](https://cdn.nlark.com/yuque/0/2023/png/22658608/1680775299560-6dc3d2e8-0060-41eb-8c3d-247c35fa405c.png#averageHue=%23fbfbfb&clientId=u113930d5-5cde-4&from=paste&id=u82eda32d&originHeight=835&originWidth=2500&originalType=url&ratio=1.25&rotation=0&showTitle=false&status=done&style=none&taskId=u179c5fb9-de8a-41d8-988f-bc58175c353&title=)
主动扫描：右键发送
![image.png](https://cdn.nlark.com/yuque/0/2023/png/22658608/1680775376139-7ab589d5-8bf6-4239-80e6-a1470d5c91f1.png#averageHue=%23f8f4f2&clientId=u113930d5-5cde-4&from=paste&height=889&id=uc96e49ac&name=image.png&originHeight=1111&originWidth=1798&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=532821&status=done&style=none&taskId=u24bc1fcd-ae55-4ac4-9d13-e20436ac17b&title=&width=1438.4)


**注意事项**，该工具会一定程度上触发waf,所以当目标站点有waf 请关闭被动扫描。

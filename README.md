# Atlas DNS 转发器

Atlas 是一个由 matcher、rule 和 action 组合驱动的 DNS 转发服务。它支持 UDP/TCP、DNS over TLS、DNS over HTTPS、静态 hosts、geosite 分流、策略级缓存、响应地址校验与回退，以及通过签名 TXT 保护代理入口的 bootstrap 解析。

默认配置行为偏向安全：DNS 监听地址为 `127.0.0.1:5353`，pprof 为 `127.0.0.1:6060`。如需对外提供递归解析，必须显式修改监听地址，并配合网络 ACL、防火墙和客户端限速。

## 本地开发

项目提供统一的 Makefile 入口。没有系统 Go 时，脚本会在仓库 `.cache/go-runtime` 安装校验过 SHA-256 的 Go 1.26.9，不修改系统环境。

```bash
make build       # 构建 bin/atlas
make test        # 单元与集成测试
make test-race   # race detector
make vet
make check       # build + test + race + vet
make fuzz-smoke  # geosite parser 短时 fuzz
```

启动完全本地、结果确定的开发环境：

```bash
make dev
```

该命令会在前台启动测试上游和 Atlas，并在退出时按 PID 与进程启动时间清理子进程。另开一个终端执行：

```bash
make smoke
```

smoke 会检查静态 hosts、UDP 转发、上游 UDP 截断后的 TCP 回退、客户端 TCP、缓存、RCODE 策略、pprof 和运行指标。开发配置位于 `config.dev.yaml`。

## 运行

```bash
./bin/atlas --config=/path/to/config.yaml
./bin/atlas --version
```

配置采用严格解析：未知字段、重复名称、非法边界、未定义 action、不可达规则，以及缺少最终 `match: any` 的规则集都会在监听端口前一次性报错。

### 完整示例

```yaml
bind: "127.0.0.1:5353"

server:
  udp_size: 4096
  max_response_udp_size: 1232
  max_inflight: 256
  request_timeout: 10       # 秒
  rate_limit_qps: 100       # 0 表示关闭按客户端限速
  rate_limit_burst: 200
  rate_limit_clients: 4096  # 有界客户端状态数量
  allowed_cidrs:             # 省略或空列表表示不启用应用层 ACL
    - "127.0.0.0/8"
    - "::1/128"

pprof:
  enable: true
  bind: "127.0.0.1:6060"

cache:
  size: 50000               # 0 表示完全关闭缓存
  max_bytes: 268435456
  max_entry_bytes: 65535
  lazy: true
  max_stale: 300            # 秒
  negative_ttl_max: 3600    # NXDOMAIN/NODATA 上限，秒
  refresh_concurrency: 8
  persist: true
  file: "/data/runtime/dns-cache.jsonl"
  interval: 600             # 秒

resource:
  host:
    records:
      www.example.test: "192.0.2.10,2001:db8::10"
    files:
      - /data/runtime/hosts.txt

  matcher:
    - name: local
      type: geosite
      data:
        file: /data/runtime/geosite.dat
        categories: [cn]

    - name: blocked
      type: domain
      data:
        domains:
          - "full:blocked.example"
          - "suffix:tracking.example"
          - "keyword:telemetry"
          - "regexp:^ad-[0-9]+\\.example$"

  action:
    - name: forward-local
      type: forward
      data:
        server_list:
          - "udp://223.5.5.5:53?timeout=1500&max_inflight=128"
        parallel: 1

    - name: forward-remote
      type: forward
      data:
        server_list:
          - "https://1.1.1.1/dns-query?timeout=2500&max_conns=16&max_inflight=16"
          - "dot://9.9.9.9:853?timeout=2500&pool=16&max_inflight=16"
        parallel: 2

    - name: refuse
      type: rcode
      data:
        code: 5

rule:
  - remark: reject blocked domains
    match: blocked
    action: refuse
  - remark: prefer local resolver
    match: local
    action: forward-local
  - remark: explicit fallback
    match: any
    action: forward-remote

log:
  level: info
  console: true
```

## 转发响应地址校验与 fallback

对于使用国内 DoH 的 forward action，可以允许指定 IP 规则集及内网地址；响应中出现未允许的地址时，丢弃整份响应，直接调用另一个 forward action。下面的配置补充到前面的示例中，域名仍由原有 matcher/rule 分流：

```yaml
resource:
  ip_set:
    - name: cn
      format: maxmind_mmdb
      files:
        - /data/GeoLite2-Country.mmdb
      countries: [CN]

  action:
    - name: forward-local
      type: forward
      data:
        server_list:
          - https://223.5.5.5/dns-query?timeout=1500
          - https://1.12.12.12/dns-query?timeout=1500
        parallel: 2
        validate:
          ip_sets: [cn]
        fallback: forward-remote

    - name: forward-remote
      type: forward
      data:
        server_list:
          - https://1.1.1.1/dns-query?timeout=2500
        parallel: 1
```

这里的 `cn` 是集合名称，`countries: [CN]` 指定它包含 GeoIP 中国网段。命中国内域名规则后，先由 `forward-local` 查询；只要响应中任一被检查的地址不属于 CN，就丢弃整份响应并执行 `forward-remote`。此示例没有额外放行内网地址。

`resource.ip_set` 支持两种本地数据格式：

- `format: maxmind_mmdb`：读取 MaxMind 原生的 GeoLite2-Country 或 GeoIP2-Country `.mmdb` 文件，`countries` 必须包含至少一个两字母国家码。多个国家码、多份文件取并集，国家码大小写不敏感。使用记录的 `country.iso_code` 判断地理归属，不使用运营商的 `registered_country` 代替；未知归属和未选中的国家不匹配该集合。`CN` 不隐含包含 `HK`、`MO` 或 `TW`。
- `format: cidr`（省略 `format` 时的默认值）：一行一个 IPv4/IPv6 CIDR，支持空行和 `#` 注释，包括行尾注释；此格式不配置 `countries`。

从 MaxMind 下载 Country 二进制数据库并解压出 `.mmdb` 文件后，即可直接配置路径，无需自行转换 CSV。Atlas 在启动时校验数据库并将所选国家的 IPv4/IPv6 网段加载为不可变集合，查询期间无需访问数据库文件。更换文件或国家选择后重启生效，程序不自动下载或更新数据。空集合仍然有效；所选国家在数据库中没有网段时，该集合不允许任何地址。

读取失败、损坏或错误类型的数据库、非法 CIDR、重复名称、未定义集合和未知网络类型均阻止启动。单个 MMDB 文件最多 256 MiB，最多遍历 200 万个网段；每个集合最多包含 100 万个不同 CIDR，纯文本单行最多 4096 字节。数据库格式说明见 [MaxMind 文档](https://dev.maxmind.com/geoip/docs/databases/city-and-country/)。

如需额外允许内网等地址，可在 `validate` 下配置 `networks: [private, loopback, link_local, shared]`。可选值如下，其他特殊地址可自行放入 CIDR 集合：

| 名称 | IPv4 | IPv6 |
| --- | --- | --- |
| `private` | `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` | `fc00::/7` |
| `loopback` | `127.0.0.0/8` | `::1/128` |
| `link_local` | `169.254.0.0/16` | `fe80::/10` |
| `shared` | `100.64.0.0/10` | 无 |

每个地址匹配任一集合或网络即可通过，但响应中所有被检查的地址都必须通过。IPv4-mapped IPv6 地址按 IPv4 判断。只检查 Answer 中的 A、AAAA，以及 HTTPS/SVCB 的 `ipv4hint`、`ipv6hint`；不检查 Authority/Additional。NXDOMAIN、NODATA、纯 CNAME、没有地址提示的 HTTPS/SVCB 等结果继续接受。

`validate` 和 `fallback` 必须同时配置，且至少配置一个集合引用或一个网络名称。`ip_sets` 可省略或为空；引用空集合也有效，只是该集合不允许任何地址。`fallback` 按名称引用已定义的 forward action，与配置顺序无关；多个 action 可共享同一目标，也支持无环的多级回退。未定义目标、指向非 forward action、自引用及循环引用均阻止启动。

上游组仍采用第一个有效 DNS 响应。该结果校验失败后立即转入 fallback，不再尝试同组其他节点，也不拼接两边的记录。只有地址校验失败触发此回退；普通超时、SERVFAIL 等继续沿用上游组原有的错误处理。fallback 直接执行目标 action，不重新匹配域名规则；目标按自己的策略处理，其最终响应不会被来源 action 的地址规则再次拒绝。完整查询及后台刷新各自共用 `server.request_timeout` 的总预算，多级回退不会逐级重置超时。

缓存位于完整策略之外。fallback 成功的结果同时进入来源 action 和目标 action 的缓存，共享现有总容量限制。乐观缓存仍可立即返回 TTL 0 的旧数据，后台刷新执行完整的校验和回退流程；刷新失败不覆盖旧数据，也不延长 `max_stale`。没有可用缓存且最终查询失败时返回 SERVFAIL。hosts 和签名 bootstrap 继续由各自的解析流程处理。

新增或修改 IP 集合（包括格式、国家选择、数据库路径和内容）、`validate`、`fallback` 不自动使已有内存或落盘缓存失效，也不重新验证缓存命中结果。若希望新策略立即影响已有缓存，应先停止服务、删除 `cache.file` 指定的普通 DNS 缓存文件，再启动服务；运行时直接删除文件可能被再次落盘覆盖。其他配置变更仍沿用原有指纹检查，无需为本功能删除 bootstrap 检查点。

这一机制按允许的地址范围筛查结果。正常 CDN 也可能返回境外地址并触发 fallback；日志中的校验失败不代表已证实遭到攻击，规则集遗漏的合法网段也需要自行补充。

## 签名 TXT bootstrap

对于 IP 固定、偶尔手动迁移的代理入口，可以将地址与有效期签名后发布为 TXT。Atlas 使用本地公钥验签，再合成 A/AAAA 响应。即使查询 TXT 的解析器返回被修改的地址，也无法生成有效签名；解析器仍可能拒绝响应或回放此前签名的数据。

### 配置与域名文件

`bootstrap` 是可选的顶层配置。所有域名共用 `public_keys`，不配置 `records`：

```yaml
bootstrap:
  server_list:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  parallel: 2              # 默认 min(3, 上游数量)
  request_timeout: 3       # 一次完整查询的总超时，秒
  ttl_max: 300             # 本地地址缓存 TTL 上限，秒
  clock_skew: 30           # issued_at 允许超前的秒数，可设为 0；不延长过期时间
  files:
    - /config/bootstrap-domains.txt
    - /config/bootstrap-extra.txt
  public_keys:
    - /config/bootstrap.pub
```

`files` 中每个路径指向一个文本文件，内容一行一条 `域名[:TXT 查询域名]`：

```text
# /config/bootstrap-domains.txt
proxy.example.test
local.example.test:_atlas.local.example.test

# 省略冒号后的名称时默认查询 _atlas.<原域名>
another.example.test:
```

文件支持空行、行尾注释、大小写和末尾点规范化；相同映射可重复，不同文件对同一域名配置不同 TXT 名称会在启动时报出文件与行号。文件在启动时加载，修改后重启生效。这里使用完整域名匹配，不包含子域名。同一域名同时出现在 bootstrap 和 hosts 中会阻止启动。

bootstrap 在 hosts 和普通规则之前处理，因此无需为这些域名额外编写 matcher/action。内部 TXT 查询直接访问 `server_list`，不会重新进入普通规则；上游地址应能在代理尚未建立时访问，例如上面的 IP 形式 DoH 地址。其余域名继续按普通规则处理，可以将最终 `match: any` 指向境外解析器。

### 生成密钥、签名与发布

命令行使用 Cobra，下面的离线命令不加载服务配置，也不自动修改 DNS：

```bash
./bin/atlas bootstrap keygen \
  --private-key /config/bootstrap.key \
  --public-key /config/bootstrap.pub

./bin/atlas bootstrap sign \
  --private-key /config/bootstrap.key \
  --domain proxy.example.test \
  --a 192.0.2.10 \
  --aaaa 2001:db8::10 \
  --expires-at 1893456000000
```

`keygen` 生成 Ed25519 PKCS#8 私钥与 PKIX 公钥 PEM 文件，拒绝覆盖已有文件；私钥权限为 `0600`。服务启动只读取公钥。`--a`、`--aaaa` 均可重复，允许只提供其中一个地址族，至少需要一个地址。

`--expires-at` 必须是 **Unix 毫秒时间戳整数**，与时区无关，必须晚于当前签名时间。有效期长度不设上限。`issued_at` 自动使用当前 Unix 毫秒时间戳，并作为版本号；修改记录时需要生成更大的时间戳。工具不提供自动续期。

`sign` 标准输出只有完整 TXT 值：`atlas1.<Base64url JSON>.<Base64url 签名>`。手动将该值发布到 `_atlas.proxy.example.test` 的**同一条 TXT 记录**。DNS 面板需要拆分长文本时，每段最多 255 字节，并保持为同一个 RR 内的多个字符串；不能拆成多条 TXT 记录。可以用下面的命令在发布前验签：

```bash
./bin/atlas bootstrap verify \
  --public-key /config/bootstrap.pub \
  --domain proxy.example.test \
  --record 'atlas1.<完整负载>.<完整签名>'

./bin/atlas bootstrap sign --help
```

签名覆盖固定前缀 `atlas1\0` 和原始 JSON 字节。JSON 包含 `kid`、`domain`、`issued_at`、`expires_at`、可选的 `a`/`aaaa`；`kid` 是公钥原始字节的 SHA-256 十六进制值。验签拒绝未知版本、未知公钥、跨域名使用、签名不匹配、重复或未知 JSON 字段、无效地址、超前时间和已过期记录。密钥轮换时可在 `public_keys` 暂时同时配置新旧公钥，手动完成重新签名、发布和重启。

### 查询、失败与缓存行为

- 每个域名的 A/AAAA 共享一次 TXT 查询和同一份签名地址集。缺少某个地址族时返回 NODATA，不向其他解析器补全。ANY 返回已签名的两个地址族；对原域名的 CNAME、TXT、HTTPS、SVCB 等其他类型返回空的 NOERROR。
- 至多并发 `parallel` 个上游，等待全部完成或总超时后，从已验签结果中选择时间戳最大的记录。单个上游失败不影响其余有效结果。同一时间戳出现不同签名内容时拒绝更新。
- 已接受的版本在当前进程内不会回退，缓存淘汰和地址过期也不会删除版本水位。同版本同内容可再次接受。首次启动、未持久化或丢弃了检查点时，仍可能接受尚未过期的历史签名。
- 保留现有 `cache.lazy/max_stale` 乐观缓存：DNS TTL 到期后可以立即返回 TTL 为 0 的已验签地址，并在后台刷新。刷新失败保留仍有效的旧缓存；超过 `max_stale` 或签名 `expires_at` 后停止返回。没有有效地址时返回 SERVFAIL，不回退到 hosts 或普通 DNS。
- 新鲜 TTL 取 TXT TTL、`ttl_max`、签名剩余有效期三者的最小值。bootstrap 缓存沿用 `cache.size/max_bytes/max_entry_bytes/refresh_concurrency` 参数，与普通 DNS 缓存分别计数；`cache.size: 0` 同时关闭地址缓存，但进程内版本水位仍保留。
- 开启 `cache.persist` 后，bootstrap 使用 `cache.file` 加 `.bootstrap` 后缀的独立检查点，沿用 `cache.interval` 周期落盘和关停落盘，采用临时文件、`fsync`、原子替换。恢复时按当前配置、公钥和绝对有效期重新验签，不续 TTL。检查点损坏或配置不匹配会丢弃重建。崩溃可能丢失尚未落盘的新版本水位，符合普通缓存的持久化时机。

## 请求链路与资源边界

Atlas 的核心处理顺序为：

```text
UDP/TCP listener
  -> 协议校验、全局并发和按客户端限速
  -> 签名 TXT bootstrap（配置的完整域名）
  -> hosts
  -> matcher expression / rule
  -> 策略命名空间缓存
  -> 有界并行解析组
  -> 有界上游 transport
  -> 响应关联校验
  -> 按客户端 UDP 能力截断
```

- 同一请求交给多个上游前会逐一复制 `dns.Msg`，不会并发共享可变 EDNS 数据。
- 普通解析组维持至多 `parallel` 个在途查询；失败或 SERVFAIL/REFUSED 等无效结果会由剩余上游补位，首个有效响应成为唯一结果。bootstrap 则等待结果汇总并选择最新有效版本。
- 每个 resolver 还有独立 `max_inflight` 上限。TCP/DoT 使用独占、有界连接池；UDP 收到 `TC=1` 会自动用 TCP 重试；DoH 显式启用 HTTP/2、PING 健康检查和故障连接代际重建，并限制连接数和响应体为 65535 字节。
- 入站 UDP 无 EDNS 时按 512 字节响应；有 EDNS 时采用客户端声明值，但不超过 `max_response_udp_size`。TCP 响应不截断。

## Resolver URL

| scheme | 示例 | 连接行为 |
| --- | --- | --- |
| `udp` | `udp://1.1.1.1:53` | UDP，截断自动回退 TCP |
| `tcp` | `tcp://1.1.1.1:53?pool=16` | 有界长连接池 |
| `dot` | `dot://1.1.1.1:853?pool=16` | TLS 1.2+，有界长连接池 |
| `https` | `https://1.1.1.1/dns-query?max_conns=16` | HTTP/2，连接复用与故障自愈 |

本地 transport 参数：

- `timeout`：毫秒，最大 300000；
- `pool`：仅 TCP/DoT，最大 256；
- `max_conns`：仅 DoH，最大 4096；
- `max_inflight`：所有 resolver，最大 100000。

DoH URL 中除这些保留参数之外的 query 参数会原样保留，可用于上游路由 token。classic resolver 不接受路径或额外 query 参数。所有 URL 在启动期完成 scheme、host、port、参数和路径校验。

未配置 transport 参数时，DoH 默认请求超时 4 秒、连接/响应头阶段超时 2/3 秒、单上游 `max_conns=max_inflight=16`。上游连续失败后自动熔断，退避从 1 秒增长到最多 10 秒；冷却结束只放行一个恢复探测。这些自愈参数当前使用面向家庭网络的内置安全默认值，不要求修改现有 YAML。

## Matcher 与规则

| matcher | 配置 |
| --- | --- |
| `domain` | `domains`、`files`；支持 `full`、`suffix`、`keyword`、`regexp` |
| `geosite` | `file`、`categories`，支持 `category@attr` 和 `category@!attr` |
| `qtype` | `types`，例如 A=1、AAAA=28 |
| `qclass` | `classes`，例如 IN=1 |
| `any` | 恒为 true，必须用于最终兜底规则 |

表达式支持 `and/or/not`、`&&/||/!` 和括号。单次请求会复用规范化域名，并按 matcher 名缓存匹配结果。domain full/suffix 共用紧凑的冻结索引；keyword 使用连续边存储的 Aho-Corasick 自动机；regexp 对 DNS 名采用大小写不敏感语义。

## 缓存语义

缓存同时受 `size`、`max_bytes` 和 `max_entry_bytes` 限制，并分片降低热点锁竞争。同 key 并发 miss 只产生一次逻辑上游查询；懒刷新受全局 semaphore 约束。

缓存 key 包含策略命名空间、Question、RD、DO、CD、AD 和 EDNS UDP size。带 ECS、COOKIE、TSIG、未知 EDNS option 或其他客户端特定数据的请求会绕过缓存。TC、SERVFAIL、协议不匹配和带响应 option 的结果不会写入缓存。

正缓存按所有返回 section 的最短 TTL 过期，命中时每条 RR 独立扣减 elapsed。NXDOMAIN/NODATA 按 SOA `min(TTL, MINIMUM)` 负缓存，并受 `negative_ttl_max` 限制。stale 最长只保留 `max_stale`，返回 TTL 为 0。

持久化文件是可丢弃的性能数据，不是业务数据。格式包含 schema version 和配置 fingerprint；损坏、旧版本或策略不匹配时会清空重建。写盘使用同目录临时文件、`fsync` 和原子 rename，失败保留 dirty generation 并自动重试；关停会等待后台任务并最终落盘。

## Hosts 文件

同时支持标准 `/etc/hosts` 顺序和旧版 Atlas 顺序，支持行尾注释与多个别名：

```text
# 标准格式
192.0.2.10 example.test alias.test
2001:db8::10 example.test

# 兼容格式
legacy.test 192.0.2.20 2001:db8::20
```

重复 IP 会去重，静态 hosts 只为 IN class 的 A/AAAA/ANY 查询生成记录。

## 调试与指标

启用 pprof 后可访问：

- `/debug/pprof/`
- `/debug/vars`
- `/debug/atlas`：DNS 请求、过载、限速、pipeline error、panic、inflight，以及缓存 hit/miss/stale/bytes/persistence error。

pprof 监听失败会作为启动错误返回，并随应用 context 优雅关闭。不要直接将调试端口暴露到公网。

## 容器

```bash
make docker-build

docker run --rm \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
  -v "$PWD/config.yaml:/data/config.yaml:ro" \
  -v "$PWD/data:/data/runtime" \
  atlas:dev --config=/data/config.yaml
```

容器内配置需要把 `bind` 设为 `0.0.0.0:5353` 才能通过端口映射访问；宿主机的持久化目录也应允许 UID/GID `10001:10001` 写入。镜像固定 builder/runtime digest，运行时包含 CA 与时区数据。发布工作流在 push 前执行测试、race、vet 和镜像漏洞扫描，并生成 amd64/arm64 镜像、provenance 与 SBOM。

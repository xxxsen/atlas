# Atlas DNS 转发器

Atlas 是一个由 matcher、rule 和 action 组合驱动的 DNS 转发服务。它支持 UDP/TCP、DNS over TLS、DNS over HTTPS、静态 hosts、geosite 分流、策略级缓存，以及有界的并发故障转移。

默认配置行为偏向安全：DNS 监听地址为 `127.0.0.1:5353`，pprof 为 `127.0.0.1:6060`。如需对外提供递归解析，必须显式修改监听地址，并配合网络 ACL、防火墙和客户端限速。

## 本地开发

项目提供统一的 Makefile 入口。没有系统 Go 时，脚本会在仓库 `.cache/go-runtime` 安装校验过 SHA-256 的 Go 1.26.5，不修改系统环境。

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
  max_inflight: 1024
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
          - "https://1.1.1.1/dns-query?timeout=2500&max_conns=100&max_inflight=100"
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

## 请求链路与资源边界

Atlas 的核心处理顺序为：

```text
UDP/TCP listener
  -> 协议校验、全局并发和按客户端限速
  -> hosts
  -> matcher expression / rule
  -> 策略命名空间缓存
  -> 有界并行解析组
  -> 有界上游 transport
  -> 响应关联校验
  -> 按客户端 UDP 能力截断
```

- 同一请求交给多个上游前会逐一复制 `dns.Msg`，不会并发共享可变 EDNS 数据。
- 解析组维持至多 `parallel` 个在途查询；失败或 SERVFAIL/REFUSED 等无效结果会由剩余上游补位，首个有效响应成为唯一结果。
- 每个 resolver 还有独立 `max_inflight` 上限。TCP/DoT 使用独占、有界连接池；UDP 收到 `TC=1` 会自动用 TCP 重试；DoH 显式启用 HTTP/2 并限制连接数和响应体为 65535 字节。
- 入站 UDP 无 EDNS 时按 512 字节响应；有 EDNS 时采用客户端声明值，但不超过 `max_response_udp_size`。TCP 响应不截断。

## Resolver URL

| scheme | 示例 | 连接行为 |
| --- | --- | --- |
| `udp` | `udp://1.1.1.1:53` | UDP，截断自动回退 TCP |
| `tcp` | `tcp://1.1.1.1:53?pool=16` | 有界长连接池 |
| `dot` | `dot://1.1.1.1:853?pool=16` | TLS 1.2+，有界长连接池 |
| `https` | `https://1.1.1.1/dns-query?max_conns=100` | HTTP/2，连接复用 |

本地 transport 参数：

- `timeout`：毫秒，最大 300000；
- `pool`：仅 TCP/DoT，最大 256；
- `max_conns`：仅 DoH，最大 4096；
- `max_inflight`：所有 resolver，最大 100000。

DoH URL 中除这些保留参数之外的 query 参数会原样保留，可用于上游路由 token。classic resolver 不接受路径或额外 query 参数。所有 URL 在启动期完成 scheme、host、port、参数和路径校验。

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

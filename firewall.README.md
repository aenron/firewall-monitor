# frps 日志封禁监控

`firewall.py` 读取 Docker 中 frps 的客户端连接事件，查询 IP 归属地，按城市和服务策略向 `/var/log/firewall-ban.log` 写入封禁请求。需要 Python 3.9+，以及 `docker`、`mysql-connector-python`、`requests`、`loguru`。已删除未使用的 `ipinfo`、`ipdata` 依赖。

在实际运行脚本的 Python 环境中安装依赖：

```bash
python3 -m pip install docker mysql-connector-python requests loguru
```

## Docker Compose 部署（Linux 宿主机）

此仓库只容器化检测脚本，沿用宿主机现有 fail2ban 和 MySQL。当前云主机的 frps 使用 host 网络；检测容器使用默认 bridge 网络，无需发布端口、host 网络或 privileged 权限。

`firewall.env` 保存本地真实配置，已被 Git 忽略；仓库仅跟踪不含真实密码的 `firewall.env.example`。`.dockerignore` 使用白名单，镜像构建上下文只包含 Dockerfile、依赖清单和脚本，密码文件及 Git 历史不会进入镜像。

将此目录部署到 Linux 云主机后执行：

```bash
# 新克隆的仓库需先生成环境文件并填写密码；已有文件直接使用。
test -f firewall.env || cp firewall.env.example firewall.env
chmod 600 firewall.env
mkdir -p log
# touch 不清空现有文件；文件必须存在，否则 Compose 拒绝启动。
sudo touch /var/log/firewall-ban.log

docker compose build
docker compose up -d
docker compose logs --tail=100 -f firewall-monitor
```

启动前停止旧 Python 检测进程，避免重复处理和重复计数；宿主机 fail2ban 保持运行。容器使用固定的内部日志路径，默认绑定宿主机 `/var/log/firewall-ban.log`，因此既有 jail 的 `logpath` 无需修改。`MYSQL_HOST=192.168.10.192` 必须能从容器访问，若依赖 Tailscale 路由，需要确认该主机允许 Docker bridge 流量到对应网段。

Compose 自动通过 `env_file` 注入 `firewall.env`，无需执行 `source`。修改配置后执行 `docker compose up -d --force-recreate`；更新代码后执行 `docker compose up -d --build`。停止服务用 `docker compose down`，不会主动清除宿主机 fail2ban 的封禁集合。

构建默认使用官方 PyPI。下载较慢时，可将 `PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple` 写入项目 `.env`，再执行 `docker compose build`。此变量只用于构建，不属于 `firewall.env` 中的运行配置；`.env` 同样被 Git 忽略。

封禁日志采用单文件绑定以兼容现有 jail。**该文件的 logrotate 必须使用 `copytruncate`，不要重命名后创建新文件**，否则容器仍会写旧 inode。如果需使用 rename/create 轮转，应改为共享专用日志目录，并同步调整宿主机 jail 的日志路径。应用日志目录 `./log` 持久化，应用与 Docker 控制台日志均有轮转限制。

日志时间默认 `Asia/Shanghai`，应与宿主机 fail2ban 解析的时区一致。其他时区可执行 `TZ=UTC docker compose up -d --force-recreate`。自定义宿主机封禁日志路径可通过 `FIREWALL_HOST_BAN_LOG=/绝对路径/firewall-ban.log docker compose up -d`，并同步配置 fail2ban；Compose 的这些变量来自 shell 或项目 `.env`，不从服务的 `firewall.env` 读取。

挂载 Docker socket 即使标记只读，仍具有高权限 Docker API 访问能力；本服务应仅运行受信任代码。容器本身不直接操作防火墙，root 用户用于访问 socket 和现有封禁日志；已去除额外 capabilities、禁用提权并设置只读根文件系统。这里不使用只检查进程存在的 healthcheck：进程运行不能证明数据库、日志解析或实际封禁可用，应结合运行日志和 `fail2ban-client status firewall-docker` 判断。

Windows 本地仅用于维护和构建文件；此 Compose 的 socket 和日志挂载路径面向 Linux 云主机。本地构建成功不代表云主机的 MySQL 路由或 fail2ban 联动已验证。

## 直接运行 Python

脚本只读取进程环境变量，不自动加载 `.env`。`MYSQL_PASSWORD` 必填；其他配置及默认值见 `firewall.env.example`。没有把旧密码或令牌写入示例。

Linux / Bash，在脚本目录中执行：

```bash
cp firewall.env.example firewall.env
chmod 600 firewall.env
# 编辑 firewall.env，填入实际密码；启用通知时填入相应令牌。
set -a
source ./firewall.env
set +a
python3 firewall.py
```

环境文件只能加载你信任的内容：`source` 会执行其中的 shell 代码。含空格、`$` 等字符的值使用单引号包裹；密码包含单引号时优先通过服务管理器或部署环境注入。

PowerShell 可直接设置进程环境变量（真实服务仍建议运行在 Linux 上）：

```powershell
$env:MYSQL_PASSWORD = '你的数据库密码'
$env:MYSQL_HOST = '192.168.10.192'
$env:FIREWALL_PUSH_MODE = 'No'
python .\firewall.py
```

systemd 服务可添加 `EnvironmentFile=/绝对路径/firewall.env`，并将 `ExecStart` 指向虚拟环境中的 Python 和脚本绝对路径。配置变更后重启脚本。Docker 部署时可通过 `--env-file` 注入；必须同时配置 Docker 访问权限和 fail2ban 日志的共享路径。

## 策略与兼容性

- 保留原策略：城市包含 `郑州/周口/上海/南京` 中任何一个时放行；其他城市的中国 IP 仅允许豁免服务；其他国家 IP 请求封禁。豁免服务不推送通知。
- 只解析带原有四段方括号前缀和 `new user connection [客户端地址:端口]` 的连接事件。支持 IPv4、带方括号的 IPv6 和裸 IP。避免从任意日志中提取所有 IP。部署前应对照实际 frps 日志格式；格式不匹配时事件会跳过。
- 同时兼容官方源码中的 `get a user connection [客户端地址:端口]` 格式：[frp 连接日志源码](https://github.com/fatedier/frp/blob/dev/server/proxy/proxy.go)。
- 非公网地址跳过归属地查询和封禁。归属地缓存默认有效 24 小时，内存最多保留 10000 个 IP；每次访问仍重新按当前服务判断策略。
- 查询失败或缺少国家/城市时，记录警告并跳过该事件，不缓存放行决定、不请求封禁。后续连接事件会重新尝试；失败事件没有持久化重试队列。
- 通知在归属地首次查询或过期刷新后发送，缓存命中不重复通知。通知失败不影响监控；移除了旧 PushPlus 域名的回退请求。

## 数据库与 fail2ban

保留原 `ip_info` 表及数据，首次运行自动增加可空列 `geo_updated_at DATETIME`，需要对应的 `ALTER` 权限。旧记录首次访问会重新查询归属地。查询时间以 UTC 保存，缓存有效期使用数据库 UTC 时间计算。

每个成功处理的连接事件只执行一次原子插入或更新，计数加一，保留 `first_seen`。`is_blocked` 表示最近一次访问的策略结果，不是 fail2ban 实际封禁状态，也不用于直接决定后续访问。历史重复计数不自动修正。

写封禁日志成功后才保存该访问；日志写入失败会跳过本次保存。文件写入和数据库提交不构成原子事务：日志成功而数据库失败时，后续重试可能再次提交封禁请求。

必须由部署环境创建可写的封禁日志路径，并让 fail2ban 的 filter/jail 读取该文件；脚本保留既有 `<BAN>` 日志格式，但不安装或修改 fail2ban。实际封禁范围由 jail/action 决定，若按 IP 全局封禁，服务豁免不能解除已经存在的全局封禁。

## 重连与日志

断线使用指数退避，默认从 5 秒增长到 60 秒。运行期间保存最后读取的 Docker 时间戳，重连回读同一秒并对最近 10000 条日志去重。进程重启从启动时刻开始，读取进度不跨重启保存；容器日志轮转也可能导致历史日志不可用。

应用日志写入脚本目录下 `log/firewall.log`，10 MB 轮转、保留 14 天。封禁请求日志仍由系统/fail2ban 的日志轮转策略管理。

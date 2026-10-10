# 地图与封禁管理看板

界面展示 frps 连接来源，不将所有访问认定为攻击。人工策略优先于归属地/服务规则；实际封禁状态来自 Fail2ban 采集。第一版单管理员，账号从环境变量读取，重启后全部会话失效。

## 升级部署

新版本自动封禁采用数据库执行队列 + 宿主机执行器，通过 `fail2ban-client set firewall-docker banip/unbanip` 执行，核验成功后才标记完成。**不再依赖检测器写 `<BAN>` 日志触发新封禁**。原日志挂载保留以兼容旧部署，已有 jail、规则和封禁集合不清空。必须先安装执行器，再升级监控容器，不能只升级检测脚本。

1. 备份数据库和旧镜像；保留旧 `ip_info` 表。以下安装目录使用 `/root/project/firewall-monitor`，其他路径须同步修改 systemd 单元。
2. 安装宿主机执行器依赖（需要系统 Python venv 支持）：

   ```bash
   cd ~/project/firewall-monitor
   python3 -m venv .agent-venv
   .agent-venv/bin/pip install -r requirements-agent.txt \
     --index-url https://mirrors.aliyun.com/pypi/simple/
   set -a
   source firewall.env
   set +a
   .agent-venv/bin/python storage.py
   # 新增表建完后，执行器不需要 DDL 权限。
   sudo install -m 644 deploy/firewall-monitor-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now firewall-monitor-agent
   ```

   `EnvironmentFile` 使用 systemd 语法，不要在值中依赖 shell 变量展开。真实环境文件权限设为 600。

3. 生成并填写看板配置：

   ```bash
   test -f dashboard.env || cp dashboard.env.example dashboard.env
   chmod 600 dashboard.env firewall.env
   # 编辑 dashboard.env，填写数据库账号、管理员账号密码与随机会话密钥。
   python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
   ```

   初始用户名为 `zmj`，管理员密码支持随机 6 位，会话密钥至少 32 字符；占位值必须替换。会话默认 8 小时，修改账号或密码后重建 dashboard 容器。只运行一个 API worker，登录限速和会话使用进程内存。

4. 使用受限数据库账号。迁移由现有检测器或运维账号完成，dashboard 账号只授权以下表：

   ```sql
   -- 用实际数据库名、来源网段和强密码替换占位符。
   CREATE USER 'firewall_dashboard'@'%' IDENTIFIED BY 'REPLACE_WITH_STRONG_PASSWORD';
   GRANT SELECT ON dev.fm_profiles TO 'firewall_dashboard'@'%';
   GRANT SELECT ON dev.fm_events TO 'firewall_dashboard'@'%';
   GRANT SELECT ON dev.fm_hourly TO 'firewall_dashboard'@'%';
   GRANT SELECT ON dev.fm_ban_current TO 'firewall_dashboard'@'%';
   GRANT SELECT ON dev.fm_ban_events TO 'firewall_dashboard'@'%';
   GRANT SELECT ON dev.fm_health TO 'firewall_dashboard'@'%';
   GRANT SELECT, INSERT, UPDATE, DELETE ON dev.fm_overrides TO 'firewall_dashboard'@'%';
   GRANT SELECT, INSERT, UPDATE ON dev.fm_commands TO 'firewall_dashboard'@'%';
   GRANT SELECT, INSERT ON dev.fm_audit TO 'firewall_dashboard'@'%';
   ```

   `%` 应根据实际网络收紧；API 不挂载 Docker socket 或 Fail2ban socket。执行器使用宿主机 root 身份访问 Fail2ban，但仅允许修改固定 `firewall-docker` jail；其他 jail 只采集。

5. 构建并启动：

   ```bash
   # 构建源写入忽略的项目 .env：
   # PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/
   # NPM_REGISTRY=https://registry.npmmirror.com
   docker compose build
   docker compose up -d
   docker compose logs --tail=100
   systemctl status firewall-monitor-agent --no-pager
   ```

   默认仅发布 `127.0.0.1:8080`。本机可通过 SSH 隧道访问：

   ```powershell
   ssh -p 2022 -i C:\Users\magic\DOCUME~1\ssh\ali-bj.pem -L 8080:127.0.0.1:8080 root@59.110.150.224
   # 浏览器访问 http://127.0.0.1:8080
   ```

   HTTPS 部署时在反向代理终止 TLS，启用 `DASHBOARD_COOKIE_SECURE=true`。API 默认不信任转发头；反向代理必须保持 Host，若登录 Origin 与应用 scheme 不一致，可配置受信任代理的 Uvicorn `--proxy-headers --forwarded-allow-ips=实际代理地址`，禁止无条件信任公网转发头。不要将 HTTP 登录直接暴露到公网。

## 人工策略和操作记录

- 放行/封禁默认 24 小时，可选 1 小时、7 天、永久。永久策略不依赖 Fail2ban 默认 bantime，执行器定期核对并恢复目标状态。
- 所有人工操作要求填写原因，记录操作人、变更前后值及关联执行指令。
- 修改策略会作废未执行的旧指令。数据库命名锁串行化同一个 IP 的策略修改与实际执行，防止旧封禁在人工放行后执行。
- 执行失败最多重试 5 次，状态核对继续每 5 分钟重新尝试保持人工策略；界面保留失败记录。Fail2ban 重启后也会恢复有效人工策略。
- 放行只影响 `firewall-docker`，不会解除 sshd 或其他 jail。实际封禁范围由现有 action 决定，页面明确提示对主机服务的影响。
- 到期会记录系统审计并恢复自动策略。无可用归属地时不自动封禁；恢复自动策略将解除本服务的人工封禁，后续连接重新判断。
- 首次采集现有封禁只能记录“观测到封禁”，无法还原旧封禁的真实发生时间；两次采集间短暂发生的其他 jail 变化可能无法捕获。

## 数据与性能

- 新表 `fm_profiles` 保存 IP 概览；旧 `ip_info` 迁移到 `legacy_counter`，不会制造历史连接事件。新成功归属地事件继续更新旧表，便于回滚旧程序。
- 连接事件保存原始事件时间、归属地快照和策略原因。Docker 日志重读通过 SHA256 唯一键去重，事件、计数、执行指令、读取游标在同一事务提交。
- 归属地查询失败也保存事件，地图列为未知；下一次连接重新查询，不把未知地址判定为安全来源。
- `fm_hourly` 保存国家/服务小时计数，不累加小时独立 IP 数冒充全时段去重。独立 IP 数使用原始事件精确去重。
- 默认连接事件 30 天、小时汇总 180 天、封禁和审计 365 天。执行器每小时每表删除最多 5000 条过期数据；高流量可增加清理频率/批次数，监控磁盘占用。
- 时间统一 UTC，页面按浏览器当地时区显示（中国用户为北京时间）。地图采用 Natural Earth 110m 数据，仅用于来源可视化，不作为精确边界依据；所有前端依赖与地图随镜像打包。
- 上方时间/国家/服务/策略筛选作用于地图、统计、趋势及 IP 来源。人工策略、当前封禁和完整历史列表独立查询，仅受 IP 搜索影响。

## 本地开发和验证

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
cd frontend
npm ci
npm run build
cd ..
.venv\Scripts\python -m pytest
# 环境变量加载后启动 API；保持单 worker。
.venv\Scripts\python -m uvicorn dashboard:app_factory --factory --host 127.0.0.1 --port 8080
```

集成测试需显式 `RUN_MYSQL_TESTS=1` 及 `MYSQL_*` 运维凭据，会创建随机 `fm_test_<uuid>` 数据库并在结束后删除；不使用生产数据表。所有 Fail2ban 调用均模拟，不操作真实封禁集合。

回滚：先停止新检测器和宿主机执行器，再恢复旧镜像/代码，仅启动旧检测器；旧表和原封禁日志仍保留。新表无需删除，人工策略仅由新版本识别，回滚前应确认其处理方式。

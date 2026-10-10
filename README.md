# Firewall Monitor

frps 连接检测、全球来源地图与 Fail2ban 封禁管理。基于 Vue 3、Apache ECharts、FastAPI、MySQL，通过 Docker Compose 部署。

## 功能

- 世界地图、来源国家排行、连接/封禁请求趋势、被访问服务排行。
- 单管理员登录，账号密码与会话密钥使用环境变量；HttpOnly 会话、CSRF 校验、登录限速。
- IP 详情、当前封禁、历史封禁、执行状态与操作审计。
- 人工放行、封禁及恢复自动策略，可设置有效期；人工策略优先于自动规则。
- 宿主机受限执行器只修改 `firewall-docker`，不会解除 `sshd` 等其他 jail。
- 原数据库兼容迁移、事件去重、持久读取游标、小时统计、数据保留策略。

界面展示连接与策略命中，不能直接认定每次访问都是攻击；当前覆盖 frps 连接事件，非整台主机的完整流量采集。

## 部署

参照 [DASHBOARD.md](DASHBOARD.md) 完成数据库迁移、宿主机执行器安装和看板配置后：

```bash
docker compose build
docker compose up -d
```

**升级必须同时安装宿主机执行器。** 新检测器通过事务执行队列提交封禁，由执行器调用 Fail2ban 并核验实际结果；仅更新监控容器不能完成封禁。

- `firewall.env.example`：检测器/宿主机执行器的数据库和自动规则配置。
- `dashboard.env.example`：看板数据库账号、管理员账号密码、会话配置。
- 实际 `firewall.env`、`dashboard.env`、`.env` 已被 Git 忽略，Docker 构建上下文同样排除密码文件。
- 看板默认只监听宿主机 `127.0.0.1:8080`，通过 SSH 隧道访问；公网访问使用 HTTPS。
- 国内构建源可在 `.env` 设置 `PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/`、`NPM_REGISTRY=https://registry.npmmirror.com`。

## 验证

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
cd frontend
npm ci
npm run build
```

数据库集成测试需显式设置 `RUN_MYSQL_TESTS=1` 及 `MYSQL_*`，仅使用随机临时测试数据库，所有真实防火墙调用均模拟。

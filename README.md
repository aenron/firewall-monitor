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
git pull --ff-only
bash deploy/update.sh
```

**升级必须同时安装宿主机执行器。** 新检测器通过事务执行队列提交封禁，由执行器调用 Fail2ban 并核验实际结果；仅更新监控容器不能完成封禁。

- `firewall.env.example`：检测器/宿主机执行器的数据库和自动规则配置。
- `dashboard.env.example`：看板数据库账号、管理员账号密码、会话配置。
- 实际 `firewall.env`、`dashboard.env`、`.env` 已被 Git 忽略，Docker 构建上下文同样排除密码文件。
- 看板默认只监听宿主机 `127.0.0.1:8080`，通过 SSH 隧道访问；公网访问使用 HTTPS。
- GitHub Actions 自动构建监控和前端镜像并发布至 GHCR；云主机仅拉取镜像，`compose.yaml` 不包含构建配置。
- 镜像为 `ghcr.io/aenron/firewall-monitor` 和 `ghcr.io/aenron/firewall-monitor-dashboard`，发布 `latest`、`sha-完整提交号` 和版本标签。
- 首次发布后，将两个 GHCR 包设为 Public，使云主机无需 GitHub 凭据即可拉取。发布进度查看仓库 Actions。
- 更新脚本先拉取两个镜像，全部成功后再重建容器，并重启宿主机执行器。指定版本更新或回滚：`bash deploy/update.sh sha-完整提交号`。如需持久固定版本，可在忽略的 `.env` 中设置 `IMAGE_TAG=sha-完整提交号`，随后执行 `docker compose pull && docker compose up -d --no-build`。
- 当前云主机在 `.env` 配置 `DASHBOARD_BIND_ADDRESS=0.0.0.0`、`DASHBOARD_PORT=8088`。Compose 通用默认值仍为 `127.0.0.1:8080`。
- 本地开发构建使用 `docker compose -f compose.yaml -f compose.build.yaml build`，再用相同的 `-f` 参数启动；生产环境无需使用 `compose.build.yaml`。

## 验证

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
cd frontend
npm ci
npm run build
```

数据库集成测试需显式设置 `RUN_MYSQL_TESTS=1` 及 `MYSQL_*`，仅使用随机临时测试数据库，所有真实防火墙调用均模拟。

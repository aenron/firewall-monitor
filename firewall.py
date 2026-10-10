"""读取 frps 连接事件，通过日志向 fail2ban 提交封禁请求。"""

import ipaddress
import os
import re
import sys
import time
import hashlib
import threading
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import docker
import mysql.connector
import requests
from loguru import logger
from storage import Store, utcnow

SERVICE_PATTERN = re.compile(r"\[[^\[\]]*\]\s*\[[^\[\]]*\]\s*\[[^\[\]]*\]\s*\[([^\[\]]+)\]")
CLIENT_PATTERN = re.compile(r"\b(?:new )?user connection\s*\[(.+)\]\s*$", re.I)


def env_list(name, default):
    return tuple(item.strip() for item in os.getenv(name, default).split(",") if item.strip())


def positive_env(name, default):
    value = float(os.getenv(name, str(default)))
    if not 0 < value < float("inf"):
        raise ValueError(f"{name} 必须是有限正数")
    return value


@dataclass(frozen=True)
class Settings:
    mysql: dict
    container: str
    cities: tuple
    exempt_services: tuple
    ban_log: Path
    log_dir: Path
    push_mode: str
    bark_url: str
    pushplus_token: str
    timeout: float
    geo_ttl: float
    retry_delay: float

    @classmethod
    def from_env(cls):
        password = os.getenv("MYSQL_PASSWORD")
        if not password:
            raise ValueError("必须设置 MYSQL_PASSWORD 环境变量")
        mode = os.getenv("FIREWALL_PUSH_MODE", "No").lower()
        bark_url = os.getenv("BARK_URL", "")
        token = os.getenv("PUSHPLUS_TOKEN", "")
        if mode not in {"no", "bark", "pushplus_bot"}:
            raise ValueError("FIREWALL_PUSH_MODE 必须是 No、bark 或 pushplus_bot")
        if mode == "bark" and not bark_url:
            raise ValueError("启用 Bark 时必须设置 BARK_URL")
        if mode == "pushplus_bot" and not token:
            raise ValueError("启用 PushPlus 时必须设置 PUSHPLUS_TOKEN")
        return cls(
            mysql={
                "host": os.getenv("MYSQL_HOST", "192.168.10.192"),
                "port": int(os.getenv("MYSQL_PORT", "3306")),
                "user": os.getenv("MYSQL_USER", "root"),
                "password": password,
                "database": os.getenv("MYSQL_DATABASE", "dev"),
                "connection_timeout": max(1, int(positive_env("MYSQL_CONNECT_TIMEOUT", 10))),
            },
            container=os.getenv("FIREWALL_CONTAINER", "frps"),
            cities=env_list("FIREWALL_ALLOWED_CITIES", "郑州,周口,上海,南京"),
            exempt_services=env_list("FIREWALL_EXEMPT_SERVICES", "http_30282,Home.sd_api,Home.Api_test,Home.sd_api2"),
            ban_log=Path(os.getenv("FIREWALL_BAN_LOG", "/var/log/firewall-ban.log")),
            log_dir=Path(os.getenv("FIREWALL_LOG_DIR", str(Path(__file__).parent / "log"))),
            push_mode=mode, bark_url=bark_url, pushplus_token=token,
            timeout=positive_env("FIREWALL_HTTP_TIMEOUT", 10),
            geo_ttl=positive_env("FIREWALL_GEO_TTL", 86400),
            retry_delay=positive_env("FIREWALL_RETRY_DELAY", 5),
        )


def configure_logging(directory):
    directory.mkdir(parents=True, exist_ok=True)
    logger.remove()
    logger.add(sys.stderr, level="INFO", backtrace=False, diagnose=False)
    logger.add(directory / "firewall.log", level="INFO", rotation="10 MB",
               retention="14 days", encoding="utf-8", enqueue=True,
               backtrace=False, diagnose=False)


def parse_connection(line):
    """只读取 user connection 事件的客户端地址，避免误封日志中的其他 IP。"""
    service = SERVICE_PATTERN.search(line)
    client = CLIENT_PATTERN.search(line)
    if not service or not client:
        return None
    endpoint = client.group(1).strip()
    try:
        address = ipaddress.ip_address(endpoint)
    except ValueError:
        host, separator, port = endpoint.rpartition(":")
        if not separator or not port.isdigit() or not 0 < int(port) <= 65535:
            return None
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None
    name = service.group(1).strip()
    return (str(address), name) if name else None


def should_block(info, name, settings):
    city_allowed = any(city in info["city"] for city in settings.cities)
    return not city_allowed and (
        info["country"] != "中国" or name not in settings.exempt_services
    )


class Firewall:
    def __init__(self, settings):
        self.settings = settings
        self.session = requests.Session()
        self.client = None
        self.since = int(time.time())
        self.seen = OrderedDict()
        self.geo_cache = OrderedDict()
        self.store = Store(settings.mysql)
        self.stop_heartbeat = threading.Event()
        self.monitor_ok = False

    @contextmanager
    def database(self):
        connection = mysql.connector.connect(**self.settings.mysql)
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            yield connection, cursor
        finally:
            try:
                if cursor is not None:
                    cursor.close()
            finally:
                connection.close()

    def init_db(self):
        with self.database() as (connection, cursor):
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_info (
                    ip_address VARCHAR(45) PRIMARY KEY,
                    country VARCHAR(100), region VARCHAR(100), city VARCHAR(100),
                    org VARCHAR(255), is_blocked BOOLEAN,
                    counter INT DEFAULT 0, access_name VARCHAR(100),
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    geo_updated_at DATETIME NULL
                )
            """)
            cursor.execute("""
                SELECT COLUMN_NAME FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=%s AND TABLE_NAME='ip_info'
                    AND COLUMN_NAME='geo_updated_at'
            """, (self.settings.mysql["database"],))
            if cursor.fetchone() is None:
                cursor.execute("ALTER TABLE ip_info ADD COLUMN geo_updated_at DATETIME NULL")
            connection.commit()
        self.store.migrate()

    def lookup(self, ip, cursor):
        cached = self.geo_cache.get(ip)
        if cached and time.monotonic() < cached[0]:
            self.geo_cache.move_to_end(ip)
            return cached[1], False
        cursor.execute("""
            SELECT country, region, city, org, geo_updated_at,
                TIMESTAMPDIFF(SECOND, geo_updated_at, UTC_TIMESTAMP()) AS geo_age
            FROM ip_info WHERE ip_address=%s
        """, (ip,))
        row = cursor.fetchone()
        if (row and row["country"] and row["city"] and row["geo_age"] is not None
                and 0 <= row["geo_age"] < self.settings.geo_ttl):
            info = {key: row[key] or "" for key in ("country", "region", "city", "org")}
            info["geo_updated_at"] = row["geo_updated_at"]
            remaining = self.settings.geo_ttl - row["geo_age"]
            refreshed = False
        else:
            response = self.session.get("https://ip9.com.cn/get", params={"ip": ip},
                                        timeout=self.settings.timeout)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(data, dict) or not data.get("country") or not data.get("city"):
                raise ValueError("IP 查询缺少有效国家或城市，暂不生成封禁决定")
            info = {key: str(data.get(field) or "") for key, field in
                    (("country", "country"), ("region", "prov"), ("city", "city"), ("org", "isp"))}
            info["geo_updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None)
            remaining = self.settings.geo_ttl
            refreshed = True
        self.geo_cache[ip] = (time.monotonic() + remaining, info)
        self.geo_cache.move_to_end(ip)
        if len(self.geo_cache) > 10000:
            self.geo_cache.popitem(last=False)
        return info, refreshed

    def save_access(self, cursor, ip, name, info, blocked):
        fields = (info["country"], info["region"], info["city"], info["org"],
                  blocked, name, info["geo_updated_at"])
        cursor.execute("""
            INSERT INTO ip_info
                (ip_address, country, region, city, org, is_blocked, access_name,
                 geo_updated_at, counter)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                country=%s, region=%s, city=%s, org=%s, is_blocked=%s,
                access_name=%s, geo_updated_at=%s,
                counter=COALESCE(counter, 0)+1, last_seen=CURRENT_TIMESTAMP
        """, (ip, *fields, *fields))

    def notify(self, ip, name, info, blocked):
        if self.settings.push_mode == "no" or name in self.settings.exempt_services:
            return
        content = {"访问对象": name, "来源IP": ip, "国家": info["country"],
                   "归属地": info["region"], "城市": info["city"], "组织": info["org"]}
        title = f"{'请求封禁' if blocked else '放行'}[{name}]访问"
        try:
            if self.settings.push_mode == "bark":
                response = self.session.post(self.settings.bark_url, json={
                    "title": title, "body": "\n".join(f"{key}:{value}" for key, value in content.items()),
                    "group": "Firewall", "level": "passive",
                }, timeout=self.settings.timeout)
            else:
                response = self.session.post("https://www.pushplus.plus/send", json={
                    "token": self.settings.pushplus_token, "title": title,
                    "content": content, "template": "json",
                }, timeout=self.settings.timeout)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or payload.get("code") != 200:
                logger.warning("通知服务返回非成功状态")
        except (requests.RequestException, ValueError):
            # 请求异常可能包含带令牌的 URL，不输出异常详情。
            logger.warning("通知发送失败，不影响后续日志处理")

    def process(self, ip, name, event_key=None, occurred_at=None, container_id=None, since_second=None):
        if not ipaddress.ip_address(ip).is_global:
            logger.debug("跳过非公网地址 {}", ip)
            return
        event_key = event_key or hashlib.sha256(f"{ip}:{name}:{time.time_ns()}".encode()).hexdigest()
        occurred_at = occurred_at or utcnow()
        with self.store.transaction() as (_, cursor):
            Store.lock_ip(cursor, ip)
            cursor.execute("SELECT id FROM fm_events WHERE event_key=%s", (event_key,))
            if cursor.fetchone():
                return
            override = Store.override(cursor, ip)
            refreshed = False
            try:
                info, refreshed = self.lookup(ip, cursor)
                blocked = should_block(info, name, self.settings)
                decision, reason = ("block", "归属地和服务规则") if blocked else ("allow", "归属地和服务规则")
            except (requests.RequestException, ValueError):
                info, blocked, decision, reason = {}, False, "unknown", "归属地查询失败，未自动封禁"
            if override:
                blocked = override["mode"] == "block"
                decision, reason = override["mode"], "人工策略：" + override["reason"]
            if Store.record(cursor,event_key,occurred_at,ip,name,info,decision,reason):
                if info:
                    self.save_access(cursor, ip, name, info, blocked)
                if blocked:
                    cursor.execute("SELECT id FROM fm_commands WHERE ip=%s AND status IN ('pending','running') LIMIT 1", (ip,))
                    if cursor.fetchone() is None:
                        cursor.execute("""INSERT INTO fm_commands (ip,action,version,created_at,updated_at)
                            VALUES (%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP())""",
                            (ip,"block" if override else "auto",override["version"] if override else None))
            if container_id:
                cursor.execute("""INSERT INTO fm_cursors VALUES (%s,%s,UTC_TIMESTAMP())
                    ON DUPLICATE KEY UPDATE since_second=GREATEST(since_second,VALUES(since_second)),updated_at=UTC_TIMESTAMP()""",
                    (container_id,since_second))
        logger.info("{} 服务={} 城市={} 策略={}", ip, name, info.get("city", "未知"), decision)
        # 保持原行为：同一 IP 只在首次或归属地刷新后通知，避免每次访问推送。
        if refreshed and info:
            self.notify(ip, name, info, blocked)

    def monitor(self):
        if self.client is None:
            self.client = docker.from_env(timeout=self.settings.timeout)
        container = self.client.containers.get(self.settings.container)
        saved = self.store.query("SELECT since_second FROM fm_cursors WHERE container_id=%s",(container.id,))
        if saved:
            self.since = saved[0]["since_second"]
        self.monitor_ok = True
        stream = container.logs(stream=True, follow=True, since=self.since, timestamps=True)
        try:
            for chunk in stream:
                for line in chunk.decode("utf-8", errors="replace").splitlines():
                    stamp, separator, message = line.partition(" ")
                    if not separator:
                        continue
                    try:
                        moment = datetime.fromisoformat(
                            re.sub(r"(\.\d{6})\d+", r"\1", stamp).replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning("跳过无法解析 Docker 时间戳的日志")
                        continue
                    if line in self.seen:
                        continue
                    event = parse_connection(message)
                    try:
                        if event:
                            self.process(*event, event_key=hashlib.sha256((container.id + line).encode()).hexdigest(),
                                occurred_at=moment.astimezone(timezone.utc).replace(tzinfo=None),
                                container_id=container.id,since_second=int(moment.timestamp()))
                    except (requests.RequestException, mysql.connector.Error, OSError, ValueError, RuntimeError) as exc:
                        logger.warning("连接事件处理失败 IP={} 服务={} ({})，重连后回读该事件",
                                       event[0], event[1], type(exc).__name__)
                        raise
                    self.since = max(self.since, int(moment.timestamp()))
                    self.seen[line] = None
                    if len(self.seen) > 10000:
                        self.seen.popitem(last=False)
        finally:
            self.monitor_ok = False
            stream.close()

    def heartbeat(self):
        while not self.stop_heartbeat.wait(15):
            try:
                # A live stream can be quiet. Container existence/running is checked independently.
                client = docker.from_env(timeout=self.settings.timeout)
                try:
                    running = client.containers.get(self.settings.container).status == "running"
                finally:
                    client.close()
                self.store.health("monitor", self.monitor_ok and running, "frps 日志监听" if running else "frps 未运行")
            except Exception as exc:
                try:
                    self.store.health("monitor", False, type(exc).__name__)
                except Exception:
                    pass

    def run(self):
        delay = self.settings.retry_delay
        heartbeat_started = False
        try:
            while True:
                started = time.monotonic()
                try:
                    self.init_db()
                    if not heartbeat_started:
                        threading.Thread(target=self.heartbeat,daemon=True).start()
                        heartbeat_started = True
                    logger.info("开始监控容器 {}", self.settings.container)
                    self.monitor()
                except (docker.errors.DockerException, requests.RequestException,
                        mysql.connector.Error, OSError, ValueError, RuntimeError) as exc:
                    logger.warning("监控连接中断 ({})，{} 秒后重试", type(exc).__name__, delay)
                if self.client is not None:
                    self.client.close()
                    self.client = None
                if time.monotonic() - started > 60:
                    delay = self.settings.retry_delay
                time.sleep(delay)
                delay = min(delay * 2, max(60, self.settings.retry_delay))
        finally:
            self.stop_heartbeat.set()
            self.session.close()
            if self.client is not None:
                self.client.close()


def main():
    try:
        settings = Settings.from_env()
        configure_logging(settings.log_dir)
        Firewall(settings).run()
    except KeyboardInterrupt:
        logger.info("监控已停止")
    except ValueError as exc:
        logger.error("配置错误: {}", exc)
        return 1
    finally:
        logger.complete()
    return 0


if __name__ == "__main__":
    sys.exit(main())

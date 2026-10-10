"""Shared MySQL storage. All new DATETIME values are UTC; legacy ip_info is retained."""
import hashlib
import ipaddress
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import mysql.connector
from mysql.connector.pooling import MySQLConnectionPool
import pycountry
from babel import Locale


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def canonical_ip(value):
    return str(ipaddress.ip_address(value))


COUNTRIES = {str(name): code for code, name in Locale.parse("zh_Hans").territories.items()
             if len(code) == 2}
COUNTRIES.update({"中国": "CN", "中国大陆": "CN", "香港": "HK", "中国香港": "HK",
                  "澳门": "MO", "中国澳门": "MO", "台湾": "TW", "中国台湾": "TW",
                  "美国": "US", "俄罗斯": "RU", "韩国": "KR", "英国": "GB"})


def country_code(name):
    if name in COUNTRIES:
        return COUNTRIES[name]
    try:
        return pycountry.countries.lookup(name).alpha_2
    except LookupError:
        return "ZZ"


TABLES = [
    """CREATE TABLE IF NOT EXISTS fm_meta (name VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL)
       ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_profiles (
       ip VARCHAR(45) CHARACTER SET ascii PRIMARY KEY, country_code CHAR(2) DEFAULT 'ZZ',
       country VARCHAR(100), region VARCHAR(100), city VARCHAR(100), org VARCHAR(255),
       first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
       legacy_counter BIGINT UNSIGNED DEFAULT 0, INDEX(last_seen)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_events (
       id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, event_key CHAR(64) CHARACTER SET ascii NOT NULL UNIQUE,
       occurred_at DATETIME(6) NOT NULL, ip VARCHAR(45) CHARACTER SET ascii NOT NULL,
       service VARCHAR(100) NOT NULL, country_code CHAR(2) NOT NULL, country VARCHAR(100),
       region VARCHAR(100), city VARCHAR(100), org VARCHAR(255), decision VARCHAR(16) NOT NULL,
       reason VARCHAR(255) NOT NULL, INDEX(occurred_at), INDEX(ip,occurred_at),
       INDEX(service,occurred_at), INDEX(country_code,occurred_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_overrides (
       ip VARCHAR(45) CHARACTER SET ascii PRIMARY KEY, mode VARCHAR(8) NOT NULL,
       expires_at DATETIME NULL, actor VARCHAR(100) NOT NULL, reason VARCHAR(255) NOT NULL,
       version CHAR(32) CHARACTER SET ascii NOT NULL, updated_at DATETIME NOT NULL,
       INDEX(expires_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_commands (
       id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(45) CHARACTER SET ascii NOT NULL,
       action VARCHAR(16) NOT NULL, version CHAR(32) CHARACTER SET ascii NULL,
       status VARCHAR(16) NOT NULL DEFAULT 'pending', attempts INT NOT NULL DEFAULT 0,
       created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, error VARCHAR(255) NULL,
       INDEX(status,updated_at), INDEX(ip,id), INDEX(ip,status)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_ban_current (
       jail VARCHAR(64) CHARACTER SET ascii NOT NULL, ip VARCHAR(45) CHARACTER SET ascii NOT NULL,
       observed_at DATETIME NOT NULL, PRIMARY KEY(jail,ip)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_ban_events (
       id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, ip VARCHAR(45) CHARACTER SET ascii NOT NULL,
       jail VARCHAR(64) NOT NULL, action VARCHAR(24) NOT NULL, source VARCHAR(24) NOT NULL,
       occurred_at DATETIME NOT NULL, command_id BIGINT UNSIGNED NULL,
       INDEX(occurred_at), INDEX(ip,occurred_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_audit (
       id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, actor VARCHAR(100) NOT NULL,
       ip VARCHAR(45) CHARACTER SET ascii NOT NULL, action VARCHAR(16) NOT NULL,
       reason VARCHAR(255) NOT NULL, before_value TEXT NULL, after_value TEXT NULL,
       command_id BIGINT UNSIGNED NOT NULL, occurred_at DATETIME NOT NULL,
       INDEX(occurred_at), INDEX(ip,occurred_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_hourly (
       hour DATETIME NOT NULL, country_code CHAR(2) NOT NULL, service VARCHAR(100) NOT NULL,
       connections BIGINT UNSIGNED NOT NULL DEFAULT 0, blocked BIGINT UNSIGNED NOT NULL DEFAULT 0,
       unknown_count BIGINT UNSIGNED NOT NULL DEFAULT 0, PRIMARY KEY(hour,country_code,service))
       ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_health (
       component VARCHAR(64) PRIMARY KEY, updated_at DATETIME NOT NULL, ok BOOLEAN NOT NULL,
       detail VARCHAR(255) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS fm_cursors (
       container_id VARCHAR(64) CHARACTER SET ascii PRIMARY KEY, since_second BIGINT NOT NULL,
       updated_at DATETIME NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


class Store:
    def __init__(self, config=None):
        self.config = config or dict(host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", "3306")), user=os.getenv("MYSQL_USER", "root"),
            password=os.environ["MYSQL_PASSWORD"], database=os.getenv("MYSQL_DATABASE", "dev"),
            connection_timeout=10)
        self.pool = None
        self.pool_lock = threading.Lock()

    @contextmanager
    def transaction(self):
        with self.pool_lock:
            if self.pool is None:
                self.pool = MySQLConnectionPool(pool_name='fm_'+uuid.uuid4().hex[:20],
                    pool_size=5,pool_reset_session=True,**self.config)
        conn = self.pool.get_connection()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SET time_zone = '+00:00'")
            yield conn, cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            # Named locks are session-scoped, not released by COMMIT. Pooled connections
            # must release them before reuse, even after a rollback or subprocess failure.
            try:
                cleanup = conn.cursor()
                cleanup.execute("SELECT RELEASE_ALL_LOCKS()")
                cleanup.fetchone()
                cleanup.close()
            finally:
                conn.close()

    def query(self, sql, args=()):
        with self.transaction() as (_, cur):
            cur.execute(sql, args)
            return cur.fetchall()

    def migrate(self):
        with self.transaction() as (conn, cur):
            schema_lock='fm-schema-'+hashlib.sha256(self.config['database'].encode()).hexdigest()[:40]
            cur.execute("SELECT GET_LOCK(%s,30) AS locked",(schema_lock,))
            if cur.fetchone()["locked"] != 1:
                raise RuntimeError("schema migration lock unavailable")
            try:
                for sql in TABLES:
                    cur.execute(sql)
                cur.execute("SELECT value FROM fm_meta WHERE name='schema_version'")
                if cur.fetchone() is None:
                    # Old rows are cumulative snapshots, never fabricated as historical events.
                    cur.execute("SELECT COUNT(*) AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ip_info'")
                    if cur.fetchone()["n"]:
                        cur.execute("""INSERT IGNORE INTO fm_profiles
                            (ip,country,region,city,org,first_seen,last_seen,legacy_counter)
                            SELECT ip_address,country,region,city,org,COALESCE(first_seen,UTC_TIMESTAMP()),
                            COALESCE(last_seen,first_seen,UTC_TIMESTAMP()),
                            GREATEST(COALESCE(counter,0),0) FROM ip_info""")
                        cur.execute("SELECT DISTINCT country FROM fm_profiles")
                        names = cur.fetchall()
                        for row in names:
                            cur.execute("UPDATE fm_profiles SET country_code=%s WHERE country <=> %s",
                                        (country_code(row["country"] or ""), row["country"]))
                    cur.execute("INSERT INTO fm_meta VALUES ('schema_version','1')")
                conn.commit()
            finally:
                cur.execute("SELECT RELEASE_LOCK(%s)",(schema_lock,))
                cur.fetchone()

    @staticmethod
    def lock_ip(cur, ip):
        cur.execute("SELECT GET_LOCK(CONCAT('fm-ip-',SUBSTRING(SHA2(CONCAT(DATABASE(),':',%s),256),1,40)),15) AS locked", (ip,))
        if cur.fetchone()["locked"] != 1:
            raise RuntimeError("IP operation busy")

    @staticmethod
    def override(cur, ip, lock=False):
        cur.execute("SELECT * FROM fm_overrides WHERE ip=%s" + (" FOR UPDATE" if lock else ""), (ip,))
        row = cur.fetchone()
        return row if row and (row["expires_at"] is None or row["expires_at"] > utcnow()) else None

    def health(self, component, ok, detail):
        with self.transaction() as (_, cur):
            cur.execute("""INSERT INTO fm_health VALUES (%s,UTC_TIMESTAMP(),%s,%s)
                ON DUPLICATE KEY UPDATE updated_at=UTC_TIMESTAMP(),ok=VALUES(ok),detail=VALUES(detail)""",
                (component, ok, detail[:255]))

    @staticmethod
    def record(cur, key, occurred_at, ip, service, info, decision, reason):
        code = country_code(info.get("country", ""))
        cur.execute("""INSERT IGNORE INTO fm_events
            (event_key,occurred_at,ip,service,country_code,country,region,city,org,decision,reason)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (key, occurred_at, ip, service[:100], code,
            *(info.get(k, "")[:255 if k == "org" else 100] for k in ("country","region","city","org")), decision, reason[:255]))
        fresh = cur.rowcount == 1
        if fresh:
            cur.execute("""INSERT INTO fm_profiles
                (ip,country_code,country,region,city,org,first_seen,last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE country_code=IF(VALUES(country_code)='ZZ',country_code,VALUES(country_code)),
                country=IF(VALUES(country_code)='ZZ',country,VALUES(country)),
                region=IF(VALUES(country_code)='ZZ',region,VALUES(region)),
                city=IF(VALUES(country_code)='ZZ',city,VALUES(city)),org=IF(VALUES(country_code)='ZZ',org,VALUES(org)),
                last_seen=GREATEST(last_seen,VALUES(last_seen))""", (ip,code,
                *(info.get(k, "")[:255 if k == "org" else 100] for k in ("country","region","city","org")), occurred_at,occurred_at))
            cur.execute("""INSERT INTO fm_hourly VALUES (%s,%s,%s,1,%s,%s)
                ON DUPLICATE KEY UPDATE connections=connections+1,blocked=blocked+VALUES(blocked),
                unknown_count=unknown_count+VALUES(unknown_count)""",
                (occurred_at.replace(minute=0,second=0,microsecond=0),code,service[:100],decision == "block",decision == "unknown"))
        return fresh

    def cleanup(self):
        # Bounded batches avoid long DELETE transactions. The agent invokes this hourly.
        for table, column, days in [("fm_events","occurred_at",int(os.getenv("EVENT_RETENTION_DAYS","30"))),
            ("fm_hourly","hour",int(os.getenv("STATS_RETENTION_DAYS","180"))),
            ("fm_ban_events","occurred_at",int(os.getenv("AUDIT_RETENTION_DAYS","365"))),
            ("fm_audit","occurred_at",int(os.getenv("AUDIT_RETENTION_DAYS","365")))]:
            if days < 1:
                raise ValueError("retention days must be positive")
            with self.transaction() as (_, cur):
                cur.execute(f"DELETE FROM {table} WHERE {column}<UTC_TIMESTAMP()-INTERVAL %s DAY LIMIT 5000",(days,))
        with self.transaction() as (_, cur):
            cur.execute("DELETE FROM fm_commands WHERE status IN ('done','superseded','failed') AND updated_at<UTC_TIMESTAMP()-INTERVAL 365 DAY LIMIT 5000")


if __name__ == "__main__":
    Store().migrate()
    print("Schema version 1 ready; legacy data retained.")

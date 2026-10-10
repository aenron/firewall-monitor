"""Restricted host executor. Only firewall-docker can be changed; other jails are observed."""
import os
import re
import subprocess
import time

from storage import Store, canonical_ip, utcnow

MANAGED_JAIL = "firewall-docker"


def f2b(*args):
    result = subprocess.run(["/usr/bin/fail2ban-client", *args],capture_output=True,text=True,timeout=15)
    if result.returncode:
        raise RuntimeError("fail2ban-client operation failed")
    return result.stdout.strip()


def automatic_decision(profile, service):
    """Same rule as monitor, with no network lookup in the privileged executor."""
    if not profile or not profile.get("country") or not profile.get("city"):
        return False
    cities = [s.strip() for s in os.getenv("FIREWALL_ALLOWED_CITIES","郑州,周口,上海,南京").split(",") if s.strip()]
    exempt = [s.strip() for s in os.getenv("FIREWALL_EXEMPT_SERVICES","http_30282,Home.sd_api,Home.Api_test,Home.sd_api2").split(",") if s.strip()]
    return not any(c in profile["city"] for c in cities) and (profile["country"]!="中国" or service not in exempt)


class Agent:
    def __init__(self, store=None):
        self.store = store or Store()

    def snapshot(self):
        status = f2b("status")
        match = re.search(r"Jail list:\s*(.*)",status)
        if not match:
            raise RuntimeError("Cannot parse jail list")
        jails = [name.strip() for name in match.group(1).split(",") if name.strip()]
        if MANAGED_JAIL not in jails or any(not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}",j) for j in jails):
            raise RuntimeError("Managed jail unavailable")
        snapshot = {}
        for jail in jails:
            snapshot[jail] = {canonical_ip(value) for value in f2b("get",jail,"banip").split()}
        with self.store.transaction() as (_,cur):
            cur.execute("SELECT jail,ip FROM fm_ban_current")
            old = {(row["jail"],row["ip"]) for row in cur.fetchall()}
            new = {(jail,ip) for jail,ips in snapshot.items() for ip in ips}
            for jail,ip in new-old:
                cur.execute("INSERT INTO fm_ban_events (ip,jail,action,source,occurred_at) VALUES (%s,%s,'observed_ban','snapshot',UTC_TIMESTAMP())",(ip,jail))
            for jail,ip in old-new:
                cur.execute("INSERT INTO fm_ban_events (ip,jail,action,source,occurred_at) VALUES (%s,%s,'observed_unban','snapshot',UTC_TIMESTAMP())",(ip,jail))
            cur.execute("DELETE FROM fm_ban_current")
            if new:
                cur.executemany("INSERT INTO fm_ban_current VALUES (%s,%s,UTC_TIMESTAMP())",list(new))
        self.store.health("fail2ban",True,"所有 jail 状态已采集；仅管理 firewall-docker")
        return snapshot[MANAGED_JAIL]

    def expire_and_reconcile(self, banned):
        rows = self.store.query("SELECT * FROM fm_overrides ORDER BY updated_at")
        for row in rows:
            ip = row["ip"]
            with self.store.transaction() as (_,cur):
                Store.lock_ip(cur,ip)
                cur.execute("SELECT * FROM fm_overrides WHERE ip=%s FOR UPDATE",(ip,))
                latest = cur.fetchone()
                if not latest or latest["version"] != row["version"]:
                    continue
                expired = latest["expires_at"] is not None and latest["expires_at"] <= utcnow()
                if expired:
                    cur.execute("DELETE FROM fm_overrides WHERE ip=%s",(ip,))
                    action,version = "auto",None
                    cur.execute("UPDATE fm_commands SET status='superseded',updated_at=UTC_TIMESTAMP() WHERE ip=%s AND status IN ('pending','failed')",(ip,))
                else:
                    action,version = latest["mode"],latest["version"]
                    if (action == "block") == (ip in banned):
                        continue
                cur.execute("SELECT id FROM fm_commands WHERE ip=%s AND (status IN ('pending','running') OR (status='failed' AND updated_at>UTC_TIMESTAMP()-INTERVAL 5 MINUTE)) LIMIT 1",(ip,))
                if cur.fetchone() is None:
                    cur.execute("INSERT INTO fm_commands (ip,action,version,created_at,updated_at) VALUES (%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP())",(ip,action,version))
                    if expired:
                        command_id=cur.lastrowid
                        cur.execute("INSERT INTO fm_audit (actor,ip,action,reason,before_value,after_value,command_id,occurred_at) VALUES ('system',%s,'auto','人工策略到期',%s,'auto',%s,UTC_TIMESTAMP())",(ip,latest['mode'],command_id))

    def execute(self, command):
        ip = canonical_ip(command["ip"])
        with self.store.transaction() as (_,cur):
            Store.lock_ip(cur,ip)
            cur.execute("SELECT * FROM fm_commands WHERE id=%s FOR UPDATE",(command["id"],))
            current = cur.fetchone()
            if not current or current["status"] not in {"pending","failed"} or current["attempts"]>=5:
                return
            override = Store.override(cur,ip)
            stale = (current["version"] is not None and (not override or override["version"] != current["version"])) or (current["version"] is None and override is not None)
            if stale:
                cur.execute("UPDATE fm_commands SET status='superseded',updated_at=UTC_TIMESTAMP() WHERE id=%s",(current["id"],))
                return
            if current["action"] == "auto":
                cur.execute("SELECT * FROM fm_profiles WHERE ip=%s",(ip,))
                profile = cur.fetchone()
                cur.execute("SELECT service FROM fm_events WHERE ip=%s ORDER BY occurred_at DESC,id DESC LIMIT 1",(ip,))
                event = cur.fetchone()
                if not event:
                    cur.execute("SELECT COUNT(*) n FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ip_info'")
                    legacy=None
                    if cur.fetchone()['n']:
                        cur.execute("SELECT access_name FROM ip_info WHERE ip_address=%s",(ip,))
                        legacy = cur.fetchone()
                    service = legacy["access_name"] if legacy else ""
                else:
                    service = event["service"]
                block = automatic_decision(profile,service)
            elif current["action"] in {"block","allow"}:
                block = current["action"] == "block"
            else:
                raise ValueError("Unsupported command action")
            try:
                f2b("set",MANAGED_JAIL,"banip" if block else "unbanip",ip)
                observed = {canonical_ip(value) for value in f2b("get",MANAGED_JAIL,"banip").split()}
                if (ip in observed) != block:
                    raise RuntimeError("Actual ban state mismatch")
            except (RuntimeError,subprocess.TimeoutExpired,OSError,ValueError) as exc:
                cur.execute("UPDATE fm_commands SET status='failed',attempts=attempts+1,error=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s",(type(exc).__name__,current["id"]))
                return
            cur.execute("UPDATE fm_commands SET status='done',attempts=attempts+1,error=NULL,updated_at=UTC_TIMESTAMP() WHERE id=%s",(current["id"],))
            cur.execute("INSERT INTO fm_ban_events (ip,jail,action,source,occurred_at,command_id) VALUES (%s,%s,%s,'command',UTC_TIMESTAMP(),%s)",(ip,MANAGED_JAIL,"ban" if block else "unban",current["id"]))
            if block:
                cur.execute("INSERT INTO fm_ban_current VALUES (%s,%s,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE observed_at=UTC_TIMESTAMP()",(MANAGED_JAIL,ip))
            else:
                cur.execute("DELETE FROM fm_ban_current WHERE jail=%s AND ip=%s",(MANAGED_JAIL,ip))

    def tick(self):
        banned = self.snapshot()
        self.expire_and_reconcile(banned)
        commands = self.store.query("SELECT * FROM fm_commands WHERE status='pending' OR (status='failed' AND attempts<5 AND updated_at<UTC_TIMESTAMP()-INTERVAL 15 SECOND) ORDER BY id LIMIT 100")
        for command in commands:
            self.execute(command)
        self.store.health("executor",True,"封禁执行器正常")

    def run(self):
        last_cleanup = 0
        while True:
            try:
                self.tick()
                if time.monotonic()-last_cleanup>3600:
                    self.store.cleanup()
                    last_cleanup = time.monotonic()
            except Exception as exc:
                # Print type only; never connection strings or passwords.
                print("Agent cycle failed:",type(exc).__name__,flush=True)
                for component in ("executor","fail2ban"):
                    try:
                        self.store.health(component,False,type(exc).__name__)
                    except Exception:
                        pass
            time.sleep(5)


if __name__ == "__main__":
    Agent().run()

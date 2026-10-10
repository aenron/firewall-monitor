"""Authenticated dashboard API. No shell access and no Docker/fail2ban socket mounts."""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from storage import Store, canonical_ip, utcnow


class Login(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=1024)


class Policy(BaseModel):
    mode: str
    duration_hours: int = Field(default=24, ge=0, le=8760)
    reason: str = Field(min_length=1, max_length=255)


def create_app(store=None, config=None):
    cfg = config or os.environ
    username = cfg.get("DASHBOARD_ADMIN_USERNAME", "")
    password = cfg.get("DASHBOARD_ADMIN_PASSWORD", "")
    secret = cfg.get("DASHBOARD_SESSION_SECRET", "")
    if not username or len(password) < 6 or len(secret) < 32 or password.startswith('replace-') or secret.startswith('replace-'):
        raise ValueError("Configure admin username, password (6+ characters), and session secret (32+ characters)")
    lifetime = int(cfg.get("DASHBOARD_SESSION_HOURS", "8")) * 3600
    if not 60 <= lifetime <= 86400:
        raise ValueError("Session lifetime must be between 1 minute and 24 hours")
    secure = cfg.get("DASHBOARD_COOKIE_SECURE", "false").lower() == "true"
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(),secret.encode(),200000)
    db = store or Store()
    sessions, failures = OrderedDict(), OrderedDict()
    mutex = threading.Lock()
    app = FastAPI(title="Firewall Monitor", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Exception)
    async def unavailable(request, exc):
        # Database errors can include connection details. Never return them to browsers.
        return JSONResponse({"detail": "服务暂时不可用，请检查数据库或服务日志"}, status_code=503)

    def authenticated(request: Request):
        token = request.cookies.get("fm_session", "")
        with mutex:
            session = sessions.get(token)
            if session is None or session["expires"] < time.time():
                sessions.pop(token, None)
                raise HTTPException(401, "请先登录")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
                raise HTTPException(403, "请求校验失败，请刷新页面")
        return session

    def check_origin(request):
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "登录请求来源不匹配")

    @app.post("/api/login")
    def login(body: Login, request: Request, response: Response):
        check_origin(request)
        peer = request.client.host if request.client else "unknown"
        now = time.time()
        with mutex:
            recent = [t for t in failures.get(peer, []) if t > now-600]
            global_recent = [t for t in failures.get("*", []) if t > now-60]
            if len(recent) >= 5 or len(global_recent) >= 30:
                raise HTTPException(429, "登录失败过多，请稍后再试")
            failures[peer] = recent + [now]
            failures["*"] = global_recent + [now]
            if len(failures)>1000:
                failures.popitem(last=False)
        supplied = hashlib.pbkdf2_hmac("sha256",body.password.encode(),secret.encode(),200000)
        if not (hmac.compare_digest(body.username.encode(),username.encode()) & hmac.compare_digest(supplied,password_hash)):
            raise HTTPException(401,"用户名或密码错误")
        nonce = secrets.token_urlsafe(32)
        token = nonce + "." + hmac.new(secret.encode(),nonce.encode(),hashlib.sha256).hexdigest()
        csrf = secrets.token_urlsafe(32)
        with mutex:
            # Re-login rotates the previous session; sessions are also revoked on restart.
            sessions.pop(request.cookies.get("fm_session", ""),None)
            sessions[token] = {"username":username,"csrf":csrf,"expires":now+lifetime}
            if len(sessions)>100:
                sessions.popitem(last=False)
            failures.pop(peer,None)
        response.set_cookie("fm_session",token,max_age=lifetime,httponly=True,secure=secure,samesite="strict",path="/")
        return {"username":username,"csrf":csrf}

    @app.get("/api/session")
    def session(current=Depends(authenticated)):
        return {"username":current["username"],"csrf":current["csrf"]}

    @app.post("/api/logout")
    def logout(request:Request,response:Response,current=Depends(authenticated)):
        with mutex:
            sessions.pop(request.cookies.get("fm_session", ""),None)
        response.delete_cookie("fm_session",path="/",secure=secure,httponly=True,samesite="strict")
        return {"ok":True}

    def window(start, end):
        try:
            upper = datetime.fromisoformat(end.replace("Z","+00:00")) if end else datetime.now(timezone.utc)
            lower = datetime.fromisoformat(start.replace("Z","+00:00")) if start else upper-timedelta(hours=24)
            if lower.tzinfo is None or upper.tzinfo is None:
                raise ValueError()
            lower,upper = [v.astimezone(timezone.utc).replace(tzinfo=None) for v in (lower,upper)]
        except ValueError:
            raise HTTPException(422,"时间必须包含时区")
        retained = int(cfg.get("EVENT_RETENTION_DAYS","30"))
        if lower >= upper or upper-lower>timedelta(days=retained) or lower<utcnow()-timedelta(days=retained,minutes=5) or upper>utcnow()+timedelta(minutes=5):
            raise HTTPException(422,f"查询范围应位于最近 {retained} 天，开始时间应早于结束时间")
        return lower,upper

    def where(start,end,country,service,ip,decision):
        lower,upper = window(start,end)
        sql,args = "occurred_at >= %s AND occurred_at < %s",[lower,upper]
        for field,value in (("country_code",country),("service",service),("ip",ip),("decision",decision)):
            if value:
                if len(value)>100:
                    raise HTTPException(422,"筛选值过长")
                sql += f" AND {field}=%s"
                if field=='ip':
                    try:
                        value=canonical_ip(value)
                    except ValueError:
                        raise HTTPException(422,'IP 地址无效')
                args.append(value)
        return sql,args

    @app.get("/api/overview")
    def overview(start:str="",end:str="",country:str="",service:str="",ip:str="",decision:str="",current=Depends(authenticated)):
        clause,args = where(start,end,country,service,ip,decision)
        summary = db.query(f"""SELECT COUNT(*) connections,COUNT(DISTINCT ip) unique_ips,
            COALESCE(SUM(decision='block'),0) blocked,COALESCE(SUM(decision='unknown'),0) unknown_count,
            COUNT(DISTINCT CASE WHEN country_code<>'ZZ' THEN country_code END) countries FROM fm_events WHERE {clause}""",args)[0]
        countries = db.query(f"""SELECT country_code,MAX(country) country,COUNT(*) connections,
            COUNT(DISTINCT ip) unique_ips,SUM(decision='block') blocked
            FROM fm_events WHERE {clause} GROUP BY country_code ORDER BY connections DESC""",args)
        services = db.query(f"""SELECT service,COUNT(*) connections,SUM(decision='block') blocked
            FROM fm_events WHERE {clause} GROUP BY service ORDER BY connections DESC LIMIT 10""",args)
        trend_sql=f"""SELECT DATE_FORMAT(occurred_at,'%Y-%m-%dT%H:00:00Z') hour,
            COUNT(*) connections,SUM(decision='block') blocked FROM fm_events
            WHERE {clause} GROUP BY hour ORDER BY hour"""
        if not ip and not decision:
            lower,upper=window(start,end)
            full_start=lower.replace(minute=0,second=0,microsecond=0)
            if lower!=full_start:
                full_start+=timedelta(hours=1)
            full_end=upper.replace(minute=0,second=0,microsecond=0)
            if full_start<full_end:
                hourly_clause,hourly_args="hour>=%s AND hour<%s",[full_start,full_end]
                for field,value in (("country_code",country),("service",service)):
                    if value:
                        hourly_clause+=f" AND {field}=%s"
                        hourly_args.append(value)
                trend=db.query(f"""SELECT DATE_FORMAT(hour,'%Y-%m-%dT%H:00:00Z') hour,
                    SUM(connections) connections,SUM(blocked) blocked FROM fm_hourly
                    WHERE {hourly_clause} GROUP BY hour ORDER BY hour""",hourly_args)
                # Partial boundary hours use exact event timestamps; middle hours use aggregates.
                edges=db.query(trend_sql.replace(f"WHERE {clause}",f"WHERE {clause} AND (occurred_at<%s OR occurred_at>=%s)"),[*args,full_start,full_end])
                trend=sorted(trend+edges,key=lambda row:row['hour'])
            else:
                trend=db.query(trend_sql,args)
        else:
            trend=db.query(trend_sql,args)
        lower,upper=window(start,end)
        by_hour={r['hour']:r for r in trend}
        trend=[]
        hour=lower.replace(minute=0,second=0,microsecond=0)
        while hour<upper:
            label=hour.strftime('%Y-%m-%dT%H:00:00Z')
            trend.append(by_hour.get(label,{'hour':label,'connections':0,'blocked':0}))
            hour+=timedelta(hours=1)
        summary["current_bans"] = db.query("SELECT COUNT(DISTINCT ip) n FROM fm_ban_current WHERE jail='firewall-docker'")[0]["n"]
        ban_countries=db.query("""SELECT COALESCE(p.country_code,'ZZ') country_code,
            MAX(p.country) country,COUNT(DISTINCT b.ip) current_bans
            FROM fm_ban_current b LEFT JOIN fm_profiles p ON p.ip=b.ip
            WHERE b.jail='firewall-docker' GROUP BY COALESCE(p.country_code,'ZZ')
            ORDER BY current_bans DESC""")
        return {"summary":summary,"countries":countries,"services":services,"trend":trend,
                "ban_countries":ban_countries,
                "health":db.query("SELECT * FROM fm_health"),"generated_at":utcnow(),
                "demo":cfg.get("DASHBOARD_DEMO_MODE","false").lower()=="true"}

    @app.get("/api/ips")
    def ips(start:str="",end:str="",country:str="",service:str="",ip:str="",decision:str="",
            page:int=Query(1,ge=1,le=100000),current=Depends(authenticated)):
        clause,args = where(start,end,country,service,ip,decision)
        total = db.query(f"SELECT COUNT(DISTINCT ip) n FROM fm_events WHERE {clause}",args)[0]["n"]
        rows = db.query(f"""SELECT ip,MAX(occurred_at) last_seen,COUNT(*) connections,
            SUM(decision='block') blocked FROM fm_events WHERE {clause}
            GROUP BY ip ORDER BY last_seen DESC,ip LIMIT 25 OFFSET %s""",[*args,(page-1)*25])
        if rows:
            addresses=[r['ip'] for r in rows]
            slots=','.join(['%s']*len(addresses))
            profiles={r['ip']:r for r in db.query(f"SELECT * FROM fm_profiles WHERE ip IN ({slots})",addresses)}
            overrides={r['ip']:r for r in db.query(f"SELECT * FROM fm_overrides WHERE ip IN ({slots}) AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP())",addresses)}
            jails=db.query(f"SELECT * FROM fm_ban_current WHERE ip IN ({slots})",addresses)
            for row in rows:
                profile=profiles.get(row['ip'],{})
                row.update({k:v for k,v in profile.items() if k not in ('first_seen','last_seen')})
                row['override']=[overrides[row['ip']]] if row['ip'] in overrides else []
                row['jails']=[j for j in jails if j['ip']==row['ip']]
        return {"items":rows,"total":total,"page":page}

    def valid_ip(ip):
        try:
            return canonical_ip(ip)
        except ValueError:
            raise HTTPException(422,"IP 地址无效")

    @app.get("/api/ip/{ip}")
    def details(ip:str,current=Depends(authenticated)):
        ip = valid_ip(ip)
        return {"ip":ip,"profile":db.query("SELECT * FROM fm_profiles WHERE ip=%s",(ip,)),
            "override":db.query("SELECT * FROM fm_overrides WHERE ip=%s",(ip,)),
            "jails":db.query("SELECT * FROM fm_ban_current WHERE ip=%s",(ip,)),
            "events":db.query("SELECT * FROM fm_events WHERE ip=%s ORDER BY occurred_at DESC,id DESC LIMIT 50",(ip,)),
            "commands":db.query("SELECT * FROM fm_commands WHERE ip=%s ORDER BY id DESC LIMIT 20",(ip,)),
            "bans":db.query("SELECT * FROM fm_ban_events WHERE ip=%s ORDER BY id DESC LIMIT 50",(ip,)),
            "audit":db.query("SELECT * FROM fm_audit WHERE ip=%s ORDER BY id DESC LIMIT 20",(ip,))}

    @app.put("/api/ip/{ip}/policy")
    def policy(ip:str,body:Policy,current=Depends(authenticated)):
        import ipaddress
        ip = valid_ip(ip)
        if not ipaddress.ip_address(ip).is_global:
            raise HTTPException(422,"仅允许管理公网 IP")
        if body.mode not in {"allow","block","auto"} or not body.reason.strip():
            raise HTTPException(422,"请选择有效策略并填写原因")
        version = secrets.token_hex(16)
        expires = utcnow()+timedelta(hours=body.duration_hours) if body.duration_hours and body.mode!="auto" else None
        with db.transaction() as (_,cur):
            Store.lock_ip(cur,ip)
            cur.execute("SELECT * FROM fm_overrides WHERE ip=%s FOR UPDATE",(ip,))
            before = cur.fetchone()
            if body.mode == "auto":
                cur.execute("DELETE FROM fm_overrides WHERE ip=%s",(ip,))
            else:
                cur.execute("""INSERT INTO fm_overrides VALUES (%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP())
                    ON DUPLICATE KEY UPDATE mode=VALUES(mode),expires_at=VALUES(expires_at),
                    actor=VALUES(actor),reason=VALUES(reason),version=VALUES(version),updated_at=UTC_TIMESTAMP()""",
                    (ip,body.mode,expires,current["username"],body.reason.strip(),version))
            cur.execute("UPDATE fm_commands SET status='superseded',updated_at=UTC_TIMESTAMP() WHERE ip=%s AND status IN ('pending','failed')",(ip,))
            cur.execute("""INSERT INTO fm_commands (ip,action,version,created_at,updated_at)
                VALUES (%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP())""",(ip,body.mode,version if body.mode!="auto" else None))
            command = cur.lastrowid
            cur.execute("""INSERT INTO fm_audit (actor,ip,action,reason,before_value,after_value,command_id,occurred_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP())""",(current["username"],ip,body.mode,body.reason.strip(),
                json.dumps(before,default=str,ensure_ascii=False),json.dumps({"mode":body.mode,"expires_at":expires},default=str),command))
        return {"command_id":command,"status":"pending","expires_at":expires}

    @app.get("/api/policies")
    def policies(ip:str="",page:int=Query(1,ge=1,le=100000),current=Depends(authenticated)):
        clause,args=(" WHERE ip=%s",[valid_ip(ip)]) if ip else ("",[])
        return {"items":db.query(f"SELECT * FROM fm_overrides{clause} ORDER BY updated_at DESC,ip LIMIT 25 OFFSET %s",[*args,(page-1)*25]),
            "total":db.query(f"SELECT COUNT(*) n FROM fm_overrides{clause}",args)[0]["n"]}

    @app.get("/api/bans")
    def bans(ip:str="",page:int=Query(1,ge=1,le=100000),current=Depends(authenticated)):
        clause,args=(" WHERE ip=%s",[valid_ip(ip)]) if ip else ("",[])
        return {"items":db.query(f"SELECT * FROM fm_ban_current{clause} ORDER BY jail,ip LIMIT 25 OFFSET %s",[*args,(page-1)*25]),
            "total":db.query(f"SELECT COUNT(*) n FROM fm_ban_current{clause}",args)[0]["n"]}

    @app.get("/api/history")
    def history(kind:str="bans",ip:str="",page:int=Query(1,ge=1,le=100000),current=Depends(authenticated)):
        table = {"bans":"fm_ban_events","audit":"fm_audit","commands":"fm_commands"}.get(kind)
        if table is None:
            raise HTTPException(422,"记录类型无效")
        clause,args = (" WHERE ip=%s",[valid_ip(ip)]) if ip else ("",[])
        return {"items":db.query(f"SELECT * FROM {table}{clause} ORDER BY id DESC LIMIT 25 OFFSET %s",[*args,(page-1)*25]),
            "total":db.query(f"SELECT COUNT(*) n FROM {table}{clause}",args)[0]["n"]}

    assets = Path(__file__).parent/"frontend"/"dist"
    if (assets/"assets").exists():
        app.mount("/assets",StaticFiles(directory=assets/"assets"),name="assets")

    @app.get("/")
    def index():
        if not (assets/"index.html").exists():
            raise HTTPException(503,"请先构建前端 npm run build")
        return FileResponse(assets/"index.html")

    return app


# Uvicorn factory: env validation happens at startup, not at import/test collection.
def app_factory():
    return create_app()

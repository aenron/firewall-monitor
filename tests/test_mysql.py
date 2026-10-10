"""Opt-in integration tests, isolated temporary database; fail2ban is always simulated."""
import hashlib
import os
import uuid
from datetime import timedelta, datetime

import mysql.connector
import pytest
from fastapi.testclient import TestClient
from dashboard import create_app
from firewall import Firewall, Settings
from host_agent import Agent
from storage import Store, utcnow
from test_security import CONFIG, authenticate

pytestmark=pytest.mark.skipif(os.getenv('RUN_MYSQL_TESTS')!='1',reason='Set RUN_MYSQL_TESTS=1 and MYSQL_* for isolated integration DB')


@pytest.fixture
def system(monkeypatch,tmp_path):
    config=Store().config
    base=dict(config);base.pop('database')
    dbname='fm_test_'+uuid.uuid4().hex
    connection=mysql.connector.connect(**base)
    cur=connection.cursor()
    cur.execute(f'CREATE DATABASE `{dbname}` CHARACTER SET utf8mb4')
    config['database']=dbname
    monkeypatch.setenv('MYSQL_DATABASE',dbname)
    monkeypatch.setenv('FIREWALL_LOG_DIR',str(tmp_path))
    monitor=Firewall(Settings.from_env())
    monitor.store=Store(config)
    monitor.init_db()
    store=monitor.store
    client=TestClient(create_app(store,CONFIG))
    csrf=authenticate(client)
    # Only an in-memory set is modified. No real host bans occur in these tests.
    bans={'firewall-docker':set(),'sshd':{'8.8.8.8'}}
    calls=[]
    def fake_f2b(*args):
        calls.append(args)
        if args==('status',):return 'Jail list: firewall-docker, sshd'
        if args[0]=='get':return ' '.join(sorted(bans[args[1]]))
        assert args[1]=='firewall-docker'
        if args[2]=='banip':bans[args[1]].add(args[3])
        else:bans[args[1]].discard(args[3])
        return '1'
    monkeypatch.setattr('host_agent.f2b',fake_f2b)
    info={'country':'美国','region':'加利福尼亚','city':'Mountain View','org':'test','geo_updated_at':utcnow()}
    monkeypatch.setattr(monitor,'lookup',lambda ip,cursor:(info,False))
    try:
        yield monitor,store,client,{'X-CSRF-Token':csrf},Agent(store),bans,calls
    finally:
        client.close()
        assert dbname.startswith('fm_test_') and len(dbname)==40
        cur.execute(f'DROP DATABASE `{dbname}`')
        cur.close();connection.close()


def test_event_dedup_stats_cursor_and_automatic_ban(system):
    monitor,store,client,headers,agent,bans,calls=system
    key=hashlib.sha256(b'event').hexdigest()
    for _ in range(2):monitor.process('8.8.8.8','test-service',key,utcnow(),'container',123)
    assert store.query('SELECT COUNT(*) n FROM fm_events')[0]['n']==1
    assert store.query('SELECT counter FROM ip_info')[0]['counter']==1
    assert store.query('SELECT connections FROM fm_hourly')[0]['connections']==1
    assert store.query('SELECT since_second FROM fm_cursors')[0]['since_second']==123
    agent.tick()
    assert '8.8.8.8' in bans['firewall-docker']
    data=client.get('/api/overview').json()
    assert data['summary']['unique_ips']==1
    assert data['countries'][0]['country_code']=='US'
    assert sum(int(row['connections']) for row in data['trend'])==1
    for row in data['trend']:
        datetime.fromisoformat(row['hour'].replace('Z','+00:00'))
    assert client.get('/api/ips').json()['items'][0]['jails']


def test_allow_cancels_stale_ban_and_does_not_unban_sshd(system):
    monitor,store,client,headers,agent,bans,calls=system
    monitor.process('8.8.8.8','test-service')
    response=client.put('/api/ip/8.8.8.8/policy',headers=headers,json={'mode':'allow','duration_hours':1,'reason':'trusted source'})
    assert response.status_code==200
    agent.tick()
    monitor.process('8.8.8.8','test-service')
    agent.tick()
    assert '8.8.8.8' not in bans['firewall-docker']
    assert '8.8.8.8' in bans['sshd']
    assert not any(c[:3]==('set','sshd','unbanip') for c in calls)
    assert store.query('SELECT decision FROM fm_events ORDER BY id DESC LIMIT 1')[0]['decision']=='allow'
    assert store.query('SELECT COUNT(*) n FROM fm_audit')[0]['n']==1


def test_expiry_restores_auto_even_when_old_command_pending(system):
    monitor,store,client,headers,agent,bans,calls=system
    monitor.process('8.8.8.8','test-service')
    client.put('/api/ip/8.8.8.8/policy',headers=headers,json={'mode':'allow','reason':'temporary'})
    with store.transaction() as (_,cur):cur.execute('UPDATE fm_overrides SET expires_at=%s',(utcnow()-timedelta(seconds=1),))
    agent.tick()
    assert '8.8.8.8' in bans['firewall-docker']
    assert not store.query('SELECT * FROM fm_overrides')
    assert store.query("SELECT COUNT(*) n FROM fm_audit WHERE actor='system'")[0]['n']==1


def test_block_restore_and_unknown_geo_record(system,monkeypatch):
    monitor,store,client,headers,agent,bans,calls=system
    client.put('/api/ip/1.1.1.1/policy',headers=headers,json={'mode':'block','duration_hours':0,'reason':'manual'})
    agent.tick();assert '1.1.1.1' in bans['firewall-docker']
    client.put('/api/ip/1.1.1.1/policy',headers=headers,json={'mode':'auto','reason':'restore'})
    agent.tick();assert '1.1.1.1' not in bans['firewall-docker']
    def failed_lookup(*args):raise ValueError('geo failure')
    monkeypatch.setattr(monitor,'lookup',failed_lookup)
    monitor.process('1.1.1.1','service')
    row=store.query('SELECT * FROM fm_events')[0]
    assert row['decision']=='unknown' and row['country_code']=='ZZ'
    assert not store.query("SELECT * FROM fm_commands WHERE status='pending'")


def test_failed_execution_is_not_marked_done(system,monkeypatch):
    monitor,store,client,headers,agent,bans,calls=system
    client.put('/api/ip/8.8.8.8/policy',headers=headers,json={'mode':'block','reason':'test failure'})
    def fail(*args):raise RuntimeError('unavailable')
    monkeypatch.setattr('host_agent.f2b',fail)
    command=store.query('SELECT * FROM fm_commands')[0]
    agent.execute(command)
    row=store.query('SELECT * FROM fm_commands')[0]
    assert row['status']=='failed' and row['attempts']==1
    assert not store.query('SELECT * FROM fm_ban_current')


def test_restore_without_legacy_table(system):
    monitor,store,client,headers,agent,bans,calls=system
    with store.transaction() as (_,cur):
        cur.execute('DROP TABLE ip_info')
    response=client.put('/api/ip/1.1.1.1/policy',headers=headers,json={'mode':'auto','reason':'fresh installation'})
    assert response.status_code==200
    agent.tick()
    assert store.query('SELECT status FROM fm_commands')[0]['status']=='done'


def test_legacy_migration_preserves_counts_without_fabricating_events(system):
    monitor,store,client,headers,agent,bans,calls=system
    with store.transaction() as (_,cur):
        cur.execute("INSERT INTO ip_info (ip_address,country,city,counter,access_name) VALUES ('8.8.8.8','美国','Mountain View',13,'old-service')")
        cur.execute("DELETE FROM fm_meta WHERE name='schema_version'")
    store.migrate();store.migrate()
    row=store.query("SELECT * FROM fm_profiles WHERE ip='8.8.8.8'")[0]
    assert row['legacy_counter']==13 and row['country_code']=='US'
    assert not store.query('SELECT * FROM fm_events')

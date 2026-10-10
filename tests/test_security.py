import pytest
from fastapi.testclient import TestClient
from dashboard import create_app
from storage import canonical_ip, country_code

CONFIG = {"DASHBOARD_ADMIN_USERNAME":"operator","DASHBOARD_ADMIN_PASSWORD":"test-password-12345",
          "DASHBOARD_SESSION_SECRET":"test-session-secret-"*3}


class NoDatabase:
    def query(self,*args):
        raise AssertionError("Unauthenticated requests must not access database")


@pytest.fixture
def client():
    return TestClient(create_app(NoDatabase(),CONFIG))


def authenticate(client):
    response=client.post('/api/login',json={"username":"operator","password":"test-password-12345"})
    assert response.status_code==200
    return response.json()['csrf']


@pytest.mark.parametrize('path',['/api/overview','/api/ips','/api/history','/api/policies','/api/ip/8.8.8.8'])
def test_requires_authentication(client,path):
    assert client.get(path).status_code==401


def test_cookie_csrf_logout_and_revocation(client):
    csrf=authenticate(client)
    assert client.get('/api/session').status_code==200
    assert client.post('/api/logout').status_code==403
    assert client.post('/api/logout',headers={'X-CSRF-Token':'wrong'}).status_code==403
    assert client.post('/api/logout',headers={'X-CSRF-Token':csrf}).status_code==200
    assert client.get('/api/session').status_code==401


def test_credentials_origin_and_rate_limit(client):
    assert client.post('/api/login',headers={'Origin':'https://evil.example'},json={'username':'operator','password':'test-password-12345'}).status_code==403
    for _ in range(5):
        assert client.post('/api/login',json={'username':'operator','password':'incorrect'}).status_code==401
    assert client.post('/api/login',json={'username':'operator','password':'test-password-12345'}).status_code==429


def test_invalid_ip_mode_and_private_addresses(client):
    csrf=authenticate(client)
    headers={'X-CSRF-Token':csrf}
    assert client.put('/api/ip/8.8.8.8/policy',json={'mode':'block','reason':'test'}).status_code==403
    for ip in ['127.0.0.1','192.168.1.1','not-an-ip','8.8.8.8;echo']:
        assert client.put(f'/api/ip/{ip}/policy',headers=headers,json={'mode':'block','reason':'test'}).status_code==422
    assert client.put('/api/ip/8.8.8.8/policy',headers=headers,json={'mode':'shell','reason':'test'}).status_code==422


def test_weak_startup_configuration_rejected():
    with pytest.raises(ValueError):
        create_app(NoDatabase(),{'DASHBOARD_ADMIN_USERNAME':'admin','DASHBOARD_ADMIN_PASSWORD':'short','DASHBOARD_SESSION_SECRET':'weak'})
    with pytest.raises(ValueError):
        create_app(NoDatabase(),{**CONFIG,'DASHBOARD_ADMIN_PASSWORD':'replace-with-at-least-12-characters'})


def test_country_and_ip_normalization():
    assert country_code('中国')=='CN'
    assert country_code('美国')=='US'
    assert country_code('United Kingdom')=='GB'
    assert country_code('没有这个国家')=='ZZ'
    assert canonical_ip('2001:4860:4860:0:0:0:0:8888')=='2001:4860:4860::8888'


def test_six_character_password_login():
    client=TestClient(create_app(NoDatabase(),{**CONFIG,'DASHBOARD_ADMIN_USERNAME':'zmj','DASHBOARD_ADMIN_PASSWORD':'Ab3dE9'}))
    response=client.post('/api/login',json={'username':'zmj','password':'Ab3dE9'})
    assert response.status_code==200
    assert response.json()['username']=='zmj'
    client.close()

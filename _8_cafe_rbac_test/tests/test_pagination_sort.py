"""목록 페이징·정렬 테스트 — 대시보드 20개씩 보기 + 컬럼 헤더 정렬.

기존 목록 API 는 `limit` 하나뿐이라 화면이 전부 한 번에 받아 그렸다. 기록이
쌓이면 표가 끝없이 길어지고, '오래된 것부터' 보거나 '심각도 높은 것부터' 보는
방법이 아예 없다. 그래서 서버가 `page·per_page·sort·order` 를 받고 **총 건수**를
함께 돌려준다(총 건수를 모르면 화면이 '마지막 페이지'를 그릴 수 없다).

여기서 특히 못 박아 두는 두 가지 — 둘 다 눈에 잘 안 띄는 버그다:
  1) `severity` 는 글자순(Critical<High<Low<Medium)이 아니라 **심각도 서열**
     (Critical>High>Medium>Low)로 정렬된다.
  2) `created_at` 이 똑같은 행이 여러 개여도 페이지 경계에서 행이 겹치거나
     빠지지 않는다 — `id` 를 2차 정렬키로 붙여 고정한다.
"""
import re
from datetime import datetime, timedelta

BASE = datetime(2026, 10, 1, 9, 0, 0)
SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


def seed_incidents(application, n=25, same_time=False, student='lab'):
    from extensions import db
    from models import Incident
    with application.app_context():
        for i in range(n):
            db.session.add(Incident(
                title=f'ticket {i}', src_ip=f'203.0.113.{i + 1}',
                severity=SEVERITIES[i % 4], status='open' if i % 2 == 0 else 'closed',
                event_count=i, student=student,
                created_at=BASE if same_time else BASE + timedelta(minutes=i)))
        db.session.commit()


def seed_events(application, n=25, student='lab'):
    from extensions import db
    from models import SecurityEvent
    with application.app_context():
        for i in range(n):
            db.session.add(SecurityEvent(
                student=student, src_ip=f'198.51.100.{i + 1}', fail_count=i,
                decision='deny' if i % 2 == 0 else 'allow', severity=SEVERITIES[i % 4],
                reason=f'seed {i}', created_at=BASE + timedelta(minutes=i)))
        db.session.commit()


def get(client, path):
    res = client.get(path)
    assert res.status_code == 200, res.get_data(as_text=True)
    return res.get_json()


# ─────────────────────────── 페이징 ───────────────────────────

def test_default_page_size_is_20(app_client):
    app, client = app_client
    seed_incidents(app, 25)
    d = get(client, '/api/security/incidents')
    assert len(d['incidents']) == 20
    assert d['total'] == 25
    assert d['total_pages'] == 2


def test_last_page_has_remainder(app_client):
    app, client = app_client
    seed_incidents(app, 25)
    d = get(client, '/api/security/incidents?page=2')
    assert len(d['incidents']) == 5


def test_page_beyond_last_is_empty_but_200(app_client):
    app, client = app_client
    seed_incidents(app, 25)
    d = get(client, '/api/security/incidents?page=99')
    assert d['incidents'] == []
    assert d['page'] == 99


def test_empty_table_reports_one_page(app_client):
    _app, client = app_client
    d = get(client, '/api/security/incidents')
    assert d['total'] == 0
    assert d['total_pages'] == 1


def test_per_page_capped_at_100(app_client):
    app, client = app_client
    seed_incidents(app, 25)
    d = get(client, '/api/security/incidents?per_page=500')
    assert d['per_page'] == 100


def test_page_zero_or_negative_falls_back_to_first(app_client):
    app, client = app_client
    seed_incidents(app, 5)
    assert get(client, '/api/security/incidents?page=0')['page'] == 1
    assert get(client, '/api/security/incidents?page=-3')['page'] == 1


def test_legacy_limit_still_works(app_client):
    app, client = app_client
    seed_incidents(app, 25)
    d = get(client, '/api/security/incidents?limit=5')
    assert d['per_page'] == 5
    assert len(d['incidents']) == 5


# ─────────────────────────── 정렬 ───────────────────────────

def test_created_at_desc_is_default(app_client):
    app, client = app_client
    seed_incidents(app, 5)
    d = get(client, '/api/security/incidents?per_page=100')
    assert d['incidents'][0]['title'] == 'ticket 4'


def test_created_at_asc(app_client):
    app, client = app_client
    seed_incidents(app, 5)
    d = get(client, '/api/security/incidents?sort=created_at&order=asc')
    assert d['incidents'][0]['title'] == 'ticket 0'


def test_severity_sorted_by_rank_not_alphabet(app_client):
    app, client = app_client
    seed_incidents(app, 8)
    d = get(client, '/api/security/incidents?sort=severity&order=desc&per_page=100')
    sevs = [i['severity'] for i in d['incidents']]
    assert sevs[0] == 'Critical'
    assert sevs[-1] == 'Low'


def test_sort_by_event_count(app_client):
    app, client = app_client
    seed_incidents(app, 10)
    d = get(client, '/api/security/incidents?sort=event_count&order=asc')
    counts = [i['event_count'] for i in d['incidents']]
    assert counts == sorted(counts)


def test_invalid_sort_returns_400(app_client):
    app, client = app_client
    seed_incidents(app, 5)
    r = client.get('/api/security/incidents?sort=password')
    assert r.status_code == 400


def test_invalid_order_returns_400(app_client):
    app, client = app_client
    seed_incidents(app, 5)
    r = client.get('/api/security/incidents?order=sideways')
    assert r.status_code == 400


def test_pages_do_not_overlap_when_created_at_identical(app_client):
    app, client = app_client
    seed_incidents(app, 10, same_time=True)
    p1 = get(client, '/api/security/incidents?per_page=5&page=1&sort=created_at&order=asc')
    p2 = get(client, '/api/security/incidents?per_page=5&page=2&sort=created_at&order=asc')
    ids1 = {i['id'] for i in p1['incidents']}
    ids2 = {i['id'] for i in p2['incidents']}
    assert ids1.isdisjoint(ids2)
    assert len(ids1 | ids2) == 10


def test_severity_sort_is_also_stable_across_pages(app_client):
    app, client = app_client
    seed_incidents(app, 12, same_time=True)
    p1 = get(client, '/api/security/incidents?per_page=6&page=1&sort=severity&order=desc')
    p2 = get(client, '/api/security/incidents?per_page=6&page=2&sort=severity&order=desc')
    ids1 = {i['id'] for i in p1['incidents']}
    ids2 = {i['id'] for i in p2['incidents']}
    assert ids1.isdisjoint(ids2)


# ─────────────────────────── 필터 ───────────────────────────

def test_filter_narrows_total_not_just_page(app_client):
    app, client = app_client
    seed_incidents(app, 25)   # status 는 open/closed 번갈아 — 대략 절반
    d = get(client, '/api/security/incidents?status=open')
    assert d['total'] < 25


def test_severity_filter(app_client):
    app, client = app_client
    seed_incidents(app, 8)
    d = get(client, '/api/security/incidents?severity=Critical')
    assert all(i['severity'] == 'Critical' for i in d['incidents'])


def test_filter_sort_and_page_together(app_client):
    app, client = app_client
    seed_incidents(app, 25, student='a')
    seed_incidents(app, 5, student='b')
    d = get(client, '/api/security/incidents?student=b&sort=event_count&order=asc')
    assert d['total'] == 5


# ─────────────────────────── 보안 이벤트 쪽도 동일 ───────────────────────────

def test_events_paging(app_client):
    app, client = app_client
    seed_events(app, 25)
    d = get(client, '/api/security/events')
    assert len(d['events']) == 20
    assert d['total'] == 25


def test_events_sort_by_fail_count_and_severity(app_client):
    app, client = app_client
    seed_events(app, 10)
    d = get(client, '/api/security/events?sort=fail_count&order=desc')
    counts = [e['fail_count'] for e in d['events']]
    assert counts == sorted(counts, reverse=True)


def test_events_decision_filter_with_total(app_client):
    app, client = app_client
    seed_events(app, 10)
    d = get(client, '/api/security/events?decision=deny&per_page=100')
    assert all(e['decision'] == 'deny' for e in d['events'])
    assert d['total'] < 10


def test_events_legacy_limit_still_works(app_client):
    app, client = app_client
    seed_events(app, 10)
    d = get(client, '/api/security/events?limit=3')
    assert len(d['events']) == 3


def test_events_invalid_sort_returns_400(app_client):
    app, client = app_client
    seed_events(app, 5)
    assert client.get('/api/security/events?sort=nope').status_code == 400


# ─────────────────────────── 화면(대시보드) ───────────────────────────

def test_dashboard_page_has_pager_and_sortable_headers(app_client):
    _app, client = app_client
    r = client.get('/security')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'incident-pager' in html
    assert 'event-pager' in html
    assert 'data-sort="created_at"' in html
    assert 'bindSortHeaders(' in html


def test_dashboard_sort_columns_match_server_whitelist(app_client):
    _app, client = app_client
    r = client.get('/security')
    html = r.get_data(as_text=True)
    from controllers.security_controller import _EVENT_SORTS, _INCIDENT_SORTS

    used = set(re.findall(r'data-sort="([a-z_]+)"', html))
    allowed = set(_EVENT_SORTS) | set(_INCIDENT_SORTS)
    assert used <= allowed

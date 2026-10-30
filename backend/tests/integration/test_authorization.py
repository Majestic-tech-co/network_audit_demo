"""
Authorization and tenant-isolation tests (real app, real DB).

These encode the security rules of the application:
  * every API route requires authentication unless explicitly public,
  * each route enforces its minimum role,
  * an organization can never see or modify another organization's data.
"""
import uuid

import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute

from app.main import app
from tests.integration.conftest import PASSWORD, bearer

AUTH_DEPENDENCIES = {
    "get_current_user", "get_current_it_user", "get_current_it_writer",
    "get_current_admin", "_authenticate_agent",
}
PUBLIC_ROUTES = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/refresh"),
    ("POST", "/api/auth/logout"),  # authenticated by possession of the refresh token itself
    ("GET", "/api/auth/login-config"),
    ("GET", "/api/{path:path}"),  # 404 catch-all
}
# WebSockets authenticate inside the handler (JWT in query string); a new one must be reviewed.
KNOWN_WEBSOCKETS = {"/ws/{org_id}", "/ws/capture/{session_id}"}


def _dependency_names(dependant) -> set:
    names = set()
    for sub in dependant.dependencies:
        if sub.call is not None:
            names.add(getattr(sub.call, "__name__", type(sub.call).__name__))
        names |= _dependency_names(sub)
    return names


def _all_routes():
    """
    Every route of every router module in app.api.routes (discovered automatically, so a new
    route file is covered without touching this test). Newer FastAPI no longer exposes a flat
    app.routes list, so we walk the routers themselves.
    """
    import importlib
    import pkgutil

    from fastapi import APIRouter

    import app.api.routes as pkg

    seen, routes = set(), []
    for info in pkgutil.iter_modules(pkg.__path__):
        module = importlib.import_module(f"{pkg.__name__}.{info.name}")
        for obj in vars(module).values():
            if isinstance(obj, APIRouter):
                for route in obj.routes:
                    if id(route) not in seen:
                        seen.add(id(route))
                        routes.append(route)
    return routes


def test_route_discovery_is_not_vacuous():
    routes = _all_routes()
    http = [r for r in routes if isinstance(r, APIRoute)]
    assert len(http) >= 50, f"only found {len(http)} HTTP routes - route discovery is broken"
    # The app must actually serve what we discovered (guards against drift between the two views)
    served = {(m, p) for p, ops in app.openapi()["paths"].items() for m in (k.upper() for k in ops)}
    discovered = {(m, r.path) for r in http for m in r.methods - {"HEAD", "OPTIONS"} if r.include_in_schema}
    assert discovered <= served


def test_every_api_route_requires_authentication():
    unprotected = []
    for route in _all_routes():
        if isinstance(route, APIRoute):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                if (method, route.path) in PUBLIC_ROUTES:
                    continue
                if not (_dependency_names(route.dependant) & AUTH_DEPENDENCIES):
                    unprotected.append((method, route.path))
    assert not unprotected, f"Routes without an auth dependency: {unprotected}"


def test_websocket_endpoints_are_known():
    ws = {r.path for r in _all_routes() if isinstance(r, APIWebSocketRoute)}
    assert ws == KNOWN_WEBSOCKETS, "New WebSocket endpoint: add authentication + update KNOWN_WEBSOCKETS"


# ── Role matrix ────────────────────────────────────────────────────

RANK = {"end_user": 0, "viewer": 1, "engineer": 2, "admin": 3}
ID = str(uuid.uuid4())
SCAN_BODY = {"scan_type": "port_scan", "target": "192.168.1.1"}
SCHEDULE_BODY = {"name": "n", "scan_type": "port_scan", "target": "192.168.1.0/24", "cron_expression": "0 * * * *"}
USER_BODY = {"email": "new@example.com", "username": "new", "password": "longenough1"}

# (method, path, json body, minimum role, safe_to_call_when_allowed)
# safe=False: handler needs Redis/network, so only the denial is asserted.
ENDPOINTS = [
    ("GET", "/api/scans", None, "viewer", True),
    ("GET", "/api/findings", None, "viewer", True),
    ("GET", "/api/devices", None, "viewer", True),
    ("GET", "/api/schedules", None, "viewer", True),
    ("GET", "/api/users", None, "viewer", True),
    ("GET", "/api/settings", None, "viewer", True),
    ("GET", "/api/settings/organization", None, "viewer", True),
    ("GET", "/api/dashboard/stats", None, "viewer", True),
    ("GET", "/api/capture/interfaces", None, "viewer", False),
    ("GET", "/api/topology/status", None, "viewer", False),
    ("POST", "/api/scans", SCAN_BODY, "engineer", True),
    ("POST", "/api/schedules", SCHEDULE_BODY, "engineer", True),
    ("POST", f"/api/findings/{ID}/remediate", None, "engineer", True),
    ("PATCH", f"/api/findings/{ID}", {}, "engineer", True),
    ("DELETE", f"/api/scans/{ID}", None, "engineer", True),
    ("DELETE", f"/api/schedules/{ID}", None, "engineer", True),
    ("POST", "/api/topology/scan", None, "engineer", True),
    ("POST", "/api/capture/start", {"interface": "eth0"}, "engineer", False),
    ("POST", f"/api/capture/{ID}/stop", None, "engineer", False),
    ("GET", f"/api/capture/{ID}/export", None, "engineer", False),
    ("POST", "/api/users", USER_BODY, "admin", True),
    ("PATCH", f"/api/users/{ID}", {"username": "x"}, "admin", True),
    ("GET", "/api/settings/ldap", None, "admin", True),
    ("PUT", "/api/settings/ldap", {}, "admin", True),
    ("GET", "/api/settings/unifi", None, "admin", True),
    ("POST", "/api/settings/test-ai", None, "admin", False),
    ("GET", "/api/agent/download/linux", None, "admin", True),
]


@pytest.mark.parametrize("method,path,body,min_role,safe", ENDPOINTS)
async def test_role_matrix(client, world, method, path, body, min_role, safe):
    r = await client.request(method, path, json=body)
    assert r.status_code == 401, f"{method} {path} accessible without a token"

    for role, user in [("end_user", world.users.end_user), ("viewer", world.users.viewer),
                       ("engineer", world.users.engineer), ("admin", world.users.admin)]:
        allowed = RANK[role] >= RANK[min_role]
        if allowed and not safe:
            continue
        r = await client.request(method, path, json=body, headers=bearer(user))
        if allowed:
            assert r.status_code not in (401, 403), f"{role} wrongly denied {method} {path}: {r.status_code}"
        else:
            assert r.status_code == 403, f"{role} should be denied {method} {path}, got {r.status_code}"


async def test_inactive_user_token_is_rejected(client, world, session_factory):
    from sqlalchemy import update
    from app.models.models import User
    async with session_factory() as db:
        await db.execute(update(User).where(User.id == world.users.admin.id).values(is_active=False))
        await db.commit()
    r = await client.get("/api/scans", headers=bearer(world.users.admin))
    assert r.status_code == 401


# ── Tenant isolation ───────────────────────────────────────────────

async def test_foreign_resources_are_invisible(client, world):
    h = bearer(world.users.admin)
    f = world.foreign
    cases = [
        ("GET", f"/api/scans/{f.scan.id}", None),
        ("GET", f"/api/scans/{f.scan.id}/findings", None),
        ("DELETE", f"/api/scans/{f.scan.id}", None),
        ("GET", f"/api/scans/{f.scan.id}/report.json", None),
        ("GET", f"/api/scans/{f.scan.id}/report.pdf", None),
        ("GET", f"/api/findings/{f.finding.id}", None),
        ("PATCH", f"/api/findings/{f.finding.id}", {"notes": "hijack"}),
        ("POST", f"/api/findings/{f.finding.id}/remediate", None),
        ("GET", f"/api/devices/{f.device.id}", None),
        ("GET", f"/api/devices/{f.device.id}/findings", None),
        ("PATCH", f"/api/schedules/{f.schedule.id}?is_active=false", None),
        ("DELETE", f"/api/schedules/{f.schedule.id}", None),
    ]
    for method, path, body in cases:
        r = await client.request(method, path, json=body, headers=h)
        assert r.status_code == 404, f"{method} {path} leaked/modified foreign data: {r.status_code}"


async def test_foreign_user_cannot_be_modified(client, world):
    r = await client.patch(f"/api/users/{world.users.b_admin.id}", json={"role": "end_user"},
                           headers=bearer(world.users.admin))
    assert r.status_code == 404


async def test_lists_only_contain_own_org(client, world):
    h = bearer(world.users.admin)
    for path in ("/api/scans", "/api/findings", "/api/devices", "/api/schedules"):
        r = await client.get(path, headers=h)
        body = r.json()
        items = body["items"] if isinstance(body, dict) else body
        assert items == [], f"{path} returned another organization's rows"
    users = (await client.get("/api/users", headers=h)).json()
    assert {u["organization_id"] for u in users} == {str(world.org_a.id)}


async def test_foreign_assignee_rejected(client, world, session_factory):
    """Assigning a finding to a user of another org must fail."""
    from app.models.models import Finding, FindingStatus, Severity, Device, Scan, ScanType
    async with session_factory() as db:
        dev = Device(organization_id=world.org_a.id, ip_address="10.1.1.1")
        db.add(dev)
        await db.flush()
        scan = Scan(organization_id=world.org_a.id, scan_type=ScanType.PORT_SCAN, target="10.1.1.1")
        db.add(scan)
        await db.flush()
        fnd = Finding(organization_id=world.org_a.id, scan_id=scan.id, device_id=dev.id,
                      finding_type="open_port", severity=Severity.LOW, status=FindingStatus.OPEN,
                      title="t", description="d")
        db.add(fnd)
        await db.commit()
        fid = fnd.id
    r = await client.patch(f"/api/findings/{fid}", json={"assigned_to_id": str(world.users.b_admin.id)},
                           headers=bearer(world.users.engineer))
    assert r.status_code == 400


# ── Authentication flows ───────────────────────────────────────────

async def test_login_and_lockout(client, world):
    email = world.users.admin.email
    ok = await client.post("/api/auth/login", data={"username": email, "password": PASSWORD})
    assert ok.status_code == 200

    for _ in range(5):
        bad = await client.post("/api/auth/login", data={"username": email, "password": "wrong-password"})
        assert bad.status_code == 401
    locked = await client.post("/api/auth/login", data={"username": email, "password": PASSWORD})
    assert locked.status_code == 429  # correct password refused while locked
    assert "retry-after" in locked.headers


async def test_unknown_user_gets_same_error_as_wrong_password(client, world):
    a = await client.post("/api/auth/login", data={"username": "nobody@example.com", "password": "whatever123"})
    b = await client.post("/api/auth/login", data={"username": world.users.viewer.email, "password": "whatever123"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


async def test_registration_closed_once_users_exist(client, world):
    r = await client.post("/api/auth/register",
                          json={"email": "evil@example.com", "username": "evil", "password": "longenough1"})
    assert r.status_code == 403


async def test_first_registration_creates_admin(client):
    r = await client.post("/api/auth/register",
                          json={"email": "first@example.com", "username": "first", "password": "longenough1",
                                "organization_name": "Acme"})
    assert r.status_code == 201
    assert r.json()["user"]["role"] == "it_admin"
    again = await client.post("/api/auth/register",
                              json={"email": "second@example.com", "username": "second", "password": "longenough1"})
    assert again.status_code == 403


async def test_refresh_token_cannot_be_used_as_access_token(client, world):
    login = await client.post("/api/auth/login", data={"username": world.users.admin.email, "password": PASSWORD})
    refresh = login.json()["refresh_token"]
    r = await client.get("/api/scans", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 401


async def test_error_responses_do_not_echo_input(client, world):
    r = await client.post("/api/users", json={"email": "a@b.test", "username": "u", "password": "short"},
                          headers=bearer(world.users.admin))
    assert r.status_code == 422
    assert "short" not in r.text  # default FastAPI 422 would echo the submitted password


async def test_security_headers_present(client):
    r = await client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"

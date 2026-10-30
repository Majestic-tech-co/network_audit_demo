"""
Settings routes — AI provider config, org settings, LDAP configuration.
GET  /api/settings
PUT  /api/settings
POST /api/settings/test-ai
GET  /api/settings/ldap
PUT  /api/settings/ldap
POST /api/settings/ldap/test
GET  /api/settings/ldap/search?q=...
GET  /api/settings/organization
PUT  /api/settings/organization
POST /api/settings/organization/logo
DELETE /api/settings/organization/logo
"""
import asyncio
import structlog
import base64
from fastapi import Request, APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from app.core.limiter import limiter
from app.db.session import get_db
from app.models.models import Organization, User
from app.core.auth import get_current_admin, get_current_it_user
from app.core.security import encrypt, decrypt
from app.schemas.schemas import (
    OrgSettingsResponse, UpdateOrgSettingsRequest, AITestResponse,
    LDAPConfigRequest, LDAPConfigResponse, LDAPTestResponse,
    UniFiConfigRequest, UniFiConfigResponse, UniFiTestResponse,
    OrgProfileResponse, OrgProfileRequest,
)
from app.services.ai_providers.service import AIService
from app.services.ldap_service import LDAPService, ldap_service_from_org
from app.services.unifi_service import UniFiService

log = structlog.get_logger()
router = APIRouter(prefix="/api/settings", tags=["settings"])


async def _get_org(user: User, db: AsyncSession) -> Organization:
    result = await db.execute(select(Organization).where(Organization.id == user.organization_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


# ─── General settings ─────────────────────────────────────────────

@router.get("", response_model=OrgSettingsResponse)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    org = await _get_org(current_user, db)
    return OrgSettingsResponse(
        ai_provider=org.ai_provider,
        ai_model=org.ai_model,
        ai_ollama_url=org.ai_ollama_url or "http://ollama:11434",
        has_api_key=bool(org.ai_api_key_encrypted),
        virustotal_enabled=False,
        default_scan_target=None,
        ldap_enabled=org.ldap_enabled,
    )


@router.put("", response_model=OrgSettingsResponse)
async def update_settings(
    req: UpdateOrgSettingsRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    if req.ai_provider is not None:
        org.ai_provider = req.ai_provider
    if req.ai_model is not None:
        org.ai_model = req.ai_model
    if req.ai_api_key is not None:
        org.ai_api_key_encrypted = encrypt(req.ai_api_key) if req.ai_api_key else None
    if req.ai_ollama_url is not None:
        org.ai_ollama_url = req.ai_ollama_url
    await db.flush()
    return OrgSettingsResponse(
        ai_provider=org.ai_provider,
        ai_model=org.ai_model,
        ai_ollama_url=org.ai_ollama_url or "http://ollama:11434",
        has_api_key=bool(org.ai_api_key_encrypted),
        virustotal_enabled=False,
        default_scan_target=None,
        ldap_enabled=org.ldap_enabled,
    )


@router.post("/test-ai", response_model=AITestResponse)
@limiter.limit("5/minute")
async def test_ai_connection(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    api_key = decrypt(org.ai_api_key_encrypted) if org.ai_api_key_encrypted else None
    try:
        service = AIService(
            provider=org.ai_provider,
            api_key=api_key,
            model=org.ai_model,
            ollama_url=org.ai_ollama_url or "http://ollama:11434",
        )
        response = await service._adapter.generate_remediation(
            "Reply with exactly: 'NetAudit AI connection successful.' Nothing else."
        )
        return AITestResponse(
            success=True, provider=org.ai_provider,
            model=org.ai_model, response_preview=response[:100],
        )
    except Exception as e:
        # Provider errors can embed request details; log them, return a generic message.
        log.error("ai_test_failed", provider=str(org.ai_provider), error=type(e).__name__)
        return AITestResponse(
            success=False, provider=org.ai_provider,
            model=org.ai_model, error="Connection test failed. Check the provider, model and API key.",
        )


# ─── LDAP settings ────────────────────────────────────────────────

@router.get("/ldap", response_model=LDAPConfigResponse)
async def get_ldap_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    config = dict(org.ldap_config or {})
    # Never return decrypted password
    config.pop("bind_password", None)
    return LDAPConfigResponse(
        enabled=org.ldap_enabled,
        server=config.get("server", ""),
        base_dn=config.get("base_dn", ""),
        bind_dn=config.get("bind_dn", ""),
        has_bind_password=bool((org.ldap_config or {}).get("bind_password")),
        user_search_base=config.get("user_search_base", ""),
        user_filter=config.get("user_filter", "(sAMAccountName={username})"),
        email_attr=config.get("email_attr", "mail"),
        name_attr=config.get("name_attr", "displayName"),
        groups_attr=config.get("groups_attr", "memberOf"),
        role_mappings=config.get("role_mappings", {}),
        use_tls=config.get("use_tls", True),
        tls_verify=config.get("tls_verify", True),
    )


@router.put("/ldap", response_model=LDAPConfigResponse)
async def update_ldap_config(
    req: LDAPConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    existing = dict(org.ldap_config or {})

    # Build updated config — keep existing encrypted password if not changed
    new_config = {
        "server": req.server,
        "base_dn": req.base_dn,
        "bind_dn": req.bind_dn,
        "user_search_base": req.user_search_base or req.base_dn,
        "user_filter": req.user_filter,
        "email_attr": req.email_attr,
        "name_attr": req.name_attr,
        "groups_attr": req.groups_attr,
        "role_mappings": req.role_mappings,
        "use_tls": req.use_tls,
        "tls_verify": req.tls_verify,
        # Keep existing encrypted password unless a new one is provided
        "bind_password": existing.get("bind_password", ""),
    }
    if req.bind_password:
        new_config["bind_password"] = encrypt(req.bind_password)

    org.ldap_config = new_config
    org.ldap_enabled = req.enabled
    await db.flush()

    return LDAPConfigResponse(
        enabled=org.ldap_enabled,
        server=req.server,
        base_dn=req.base_dn,
        bind_dn=req.bind_dn,
        has_bind_password=bool(new_config.get("bind_password")),
        user_search_base=req.user_search_base or req.base_dn,
        user_filter=req.user_filter,
        email_attr=req.email_attr,
        name_attr=req.name_attr,
        groups_attr=req.groups_attr,
        role_mappings=req.role_mappings,
        use_tls=req.use_tls,
        tls_verify=req.tls_verify,
    )


@router.post("/ldap/test", response_model=LDAPTestResponse)
@limiter.limit("10/minute")
async def test_ldap_connection(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """Test the service account bind to the LDAP server."""
    org = await _get_org(current_user, db)
    if not org.ldap_config:
        return LDAPTestResponse(success=False, message="LDAP not configured")

    ldap_svc = ldap_service_from_org(org)
    if not ldap_svc:
        return LDAPTestResponse(success=False, message="LDAP service could not be initialised")

    success, message = await asyncio.get_event_loop().run_in_executor(
        None, ldap_svc.test_connection
    )
    return LDAPTestResponse(success=success, message=message)


@router.get("/ldap/search")
@limiter.limit("20/minute")
async def search_ldap_users(
    request: Request,
    q: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """Search for users in LDAP/AD — used for the import UI."""
    org = await _get_org(current_user, db)
    ldap_svc = ldap_service_from_org(org)
    if not ldap_svc:
        raise HTTPException(status_code=400, detail="LDAP not enabled or not configured")

    results = await asyncio.get_event_loop().run_in_executor(
        None, ldap_svc.search_users, q, 25
    )
    return {"results": results}


# ─── UniFi settings ───────────────────────────────────────────────

@router.get("/unifi", response_model=UniFiConfigResponse)
async def get_unifi_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    return UniFiConfigResponse(
        enabled=bool(org.unifi_host and org.unifi_api_key_encrypted),
        host=org.unifi_host or "",
        site=org.unifi_site or "default",
        has_api_key=bool(org.unifi_api_key_encrypted),
    )


@router.put("/unifi", response_model=UniFiConfigResponse)
async def update_unifi_config(
    req: UniFiConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    if req.host is not None:
        org.unifi_host = req.host.rstrip("/") if req.host else None
    if req.site:
        org.unifi_site = req.site
    if req.api_key is not None:
        org.unifi_api_key_encrypted = encrypt(req.api_key) if req.api_key else None
    await db.flush()
    return UniFiConfigResponse(
        enabled=bool(org.unifi_host and org.unifi_api_key_encrypted),
        host=org.unifi_host or "",
        site=org.unifi_site or "default",
        has_api_key=bool(org.unifi_api_key_encrypted),
    )


@router.post("/unifi/test", response_model=UniFiTestResponse)
@limiter.limit("10/minute")
async def test_unifi_connection(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    if not org.unifi_host or not org.unifi_api_key_encrypted:
        return UniFiTestResponse(success=False, message="UniFi host and API key are required")

    api_key = decrypt(org.unifi_api_key_encrypted)
    svc = UniFiService(host=org.unifi_host, api_key=api_key, site=org.unifi_site or "default")
    success, message = await svc.test_connection()
    return UniFiTestResponse(success=success, message=message)


# ─── Organization profile ─────────────────────────────────────────

def _org_profile_response(org: Organization) -> OrgProfileResponse:
    return OrgProfileResponse(
        name=org.name,
        slug=org.slug,
        has_logo=bool(org.logo_data),
        logo_data=org.logo_data,
    )


@router.get("/organization", response_model=OrgProfileResponse)
async def get_org_profile(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    org = await _get_org(current_user, db)
    return _org_profile_response(org)


@router.put("/organization", response_model=OrgProfileResponse)
async def update_org_profile(
    req: OrgProfileRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    if req.name is not None and req.name.strip():
        org.name = req.name.strip()
    await db.flush()
    return _org_profile_response(org)


@router.post("/organization/logo", response_model=OrgProfileResponse)
@limiter.limit("10/minute")
async def upload_org_logo(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    content = await file.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:  # 2 MB limit
        raise HTTPException(status_code=400, detail="Logo must be under 2 MB")

    # Trust the file bytes, not the client-supplied Content-Type. SVG is not allowed (can carry scripts).
    signatures = {
        b"\x89PNG\r\n\x1a\n": "image/png",
        b"\xff\xd8\xff": "image/jpeg",
        b"GIF87a": "image/gif",
        b"GIF89a": "image/gif",
    }
    mime = next((m for sig, m in signatures.items() if content.startswith(sig)), None)
    if mime is None and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        mime = "image/webp"
    if mime is None:
        raise HTTPException(status_code=400, detail="Logo must be a PNG, JPEG, GIF or WebP image")

    b64 = base64.b64encode(content).decode()
    org = await _get_org(current_user, db)
    org.logo_data = f"data:{mime};base64,{b64}"
    await db.flush()
    return _org_profile_response(org)


@router.delete("/organization/logo", response_model=OrgProfileResponse)
async def delete_org_logo(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    org = await _get_org(current_user, db)
    org.logo_data = None
    await db.flush()
    return _org_profile_response(org)

"""
Pydantic v2 schemas for API request/response validation.
Keeps API contracts separate from database models.
"""
import ipaddress
import re
import socket

import json

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID
from app.models.models import UserRole, ScanType, ScanStatus, Severity, FindingStatus, AIProvider


# ─── Shared validation helpers ────────────────────────────────────
# Client-side checks are never trusted; everything below is enforced on the server.

def _check_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(v.encode()) > 72:  # bcrypt ignores everything past 72 bytes
        raise ValueError("Password must be at most 72 bytes")
    return v


def _check_ip(v: Optional[str]) -> Optional[str]:
    if v is None or v == "":
        return None
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        raise ValueError("Invalid IP address")


def _check_http_url(v: str) -> str:
    v = v.strip()
    if v and not re.match(r"^https?://[^\s/]+(/[^\s]*)?$", v):
        raise ValueError("Must be an http(s) URL")
    return v


def _check_json_size(v, max_bytes: int):
    if len(json.dumps(v, default=str)) > max_bytes:
        raise ValueError("Payload too large")
    return v


# ─── Auth ─────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=100)
    password: str
    organization_name: Optional[str] = Field(default=None, max_length=100)  # Only for first user (creates org)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _check_password(v)


class LoginRequest(BaseModel):
    username: str  # email used as username
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserResponse"


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=4096)


# ─── Users ────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    role: UserRole
    organization_id: UUID
    is_active: bool
    assigned_device_ip: Optional[str]
    last_login: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=100)
    password: str
    role: UserRole = UserRole.END_USER
    assigned_device_ip: Optional[str] = None

    @field_validator("password")
    @classmethod
    def _pw(cls, v):
        return _check_password(v)

    @field_validator("assigned_device_ip")
    @classmethod
    def _ip(cls, v):
        return _check_ip(v)


class UpdateUserRequest(BaseModel):
    username: Optional[str] = Field(default=None, min_length=1, max_length=100)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    assigned_device_ip: Optional[str] = None

    @field_validator("assigned_device_ip")
    @classmethod
    def _ip(cls, v):
        return _check_ip(v)


class AgentTokenResponse(BaseModel):
    id: UUID
    label: Optional[str]
    token: Optional[str] = None  # Only returned on creation
    last_used: Optional[datetime]
    created_at: datetime
    is_active: bool

    model_config = {"from_attributes": True}


# ─── Devices ──────────────────────────────────────────────────────

class PortResponse(BaseModel):
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str]
    service_version: Optional[str]
    service_product: Optional[str]

    model_config = {"from_attributes": True}


class DeviceResponse(BaseModel):
    id: UUID
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    os_guess: Optional[str]
    os_confidence: Optional[int]
    device_type: Optional[str]
    risk_score: float
    is_agent_registered: bool
    agent_version: Optional[str]
    last_agent_checkin: Optional[datetime]
    last_seen: Optional[datetime]
    first_seen: Optional[datetime]
    ports: List[PortResponse] = []
    open_findings_count: Optional[int] = 0

    model_config = {"from_attributes": True}


class DeviceListResponse(BaseModel):
    items: List[DeviceResponse]
    total: int


# ─── Scans ────────────────────────────────────────────────────────

_ALLOWED_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "fc00::/7", "::1/128",
    )
]
_MIN_PREFIX_V4 = 16   # largest scannable CIDR block is a /16 (65k hosts)
_MIN_PREFIX_V6 = 112
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _is_allowed(net) -> bool:
    return any(net.version == a.version and net.subnet_of(a) for a in _ALLOWED_NETWORKS)


def validate_scan_target(v: str) -> str:
    """
    Accept a single private IP, a private CIDR no larger than /16, or a
    hostname that resolves only to private addresses. Anything else (public
    ranges, option-like strings starting with '-', multiple targets) is rejected.
    """
    v = (v or "").strip()
    if not v or v.startswith("-"):
        raise ValueError("Invalid scan target")

    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        net = None

    if net is not None:
        min_prefix = _MIN_PREFIX_V4 if net.version == 4 else _MIN_PREFIX_V6
        if net.prefixlen < min_prefix:
            raise ValueError(f"CIDR range too large (minimum prefix /{min_prefix})")
        if not _is_allowed(net):
            raise ValueError("Only private IP ranges (RFC 1918) are permitted")
        return v

    if "/" in v or not _HOSTNAME_RE.match(v):
        raise ValueError("Target must be a private IP, a private CIDR range, or a hostname")
    try:
        infos = socket.getaddrinfo(v, None)
    except socket.gaierror:
        raise ValueError(f"Hostname '{v}' does not resolve")
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if not _is_allowed(ipaddress.ip_network(addr)):
            raise ValueError("Hostname resolves to a non-private address")
    return v


class StartScanRequest(BaseModel):
    scan_type: ScanType
    target: str = Field(max_length=255)
    options: dict = {}

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return validate_scan_target(v)

    @field_validator("options")
    @classmethod
    def _options_size(cls, v):
        return _check_json_size(v, 4096)


class ScanResponse(BaseModel):
    id: UUID
    scan_type: ScanType
    status: ScanStatus
    target: str
    hosts_discovered: int
    findings_count: int
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    initiated_by: Optional[UserResponse]

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int


# ─── Findings ─────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: UUID
    finding_type: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    virus_name: Optional[str]
    file_path: Optional[str]
    file_hash: Optional[str]
    virustotal_result: Optional[dict]
    ai_remediation: Optional[str]
    ai_generated_at: Optional[datetime]
    ai_provider_used: Optional[AIProvider]
    notes: Optional[str]
    resolved_at: Optional[datetime]
    created_at: datetime
    device: Optional[DeviceResponse]
    assigned_to: Optional[UserResponse]

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int


class UserFindingResponse(BaseModel):
    """Minimal finding view for end users: no assignee identity, device internals or raw data."""
    id: UUID
    finding_type: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    virus_name: Optional[str]
    ai_remediation: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class UserFindingListResponse(BaseModel):
    items: List[UserFindingResponse]
    total: int


class UpdateFindingRequest(BaseModel):
    status: Optional[FindingStatus] = None
    assigned_to_id: Optional[UUID] = None
    notes: Optional[str] = Field(default=None, max_length=5000)


# ─── Dashboard Stats ───────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_devices: int
    active_devices_24h: int
    critical_findings: int
    high_findings: int
    open_findings: int
    resolved_30d: int
    virus_threats: int
    last_scan: Optional[datetime]
    agent_registered_devices: int


# ─── Settings ─────────────────────────────────────────────────────

class OrgSettingsResponse(BaseModel):
    ai_provider: AIProvider
    ai_model: Optional[str]
    ai_ollama_url: str
    has_api_key: bool  # Never return the actual key
    virustotal_enabled: bool
    default_scan_target: Optional[str]
    ldap_enabled: bool


class UpdateOrgSettingsRequest(BaseModel):
    ai_provider: Optional[AIProvider] = None
    ai_model: Optional[str] = Field(default=None, max_length=100)
    ai_api_key: Optional[str] = Field(default=None, max_length=512)  # Set to "" to clear
    ai_ollama_url: Optional[str] = Field(default=None, max_length=255)
    virustotal_enabled: Optional[bool] = None
    default_scan_target: Optional[str] = Field(default=None, max_length=255)

    @field_validator("ai_ollama_url")
    @classmethod
    def _ollama_url(cls, v):
        return _check_http_url(v) if v else v

    @field_validator("default_scan_target")
    @classmethod
    def _default_target(cls, v):
        return validate_scan_target(v) if v else v


class AITestResponse(BaseModel):
    success: bool
    provider: AIProvider
    model: Optional[str]
    error: Optional[str]
    response_preview: Optional[str]


# ─── LDAP ─────────────────────────────────────────────────────────

class LDAPConfigRequest(BaseModel):
    enabled: bool = False
    server: str = Field(default="", max_length=255)             # ldap://dc01.company.com or ldaps://...
    base_dn: str = Field(default="", max_length=500)            # DC=company,DC=com
    bind_dn: str = Field(default="", max_length=500)            # CN=svc,OU=ServiceAccounts,DC=company,DC=com
    bind_password: Optional[str] = Field(default=None, max_length=256)  # Only set to update; None = keep existing
    user_search_base: Optional[str] = Field(default=None, max_length=500)  # Defaults to base_dn if blank
    user_filter: str = Field(default="(sAMAccountName={username})", max_length=500)
    email_attr: str = Field(default="mail", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
    name_attr: str = Field(default="displayName", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
    groups_attr: str = Field(default="memberOf", pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
    role_mappings: dict = {}                  # {group_dn: "it_admin"|"it_engineer"|...}
    use_tls: bool = True
    tls_verify: bool = True

    @field_validator("server")
    @classmethod
    def _server_scheme(cls, v):
        if v and not re.match(r"^ldaps?://[^\s/]+(:\d+)?$", v):
            raise ValueError("LDAP server must look like ldap://host[:port] or ldaps://host[:port]")
        return v

    @field_validator("user_filter")
    @classmethod
    def _filter_has_username(cls, v):
        rest = v.replace("{username}", "")
        if v.count("{username}") != 1 or "{" in rest or "}" in rest:
            raise ValueError("user_filter must contain exactly one {username} placeholder and no other braces")
        return v

    @field_validator("role_mappings")
    @classmethod
    def _role_values(cls, v):
        allowed = {r.value for r in UserRole}
        if len(v) > 200 or any(not isinstance(k, str) or len(k) > 500 or val not in allowed for k, val in v.items()):
            raise ValueError("role_mappings must map group DNs to valid roles")
        return v


class LDAPConfigResponse(BaseModel):
    enabled: bool
    server: str
    base_dn: str
    bind_dn: str
    has_bind_password: bool
    user_search_base: str
    user_filter: str
    email_attr: str
    name_attr: str
    groups_attr: str
    role_mappings: dict
    use_tls: bool
    tls_verify: bool


class LDAPTestResponse(BaseModel):
    success: bool
    message: str


# ─── UniFi ────────────────────────────────────────────────────────

class UniFiConfigRequest(BaseModel):
    host: str = Field(default="", max_length=255)       # https://192.168.1.1
    api_key: Optional[str] = Field(default=None, max_length=512)  # None = keep existing
    site: str = Field(default="default", pattern=r"^[A-Za-z0-9_-]{1,100}$")  # used in a URL path

    @field_validator("host")
    @classmethod
    def _host_url(cls, v):
        return _check_http_url(v)


class UniFiConfigResponse(BaseModel):
    enabled: bool        # True if host + key are configured
    host: str
    site: str
    has_api_key: bool


class UniFiTestResponse(BaseModel):
    success: bool
    message: str


# ─── Organization profile ──────────────────────────────────────────

class OrgProfileResponse(BaseModel):
    name: str
    slug: str
    has_logo: bool
    logo_data: Optional[str] = None


class OrgProfileRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)


# ─── Agent ────────────────────────────────────────────────────────

class AgentCheckinRequest(BaseModel):
    system_info: dict
    local_ip: str
    clamav_available: bool = False
    clamav_version: Optional[str] = Field(default=None, max_length=100)

    @field_validator("system_info")
    @classmethod
    def _sysinfo_size(cls, v):
        return _check_json_size(v, 20_000)

    @field_validator("local_ip")
    @classmethod
    def _local_ip(cls, v):
        ip = _check_ip(v)
        if ip is None:
            raise ValueError("local_ip is required")
        return ip


class AgentJob(BaseModel):
    id: str
    type: str
    options: dict = {}


class AgentCheckinResponse(BaseModel):
    status: str = "ok"
    pending_jobs: List[AgentJob] = []


class AgentResultRequest(BaseModel):
    type: str = Field(max_length=50)
    results: dict

    @field_validator("results")
    @classmethod
    def _results_size(cls, v):
        return _check_json_size(v, 5_000_000)


class AgentErrorRequest(BaseModel):
    error: str = Field(max_length=2000)


# ─── Scheduled Scans ──────────────────────────────────────────────

class CreateScheduledScanRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scan_type: ScanType
    target: str = Field(max_length=255)
    cron_expression: str = Field(max_length=100)
    options: dict = {}

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return validate_scan_target(v)

    @field_validator("options")
    @classmethod
    def _options_size(cls, v):
        return _check_json_size(v, 4096)


class ScheduledScanResponse(BaseModel):
    id: UUID
    name: str
    scan_type: ScanType
    target: str
    cron_expression: str
    is_active: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── User Self-Service ────────────────────────────────────────────

class UserDeviceResponse(BaseModel):
    ip_address: Optional[str]
    hostname: Optional[str]
    os_guess: Optional[str]
    agent_connected: bool
    last_agent_checkin: Optional[datetime]
    last_scan: Optional[datetime]
    risk_score: float


class StartUserScanRequest(BaseModel):
    scan_type: str  # virus_quick, virus_full, network_device, full_device

    @field_validator("scan_type")
    @classmethod
    def valid_scan_type(cls, v: str) -> str:
        allowed = {"virus_quick", "virus_full", "network_device", "full_device"}
        if v not in allowed:
            raise ValueError(f"scan_type must be one of {allowed}")
        return v


# ─── Pagination ───────────────────────────────────────────────────

class PaginationParams(BaseModel):
    page: int = 1
    limit: int = 20

    @field_validator("limit")
    @classmethod
    def cap_limit(cls, v: int) -> int:
        return min(v, 100)

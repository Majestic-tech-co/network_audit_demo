"""
Complete database schema for NetAudit.
All models use UUID primary keys and include audit timestamps.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer,
    ForeignKey, JSON, Enum, Float, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


# ─── Enums ────────────────────────────────────────────────────────

class UserRole(str, PyEnum):
    IT_ADMIN = "it_admin"        # Full access + user management + settings
    IT_ENGINEER = "it_engineer"  # Run scans, action findings
    IT_VIEWER = "it_viewer"      # Read-only IT dashboard
    END_USER = "end_user"        # Self-scan own device only


class ScanType(str, PyEnum):
    NETWORK_DISCOVERY = "network_discovery"
    PORT_SCAN = "port_scan"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    VIRUS = "virus"
    FULL_DEVICE = "full_device"   # End-user: all host-based scans
    FULL_NETWORK = "full_network" # IT: all network scans


class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, PyEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AIProvider(str, PyEnum):
    CLAUDE = "claude"
    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"


# ─── Models ───────────────────────────────────────────────────────

class Organization(Base):
    """Top-level tenant. One Docker stack = one org."""
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # AI provider configuration (encrypted at rest)
    ai_provider = Column(Enum(AIProvider), default=AIProvider.OLLAMA)
    ai_api_key_encrypted = Column(Text, nullable=True)  # AES-256 encrypted
    ai_model = Column(String(100), nullable=True)
    ai_ollama_url = Column(String(255), default="http://ollama:11434")

    # LDAP config
    ldap_enabled = Column(Boolean, default=False)
    ldap_config = Column(JSON, nullable=True)  # encrypted config blob

    # Branding
    logo_data = Column(Text, nullable=True)  # base64-encoded image (data URI)

    # UniFi integration
    unifi_host = Column(String(255), nullable=True)        # e.g. https://192.168.1.1
    unifi_api_key_encrypted = Column(Text, nullable=True)  # AES-256 encrypted
    unifi_site = Column(String(100), default="default")

    # Relationships
    users = relationship("User", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
    devices = relationship("Device", back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=True)  # null = LDAP-only user
    role = Column(Enum(UserRole), nullable=False, default=UserRole.END_USER)
    is_active = Column(Boolean, default=True)
    is_ldap_user = Column(Boolean, default=False)

    # End-user device binding (locked to their own machine)
    assigned_device_ip = Column(String(45), nullable=True)
    agent_token_hash = Column(String(255), nullable=True)  # hashed token for agent auth

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    # Brute-force protection (local password logins)
    failed_login_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    scans = relationship("Scan", back_populates="initiated_by")
    assigned_findings = relationship("Finding", back_populates="assigned_to")


class Device(Base):
    """A discovered network device or registered end-user machine."""
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)

    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)
    os_guess = Column(String(255), nullable=True)
    os_confidence = Column(Integer, nullable=True)  # Nmap confidence %
    device_type = Column(String(100), nullable=True)  # server, workstation, printer, etc.

    # Agent registration (end-user devices)
    is_agent_registered = Column(Boolean, default=False)
    agent_version = Column(String(50), nullable=True)
    last_agent_checkin = Column(DateTime(timezone=True), nullable=True)
    registered_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Risk posture
    risk_score = Column(Float, default=0.0)  # 0-100
    last_seen = Column(DateTime(timezone=True), nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="devices")
    ports = relationship("Port", back_populates="device", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="device")

    __table_args__ = (
        Index("ix_devices_org_ip", "organization_id", "ip_address", unique=True),
    )


class Port(Base):
    """Open port on a device, from Nmap scan."""
    __tablename__ = "ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20), default="open")
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(255), nullable=True)
    service_product = Column(String(255), nullable=True)
    extra_info = Column(Text, nullable=True)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    device = relationship("Device", back_populates="ports")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    initiated_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)

    # Target (network CIDR for IT, single IP for end-user)
    target = Column(String(255), nullable=False)
    options = Column(JSON, default={})  # extra nmap flags, scan depth, etc.

    # Results
    hosts_discovered = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    raw_output_path = Column(String(500), nullable=True)  # path to XML in volume
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Celery task ID for cancellation
    task_id = Column(String(255), nullable=True)

    # For agent-run scans: the device (and therefore agent token) the job is addressed to
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)

    # Relationships
    organization = relationship("Organization", back_populates="scans")
    initiated_by = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """A single security issue found during a scan."""
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=True)

    # Classification
    finding_type = Column(String(100), nullable=False)  # e.g. "open_port", "virus", "cve"
    severity = Column(Enum(Severity), nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    raw_data = Column(JSON, default={})  # original scan data that produced this finding

    # CVE / virus specific
    cve_id = Column(String(50), nullable=True)
    cvss_score = Column(Float, nullable=True)
    virus_name = Column(String(255), nullable=True)
    file_path = Column(Text, nullable=True)
    file_hash = Column(String(64), nullable=True)  # SHA-256
    virustotal_result = Column(JSON, nullable=True)

    # AI remediation
    ai_remediation = Column(Text, nullable=True)
    ai_generated_at = Column(DateTime(timezone=True), nullable=True)
    ai_provider_used = Column(Enum(AIProvider), nullable=True)

    # Assignment
    assigned_to_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    device = relationship("Device", back_populates="findings")
    assigned_to = relationship("User", back_populates="assigned_findings")

    __table_args__ = (
        Index("ix_findings_org_severity", "organization_id", "severity"),
        Index("ix_findings_org_status", "organization_id", "status"),
    )


class AgentToken(Base):
    """Tokens issued to local agents for secure check-in."""
    __tablename__ = "agent_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    label = Column(String(255), nullable=True)  # e.g. "John's MacBook"
    # The one device this token speaks for; set on the first check-in. An agent can only
    # fetch jobs for, and report results about, this device.
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)


class RefreshToken(Base):
    """One row per issued refresh token (single use; see app/core/refresh_tokens.py)."""
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)  # the JWT's jti
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    family_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TopologyLink(Base):
    """
    Confirmed L2 link discovered via LLDP, UniFi API, or SNMP.
    When link_type='lldp' and source_device_id IS NULL: passive LLDP confirmation
      (we saw this device announce itself; no specific parent known).
    When source_device_id IS NOT NULL: a real port-level connection.
    """
    __tablename__ = "topology_links"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    source_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    target_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    source_port    = Column(String(100), nullable=True)
    target_ip      = Column(String(45), nullable=True)
    target_hostname = Column(String(255), nullable=True)
    target_mac     = Column(String(50), nullable=True)
    capabilities   = Column(JSON, default=dict)   # {bridge, router, wlan, station}
    is_bridge      = Column(Boolean, default=False)
    is_router      = Column(Boolean, default=False)
    is_wlan        = Column(Boolean, default=False)
    link_type      = Column(String(20), default="lldp")  # lldp | unifi | snmp
    last_seen      = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    raw_data       = Column(JSON, default=dict)


class ScheduledScan(Base):
    """Recurring scan schedule for IT team."""
    __tablename__ = "scheduled_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    target = Column(String(255), nullable=False)
    options = Column(JSON, default={})
    cron_expression = Column(String(100), nullable=False)  # e.g. "0 2 * * 0" = Sunday 2am
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime(timezone=True), nullable=True)
    next_run = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

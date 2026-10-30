"""Server-side validation: scan targets and request-size limits."""
import pytest
from pydantic import ValidationError

from app.schemas.schemas import (
    StartScanRequest, CreateScheduledScanRequest, CreateUserRequest,
    LDAPConfigRequest, UniFiConfigRequest, AgentCheckinRequest, validate_scan_target,
)


@pytest.mark.parametrize("target", [
    "192.168.1.10", "10.0.0.0/24", "172.16.0.0/16", "192.168.0.0/16", "localhost", "127.0.0.1",
])
def test_valid_targets(target):
    assert validate_scan_target(target) == target


@pytest.mark.parametrize("target", [
    "10.0.0.0/0",           # huge range hidden behind a private base address
    "10.0.0.0/8",           # larger than /16
    "8.8.8.8",              # public
    "8.8.8.0/24",
    "-oN/tmp/x",            # nmap option injection
    "--script=vuln",
    "10.0.0.1 8.8.8.8",     # multiple targets
    "",
    "   ",
    "host/with/slash",
])
def test_rejected_targets(target):
    with pytest.raises(ValueError):
        validate_scan_target(target)


def test_schedule_target_is_validated():
    with pytest.raises(ValidationError):
        CreateScheduledScanRequest(name="x", scan_type="port_scan", target="8.8.8.8", cron_expression="* * * * *")


def test_scan_options_size_limit():
    with pytest.raises(ValidationError):
        StartScanRequest(scan_type="port_scan", target="192.168.1.1", options={"a": "x" * 5000})


def test_create_user_password_and_ip_checks():
    with pytest.raises(ValidationError):
        CreateUserRequest(email="a@b.com", username="u", password="short")
    with pytest.raises(ValidationError):
        CreateUserRequest(email="a@b.com", username="u", password="x" * 73)
    with pytest.raises(ValidationError):
        CreateUserRequest(email="a@b.com", username="u", password="longenough1", assigned_device_ip="not-an-ip")


def test_ldap_filter_must_have_single_placeholder():
    with pytest.raises(ValidationError):
        LDAPConfigRequest(user_filter="(uid=admin)")
    with pytest.raises(ValidationError):
        LDAPConfigRequest(user_filter="(&(uid={username})(x={other}))")
    assert LDAPConfigRequest(user_filter="(sAMAccountName={username})")


def test_unifi_site_is_path_safe():
    with pytest.raises(ValidationError):
        UniFiConfigRequest(host="https://10.0.0.1", site="../../admin")


def test_agent_checkin_requires_valid_ip():
    with pytest.raises(ValidationError):
        AgentCheckinRequest(system_info={}, local_ip="999.1.1.1")

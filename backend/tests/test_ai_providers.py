"""
Unit tests for the AI provider adapter system.
External API calls are mocked — no real keys required.
"""
import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.ai_providers.service import (
    AIService,
    ClaudeAdapter,
    OpenAIAdapter,
    GeminiAdapter,
    OllamaAdapter,
)
from app.models.models import (
    AIProvider as AIProviderEnum,
    Finding, Device, Severity, FindingStatus,
)


# ── Fixtures ──────────────────────────────────────────────────────

def make_finding(**overrides) -> Finding:
    now = datetime.now(timezone.utc)
    fields = dict(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        device_id=uuid.uuid4(),
        finding_type="open_port",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        title="RDP exposed to network",
        description="Port 3389 is open and accessible.",
        raw_data={"port": 3389, "service": "ms-wbt-server"},
        cve_id=None,
        cvss_score=None,
        virus_name=None,
        file_path=None,
        file_hash=None,
        virustotal_result=None,
        ai_remediation=None,
        ai_generated_at=None,
        ai_provider_used=None,
        assigned_to_id=None,
        resolved_at=None,
        notes=None,
        created_at=now,
        updated_at=None,
    )
    fields.update(overrides)
    return Finding(**fields)


def make_device(**overrides) -> Device:
    now = datetime.now(timezone.utc)
    fields = dict(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        ip_address="192.168.1.10",
        hostname="DESKTOP-01",
        os_guess="Windows 11",
        os_confidence=90,
        device_type="workstation",
        mac_address=None,
        is_agent_registered=False,
        agent_version=None,
        last_agent_checkin=None,
        registered_user_id=None,
        risk_score=75.0,
        last_seen=now,
        first_seen=now,
    )
    fields.update(overrides)
    return Device(**fields)


# ── build_prompt ───────────────────────────────────────────────────

def test_build_prompt_contains_device_info():
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    finding = make_finding()
    device = make_device()
    prompt = adapter.build_prompt(finding, device)
    assert device.ip_address in prompt
    assert device.hostname in prompt
    assert device.os_guess in prompt


def test_build_prompt_contains_finding_info():
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    finding = make_finding()
    device = make_device()
    prompt = adapter.build_prompt(finding, device)
    assert finding.title in prompt
    assert "HIGH" in prompt


def test_build_prompt_includes_cve_section_when_present():
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    finding = make_finding(cve_id="CVE-2021-44228", cvss_score=10.0)
    device = make_device()
    prompt = adapter.build_prompt(finding, device)
    assert "CVE-2021-44228" in prompt
    assert "10.0" in prompt


def test_build_prompt_no_cve_section_when_absent():
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    finding = make_finding(cve_id=None, cvss_score=None)
    device = make_device()
    prompt = adapter.build_prompt(finding, device)
    assert "CVE INFORMATION" not in prompt


def test_build_prompt_includes_malware_section_when_virus():
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    finding = make_finding(
        virus_name="Trojan.Generic",
        file_path="/tmp/evil.exe",
        file_hash="deadbeef" * 8,
    )
    device = make_device()
    prompt = adapter.build_prompt(finding, device)
    assert "Trojan.Generic" in prompt
    assert "/tmp/evil.exe" in prompt


def test_build_prompt_contains_response_format_headers():
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    prompt = adapter.build_prompt(make_finding(), make_device())
    for section in ("## Summary", "## Immediate Actions", "## Long-term Hardening", "## Verification"):
        assert section in prompt


# ── ClaudeAdapter ─────────────────────────────────────────────────

async def test_claude_adapter_returns_text_content():
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="Disable RDP or restrict with firewall rules.")]
    mock_client.messages.create.return_value = mock_response

    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    adapter.client = mock_client
    adapter.model = "claude-sonnet-4-20250514"

    result = await adapter.generate_remediation("test prompt")
    assert result == "Disable RDP or restrict with firewall rules."
    mock_client.messages.create.assert_called_once()


async def test_claude_adapter_passes_correct_model():
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="ok")]
    mock_client.messages.create.return_value = mock_response

    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    adapter.client = mock_client
    adapter.model = "claude-opus-4-7-20251101"

    await adapter.generate_remediation("prompt")
    call_kwargs = mock_client.messages.create.call_args.kwargs
    assert call_kwargs["model"] == "claude-opus-4-7-20251101"


# ── OpenAIAdapter ─────────────────────────────────────────────────

async def test_openai_adapter_returns_message_content():
    mock_client = AsyncMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Patch the system immediately."
    mock_completion = MagicMock()
    mock_completion.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_completion

    adapter = OpenAIAdapter.__new__(OpenAIAdapter)
    adapter.client = mock_client
    adapter.model = "gpt-4o"

    result = await adapter.generate_remediation("test prompt")
    assert result == "Patch the system immediately."


# ── OllamaAdapter ─────────────────────────────────────────────────

async def test_ollama_adapter_returns_response_field():
    with patch("app.services.ai_providers.service.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"response": "Update your firewall."}
        mock_http.post.return_value = mock_resp

        adapter = OllamaAdapter(base_url="http://ollama:11434", model="llama3")
        result = await adapter.generate_remediation("test prompt")

    assert result == "Update your firewall."


# ── GeminiAdapter ─────────────────────────────────────────────────

async def test_gemini_adapter_returns_text():
    with patch("app.services.ai_providers.service.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "Apply the patch now."}]}}]
        }
        mock_http.post.return_value = mock_resp

        adapter = GeminiAdapter(api_key="fake-key", model="gemini-1.5-pro")
        result = await adapter.generate_remediation("test prompt")

    assert result == "Apply the patch now."


# ── AIService factory ─────────────────────────────────────────────

def test_ai_service_builds_claude_adapter():
    svc = AIService(
        provider=AIProviderEnum.CLAUDE,
        api_key="fake-key",
        model="claude-sonnet-4-20250514",
        ollama_url="http://ollama:11434",
    )
    assert isinstance(svc._adapter, ClaudeAdapter)


def test_ai_service_builds_openai_adapter():
    svc = AIService(
        provider=AIProviderEnum.OPENAI,
        api_key="fake-key",
        model="gpt-4o",
        ollama_url="http://ollama:11434",
    )
    assert isinstance(svc._adapter, OpenAIAdapter)


def test_ai_service_builds_gemini_adapter():
    svc = AIService(
        provider=AIProviderEnum.GEMINI,
        api_key="fake-key",
        model="gemini-1.5-pro",
        ollama_url="http://ollama:11434",
    )
    assert isinstance(svc._adapter, GeminiAdapter)


def test_ai_service_builds_ollama_adapter():
    svc = AIService(
        provider=AIProviderEnum.OLLAMA,
        api_key=None,
        model="llama3",
        ollama_url="http://ollama:11434",
    )
    assert isinstance(svc._adapter, OllamaAdapter)


def test_ai_service_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown AI provider"):
        AIService(
            provider="invalid",  # type: ignore[arg-type]
            api_key=None,
            model=None,
            ollama_url="http://ollama:11434",
        )


async def test_ai_service_generate_remediation_returns_text():
    svc = AIService(
        provider=AIProviderEnum.CLAUDE,
        api_key="fake",
        model="claude-sonnet-4-20250514",
        ollama_url="",
    )
    svc._adapter.generate_remediation = AsyncMock(return_value="## Summary\nFix it.")
    result = await svc.generate_remediation(make_finding(), make_device())
    assert "Fix it." in result


async def test_ai_service_generate_remediation_handles_exception():
    svc = AIService(
        provider=AIProviderEnum.CLAUDE,
        api_key="fake",
        model="claude-sonnet-4-20250514",
        ollama_url="",
    )
    svc._adapter.generate_remediation = AsyncMock(side_effect=Exception("API down"))
    result = await svc.generate_remediation(make_finding(), make_device())
    assert "AI remediation generation failed" in result
    # Provider error details must stay in the server log, not in the stored/shown text
    assert "API down" not in result

"""
Pluggable AI provider adapter system.
Add new providers by subclassing AIProvider and registering in get_provider().
"""
from abc import ABC, abstractmethod
from typing import Optional
import httpx
import anthropic
import openai
import structlog

from app.models.models import AIProvider as AIProviderEnum, Finding, Device

log = structlog.get_logger()


# ─── Base Interface ────────────────────────────────────────────────

class AIProvider(ABC):
    @abstractmethod
    async def generate_remediation(self, prompt: str) -> str:
        """Generate remediation advice for a security finding."""
        ...

    def build_prompt(self, finding: Finding, device: Device) -> str:
        """Build a structured remediation prompt from a finding."""
        virus_section = ""
        if finding.virus_name:
            virus_section = f"""
MALWARE DETECTED:
- Threat name: {finding.virus_name}
- File path: {finding.file_path}
- File hash (SHA-256): {finding.file_hash}
- VirusTotal result: {finding.virustotal_result or 'Not checked'}
"""
        cve_section = ""
        if finding.cve_id:
            cve_section = f"""
CVE INFORMATION:
- CVE ID: {finding.cve_id}
- CVSS Score: {finding.cvss_score}
"""
        return f"""You are a senior cybersecurity engineer writing remediation instructions for an IT team.

DEVICE INFORMATION:
- IP Address: {device.ip_address}
- Hostname: {device.hostname or 'Unknown'}
- Operating System: {device.os_guess or 'Unknown'}
- Device Type: {device.device_type or 'Unknown'}

SECURITY FINDING:
- Type: {finding.finding_type}
- Severity: {finding.severity.value.upper()}
- Title: {finding.title}
- Description: {finding.description}
{cve_section}{virus_section}
RAW SCAN DATA:
{finding.raw_data}

Write clear, actionable remediation steps for this specific finding.
Format your response as:

## Summary
[2-3 sentence plain-English explanation of the risk]

## Immediate Actions
[Numbered list of steps to take right now]

## Long-term Hardening
[Steps to prevent recurrence]

## Verification
[How to confirm the issue is resolved]

Be specific to the OS and service versions shown. Do not include generic advice."""


# ─── Provider Adapters ─────────────────────────────────────────────

class ClaudeAdapter(AIProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    async def generate_remediation(self, prompt: str) -> str:
        message = await self.client.messages.create(
            model=self.model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text


class OpenAIAdapter(AIProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.client = openai.AsyncOpenAI(api_key=api_key)
        self.model = model

    async def generate_remediation(self, prompt: str) -> str:
        response = await self.client.chat.completions.create(
            model=self.model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


class GeminiAdapter(AIProvider):
    def __init__(self, api_key: str, model: str = "gemini-1.5-pro"):
        self.api_key = api_key
        self.model = model
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    async def generate_remediation(self, prompt: str) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.base_url,
                headers={"x-goog-api-key": self.api_key},
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]


class OllamaAdapter(AIProvider):
    def __init__(self, base_url: str = "http://ollama:11434", model: str = "llama3"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def generate_remediation(self, prompt: str) -> str:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
            )
            response.raise_for_status()
            return response.json()["response"]


# ─── Factory ───────────────────────────────────────────────────────

class AIService:
    """
    Resolves the correct provider adapter based on org configuration.
    Decrypts stored API keys before use.
    """

    def __init__(self, provider: AIProviderEnum, api_key: Optional[str], model: Optional[str], ollama_url: str):
        self._adapter = self._build_adapter(provider, api_key, model, ollama_url)
        self._provider = provider

    def _build_adapter(self, provider, api_key, model, ollama_url) -> AIProvider:
        if provider == AIProviderEnum.CLAUDE:
            return ClaudeAdapter(api_key=api_key, model=model or "claude-sonnet-4-20250514")
        elif provider == AIProviderEnum.OPENAI:
            return OpenAIAdapter(api_key=api_key, model=model or "gpt-4o")
        elif provider == AIProviderEnum.GEMINI:
            return GeminiAdapter(api_key=api_key, model=model or "gemini-1.5-pro")
        elif provider == AIProviderEnum.OLLAMA:
            return OllamaAdapter(base_url=ollama_url, model=model or "llama3")
        else:
            raise ValueError(f"Unknown AI provider: {provider}")

    async def generate_remediation(self, finding: Finding, device: Device) -> str:
        prompt = self._adapter.build_prompt(finding, device)
        try:
            return await self._adapter.generate_remediation(prompt)
        except Exception as e:
            log.error("ai_generation_failed", provider=str(self._provider), error=type(e).__name__)
            # Stored on the finding and shown to users: keep provider error details in the log only.
            return "AI remediation generation failed. Please review this finding manually."

#
#  MIT License
#
#  Copyright (c) 2026 Andrea Michael M. Molino
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#

"""AI-powered decision support engine for Apollyon.

Provides LLM-backed threat analysis, module recommendations, disinfection strategies,
and scan result summaries. Supports multiple providers via LiteLLM:
- OpenAI (cloud API)
- Ollama (local LLM)
- Anthropic (cloud API)
- Any provider compatible with the OpenAI API format

Configuration is loaded from environment variables (.env file or OS environment).
"""

import os
import sys
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    from dotenv import load_dotenv
    
    # Resolve .env path relative to the actual executable location.
    # When frozen (PyInstaller), look for .env next to the executable file.
    # When running from source, use the project root directory.
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running as PyInstaller extracted folder — fall back to exe location
        base_dir = Path(sys.executable).parent
    elif getattr(sys, 'frozen', False):
        # Running as a single-file executable (onefile)
        base_dir = Path(sys.executable).parent
    elif hasattr(sys, '_original_file'):
        # Running as PyInstaller single-file mode (older versions)
        base_dir = Path(sys._original_file).parent
    else:
        # Running from source code
        base_dir = Path(__file__).parent.parent
    
    _dotenv_path = base_dir / ".env"
    if _dotenv_path.exists():
        load_dotenv(_dotenv_path)
    else:
        load_dotenv()
except ImportError:
    # python-dotenv not installed; fall back to os.environ
    pass

from litellm import completion, ModelInfo
from litellm.exceptions import (
    APIConnectionError,
    Timeout as LiteLLMTimeout,
    RateLimitError as LiteLLMRateLimitError,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AIConfig:
    """Configuration for the AI decision engine, loaded from environment variables."""

    enabled: bool = True
    provider: str = "ollama"  # 'openai', 'anthropic', 'ollama', 'litellm'
    temperature: float = 0.3
    max_tokens: int = 2048
    timeout_seconds: float = 60.0

    # Provider-specific settings
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    openai_base_url: str = ""

    ollama_model: str = "llama3.2"
    ollama_host: str = "http://localhost:11434"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"

    # LiteLLM unified settings (overrides provider-specific)
    litellm_model: str = ""
    litellm_api_key: str = ""
    litellm_base_url: str = ""
    litellm_provider: str = "openai"

    @classmethod
    def from_env(cls) -> "AIConfig":
        """Create AIConfig from environment variables.

        Reads .env file (via python-dotenv) and OS environment variables.
        Falls back to sensible defaults for all settings.
        """
        def _bool(key: str, default: bool = False) -> bool:
            val = os.environ.get(key, str(default)).lower()
            return val in ("true", "1", "yes")

        config = cls(
            enabled=_bool("AI_ENABLED", True),
            provider=os.environ.get("AI_PROVIDER", "ollama"),
            temperature=float(os.environ.get("AI_TEMPERATURE", "0.3")),
            max_tokens=int(os.environ.get("AI_MAX_TOKENS", "2048")),
            timeout_seconds=float(os.environ.get("AI_TIMEOUT_SECONDS", "60")),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            openai_model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            openai_base_url=os.environ.get("OPENAI_BASE_URL", ""),
            ollama_model=os.environ.get("OLLAMA_MODEL", "llama3.2"),
            ollama_host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            litellm_model=os.environ.get("LITELLM_MODEL", ""),
            litellm_api_key=os.environ.get("LITELLM_API_KEY", ""),
            litellm_base_url=os.environ.get("LITELLM_BASE_URL", ""),
            litellm_provider=os.environ.get("LITELLM_PROVIDER", "openai"),
        )
        return config


@dataclass
class AIResponse:
    """Wrapper for LLM response data."""

    content: str = ""
    model_used: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    latency: float = 0.0
    error: str = ""
    success: bool = True

    def __bool__(self) -> bool:
        return self.success and bool(self.content)


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

def _build_model_string(config: AIConfig) -> str:
    """Build the model string for LiteLLM based on configuration.

    Args:
        config: The AI configuration.

    Returns:
        A model string like 'openai/gpt-4o', 'ollama/llama3.2', or 'anthropic/claude-sonnet-4-20250514'.
    """
    if config.litellm_model:
        # Use explicit LiteLLM settings if provided
        provider = config.litellm_provider or config.provider
        return f"{provider}/{config.litellm_model}"

    provider = config.provider.lower()
    if provider == "openai":
        return f"openai/{config.openai_model}"
    elif provider == "ollama":
        host = config.ollama_host.rstrip("/")
        # LiteLLM ollama format: ollama/<model> (the host is handled internally)
        return f"ollama/{config.ollama_model}"
    elif provider == "anthropic":
        return f"anthropic/{config.anthropic_model}"
    else:
        # Default to OpenAI-compatible
        return f"openai/{config.openai_model}"


def _build_extra_headers(config: AIConfig) -> dict[str, str]:
    """Build extra headers/parameters based on provider settings.

    Args:
        config: The AI configuration.

    Returns:
        Dictionary of extra parameters for the LiteLLM completion call.
    """
    params: dict[str, Any] = {}

    # OpenAI base URL override (for compatible providers like Groq, Together, etc.)
    if config.openai_base_url and config.provider == "openai":
        params["api_base"] = config.openai_base_url

    return params


# ---------------------------------------------------------------------------
# Core AI Decision Engine
# ---------------------------------------------------------------------------

class AIDecisionEngine:
    """Main AI decision support engine for Apollyon.

    This class handles all LLM interactions including:
    - Threat analysis and classification
    - Module recommendations
    - Disinfection strategy suggestions
    - Scan result summarization
    - General security Q&A

    Usage:
        config = AIConfig.from_env()
        engine = AIDecisionEngine(config)
        response = await engine.analyze_threats(scan_results)
    """

    def __init__(self, config: Optional[AIConfig] = None):
        """Initialize the decision engine.

        Args:
            config: AI configuration. If None, loads from environment variables.
        """
        self.config = config or AIConfig.from_env()
        self._model: str = _build_model_string(self.config)
        self._extra_params: dict[str, Any] = _build_extra_headers(self.config)

    # -----------------------------------------------------------------------
    # Core LLM Interface
    # -----------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> AIResponse:
        """Send a chat request to the configured LLM and return the response.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            temperature: Override config temperature (uses config default if None).
            max_tokens: Override config max_tokens (uses config default if None).

        Returns:
            AIResponse with the model's output and metadata.
        """
        if not self.config.enabled:
            return AIResponse(
                success=False,
                error="AI is disabled (set AI_ENABLED=true in .env)",
            )

        start_time = time.time()
        temperature = temperature if temperature is not None else self.config.temperature
        max_tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        try:
            response = completion(
                model=self._model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=self.config.timeout_seconds,
                **self._extra_params,
            )

            # Extract data from LiteLLM response
            choice = response.choices[0]
            message = choice.message
            usage = response.usage

            return AIResponse(
                success=True,
                content=message.content or "",
                model_used=response.model if hasattr(response, "model") else self._model,
                prompt_tokens=usage.prompt_tokens if usage else 0,
                completion_tokens=usage.completion_tokens if usage else 0,
                total_tokens=usage.total_tokens if usage else 0,
                finish_reason=choice.finish_reason or "",
                latency=time.time() - start_time,
            )

        except (APIConnectionError, LiteLLMTimeout) as e:
            return AIResponse(
                success=False,
                error=f"LLM request failed: {type(e).__name__}: {e}",
                latency=time.time() - start_time,
            )
        except LiteLLMRateLimitError as e:
            return AIResponse(
                success=False,
                error=f"Rate limit exceeded: {e}",
                latency=time.time() - start_time,
            )
        except Exception as e:
            return AIResponse(
                success=False,
                error=f"Unexpected error: {type(e).__name__}: {e}",
                latency=time.time() - start_time,
            )

    def build_context(
        self,
        scenario: str,
        data: dict[str, Any],
    ) -> list[dict[str, str]]:
        """Build system + user messages from a prompt template and scan data.

        Args:
            scenario: The prompt template name (e.g., 'threat_analysis').
            data: Dictionary of variables to fill into the user message template.

        Returns:
            List of messages for the LLM conversation.
        """
        # Import here to avoid circular dependency
        from .ai_prompts import AIPrompts

        prompts = AIPrompts()
        template = prompts.get_template(scenario)

        if template is None:
            return [
                {
                    "role": "system",
                    "content": "You are an AI assistant helping with malware analysis.",
                },
                {
                    "role": "user",
                    "content": json.dumps(data, default=str),
                },
            ]

        system_content = template.system_template
        user_content = template.format_user(**data)

        return [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ]

    # -----------------------------------------------------------------------
    # Decision Support Methods
    # -----------------------------------------------------------------------

    def analyze_threats(self, scan_results: dict[str, Any]) -> AIResponse:
        """Analyze and classify detected threats from a module scan.

        Args:
            scan_results: Dictionary containing module name, category, threat count,
                         and detailed threat information.

        Returns:
            AIResponse with structured threat analysis.
        """
        messages = self.build_context("threat_analysis", {
            "module_name": scan_results.get("module_name", "Unknown"),
            "category": scan_results.get("category", "Unknown"),
            "threats_count": scan_results.get("threats_count", 0),
            "threat_details": json.dumps(
                scan_results.get("threat_details", []), default=str, indent=2
            ),
        })
        return self.chat(messages)

    def recommend_modules(
        self,
        detected_threats: list[dict[str, Any]],
        available_modules: list[dict[str, Any]],
        os_info: Optional[str] = None,
        affected_paths: Optional[list[str]] = None,
    ) -> AIResponse:
        """Recommend which modules to run based on detected threats.

        Args:
            detected_threats: List of detected threat dictionaries.
            available_modules: List of module info dicts (name, category, tags).
            os_info: Operating system description.
            affected_paths: List of paths where threats were found.

        Returns:
            AIResponse with prioritized module recommendations.
        """
        messages = self.build_context("module_recommendation", {
            "threat_details": json.dumps(detected_threats, default=str, indent=2),
            "os_info": os_info or "Windows 11",
            "affected_paths": json.dumps(affected_paths or [], default=str),
            "available_modules": json.dumps(
                [{"name": m.get("name"), "category": m.get("category")} for m in available_modules],
                default=str,
                indent=2,
            ),
        })
        return self.chat(messages)

    def suggest_disinfection_strategy(self, scan_summary: dict[str, Any]) -> AIResponse:
        """Recommend a disinfection strategy based on scan results.

        Args:
            scan_summary: Dictionary with total threats, affected files, infection types,
                         and detailed threat information.

        Returns:
            AIResponse with recommended strategy and step-by-step plan.
        """
        messages = self.build_context("disinfection_strategy", {
            "total_threats": scan_summary.get("total_threats", 0),
            "files_affected": json.dumps(
                scan_summary.get("files_affected", []), default=str, indent=2
            ),
            "infection_types": json.dumps(
                scan_summary.get("infection_types", []), default=str, indent=2
            ),
            "threat_details": json.dumps(
                scan_summary.get("threat_details", []), default=str, indent=2
            ),
        })
        return self.chat(messages)

    def summarize_scan(self, full_results: dict[str, Any]) -> AIResponse:
        """Generate an executive summary of comprehensive scan results.

        Args:
            full_results: Dictionary with files_scanned, total_threats, modules_run,
                         scan_duration, and module_results.

        Returns:
            AIResponse with structured executive summary.
        """
        messages = self.build_context("scan_summary", {
            "files_scanned": full_results.get("files_scanned", 0),
            "total_threats": full_results.get("total_threats", 0),
            "modules_run": json.dumps(
                full_results.get("modules_run", []), default=str, indent=2
            ),
            "scan_duration": f"{full_results.get('scan_duration', 0):.1f}s",
            "module_results": json.dumps(
                full_results.get("module_results", {}), default=str, indent=2
            ),
        })
        return self.chat(messages)

    def answer_question(self, question: str) -> AIResponse:
        """Ask a general security question to the AI.

        Args:
            question: The user's question about malware, security, or remediation.

        Returns:
            AIResponse with the AI's answer.
        """
        messages = self.build_context("quick_question", {
            "user_question": question,
        })
        return self.chat(messages)

    def explain_module_result(
        self,
        module_name: str,
        status: str,
        result_details: dict[str, Any],
    ) -> AIResponse:
        """Explain a specific module's scan results in plain language.

        Args:
            module_name: Name of the Apollyon module.
            status: Execution status ('Success' or 'Failed').
            result_details: Dictionary with findings from the module execution.

        Returns:
            AIResponse with plain-language explanation.
        """
        messages = self.build_context("module_result_explanation", {
            "module_name": module_name,
            "status": status,
            "result_details": json.dumps(result_details, default=str, indent=2),
        })
        return self.chat(messages)

    # -----------------------------------------------------------------------
    # Utility Methods
    # -----------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Check if the AI provider is reachable and configured.

        Returns:
            True if AI is enabled and at least one API key or local endpoint is configured.
        """
        if not self.config.enabled:
            return False

        # Check that at least one provider has credentials configured
        has_keys = bool(
            self.config.openai_api_key
            or self.config.anthropic_api_key
            or self.config.litellm_api_key
        )
        is_local = self.config.provider == "ollama"

        return has_keys or is_local

    def status_report(self) -> dict[str, Any]:
        """Get a summary of the current AI configuration.

        Returns:
            Dictionary with AI status information.
        """
        return {
            "enabled": self.config.enabled,
            "provider": self.config.provider,
            "model": self._model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "timeout_seconds": self.config.timeout_seconds,
            "is_available": self.is_available,
        }

    def __repr__(self) -> str:
        status = "available" if self.is_available else "unavailable"
        return f"AIDecisionEngine(model={self._model}, status={status})"


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def get_ai_engine() -> AIDecisionEngine:
    """Get or create the default AI decision engine instance.

    This is a convenience function that creates an engine from environment config.
    For production use, instantiate AIDecisionEngine directly with explicit config.

    Returns:
        Configured AIDecisionEngine instance.
    """
    return AIDecisionEngine()
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

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime


class ModuleStatus(Enum):
    """Possible states of a module's execution lifecycle."""
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ModuleResult:
    """Container for a module's execution result."""
    success: bool
    data: Any = None
    error: str = None
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def __bool__(self):
        return self.success


@dataclass
class ModuleInfo:
    """Metadata about a module."""
    name: str
    description: str
    category: str
    version: str = "1.0.0"
    author: str = ""
    tags: list = field(default_factory=list)
    platform: str = ""
    supported_targets: list[str] = field(default_factory=lambda: ["system", "usb"])


class BaseModule(ABC):
    """Abstract base class for all malware tracking modules.

    All modules must implement the `run` method and provide module metadata
    through the `MODULE_INFO` class attribute.
    """

    # Each module must define this class attribute
    MODULE_INFO: ModuleInfo = None  # type: ignore

    def __init__(self):
        self._status = ModuleStatus.READY
        self._last_result: ModuleResult | None = None
        self._execution_start: datetime | None = None

    @property
    def status(self) -> ModuleStatus:
        """Return the current execution status of the module."""
        return self._status

    @property
    def last_result(self) -> ModuleResult | None:
        """Return the result from the last execution."""
        return self._last_result

    @abstractmethod
    def run(self, target: str, **kwargs) -> ModuleResult:
        """Execute the module against the given target.

        Args:
            target: The scan/analysis target (e.g., file path, directory, drive letter).
            **kwargs: Additional parameters specific to the module implementation.

        Returns:
            ModuleResult containing success status and any data/error information.
        """
        pass

    @abstractmethod
    def analyze(self, target: str, **kwargs) -> ModuleResult:
        """Perform a read-only analysis of a target for threats.

        Analyzes USB paths for malicious indicators or scans the system,
        depending on whether the target path corresponds to a removable drive.
        This method is read-only and does not perform any disinfection actions.

        Args:
            target: File path, directory, or drive letter to analyze.
            **kwargs: Additional parameters (e.g., deep_scan=True).

        Returns:
            ModuleResult with analysis findings data (no modifications made).
        """
        pass

    @abstractmethod
    def disinfect_usb(self, target: str, **kwargs) -> ModuleResult:
        pass

    @abstractmethod
    def disinfect_system(self, target: str, **kwargs) -> ModuleResult:
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(status={self._status.value})"

    def _set_status(self, status: ModuleStatus):
        """Internal helper to update status and track timing."""
        self._status = status
        if status == ModuleStatus.RUNNING:
            self._execution_start = datetime.now()
        elif status in (ModuleStatus.COMPLETED, ModuleStatus.FAILED, ModuleStatus.CANCELLED) and self._execution_start:
            elapsed = (datetime.now() - self._execution_start).total_seconds()
            if self._last_result is not None:
                self._last_result.execution_time = elapsed
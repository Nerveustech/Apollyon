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


from importlib.util import spec_from_file_location, module_from_spec
import inspect
import sys
from pathlib import Path
from typing import Type, Optional
from collections import defaultdict

from .base import BaseModule, ModuleInfo, ModuleStatus, ModuleResult


class ModuleRegistry:
    """Central registry for discovering, tracking, and managing modules.

    The registry auto-discovers module files in the src/modules directory,
    loads them, and provides methods to filter, list, and instantiate modules.
    """

    def __init__(self, modules_dir: Optional[str] = None):
        """Initialize the registry.

        Args:
            modules_dir: Path to the modules directory. Defaults to 'src/modules'.
        """
        self._modules: dict[str, BaseModule] = {}  # name -> instance
        self._module_classes: dict[str, Type[BaseModule]] = {}  # name -> class
        self._categories: dict[str, list[str]] = defaultdict(list)  # category -> [module names]

        if modules_dir:
            self._modules_dir = Path(modules_dir)
        else:
            # Resolve relative to this file's parent (src/modules/)
            self._modules_dir = Path(__file__).parent

        self._discover_modules()

    def _discover_modules(self):
        """Auto-discover and load module files from the modules directory.

        Scans for Python files in the modules directory, imports them,
        and registers any classes that inherit from BaseModule.
        """
        if not self._modules_dir.exists():
            print(f"Warning: Modules directory not found: {self._modules_dir}")
            return

        # Ensure the parent package 'modules' is registered in sys.modules
        # so that relative imports (e.g., .base) resolve correctly.
        parent_pkg_name = "src.modules"
        if parent_pkg_name not in sys.modules:
            parent_pkg = type(sys.modules.get("src", type(sys)("src")))(parent_pkg_name)
            parent_pkg.__path__ = []  # Mark as a package
            parent_pkg.__file__ = str(Path(__file__).parent.parent)
            if "src" not in sys.modules:
                src_pkg = type(sys)("src")
                src_pkg.__path__ = []
                src_pkg.__file__ = str(Path(__file__).parent.parent)
                sys.modules["src"] = src_pkg
            sys.modules[parent_pkg_name] = parent_pkg

        for file_path in self._modules_dir.glob("*.py"):
            # Skip special files
            if file_path.name.startswith("_") or file_path.name in ("base.py", "registry.py"):
                continue

            module_name = file_path.stem
            try:
                full_module_name = f"modules.{module_name}"
                
                # Dynamically import the module with proper package context.
                spec = spec_from_file_location(
                    full_module_name, file_path,
                    submodule_search_locations=[str(self._modules_dir)]
                )
                if spec is None or spec.loader is None:
                    continue

                module = module_from_spec(spec)
                # Register in sys.modules so relative imports can resolve siblings.
                sys.modules[full_module_name] = module
                
                spec.loader.exec_module(module)

                # Find all BaseModule subclasses in the module
                for cls_name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and issubclass(obj, BaseModule) and obj != BaseModule):
                        # Instantiate to get MODULE_INFO
                        instance = obj()
                        info = instance.MODULE_INFO

                        self._module_classes[info.name] = obj
                        self._modules[info.name] = instance
                        self._categories[info.category].append(info.name)

            except Exception as e:
                print(f"Warning: Failed to load module '{module_name}': {e}")

    @property
    def modules(self) -> dict[str, BaseModule]:
        """Return all registered module instances."""
        return self._modules.copy()

    @property
    def categories(self) -> list[str]:
        """Return available module categories."""
        return sorted(set(self._categories.keys()))

    def get_by_category(self, category: str) -> dict[str, BaseModule]:
        """Get all modules in a specific category.

        Args:
            category: The category name to filter by.

        Returns:
            Dictionary of module name -> instance for matching category.
        """
        return {name: self._modules[name] for name in self._categories.get(category, [])}

    def get_by_status(self, status: ModuleStatus) -> dict[str, BaseModule]:
        """Get all modules with a specific execution status.

        Args:
            status: The ModuleStatus to filter by.

        Returns:
            Dictionary of module name -> instance matching the status.
        """
        return {name: mod for name, mod in self._modules.items() if mod.status == status}

    def get_all_info(self) -> list[ModuleInfo]:
        """Return metadata for all registered modules."""
        return [mod.MODULE_INFO for mod in self._modules.values()]

    def get_module(self, name: str) -> Optional[BaseModule]:
        """Get a specific module by name.

        Args:
            name: The module name.

        Returns:
            Module instance or None if not found.
        """
        return self._modules.get(name)

    def run_module(self, name: str, target: str, **kwargs) -> Optional[ModuleResult]:
        """Execute a specific module and track the result.

        Args:
            name: The module name to execute.
            target: The scan/analysis target path.
            **kwargs: Additional parameters passed to the module's run method.

        Returns:
            ModuleResult from execution, or None if module not found.
        """
        from .base import ModuleResult

        module = self._modules.get(name)
        if module is None:
            return ModuleResult(success=False, error=f"Module '{name}' not found")

        try:
            # Reset status to running
            module._set_status(ModuleStatus.RUNNING)
            result = module.run(target, **kwargs)
            result.success = True  # Assume success unless run raises
            module._last_result = result
            module._set_status(ModuleStatus.COMPLETED)
        except Exception as e:
            from datetime import datetime
            result = ModuleResult(
                success=False,
                error=str(e),
                execution_time=0.0,
                timestamp=datetime.now()
            )
            module._last_result = result
            module._set_status(ModuleStatus.FAILED)

        return module._last_result

    def run_all(self, target: str, **kwargs) -> dict[str, ModuleResult]:
        """Execute all registered modules against a target.

        Args:
            target: The scan/analysis target path.
            **kwargs: Additional parameters passed to each module's run method.

        Returns:
            Dictionary of module name -> ModuleResult for each execution.
        """
        results = {}
        for name in self._modules:
            results[name] = self.run_module(name, target, **kwargs) or ModuleResult(success=False, error="Module not found")
        return results

    def summary(self) -> dict[str, int]:
        """Return a count of modules by status.

        Returns:
            Dictionary mapping ModuleStatus values to their counts.
        """
        counts = {status: 0 for status in ModuleStatus}
        for mod in self._modules.values():
            counts[mod.status] += 1
        return counts

    def __len__(self) -> int:
        return len(self._modules)

    def __iter__(self):
        return iter(self._modules)

    def __contains__(self, name: str) -> bool:
        return name in self._modules

    def get_all_supported_targets(self) -> list[str]:
        """Return the union of all supported targets across modules.
        
        Returns:
            Sorted list of unique target strings (e.g., ["system", "usb"]).
        """
        targets = set()
        for mod in self._modules.values():
            targets.update(mod.MODULE_INFO.supported_targets)
        return sorted(targets)

    def get_module_target_support(self, name: str) -> list[str]:
        """Return the supported targets for a specific module.
        
        Args:
            name: The module name.
            
        Returns:
            List of target strings this module supports.
        """
        mod = self._modules.get(name)
        if mod is None:
            return []
        return list(mod.MODULE_INFO.supported_targets)

    def get_modules_by_target(self, target: str) -> dict[str, BaseModule]:
        """Get all modules that support a specific target.
        
        Args:
            target: The target string (e.g., "system" or "usb").
            
        Returns:
            Dictionary of module name -> instance for matching modules.
        """
        return {
            name: mod for name, mod in self._modules.items()
            if target in mod.MODULE_INFO.supported_targets
        }

    def __repr__(self) -> str:
        return f"ModuleRegistry(modules={len(self)}, categories={self.categories})"

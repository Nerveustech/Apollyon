# Modules Documentation

This directory contains detailed documentation for all built-in Apollyon modules.

---

## Table of Contents

- [MoveMenoreg Scanner](#movemenoreg-scanner)
- [Module Interface Reference](#module-interface-reference)
- [Module Metadata](#module-metadata)
- [Developing Custom Modules](#developing-custom-modules)

---

## MoveMenoreg Scanner

| Property | Value |
|----------|-------|
| **Name** | `movemenoreg_scanner` |
| **Category** | `disinfection` |
| **Version** | `1.0.0` |
| **Author** | Andrea Michael Maria Molino |
| **Platform** | Windows |
| **Supported Targets** | `system`, `usb` |
| **Tags** | `malware`, `disinfection`, `persistence`, `movemenoreg`, `vbs` |

### Overview

Detects and removes the **MoveMenoreg** malware family, which uses a VBS-based persistence mechanism to maintain execution across reboots. This module can scan both Windows systems and removable (USB) drives.

### Malware Behavior

The MoveMenoreg malware operates by:

1. Creating `%APPDATA%\WindowsServices\movemenoreg.vbs` as the main payload
2. Dropping `helper.vbs` in the current working directory
3. Creating a startup LNK file (`helper.lnk`) that executes:
   ```
   wscript.exe /C .\WindowsServices\movemenoreg.vbs
   ```
4. Backing up original files to a `_` subdirectory

### Indicators of Compromise (IOCs)

| Indicator | Type | Location |
|-----------|------|----------|
| `movemenoreg.vbs` | Malware payload | `%APPDATA%\WindowsServices\` or USB root |
| `helper.vbs` | Helper script | Current directory or USB root |
| `installer.vbs` | Installer script | Current directory or USB root |
| `WindowsServices.exe` | Miner executable | `%APPDATA%\WindowsServices\` or USB root |
| `WindowsServices\` | Malware folder | `%APPDATA%\` or USB root |
| `helper.lnk` | Startup LNK | User Startup folder or USB root |
| `_ \` | Backup folder | Current directory or USB root |

### Detection Logic

**USB Mode:**
- Scans for `.lnk` files with malicious arguments matching `/C .\\WindowsServices\\movemenoreg.vbs`
- Checks for the presence of `WindowsServices/` malware folder
- Detects helper scripts: `helper.vbs`, `installer.vbs`, `movemenoreg.vbs`, `WindowsServices.exe`
- Identifies backup folder (`_`) indicating previous infection

**System Mode:**
- Checks if `wscript.exe` process is running (informational)
- Scans `%APPDATA%\WindowsServices\` for malware artifacts
- Checks the User Startup folder for malicious `helper.lnk`

### Actions Performed

| Action | Description |
|--------|-------------|
| Remove malicious LNK files | Deletes `.lnk` files with matching malware arguments |
| Remove malware folder | Recursively deletes `WindowsServices/` directory and contents |
| Kill wscript.exe | Terminates the WScript host process (system mode only) |
| Remove startup LNK | Deletes `helper.lnk` from User Startup folder |
| Restore original files | Moves files from `_` backup folder back to their original locations |
| Clean backup folder | Removes the `_` backup folder after successful restoration |

### Usage Examples

```python
from modules.registry import ModuleRegistry

registry = ModuleRegistry()
scanner = registry.get_module("movemenoreg_scanner")

# Read-only analysis of a USB drive
result = scanner.analyze(r"D:\")
print(result.data["findings"])       # List of detected threats
print(result.data["total_threats_found"])  # Number of threats

# Disinfect a USB drive (removes malware, restores originals)
result = scanner.disinfect_usb(r"D:\", deep_scan=True)
print(result.data["actions"])        # List of actions taken
print(result.data["restored_files"]) # Files restored from backup

# Analyze the system (read-only)
result = scanner.analyze("system")

# Disinfect the system (removes malware artifacts)
result = scanner.disinfect_system()
```

### Method Details

#### `analyze(target, **kwargs)` → `ModuleResult`

Performs a read-only scan. Returns findings without modifying any files.

**Parameters:**
- `target` (`str`): Path to USB drive, or `"system"` for system analysis
- `deep_scan` (`bool`, default `True`): Enable deep LNK file analysis

**Returns:** `ModuleResult` with `data.findings` list containing threat objects:
```python
{
    "type": "malicious_lnk",       # One of: malicious_lnk, malware_folder, 
                                   # malicious_file, startup_lnk, process_running
    "path": "...",                  # Full path to the indicator
    "severity": "critical",         # One of: critical, high, medium, info
    "description": "..."            # Human-readable description
}
```

#### `disinfect_usb(target, **kwargs)` → `ModuleResult`

Removes malware from a USB/removable drive and restores original files.

**Parameters:**
- `target` (`str`): Path to the USB drive (e.g., `"D:\\"`)
- `deep_scan` (`bool`, default `True`): Enable deep LNK analysis

**Returns:** `ModuleResult` with:
- `data.findings`: List of detected threats
- `data.actions`: List of actions taken (with status)
- `data.restored_files`: List of files restored from backup

#### `disinfect_system(target, **kwargs)` → `ModuleResult`

Removes malware artifacts from the Windows system.

**Parameters:**
- `target` (`str`, default `""`): Ignored in system mode
- `deep_scan` (`bool`, default `True`): Unused in system disinfection

**Returns:** `ModuleResult` with:
- `data.findings`: List of detected threats
- `data.actions`: List of actions taken (process killed, folders removed, LNK deleted)

---

## Module Interface Reference

Every Apollyon module extends `BaseModule` and must implement the following methods:

### `run(target: str, **kwargs) -> ModuleResult`

Execute the module against a given target. This is the primary entry point used by the registry.

**Parameters:**
- `target`: The scan/analysis target (e.g., file path, directory, drive letter)
- `**kwargs`: Additional parameters specific to the module implementation

**Returns:** `ModuleResult` containing success status and data/error information

---

### `analyze(target: str, **kwargs) -> ModuleResult`

Perform a read-only analysis of a target for threats. This method must NOT modify any files on disk.

**Parameters:**
- `target`: File path, directory, or drive letter to analyze
- `**kwargs`: Additional parameters (e.g., `deep_scan=True`)

**Returns:** `ModuleResult` with analysis findings in `data.findings`

---

### `disinfect_usb(target: str, **kwargs) -> ModuleResult`

Remove threats from USB/removable drives. This method may delete files and restore originals.

**Parameters:**
- `target`: Path to the USB drive or directory to disinfect
- `**kwargs`: Additional parameters (e.g., `deep_scan=True`)

**Returns:** `ModuleResult` with findings, actions, and optionally restored_files

---

### `disinfect_system(target: str, **kwargs) -> ModuleResult`

Remove threats from the Windows system. This method may delete files, kill processes, and modify registry-related artifacts.

**Parameters:**
- `target`: Target path (may be ignored depending on module implementation)
- `**kwargs`: Additional parameters

**Returns:** `ModuleResult` with findings and actions taken

---

## Module Metadata

Each module defines a `MODULE_INFO` class attribute using the `ModuleInfo` dataclass:

```python
from modules.base import ModuleInfo

MODULE_INFO = ModuleInfo(
    name="my_module",              # Unique identifier (required)
    description="Description...",  # Human-readable description (required)
    category="disinfection",       # Category for grouping (required)
    version="1.0.0",               # Semantic version string
    author="Your Name",            # Author name
    tags=["tag1", "tag2"],         # Searchable tags list
    platform="Windows",            # Target platform
    supported_targets=["system", "usb"],  # Supported targets
)
```

### Available Categories

| Category | Description |
|----------|-------------|
| `disinfection` | Active malware removal modules |
| `scanning` | Read-only scanning and detection modules |
| `analysis` | Deep analysis and reporting modules |

### Supported Targets

| Target | Description |
|--------|-------------|
| `system` | Windows operating system (AppData, Startup, processes) |
| `usb` | Removable/USB drives (detected via `GetDriveType`) |

---

## Developing Custom Modules

Create a new Python file in `src/modules/` (name must not start with `_`):

```python
# src/modules/my_scanner.py
from modules.base import BaseModule, ModuleInfo, ModuleResult

class MyScanner(BaseModule):
    MODULE_INFO = ModuleInfo(
        name="my_scanner",
        description="Custom scanner module description",
        category="scanning",
        version="1.0.0",
        author="Your Name",
        tags=["custom", "scanner"],
        platform="Windows",
        supported_targets=["system", "usb"],
    )

    def run(self, target: str, **kwargs) -> ModuleResult:
        """Execute the module."""
        pass

    def analyze(self, target: str, **kwargs) -> ModuleResult:
        """Read-only analysis."""
        pass

    def disinfect_usb(self, target: str, **kwargs) -> ModuleResult:
        """Remove threats from USB."""
        pass

    def disinfect_system(self, target: str, **kwargs) -> ModuleResult:
        """Remove threats from system."""
        pass
```

The `ModuleRegistry` will auto-discover and register your module on startup. No additional configuration is required.

### Result Data Structure

All methods return a `ModuleResult`:

```python
from modules.base import ModuleResult

result = ModuleResult(
    success=True,                    # Boolean: operation succeeded?
    data={                           # Dict: findings, actions, etc.
        "target": "...",
        "findings": [...],           # List of detected threats
        "actions": [...],            # List of actions taken
        "restored_files": [...],     # List of restored files (optional)
    },
    error=None,                      # Error message if failed
    execution_time=0.0,              # Execution time in seconds
)
```

### Threat Finding Structure

Each finding in `data.findings` follows this structure:

```python
{
    "type": "malicious_lnk",       # Indicator type identifier
    "path": "...",                 # Full file/system path
    "severity": "critical",        # One of: critical, high, medium, info
    "description": "Human-readable description"
}
```

### Action Structure

Each action in `data.actions` follows this structure:

```python
{
    "action": "lnk_removed",       # Action type identifier
    "path": "...",                 # Path affected
    "status": "success"            # One of: success, failed
}
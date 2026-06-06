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

# Jigsaw sample: 3ae96f73d805e1d3995253db4d910300d8442ea603737a1428b613061e7f61e7

from os import environ
from os.path import (
    exists,
    expandvars,
    normpath,
    join,
    dirname
)
from shutil import rmtree
from pathlib import Path
from datetime import datetime
from base64 import b64decode
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

from psutil import (
    process_iter,
    NoSuchProcess,
    AccessDenied,
    ZombieProcess
)

from winreg import (
    OpenKey,
    QueryValueEx,
    DeleteValue,
    HKEY_CURRENT_USER,
    KEY_READ,
    KEY_SET_VALUE,
)

from Crypto.Cipher import AES

try:
    from modules.base import BaseModule, ModuleInfo, ModuleResult 
except ImportError:
    from src.modules.base import BaseModule, ModuleInfo, ModuleResult


class JigsawScanner(BaseModule):
    """Module for detecting and disinfecting Jigsaw ransomware on Windows systems.

    This module scans for and restores files encrypted by the Jigsaw ransomware
    family (sample hash: 3ae96f73d805e1d3995253db4d910300d8442ea603737a1428b613061e7f61e7).

    Jigsaw ransomware characteristics:
        - Encrypts files and appends .fun extension
        - Drops malicious binaries (drpbx.exe, firefox.exe) for persistence
        - Creates registry entries for auto-execution on boot
        - Uses AES-CBC encryption with a fixed key/IV pair

    The module supports both read-only analysis and full disinfection of infected systems.
    """

    MODULE_INFO = ModuleInfo(
        name="jigsaw_scanner",
        description="Detects and disinfects Jigsaw ransomware on Windows systems, restoring .fun encrypted files",
        category="disinfection",
        version="1.0.0",
        author="Andrea Michael Maria Molino",
        tags=[
            "ransomware",
            "jigsaw",
            "disinfection",
            "recovery",
            "persistence",
            "encryption",
            "aes"
        ],
        platform="Windows",
        supported_targets=["system"],
    )

    EXTENSIONS = [".fun"]

    # Jigsaw AES decryption key (base64 encoded) and IV
    KEY = b64decode("OoIsAwwF23cICQoLDA0ODe==")
    IV = b'\x00\x01\x00\x03\x05\x03\x00\x01\x00\x00\x02\x00\x06\x07\x06\x00'

    # Malicious process names used by Jigsaw
    MALICIOUS_PROCESSES = ["drpbx.exe", "firefox.exe"]

    # Persistence file paths created by Jigsaw
    PERSISTENCE_FILES = [
        Path("%LOCALAPPDATA%\\Drpbx\\drpbx.exe"),
        Path("%APPDATA%\\Frfx\\firefox.exe"),
        Path("%TEMP%\\drpbx.exe"),
    ]

    # Registry persistence entry
    REGISTRY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    REGISTRY_VALUE_NAME = "firefox.exe"

    def analyze(self, target: str, **kwargs) -> ModuleResult:
        """Perform a read-only analysis of the system for Jigsaw ransomware threats.

        Scans common user directories for .fun encrypted files and checks for
        persistence mechanisms without making any modifications to the system.

        Args:
            target: File path or directory to analyze. If empty or "system", scans
                    all common user directories.
            **kwargs: Additional parameters (e.g., deep_scan=True).

        Returns:
            ModuleResult with analysis findings data (no modifications made).
        """
        deep_scan = kwargs.get("deep_scan", True)

        # Determine which paths to scan
        if target and exists(target):
            search_paths = [Path(target)]
        else:
            search_paths = self._get_search_paths()

        findings = []

        for search_path in search_paths:
            if not search_path.exists():
                continue

            # Find all .fun files
            fun_files = self._find_fun_files(str(search_path))

            for file_path in fun_files:
                is_encrypted = True  # Assume .fun files are Jigsaw-encrypted

                findings.append({
                    "type": "encrypted_file",
                    "path": str(file_path),
                    "original_name": str(file_path).replace(".fun", ""),
                    "extension": ".fun",
                    "file_size": file_path.stat().st_size if file_path.exists() else 0,
                    "severity": "critical",
                    "description": f"Jigsaw-encrypted file detected: {file_path}",
                })

        # Check for persistence mechanisms
        persistence_findings = self._check_persistence()
        findings.extend(persistence_findings)

        return ModuleResult(
            success=True,
            data={
                "target": target or "system",
                "mode": "analysis",
                "findings": findings,
                "total_encrypted_files": len([f for f in findings if f["type"] == "encrypted_file"]),
                "total_persistence_entries": len([f for f in findings if f["type"] != "encrypted_file"]),
                "total_threats_found": len(findings),
                "analysis_type": "read_only",
                "timestamp": datetime.now().isoformat(),
            },
        )

    def run(self, target: str = "", **kwargs) -> ModuleResult:
        """Execute the Jigsaw disinfection against the given target.

        Args:
            target: File path or directory to disinfect. If empty or "system",
                    performs a full system disinfection.
            **kwargs: Additional parameters (e.g., force=True, dry_run=False).

        Returns:
            ModuleResult with findings and actions data.
        """
        return self.disinfect_system(target, **kwargs)

    def disinfect_usb(self, target: str, **kwargs) -> ModuleResult:
        """Disinfection stub for USB targets.

        Jigsaw ransomware only infects the Windows system and does not target
        USB drives directly. This method returns success with no actions taken.

        Args:
            target: Ignored (USB path).

        Returns:
            ModuleResult indicating no action was necessary.
        """
        return ModuleResult(
            success=True,
            data={
                "target": target,
                "mode": "usb",
                "findings": [],
                "actions": [],
                "total_threats_found": 0,
                "note": "Jigsaw ransomware does not target USB drives; it only infects the Windows system",
            },
        )

    def disinfect_system(self, target: str = "", **kwargs) -> ModuleResult:
        """Disinfect a Windows system from Jigsaw ransomware.

        Performs the following remediation steps in order:

        1. Kill malicious processes (drpbx.exe, firefox.exe)
        2. Delete dropped persistence files
        3. Remove registry persistence entries
        4. Restore all .fun encrypted files using AES decryption

        Args:
            target: File path or directory to disinfect. If empty, scans all
                    common user directories.
            **kwargs:
                - force: bool - Force disinfection without confirmation (default False).
                - dry_run: bool - Report what would be done without making changes (default False).

        Returns:
            ModuleResult with findings and actions data.
        """
        force = kwargs.get("force", False)
        dry_run = kwargs.get("dry_run", False)

        findings = []
        actions_taken = []

        # Step 1: Kill malicious processes (must complete first to ensure no locks on files)
        kill_result = self._kill_malicious_processes()
        findings.extend(kill_result.get("findings", []))
        actions_taken.extend(kill_result.get("actions", []))
        sleep(2)

        # Determine search paths for encrypted file restoration
        restore_paths = self._get_search_paths()
        if target and exists(target):
            restore_paths = [Path(target)]

        # Step 2 & 3: Run in parallel using ThreadPoolExecutor
        # These operations are independent:
        #   - _restore_encrypted_files: decrypts .fun files back to original format
        #   - _delete_persistence_files: removes Jigsaw dropped executables
        # Both operate on different file paths and can safely execute concurrently.
        restore_future = None
        delete_future = None

        with ThreadPoolExecutor(max_workers=2) as executor:
            restore_future = executor.submit(self._restore_encrypted_files, restore_paths, force=force, dry_run=dry_run)
            delete_future = executor.submit(self._delete_persistence_files, force=force, dry_run=dry_run)

            # Collect results from both parallel tasks
            for future in as_completed([restore_future, delete_future]):
                result = future.result()
                findings.extend(result.get("findings", []))
                actions_taken.extend(result.get("actions", []))

        # Step 4: Remove registry persistence (runs after file operations complete)
        reg_result = self._remove_registry_persistence(force=force, dry_run=dry_run)
        findings.extend(reg_result.get("findings", []))
        actions_taken.extend(reg_result.get("actions", []))


        return ModuleResult(
            success=True,
            data={
                "target": target or "system",
                "mode": "system",
                "findings": findings,
                "actions": actions_taken,
                "total_threats_found": len(findings),
                "total_actions_taken": len(actions_taken),
                "dry_run": dry_run,
                "timestamp": datetime.now().isoformat(),
            },
        )

    def _get_search_paths(self) -> list[Path]:
        """Get all paths to search for .fun files.

        Scans the entire system (all drives) since Jigsaw encrypts files everywhere,
        including Program Files, Python installations, and system directories.

        Returns:
            List of paths to scan for encrypted files.
        """
        paths = []

        # User profile directories
        user_dirs = [
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
            Path.home() / "Pictures",
            Path.home() / "Videos",
            Path.home() / "Music",
        ]

        for user_dir in user_dirs:
            if user_dir.exists():
                paths.append(user_dir)

        # Public user directories (use expandvars for portability)
        public_base = join(environ.get("SystemDrive", "C:\\"), "Users", "Public")
        public_dirs = [
            Path(public_base) / "Documents",
            Path(public_base) / "Pictures",
            Path(public_base) / "Desktop",
        ]

        for d in public_dirs:
            if d.exists():
                paths.append(d)

        # Legacy Windows paths (for compatibility with older systems)
        program_data = environ.get("ProgramData", "")
        if program_data:
            program_data_path = Path(program_data)
            if program_data_path.exists():
                paths.append(program_data_path)

        # Scan all fixed drives recursively (C:, D:, etc.)
        try:
            for drive in range(65, 91):  # A-Z
                letter = chr(drive)
                drive_path = Path(f"{letter}:\\")
                if drive_path.exists() and drive_path.is_mount():
                    paths.append(drive_path)
        except Exception:
            pass

        return paths

    def _resolve_path(self, template: Path) -> str:
        """Resolve a path template with environment variables.

        Args:
            template: A Path object containing %VAR% placeholders.

        Returns:
            The resolved file system path as a string.
        """
        return expandvars(str(template))

    def _find_fun_files(self, root_path: str) -> list[Path]:
        """Recursively find all files with .fun extension under a path.

        Args:
            root_path: The directory to search recursively.

        Returns:
            List of Path objects for .fun files found.
        """
        fun_files = []
        root = Path(root_path)

        if not root.exists() or not root.is_dir():
            return fun_files

        try:
            for entry in root.rglob("*.fun"):
                if entry.is_file():
                    fun_files.append(entry)
        except PermissionError:
            pass  # Skip directories we don't have permission to access
        except OSError:
            pass

        return fun_files

    def _kill_malicious_processes(self) -> dict:
        """Kill Jigsaw-related processes using psutil for safe validation.

        Uses psutil to verify that process executables match known malicious paths
        before termination, avoiding false positives on legitimate processes with
        the same name (e.g., legitimate firefox.exe vs Jigsaw's firefox.exe).

        Returns:
            Dictionary with 'findings' and 'actions' lists.
        """
        findings = []
        actions = []

        # Resolve known malicious paths for comparison
        malicious_paths = set()
        for path_template in self.PERSISTENCE_FILES:
            resolved = self._resolve_path(path_template)
            if resolved:
                malicious_paths.add(resolved.lower())

        # Also add TEMP path
        temp_exe = join(environ.get("TEMP", ""), "drpbx.exe")
        malicious_paths.add(temp_exe.lower())

        # Build a set of known Jigsaw parent directories for matching
        malicious_parent_dirs = {dirname(mp).lower() for mp in malicious_paths if dirname(mp)}

        def _is_malicious_process(proc_exe: str) -> bool:
            """Check if an executable path matches known Jigsaw paths.

            A process is considered malicious if its exact path matches a known
            malicious executable, or if it resides in a known Jigsaw parent directory.

            Args:
                proc_exe: The full path of the process executable (lowercase).

            Returns:
                True if the process is confirmed malicious.
            """
            if not proc_exe:
                return False

            # Normalize both paths to handle Windows path differences
            normalized_proc = normpath(proc_exe)

            # Direct path match (normalize both sides for comparison)
            for mal_path in malicious_paths:
                if normalized_proc == normpath(mal_path):
                    return True

            # Check if process is inside any known malicious directory
            proc_dir = dirname(normalized_proc)
            for mal_dir in malicious_parent_dirs:
                normalized_mal_dir = normpath(mal_dir)
                # Exact directory match or process dir starts with malicious dir
                if (proc_dir == normalized_mal_dir or
                    proc_dir.startswith(normalized_mal_dir + "\\") or
                    proc_dir.startswith(normalized_mal_dir + "/")):
                    return True

            return False

        # Single pass through all running processes
        try:
            for proc in process_iter(["pid", "name", "exe"]):
                try:
                    proc_name = (proc.name() or "").lower()
                    if not proc_name:
                        continue

                    # Check if this process matches any known malicious name
                    if proc_name not in self.MALICIOUS_PROCESSES:
                        continue

                    proc_exe = (proc.exe() or "").lower()

                    if _is_malicious_process(proc_exe):
                        try:
                            proc.suspend()
                            proc.kill()
                            actions.append({
                                "action": "process_killed",
                                "process": proc_name,
                                "path": proc_exe,
                                "status": "success",
                                "description": f"Successfully terminated malicious {proc_name} at {proc_exe}",
                            })
                        except NoSuchProcess:
                            findings.append({
                                "type": "process_already_terminated",
                                "process": proc_name,
                                "path": proc_exe,
                                "severity": "info",
                                "description": f"{proc_name} at {proc_exe} already terminated",
                            })
                        except AccessDenied:
                            findings.append({
                                "type": "access_denied",
                                "process": proc_name,
                                "path": proc_exe,
                                "severity": "warning",
                                "description": f"Access denied when trying to kill {proc_name} at {proc_exe}",
                            })
                    else:
                        # Legitimate process with same name - skip it
                        if proc_exe:
                            findings.append({
                                "type": "legitimate_process_skipped",
                                "process": proc_name,
                                "path": proc_exe,
                                "severity": "info",
                                "description": f"Skipping legitimate {proc_name} at {proc_exe}",
                            })

                except (NoSuchProcess, AccessDenied, ZombieProcess):
                    pass  # Process already gone or inaccessible
                except Exception as e:
                    findings.append({
                        "type": "psutil_error",
                        "process": proc_name or "unknown",
                        "severity": "warning",
                        "description": f"Error checking process: {e}",
                    })

        except Exception as e:
            for process_name in self.MALICIOUS_PROCESSES:
                findings.append({
                    "type": "psutil_scan_error",
                    "process": process_name,
                    "severity": "critical",
                    "description": f"Failed to scan processes with psutil: {e}",
                })

        # Report if no malicious processes were found
        if not any(a["action"] == "process_killed" for a in actions):
            for process_name in self.MALICIOUS_PROCESSES:
                findings.append({
                    "type": "no_malicious_process_found",
                    "process": process_name,
                    "severity": "info",
                    "description": f"No malicious {process_name} instances found matching known paths",
                })

        return {"findings": findings, "actions": actions}

    def _delete_persistence_files(self, force: bool = False, dry_run: bool = False) -> dict:
        """Delete Jigsaw persistence files.

        Removes the malicious executables dropped by Jigsaw for persistence.

        Args:
            force: Force deletion without additional checks.
            dry_run: If True, only report what would be done.

        Returns:
            Dictionary with 'findings' and 'actions' lists.
        """
        findings = []
        actions = []

        for path_template in self.PERSISTENCE_FILES:
            file_path = Path(self._resolve_path(path_template))

            if not file_path.exists():
                continue

            findings.append({
                "type": "persistence_file",
                "path": str(file_path),
                "severity": "high",
                "description": f"Jigsaw persistence file detected: {file_path}",
            })

            if dry_run:
                actions.append({
                    "action": "dry_run_delete",
                    "path": str(file_path),
                    "status": "would_delete",
                    "description": f"Would delete: {file_path}",
                })
                continue

            try:
                file_path.unlink()
                actions.append({
                    "action": "persistence_file_removed",
                    "path": str(file_path),
                    "status": "success",
                    "description": f"Successfully removed persistence file: {file_path}",
                })

                # Remove the parent directory if it exists and is safe to delete
                parent_dir = file_path.parent
                resolved_parent = str(parent_dir)

                # Skip removal for TEMP paths (no subfolder to clean) or empty paths
                normalized_parent = normpath(resolved_parent)
                if "TEMP" in normalized_parent.upper():
                    actions.append({
                        "action": "parent_directory_skipped",
                        "path": resolved_parent,
                        "status": "skipped",
                        "description": f"Skipped parent directory removal (TEMP path): {resolved_parent}",
                    })
                    continue

                # Safety check: prevent deletion of critical system paths
                # Only allow removing Jigsaw-created subdirectories (e.g., Drpbx, Frfx)
                normalized_parent_slash = normalized_parent.replace("\\", "/")
                critical_paths_normalized = {
                    str(parent_dir.drive) + "/",  # Root drive (e.g., "C:/")
                    str(Path.home()).replace("\\", "/"),  # User home directory
                    str(Path.home() / "AppData" / "Local").replace("\\", "/"),
                    str(Path.home() / "AppData" / "Roaming").replace("\\", "/"),
                }

                if normalized_parent_slash in critical_paths_normalized:
                    actions.append({
                        "action": "parent_directory_skipped",
                        "path": resolved_parent,
                        "status": "skipped",
                        "description": f"Skipped parent directory removal (critical path): {resolved_parent}",
                    })
                    continue

                if parent_dir.exists():
                    try:
                        rmtree(resolved_parent)
                        actions.append({
                            "action": "persistence_directory_removed",
                            "path": resolved_parent,
                            "status": "success",
                            "description": f"Successfully removed persistence directory: {resolved_parent}",
                        })
                    except (PermissionError, OSError) as e:
                        findings.append({
                            "type": "directory_removal_failed",
                            "path": resolved_parent,
                            "severity": "warning",
                            "description": f"Could not remove persistence directory {resolved_parent}: {e}",
                        })
            except PermissionError as e:
                findings.append({
                    "type": "removal_failed",
                    "path": str(file_path),
                    "severity": "critical",
                    "description": f"Could not delete {file_path}: Permission denied",
                })
            except OSError as e:
                findings.append({
                    "type": "removal_failed",
                    "path": str(file_path),
                    "severity": "critical",
                    "description": f"Could not delete {file_path}: {e}",
                })

        return {"findings": findings, "actions": actions}

    def _remove_registry_persistence(self, force: bool = False, dry_run: bool = False) -> dict:
        """Remove Jigsaw registry persistence entry.

        Deletes the Run key entry that launches Jigsaw on Windows startup.

        Args:
            force: Force removal without additional checks.
            dry_run: If True, only report what would be done.

        Returns:
            Dictionary with 'findings' and 'actions' lists.
        """
        findings = []
        actions = []

        # Resolve the full path that's stored as registry data
        payload_path = self._resolve_path(self.PERSISTENCE_FILES[1])  # Frfx\\firefox.exe

        try:
            reg_subkey = self.REGISTRY_KEY

            with OpenKey(HKEY_CURRENT_USER, reg_subkey, 0, KEY_READ) as handle:
                # Check if the value exists (using REGISTRY_VALUE_NAME, not full path)
                try:
                    value, _ = QueryValueEx(handle, self.REGISTRY_VALUE_NAME)
                    # Value exists - it's malicious

                    findings.append({
                        "type": "malicious_registry_entry",
                        "key": rf"HKEY_CURRENT_USER\{reg_subkey}",
                        "value_name": self.REGISTRY_VALUE_NAME,
                        "value_data": value,
                        "severity": "high",
                        "description": f"Jigsaw registry persistence detected: {self.REGISTRY_VALUE_NAME} -> {value}",
                    })

                    if dry_run:
                        actions.append({
                            "action": "dry_run_registry_delete",
                            "key": rf"HKEY_CURRENT_USER\{reg_subkey}",
                            "value_name": self.REGISTRY_VALUE_NAME,
                            "status": "would_delete",
                            "description": f"Would remove registry value: {self.REGISTRY_VALUE_NAME}",
                        })
                    else:
                        # Open with KEY_SET_VALUE to delete
                        with OpenKey(HKEY_CURRENT_USER, reg_subkey, 0, KEY_SET_VALUE) as h:
                            DeleteValue(h, self.REGISTRY_VALUE_NAME)

                        actions.append({
                            "action": "registry_entry_removed",
                            "key": rf"HKEY_CURRENT_USER\{reg_subkey}",
                            "value_name": self.REGISTRY_VALUE_NAME,
                            "status": "success",
                            "description": f"Successfully removed registry persistence: {self.REGISTRY_VALUE_NAME}",
                        })

                except FileNotFoundError:
                    # Value doesn't exist with the correct name - that's fine
                    findings.append({
                        "type": "registry_value_not_found",
                        "key": rf"HKEY_CURRENT_USER\{reg_subkey}",
                        "value_name": self.REGISTRY_VALUE_NAME,
                        "severity": "info",
                        "description": f"Registry value {self.REGISTRY_VALUE_NAME} not found (already removed or never created)",
                    })

        except PermissionError as e:
            findings.append({
                "type": "registry_access_denied",
                "key": rf"HKEY_CURRENT_USER\{self.REGISTRY_KEY}",
                "severity": "critical",
                "description": f"Access denied when accessing registry: {e}",
            })
        except Exception as e:
            findings.append({
                "type": "registry_error",
                "key": rf"HKEY_CURRENT_USER\{self.REGISTRY_KEY}",
                "severity": "critical",
                "description": f"Registry operation failed: {e}",
            })

        return {"findings": findings, "actions": actions}

    def _restore_encrypted_files(self, search_paths: list[Path], force: bool = False, dry_run: bool = False) -> dict:
        """Restore Jigsaw-encrypted files using AES decryption.

        Finds all .fun files in the specified paths and decrypts them using
        the Jigsaw AES key/IV pair. The decrypted content is written back
        to the original filename (without .fun extension).

        Args:
            search_paths: List of directories to search for .fun files.
            force: Force restoration without additional checks.
            dry_run: If True, only report what would be done.

        Returns:
            Dictionary with 'findings' and 'actions' lists.
        """
        findings = []
        actions = []

        # Collect all .fun files
        fun_files = []
        for search_path in search_paths:
            if not search_path.exists():
                continue
            try:
                found = self._find_fun_files(str(search_path))
                fun_files.extend(found)
            except (PermissionError, OSError):
                continue

        if not fun_files:
            findings.append({
                "type": "no_encrypted_files",
                "severity": "info",
                "description": "No .fun encrypted files found in search paths",
            })
            return {"findings": findings, "actions": actions}

        for file_path in fun_files:
            original_path = Path(str(file_path)[:-4])  # Remove .fun extension

            # Skip if the encrypted file no longer exists (race condition / already removed)
            if not file_path.exists():
                findings.append({
                    "type": "encrypted_file_missing",
                    "path": str(file_path),
                    "severity": "warning",
                    "description": f"Encrypted file {file_path} was found but no longer exists",
                })
                continue

            findings.append({
                "type": "encrypted_file_found",
                "path": str(file_path),
                "original_path": str(original_path),
                "file_size": file_path.stat().st_size,
                "severity": "critical",
                "description": f"Found encrypted file for restoration: {file_path}",
            })

            if dry_run:
                actions.append({
                    "action": "dry_run_restore",
                    "encrypted_path": str(file_path),
                    "original_path": str(original_path),
                    "status": "would_restore",
                    "description": f"Would restore {file_path} -> {original_path}",
                })
                continue

            try:
                # Read encrypted content
                with open(file_path, "rb") as f:
                    encrypted_content = f.read()

                # Validate block size alignment (AES block size is 16 bytes)
                if len(encrypted_content) % 16 != 0:
                    findings.append({
                        "type": "invalid_block_size",
                        "path": str(file_path),
                        "severity": "critical",
                        "description": f"Encrypted file {file_path} is not aligned to AES block boundary ({len(encrypted_content)} bytes, expected multiple of 16)",
                    })
                    continue

                # Create a fresh AES cipher instance for this file (avoid state reuse bug)
                file_cipher = AES.new(self.KEY, AES.MODE_CBC, iv=self.IV)
                decrypted_content = file_cipher.decrypt(encrypted_content)

                # Remove PKCS7 padding (AES uses block size of 16 bytes)
                decrypted_content = self._remove_pkcs7_padding(decrypted_content)

                # Write restored content
                with open(original_path, "wb") as f:
                    f.write(decrypted_content)

                # Remove the encrypted .fun file
                try:
                    file_path.unlink()
                except (PermissionError, OSError):
                    pass  # Keep the .fun file if we can't delete it

                actions.append({
                    "action": "file_restored",
                    "encrypted_path": str(file_path),
                    "original_path": str(original_path),
                    "restored_size": len(decrypted_content),
                    "status": "success",
                    "description": f"Successfully restored: {original_path}",
                })

            except ValueError as e:
                # Invalid padding or corrupted data
                findings.append({
                    "type": "restoration_failed",
                    "path": str(file_path),
                    "severity": "critical",
                    "description": f"Failed to decrypt {file_path}: invalid AES padding or corrupted data - {e}",
                })
            except Exception as e:
                findings.append({
                    "type": "restoration_failed",
                    "path": str(file_path),
                    "severity": "critical",
                    "description": f"Failed to restore {file_path}: {e}",
                })

        return {"findings": findings, "actions": actions}

    @staticmethod
    def _remove_pkcs7_padding(data: bytes) -> bytes:
        """Remove PKCS7 padding from decrypted data.

        AES uses a block size of 16 bytes. PKCS7 padding adds bytes with
        the value equal to the number of padding bytes added.

        Args:
            data: The decrypted byte data with potential PKCS7 padding.

        Returns:
            The unpadded decrypted data.
        """
        if not data:
            return data

        pad_length = data[-1]

        # Validate PKCS7 padding
        if pad_length > 16 or pad_length == 0:
            # Invalid padding - return raw data
            return data

        # Check if the tail matches the expected padding pattern
        if data[-pad_length:] == bytes([pad_length] * pad_length):
            return data[:-pad_length]

        # Padding doesn't match - return raw data (file may not use PKCS7)
        return data

    def _check_persistence(self) -> list[dict]:
        """Check for Jigsaw persistence mechanisms.

        Scans for malicious processes, dropped files, and registry entries.

        Returns:
            List of finding dictionaries describing detected persistence.
        """
        findings = []

        # Check for running malicious processes using psutil
        malicious_paths = set()
        for path_template in self.PERSISTENCE_FILES:
            resolved = self._resolve_path(path_template)
            if resolved:
                malicious_paths.add(resolved.lower())

        temp_exe = join(environ.get("TEMP", ""), "drpbx.exe")
        malicious_paths.add(temp_exe.lower())

        for process_name in self.MALICIOUS_PROCESSES:
            for proc in process_iter(["pid", "name", "exe"]):
                try:
                    if proc.name() and proc.name().lower() == process_name.lower():
                        proc_exe = proc.exe() or ""

                        is_malicious = False
                        for mal_path in malicious_paths:
                            if proc_exe.lower() == mal_path or (proc_exe and proc_exe.lower().startswith(dirname(mal_path).lower())):
                                is_malicious = True
                                break

                        if is_malicious:
                            findings.append({
                                "type": "malicious_process",
                                "process": f"{process_name} (Jigsaw variant)",
                                "path": proc_exe,
                                "severity": "critical",
                                "description": f"Jigsaw persistence process {process_name} detected at {proc_exe}",
                            })
                except (NoSuchProcess, AccessDenied, ZombieProcess):
                    pass

        # Check for persistence files
        for path_template in self.PERSISTENCE_FILES:
            file_path = Path(self._resolve_path(path_template))
            if file_path.exists():
                findings.append({
                    "type": "persistence_file",
                    "path": str(file_path),
                    "severity": "high",
                    "description": f"Jigsaw persistence file detected: {file_path}",
                })

        # Check for registry persistence (best-effort, non-destructive)
        try:
            reg_subkey = self.REGISTRY_KEY
            with OpenKey(HKEY_CURRENT_USER, reg_subkey, 0, KEY_READ) as handle:
                try:
                    value, _ = QueryValueEx(handle, self.REGISTRY_VALUE_NAME)

                    findings.append({
                        "type": "malicious_registry_entry",
                        "key": rf"HKEY_CURRENT_USER\{reg_subkey}",
                        "value_name": self.REGISTRY_VALUE_NAME,
                        "value_data": value,
                        "severity": "high",
                        "description": f"Jigsaw registry persistence detected: {self.REGISTRY_VALUE_NAME} -> {value}",
                    })
                except FileNotFoundError:
                    pass  # Value doesn't exist - that's fine
        except (PermissionError, OSError):
            pass  # Registry check not available or not accessible

        return findings

if __name__ == '__main__':
    module = JigsawScanner()
    result: ModuleResult = module.disinfect_system()
    print(result)